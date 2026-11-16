//! Short-lived daemon connections; no display route survives a write attempt.

use super::*;
use std::path::PathBuf;
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;

pub(crate) struct DaemonDisplay {
    connection_file: PathBuf,
    module_id: String,
}

impl DaemonDisplay {
    pub(crate) fn new(connection_file: PathBuf, module_id: String) -> Self {
        Self {
            connection_file,
            module_id,
        }
    }

    /// A connection for opening a display route. On a channel launch it first
    /// presents a self claim, so the daemon stamps the route as this module.
    async fn connection(&self) -> Option<TcpStream> {
        let mut stream = authenticated(&self.connection_file).await?;
        crate::registration::bind_consumer(&mut stream, super::WRITE_WINDOW)
            .await
            .ok()?;
        Some(stream)
    }
}

async fn authenticated(connection_file: &std::path::Path) -> Option<TcpStream> {
    let info = connection_file::read(connection_file).ok()?;
    let endpoint = info.endpoints.first()?;
    let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .ok()?;
    authenticate_client(&mut stream, &info, super::WRITE_WINDOW)
        .await
        .ok()?;
    Some(stream)
}

/// Read the daemon's catalog on a connection of its own that presents no claim.
///
/// `route.bind` reads the catalog to recognise display modules, so this runs
/// for nearly every bind. The daemon serves `catalog.list` to any authenticated
/// client, and a claim would cost a mint on the module connection for each
/// bind. The connection never leaves this function and carries nothing but
/// `catalog.list`: a route opened on it would be stamped as an unattested
/// direct client, so anything that acts as this module needs
/// [`DaemonDisplay::connection`] or its own claimed connection instead.
async fn read_catalog_unclaimed(
    connection_file: &std::path::Path,
) -> Option<Vec<subc_control::CatalogEntry>> {
    let mut stream = authenticated(connection_file).await?;
    let response = call(&mut stream, 0, 0, 1, json!({"op":"catalog.list"})).await?;
    let subc_control::ClientControlResponse::CatalogList { modules, .. } =
        serde_json::from_value(response).ok()?
    else {
        return None;
    };
    Some(modules)
}

async fn call(
    stream: &mut TcpStream,
    channel: u16,
    epoch: u32,
    corr: u64,
    body: Value,
) -> Option<Value> {
    let frame = Frame::build(
        FrameType::Request,
        crate::control_flags(),
        channel,
        epoch,
        corr,
        serde_json::to_vec(&body).ok()?,
    )
    .ok()?;
    write_frame(stream, &frame).await.ok()?;
    loop {
        let frame = read_frame(stream).await.ok()??;
        if (frame.header.channel, frame.header.epoch, frame.header.corr) == (channel, epoch, corr) {
            return (frame.header.ty == FrameType::Response)
                .then(|| serde_json::from_slice(&frame.body).ok())
                .flatten();
        }
    }
}

pub(crate) fn declarers(modules: &[subc_control::CatalogEntry]) -> Vec<String> {
    modules
        .iter()
        .filter(|module| {
            module.capabilities.as_ref().is_some_and(|caps| {
                caps.provides
                    .iter()
                    .any(|cap| cap == cortexkit_role_tool_display::TOOL_DISPLAY_CAPABILITY)
            })
        })
        .map(|module| module.module_id.clone())
        .collect()
}

impl Backend for DaemonDisplay {
    fn declarers(&self) -> Future<'_, Option<Vec<String>>> {
        Box::pin(async move {
            let modules = read_catalog_unclaimed(&self.connection_file).await?;
            Some(declarers(&modules))
        })
    }

    fn write<'a>(&'a self, module: &'a str, write: DisplayWrite) -> Future<'a, bool> {
        Box::pin(async move {
            let attempt = async {
                let mut stream = self.connection().await?;
                let open = if subc_os::registration_channel::supervised() {
                    serde_json::from_slice(&crate::channel_route::open(
                        subc_protocol::RouteTarget::ToolProvider {
                            module_id: module.into(),
                        },
                        &subc_protocol::BindIdentity::new("cerebellum", "tool-display"),
                        None,
                    ))
                    .ok()?
                } else {
                    let mut open = json!({
                        "op":"route.open", "target":subc_protocol::RouteTarget::ToolProvider { module_id: module.into() },
                        "identity":subc_protocol::BindIdentity::new("cerebellum", "tool-display"),
                    });
                    // The daemon verifies the launch nonce to attest a module writer,
                    // rather than a direct or unverified client claiming a module id.
                    let nonce = crate::launch_nonce::for_consumer_identity()?;
                    open["consumer_identity"] =
                        json!({"module_id":self.module_id,"launch_nonce":nonce});
                    open
                };
                // Bounded post-reply exception to live-call-only outbound routes:
                // the outer three-second budget drops this socket on every ending.
                let opened = call(&mut stream, 0, 0, 1, open).await?;
                let channel = u16::try_from(opened["route_channel"].as_u64()?).ok()?;
                let epoch = u32::try_from(opened["route_epoch"].as_u64()?).ok()?;
                let describe = call(
                    &mut stream,
                    channel,
                    epoch,
                    2,
                    json!({"name":"role.describe","arguments":{}}),
                )
                .await?;
                let limits: cortexkit_role_tool_display::DisplayLimits =
                    serde_json::from_value(describe["tool_display"].clone()).ok()?;
                cortexkit_role_tool_display::validate_write(&write, &limits).ok()?;
                // Validate locally too, so invalid writes or fields not declared by
                // the record schema do not leave the provider.
                match write.kind {
                    DisplayKind::Record => {
                        cortexkit_role_tool_display::schema::validate_record(&write.body, &schema())
                            .ok()?
                    }
                    DisplayKind::Completion => {
                        cortexkit_role_tool_display::schema::validate_completion(
                            &write.body,
                            &schema(),
                        )
                        .ok()?
                    }
                    _ => return None,
                }
                let result = call(
                    &mut stream,
                    channel,
                    epoch,
                    3,
                    json!({"name":"display.write","arguments":write}),
                )
                .await?;
                // Dropping the socket closes this attempt's route even on refusal.
                Some(matches!(
                    result["result"].as_str(),
                    Some("stored" | "already_stored")
                ))
            };
            attempt.await.unwrap_or(false)
        })
    }
}
