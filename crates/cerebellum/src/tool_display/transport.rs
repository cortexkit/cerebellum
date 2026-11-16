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

    async fn connection(&self) -> Option<TcpStream> {
        let info = connection_file::read(&self.connection_file).ok()?;
        let endpoint = info.endpoints.first()?;
        let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
            .await
            .ok()?;
        authenticate_client(&mut stream, &info, super::WRITE_WINDOW)
            .await
            .ok()?;
        crate::registration::bind_consumer(&mut stream, super::WRITE_WINDOW)
            .await
            .ok()?;
        Some(stream)
    }
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
            let mut stream = self.connection().await?;
            let response = call(&mut stream, 0, 0, 1, json!({"op":"catalog.list"})).await?;
            let subc_control::ClientControlResponse::CatalogList { modules, .. } =
                serde_json::from_value(response).ok()?
            else {
                return None;
            };
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
