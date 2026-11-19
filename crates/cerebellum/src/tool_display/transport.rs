//! Short-lived daemon connections for reading the module catalog.

use super::*;
use std::path::PathBuf;
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;

pub(crate) struct DaemonDisplay {
    connection_file: PathBuf,
}

impl DaemonDisplay {
    pub(crate) fn new(connection_file: PathBuf) -> Self {
        Self { connection_file }
    }
}

async fn authenticated(connection_file: &std::path::Path) -> Option<TcpStream> {
    let info = connection_file::read(connection_file).ok()?;
    let endpoint = info.endpoints.first()?;
    let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .ok()?;
    authenticate_client(&mut stream, &info, super::CATALOG_WINDOW)
        .await
        .ok()?;
    Some(stream)
}

/// Read the daemon's catalog on a connection of its own that presents no claim.
///
/// `route.bind` reads the catalog to recognise display modules when the declarer
/// cache expires. The daemon serves `catalog.list` to any authenticated
/// client, and a claim would cost a mint on the module connection for each
/// refresh. The connection never leaves this function and carries nothing but
/// `catalog.list`: a route opened on it would be stamped as an unattested
/// direct client, so anything that acts as this module needs its own claimed
/// connection instead.
async fn read_catalog_unclaimed(
    connection_file: &std::path::Path,
) -> Option<Vec<subc_control::CatalogEntry>> {
    let mut stream = authenticated(connection_file).await?;
    let response = control_call(&mut stream, json!({"op":"catalog.list"})).await?;
    let subc_control::ClientControlResponse::CatalogList { modules, .. } =
        serde_json::from_value(response).ok()?
    else {
        return None;
    };
    Some(modules)
}

/// One request on the control channel, answered by the frame that carries the
/// same correlation id.
async fn control_call(stream: &mut TcpStream, body: Value) -> Option<Value> {
    const CHANNEL: u16 = 0;
    const EPOCH: u32 = 0;
    const CORR: u64 = 1;
    let frame = Frame::build(
        FrameType::Request,
        crate::control_flags(),
        CHANNEL,
        EPOCH,
        CORR,
        serde_json::to_vec(&body).ok()?,
    )
    .ok()?;
    write_frame(stream, &frame).await.ok()?;
    loop {
        let frame = read_frame(stream).await.ok()??;
        if (frame.header.channel, frame.header.epoch, frame.header.corr) == (CHANNEL, EPOCH, CORR) {
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
}
