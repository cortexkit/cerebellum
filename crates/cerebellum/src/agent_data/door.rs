//! Short-lived authenticated routes to engram's session door.

use super::{error, unavailable, ErrorBody, RefusalCode};
use crate::login_capture::vault::BoxFuture;
use serde_json::{json, Value};
use std::{path::PathBuf, time::Duration};
use subc_protocol::{BindIdentity, Frame, FrameType, RouteTarget};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};

pub(crate) trait Door: Send + Sync {
    fn call<'a>(
        &'a self,
        method: &'a str,
        params: Value,
    ) -> BoxFuture<'a, Result<Value, ErrorBody>>;
}

pub(crate) struct DaemonDoor {
    connection_file: PathBuf,
    module_id: String,
}

impl DaemonDoor {
    pub(crate) fn new(connection_file: PathBuf, module_id: String) -> Self {
        Self {
            connection_file,
            module_id,
        }
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value, ErrorBody> {
        let connection = connection_file::read(&self.connection_file).map_err(unavailable)?;
        let endpoint = connection
            .endpoints
            .first()
            .ok_or_else(|| unavailable("no daemon endpoint"))?;
        let mut stream =
            tokio::net::TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port))
                .await
                .map_err(unavailable)?;
        let _ = stream.set_nodelay(true);
        authenticate_client(&mut stream, &connection, Duration::from_secs(5))
            .await
            .map_err(unavailable)?;
        crate::registration::bind_consumer(&mut stream, Duration::from_secs(5))
            .await
            .map_err(unavailable)?;
        let target = RouteTarget::InternalService {
            module_id: "engram".into(),
            service_id: "session-door".into(),
        };
        let identity = BindIdentity::new("cerebellum", "agent-data");
        let open = if subc_os::registration_channel::supervised() {
            crate::channel_route::open(target, &identity, None)
        } else {
            let mut body = json!({"op":"route.open","target":target,"identity":identity});
            if let Some(nonce) = crate::launch_nonce::for_consumer_identity() {
                body["consumer_identity"] =
                    json!({"module_id":self.module_id,"launch_nonce":nonce});
            }
            serde_json::to_vec(&body).map_err(unavailable)?
        };
        let frame = Frame::build(FrameType::Request, crate::control_flags(), 0, 0, 1, open)
            .map_err(unavailable)?;
        write_frame(&mut stream, &frame)
            .await
            .map_err(unavailable)?;
        let opened = receive(&mut stream, 0, 1).await?;
        let channel = opened["route_channel"]
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| unavailable("invalid route channel"))?;
        let epoch = opened["route_epoch"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| unavailable("invalid route epoch"))?;
        let request =
            serde_json::to_vec(&json!({"method":method,"params":params})).map_err(unavailable)?;
        let frame = Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Background, false),
            channel,
            epoch,
            2,
            request,
        )
        .map_err(unavailable)?;
        write_frame(&mut stream, &frame)
            .await
            .map_err(unavailable)?;
        let reply = receive(&mut stream, channel, 2).await?;
        reply
            .get("result")
            .cloned()
            .ok_or_else(|| unavailable("door reply has no result"))
    }
}

async fn receive(
    stream: &mut tokio::net::TcpStream,
    channel: u16,
    corr: u64,
) -> Result<Value, ErrorBody> {
    loop {
        let frame = read_frame(stream)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("door connection closed"))?;
        if frame.header.channel != channel || frame.header.corr != corr {
            continue;
        }
        if frame.header.ty == FrameType::Error {
            return Err(serde_json::from_slice(&frame.body)
                .unwrap_or_else(|_| error(RefusalCode::Unavailable, "malformed door refusal")));
        }
        if frame.header.ty == FrameType::Response {
            return serde_json::from_slice(&frame.body).map_err(unavailable);
        }
    }
}

impl Door for DaemonDoor {
    fn call<'a>(
        &'a self,
        method: &'a str,
        params: Value,
    ) -> BoxFuture<'a, Result<Value, ErrorBody>> {
        Box::pin(async move {
            tokio::time::timeout(Duration::from_secs(15), self.request(method, params))
                .await
                .map_err(|_| unavailable("session door deadline exceeded"))?
        })
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn unhex(text: &str) -> Result<Vec<u8>, ErrorBody> {
    if !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(error(
            RefusalCode::DigestMismatch,
            "invalid hex in marks stream",
        ));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(unavailable))
        .collect()
}
