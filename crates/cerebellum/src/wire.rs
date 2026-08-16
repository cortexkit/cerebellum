//! Frame encoding and writer-queue helpers used by the subc transport edge.

use std::fmt;

use subc_protocol::{ErrorBody, Flags, Frame, FrameType, Priority};
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum SubcError {
    WriterClosed,
    FrameBuild(subc_protocol::FrameBuildError),
    Json(serde_json::Error),
}

impl fmt::Display for SubcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WriterClosed => write!(f, "subc writer channel closed"),
            Self::FrameBuild(e) => write!(f, "subc frame build error: {e}"),
            Self::Json(e) => write!(f, "subc json error: {e}"),
        }
    }
}

impl std::error::Error for SubcError {}

/// Control-channel flags: not binary, passive priority, not last.
pub fn control_flags() -> Flags {
    Flags::new(false, Priority::Passive, false)
}

/// Build a transport Error frame on the given channel/epoch/corr.
pub fn build_error_frame(
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    code: &str,
    message: &str,
) -> Result<Frame, SubcError> {
    let body = serde_json::to_vec(&ErrorBody {
        code: code.to_string(),
        message: message.to_string(),
        // Absent rather than empty: this builder is the generic transport-error
        // path and knows only a code and a message. A caller reads `detail` as
        // structured facts about THIS failure, so inventing one here would
        // describe the frame builder rather than the error.
        detail: None,
    })
    .map_err(SubcError::Json)?;
    Frame::build_with_version(
        ver,
        FrameType::Error,
        control_flags(),
        channel,
        epoch,
        corr,
        body,
    )
    .map_err(SubcError::FrameBuild)
}

/// Send a frame on the egress channel.
pub async fn send(writer: &mpsc::Sender<Frame>, frame: Frame) -> Result<(), crate::ModuleError> {
    writer
        .send(frame)
        .await
        .map_err(|_| crate::ModuleError::Message("egress channel closed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use subc_protocol::PROTOCOL_VERSION;

    #[test]
    fn control_flags_are_passive_non_binary_non_last() {
        let flags = control_flags();
        assert!(!flags.is_binary());
        assert!(!flags.is_last());
        assert_eq!(flags.priority(), Some(Priority::Passive));
    }

    #[test]
    fn build_error_frame_carries_code_and_message() {
        let frame = build_error_frame(
            PROTOCOL_VERSION,
            0,
            0,
            42,
            "principal_denied",
            "not eligible",
        )
        .unwrap();
        assert_eq!(frame.header.ty, FrameType::Error);
        assert_eq!(frame.header.channel, 0);
        assert_eq!(frame.header.epoch, 0);
        assert_eq!(frame.header.corr, 42);
        let body: ErrorBody = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(body.code, "principal_denied");
        assert_eq!(body.message, "not eligible");
    }
}
