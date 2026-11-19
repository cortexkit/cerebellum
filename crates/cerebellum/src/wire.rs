//! Encode wire frames, check incoming requests, and enqueue replies.

use std::fmt;
use std::ops::ControlFlow;
use std::sync::Arc;

use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::json;
use subc_protocol::{ErrorBody, Flags, Frame, FrameType, Priority};
use tokio::sync::mpsc;

use crate::{tool_display, tool_provider, ModuleError, Planes, RouteSurface};

pub(super) async fn preflight_request(
    frame: &Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<ControlFlow<(), Option<Arc<tool_display::Timing>>>, ModuleError> {
    let header = &frame.header;
    let Some(facts) = planes.routes.get(header.channel, header.epoch) else {
        return Ok(ControlFlow::Continue(None));
    };

    // Fork replies go to the asker, outside the session that holds the grants.
    // Refuse before arming display records or entering the route worker, which
    // can settle pending consent and write call records before dispatch.
    if facts.surface == RouteSurface::Tools && has_fork_id(&frame.body) {
        tool_provider::send_error(
            ErrorBody::new(
                "fork_calls_unsupported",
                "this provider does not serve fork tool calls",
            )
            .with_detail(json!({"field": "fork_id", "retryable": false})),
            (header.ver, header.channel, header.epoch, header.corr),
            writer,
        )
        .await?;
        return Ok(ControlFlow::Break(()));
    }

    Ok(ControlFlow::Continue(
        planes.routes.display.arm(frame, &facts),
    ))
}

fn has_fork_id(body: &[u8]) -> bool {
    // Read just the field's presence and nullness without decoding arguments.
    #[derive(serde::Deserialize)]
    #[serde(field_identifier, rename_all = "snake_case")]
    enum Field {
        ForkId,
        #[serde(other)]
        Other,
    }

    struct ForkMarker;
    impl<'de> Visitor<'de> for ForkMarker {
        type Value = bool;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a tool call object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
            let mut found = false;
            while let Some(field) = map.next_key()? {
                match field {
                    Field::ForkId => found |= map.next_value::<Option<IgnoredAny>>()?.is_some(),
                    Field::Other => {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
            }
            Ok(found)
        }
    }

    let mut decoder = serde_json::Deserializer::from_slice(body);
    matches!(decoder.deserialize_map(ForkMarker), Ok(true)) && decoder.end().is_ok()
}

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

    #[test]
    fn fork_marker_requires_a_non_null_top_level_member() {
        for marked in [
            br#"{"fork_id":"fork_1"}"#.as_slice(),
            br#"{"fork_id":false}"#,
            br#"{"fork_id":{},"fork_id":null}"#,
        ] {
            assert!(has_fork_id(marked));
        }
        for unmarked in [
            br#"{"fork_id":null}"#.as_slice(),
            br#"{"arguments":{"fork_id":"fork_1"}}"#,
            br#"[{"fork_id":"fork_1"}]"#,
        ] {
            assert!(!has_fork_id(unmarked));
        }
    }

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
