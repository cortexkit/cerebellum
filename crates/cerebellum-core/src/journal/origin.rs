//! Who really asked for a tool call that another module relayed, as the audit
//! records write it down.
//!
//! A relaying module (Prefrontal, for every agent call) is the route's own
//! principal, so without this every relayed call reads as that module's call.
//! The request's `origin` member names the caller behind it. It is the
//! relaying module's claim and nothing checks it, so it is recorded for
//! attribution only: admission, call-key lookups and cancellation stay keyed
//! on the route's own principal and bind facts and never read this value.
//!
//! The recorded attribution carries only `carrier` and `call_key`, each
//! within the protocol's own bounds. Any other member a caller sends is
//! dropped while decoding, so no caller-chosen text beyond those bounds can
//! reach an audit record.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use subc_protocol::tool_call::{
    validate_call_key, validate_call_origin, CallOrigin, MessagePosition,
};
use subc_protocol::Principal;

/// The marker an audit record carries when a call arrived with an origin
/// that failed validation. The origin itself is then not recorded at all.
pub const ORIGIN_INVALID_MARKER: &str = "origin_invalid";

/// The longest carrier `module_id` recorded, in bytes.
///
/// The wire crate bounds an origin's `call_key` and leaves the carrier's
/// module id to the daemon, which refuses to register a module id longer
/// than 255 bytes. Nothing longer can name a real module, so a longer one is
/// refused here rather than written into an audit record.
pub const ORIGIN_MODULE_ID_MAX_LEN: usize = 255;

static ORIGIN_INVALID_COUNT: AtomicU64 = AtomicU64::new(0);
static MESSAGE_POSITION_INVALID_COUNT: AtomicU64 = AtomicU64::new(0);

/// Indices larger than a small integer are not useful for a bounded ordering
/// window. Reject only the hint, never the call or its caller attribution.
pub const MESSAGE_INDEX_MAX: u32 = u16::MAX as u32;

pub fn message_position_invalid_count() -> u64 {
    MESSAGE_POSITION_INVALID_COUNT.load(Ordering::Relaxed)
}

/// Decode the ordering hint independently of attribution. The opaque message
/// id stays in memory only; audit records keep the index and ordering outcome.
pub fn message_position_from_request_member(member: Option<&Value>) -> Option<MessagePosition> {
    let position = member?
        .get("message_position")
        .filter(|value| !value.is_null())?;
    match MessagePosition::deserialize(position) {
        Ok(position)
            if position.index <= MESSAGE_INDEX_MAX
                && validate_call_key(&position.message_id).is_ok() =>
        {
            Some(position)
        }
        _ => {
            MESSAGE_POSITION_INVALID_COUNT.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// How a computer call obtained its conversation position. This is audit
/// metadata, not a tool reply or an authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputerOrdering {
    Position,
    Arrival,
    SkippedGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputerOrderRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_index: Option<u32>,
    pub ordering: ComputerOrdering,
}

/// How many requests in this process carried an origin that failed
/// validation and were recorded with [`ORIGIN_INVALID_MARKER`] instead.
pub fn origin_invalid_count() -> u64 {
    ORIGIN_INVALID_COUNT.load(Ordering::Relaxed)
}

/// The caller behind a relayed call, in the same shape the daemon stamps a
/// route's principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OriginCarrier {
    Reserved { module_id: String },
    Direct,
    Unverified,
}

/// What one request said about the caller behind it.
///
/// Serialized into audit records as an `origin` member that is omitted when
/// the request named no origin, `{"status":"relayed","carrier":…,"call_key":…}`
/// when it named a valid one, and `{"status":"origin_invalid"}` when it named
/// one that failed validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CallOriginRecord {
    /// The request named no origin: the route's principal is the caller.
    #[default]
    Absent,
    /// The request named a valid origin.
    Relayed {
        carrier: OriginCarrier,
        call_key: String,
    },
    /// The request named an origin that failed validation. Nothing from it
    /// is kept, not even the parts that would have passed.
    OriginInvalid,
}

impl CallOriginRecord {
    /// Read a tool request's `origin` member.
    ///
    /// Never refuses the call: an origin is attribution, not authorization,
    /// so one that fails validation costs only the attribution. It is recorded
    /// as [`Self::OriginInvalid`] and counted in [`origin_invalid_count`], and
    /// the call is served exactly as it would have been without it.
    pub fn from_request_member(member: Option<&Value>) -> Self {
        let Some(member) = member.filter(|member| !member.is_null()) else {
            return Self::Absent;
        };
        match Self::validated(member) {
            Some(record) => record,
            None => {
                ORIGIN_INVALID_COUNT.fetch_add(1, Ordering::Relaxed);
                Self::OriginInvalid
            }
        }
    }

    fn validated(member: &Value) -> Option<Self> {
        // A malformed ordering hint must not discard otherwise valid caller
        // attribution. Validate the two independently, and never persist the id.
        let mut attribution = member.as_object()?.clone();
        attribution.remove("message_position");
        let origin = CallOrigin::deserialize(Value::Object(attribution)).ok()?;
        validate_call_origin(&origin).ok()?;
        let carrier = match origin.carrier {
            Principal::Reserved { module_id } => {
                if !valid_module_id(&module_id) {
                    return None;
                }
                OriginCarrier::Reserved { module_id }
            }
            Principal::Direct => OriginCarrier::Direct,
            Principal::Unverified => OriginCarrier::Unverified,
        };
        Some(Self::Relayed {
            carrier,
            call_key: origin.call_key,
        })
    }

    /// Whether the request named no origin; such a record writes no member.
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

/// A module id fit to record: 1 to [`ORIGIN_MODULE_ID_MAX_LEN`] bytes of
/// printable ASCII without spaces, the character rule the wire crate applies
/// to the origin's `call_key`, so nothing invisible or ambiguous enters a
/// record a person reads.
fn valid_module_id(module_id: &str) -> bool {
    !module_id.is_empty()
        && module_id.len() <= ORIGIN_MODULE_ID_MAX_LEN
        && module_id.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn relayed(module_id: &str, call_key: &str) -> CallOriginRecord {
        CallOriginRecord::Relayed {
            carrier: OriginCarrier::Reserved {
                module_id: module_id.to_string(),
            },
            call_key: call_key.to_string(),
        }
    }

    #[test]
    fn a_valid_origin_keeps_exactly_its_protocol_members() {
        let record = CallOriginRecord::from_request_member(Some(&json!({
            "carrier": {"kind": "reserved", "module_id": "agent-host"},
            "call_key": "agent:call-1",
            "note": "free text the protocol does not define",
        })));
        assert_eq!(record, relayed("agent-host", "agent:call-1"));
        assert_eq!(
            serde_json::to_value(&record).unwrap(),
            json!({
                "status": "relayed",
                "carrier": {"kind": "reserved", "module_id": "agent-host"},
                "call_key": "agent:call-1",
            })
        );
        for (carrier, expected) in [
            (json!({"kind": "direct"}), OriginCarrier::Direct),
            (json!({"kind": "unverified"}), OriginCarrier::Unverified),
        ] {
            assert_eq!(
                CallOriginRecord::from_request_member(Some(
                    &json!({"carrier": carrier, "call_key": "k"})
                )),
                CallOriginRecord::Relayed {
                    carrier: expected,
                    call_key: "k".to_string(),
                }
            );
        }
    }

    #[test]
    fn no_origin_and_a_null_origin_are_absent_and_not_counted_invalid() {
        assert_eq!(
            CallOriginRecord::from_request_member(None),
            CallOriginRecord::Absent
        );
        assert_eq!(
            CallOriginRecord::from_request_member(Some(&Value::Null)),
            CallOriginRecord::Absent
        );
    }

    #[test]
    fn an_origin_outside_the_protocol_bounds_is_invalid_and_counted() {
        let too_long_key = "k".repeat(257);
        let too_long_module = "m".repeat(ORIGIN_MODULE_ID_MAX_LEN + 1);
        let cases = [
            json!("prefrontal"),
            json!({"call_key": "k"}),
            json!({"carrier": {"kind": "reserved", "module_id": "m"}}),
            json!({"carrier": {"kind": "nobody"}, "call_key": "k"}),
            json!({"carrier": {"kind": "direct"}, "call_key": ""}),
            json!({"carrier": {"kind": "direct"}, "call_key": "has space"}),
            json!({"carrier": {"kind": "direct"}, "call_key": too_long_key}),
            json!({"carrier": {"kind": "reserved", "module_id": ""}, "call_key": "k"}),
            json!({"carrier": {"kind": "reserved", "module_id": "a b"}, "call_key": "k"}),
            json!({"carrier": {"kind": "reserved", "module_id": too_long_module}, "call_key": "k"}),
        ];
        for case in cases {
            let before = origin_invalid_count();
            assert_eq!(
                CallOriginRecord::from_request_member(Some(&case)),
                CallOriginRecord::OriginInvalid,
                "{case}"
            );
            // Other tests in this process may count too, so only growth is
            // checked.
            assert!(origin_invalid_count() > before, "{case} was not counted");
        }
        assert_eq!(
            serde_json::to_value(CallOriginRecord::OriginInvalid).unwrap(),
            json!({"status": ORIGIN_INVALID_MARKER})
        );
    }

    #[test]
    fn the_longest_bounded_members_are_kept() {
        let key = "k".repeat(256);
        let module = "m".repeat(ORIGIN_MODULE_ID_MAX_LEN);
        assert_eq!(
            CallOriginRecord::from_request_member(Some(&json!({
                "carrier": {"kind": "reserved", "module_id": module},
                "call_key": key,
            }))),
            relayed(&module, &key)
        );
    }
}
