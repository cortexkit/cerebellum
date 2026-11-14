//! Internal binding authority, independent of core's not-yet-installed wire reader.

use std::{collections::BTreeSet, future::Future, pin::Pin, sync::Arc, time::Duration};

use cerebellum_ability::{BoundScope, Token};
use serde_json::Value;

use super::Refusal;
use crate::terminal_arbiter::TerminalArbiter;

const BINDING_LIMIT: Duration = Duration::from_secs(10);
const STOP_POLL: Duration = Duration::from_millis(250);

/// This is an internal projection, not a serialization of core's install reply.
/// Only the wire adapter may turn a well-formed, bound install into this record.
#[derive(Clone)]
pub(super) struct BindingRecord {
    pub install_id: String,
    pub version: String,
    pub entries: Vec<BindingEntry>,
    // Carried catalog availability is not authority for either scope or current
    // source availability. Keep it opaque to the binding check.
    pub _description: Value,
}

#[derive(Clone)]
pub(super) struct BindingEntry {
    pub key: String,
    pub token: Token,
    pub ids: BTreeSet<String>,
}

/// The install provenance must accompany the checked call into journaling.
pub(super) type Install = (String, String);
pub(super) type BindingRead<'a> =
    Pin<Box<dyn Future<Output = Result<BindingRecord, ()>> + Send + 'a>>;

pub(super) trait BindingReader: Send + Sync {
    fn read<'a>(&'a self, flow_id: &'a str) -> BindingRead<'a>;
}

pub(super) struct UnavailableBindingReader;

impl BindingReader for UnavailableBindingReader {
    fn read<'a>(&'a self, _flow_id: &'a str) -> BindingRead<'a> {
        Box::pin(async { Err(()) })
    }
}

pub(super) async fn authorize(
    reader: &dyn BindingReader,
    flow_id: &str,
    key: &str,
    scope: &BoundScope,
    gate: &Arc<TerminalArbiter>,
) -> Result<Option<Install>, Refusal> {
    if gate.gate.stopped() {
        return Ok(None);
    }
    let read = reader.read(flow_id);
    tokio::pin!(read);
    let deadline = tokio::time::Instant::now() + BINDING_LIMIT;
    let record = loop {
        if gate.gate.stopped() {
            return Ok(None);
        }
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => return Err(Refusal::BindingUnavailable),
            result = &mut read => break result.map_err(|_| Refusal::BindingUnavailable)?,
            _ = tokio::time::sleep(STOP_POLL) => {}
        }
    };
    if gate.gate.stopped() {
        return Ok(None);
    }
    let entry = record
        .entries
        .iter()
        .find(|entry| entry.key == key)
        .ok_or(Refusal::OutOfScope)?;
    if entry.token != scope.token() || !scope.ids().is_subset(&entry.ids) {
        return Err(Refusal::OutOfScope);
    }
    Ok(Some((record.install_id, record.version)))
}
