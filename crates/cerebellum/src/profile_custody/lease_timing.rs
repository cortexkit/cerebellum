//! Lease timing is stored only in this process; the profile custody record
//! format is not changed.
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use cortexkit_resource_busy::{Holder, ResourceBusy};

struct Timing {
    since_ms: u64,
    deadline: Option<Instant>,
}
static TIMINGS: OnceLock<Mutex<HashMap<String, Timing>>> = OnceLock::new();

pub(crate) fn acquired(holder_id: &str) {
    TIMINGS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            holder_id.to_owned(),
            Timing {
                since_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
                    .min(u64::MAX as u128) as u64,
                deadline: None,
            },
        );
}

pub(crate) fn deadline(holder_id: &str, deadline: Instant) {
    if let Some(timing) = TIMINGS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_mut(holder_id)
    {
        timing.deadline = Some(deadline);
    }
}

pub(crate) fn released(holder_id: &str) {
    TIMINGS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(holder_id);
}

/// When browser flows are supported, map their route's flow_id to a Holder here.
fn browser_profile_holder() -> Holder {
    Holder::head()
}

pub(crate) fn refusal(holder_id: &str) -> Option<ResourceBusy> {
    let timings = TIMINGS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let timing = timings.get(holder_id)?;
    let remaining = timing
        .deadline?
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let detail = ResourceBusy::new(
        "browser_profile",
        browser_profile_holder(),
        timing.since_ms,
        remaining,
    );
    detail
        .validate()
        .expect("provider-owned browser profile lease is valid");
    Some(detail)
}
