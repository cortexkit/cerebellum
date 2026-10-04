//! Lease timing is stored only in this process; the profile custody record
//! format is not changed.
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use cortexkit_resource_busy::{Holder, ResourceBusy};

struct Timing {
    since_ms: u64,
    deadline: Option<Instant>,
    holder: Holder,
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
                holder: ACQUIRING_HOLDER.with(|holder| holder.borrow().clone()),
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

thread_local! {
    static ACQUIRING_HOLDER: std::cell::RefCell<Holder> = std::cell::RefCell::new(Holder::head());
}

/// Carry the route's head-or-flow identity while acquiring the browser profile
/// lock, without changing its on-disk record. Restore the previous identity even
/// when acquisition unwinds.
pub(crate) fn with_holder<T>(holder: Holder, acquire: impl FnOnce() -> T) -> T {
    struct Restore(Holder);
    impl Drop for Restore {
        fn drop(&mut self) {
            ACQUIRING_HOLDER.with(|holder| *holder.borrow_mut() = self.0.clone());
        }
    }
    let _restore = Restore(ACQUIRING_HOLDER.with(|current| current.replace(holder)));
    acquire()
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
        timing.holder.clone(),
        timing.since_ms,
        remaining,
    );
    detail
        .validate()
        .expect("provider-owned browser profile lease is valid");
    Some(detail)
}
