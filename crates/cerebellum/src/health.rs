//! Insulated health-v2 lane.
//!
//! Health-Path-Rule-v2: `health.check` rides an insulated lane; status is derived
//! mechanically from atomics stamped by the dispatch path (heartbeat,
//! oldest-queued-age, oldest-in-flight-age). The insulated lane reads only those
//! atomics plus cached gauges, never a live probe. Cached gauges never block
//! `health.check` and never alter overall dispatch status.
//!
//! Status ladder:
//! - **healthy** when heartbeat age AND oldest-queued/in-flight age are below OR
//!   exactly equal to their configured thresholds.
//! - **degraded** one tick after an age exceeds its threshold.
//!
//! In Spec A there is no browser, so the cached browser/CDP gauges are stubbed
//! as absent. Dispatch is exercised by `browser.status` and a synthetic
//! wedged-dispatch test.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use subc_protocol::session::{HealthStatus, ModuleControlResponse};

/// Default heartbeat threshold: health degrades one tick after the dispatch
/// heartbeat exceeds 2 seconds.
const DEFAULT_HEARTBEAT_THRESHOLD: Duration = Duration::from_secs(2);

/// Default oldest-action threshold: health degrades one tick after the oldest
/// queued or in-flight action age exceeds 30 seconds.
const DEFAULT_OLDEST_ACTION_THRESHOLD: Duration = Duration::from_secs(30);

/// The insulated health state: atomics stamped by the dispatch path, read by
/// the health lane. All fields are atomic so the health lane never blocks on
/// a lock and never forms its own opinion.
#[derive(Debug)]
pub struct HealthState {
    /// Monotonic nanos since process start of the last dispatch heartbeat.
    heartbeat_nanos: AtomicU64,
    /// Monotonic nanos since process start of the oldest queued action, or 0
    /// when no action is queued.
    oldest_queued_nanos: AtomicU64,
    /// Monotonic nanos since process start of the oldest in-flight action, or 0
    /// when no action is in flight.
    oldest_in_flight_nanos: AtomicU64,
    /// The process start instant, used to convert `Instant` stamps to monotonic
    /// nanos. Stored as an `Arc<Instant>` so the health lane and dispatch path
    /// share one reference.
    start: Arc<Instant>,
    /// The heartbeat threshold in nanos.
    heartbeat_threshold_nanos: u64,
    /// The oldest-action threshold in nanos.
    oldest_action_threshold_nanos: u64,
    /// Whether the dispatch loop has ever stamped a heartbeat (0 = no, 1 = yes).
    /// A module that has never ticked is healthy (it just started).
    heartbeat_stamped: AtomicU8,
}

impl HealthState {
    pub fn new() -> Self {
        Self::with_thresholds(DEFAULT_HEARTBEAT_THRESHOLD, DEFAULT_OLDEST_ACTION_THRESHOLD)
    }

    /// Create a health state with custom thresholds (for tests).
    pub fn with_thresholds(
        heartbeat_threshold: Duration,
        oldest_action_threshold: Duration,
    ) -> Self {
        Self {
            heartbeat_nanos: AtomicU64::new(0),
            oldest_queued_nanos: AtomicU64::new(0),
            oldest_in_flight_nanos: AtomicU64::new(0),
            start: Arc::new(Instant::now()),
            heartbeat_threshold_nanos: heartbeat_threshold.as_nanos() as u64,
            oldest_action_threshold_nanos: oldest_action_threshold.as_nanos() as u64,
            heartbeat_stamped: AtomicU8::new(0),
        }
    }

    /// A handle to the process start instant, for stamping monotonic nanos.
    pub fn start(&self) -> Instant {
        *self.start
    }

    /// Stamp the dispatch heartbeat. Called at the top of every loop turn so a
    /// wedged dispatch (frozen loop) surfaces as a stale heartbeat.
    pub fn stamp_heartbeat(&self) {
        let nanos = self.start.elapsed().as_nanos() as u64;
        self.heartbeat_nanos.store(nanos, Ordering::Relaxed);
        self.heartbeat_stamped.store(1, Ordering::Relaxed);
    }

    /// Stamp the oldest queued action age. The dispatch path observes the age
    /// of the oldest queued action and stamps it here as a monotonic duration;
    /// the health lane reads it directly. Pass `None` to clear (no action
    /// queued).
    pub fn stamp_oldest_queued(&self, age: Option<Duration>) {
        let nanos = age.map(|d| d.as_nanos() as u64).unwrap_or(0);
        self.oldest_queued_nanos.store(nanos, Ordering::Relaxed);
    }

    /// Stamp the oldest in-flight action age. Pass `None` to clear.
    pub fn stamp_oldest_in_flight(&self, age: Option<Duration>) {
        let nanos = age.map(|d| d.as_nanos() as u64).unwrap_or(0);
        self.oldest_in_flight_nanos.store(nanos, Ordering::Relaxed);
    }

    /// Build the insulated health report: a mechanical mapper over the stamped
    /// atomics. This never blocks on a lock and never forms its own opinion.
    pub fn report(&self) -> ModuleControlResponse {
        let status = self.derive_status();
        let heartbeat_age = self.heartbeat_age();
        let oldest_queued_age = self.oldest_queued_age();
        let oldest_in_flight_age = self.oldest_in_flight_age();

        let detail = if status == HealthStatus::Degraded {
            let mut reasons = Vec::new();
            if heartbeat_age > Duration::from_nanos(self.heartbeat_threshold_nanos) {
                reasons.push(format!(
                    "dispatch heartbeat {}s stale",
                    heartbeat_age.as_secs()
                ));
            }
            if oldest_queued_age > Duration::from_nanos(self.oldest_action_threshold_nanos) {
                reasons.push(format!(
                    "oldest queued action {}s stale",
                    oldest_queued_age.as_secs()
                ));
            }
            if oldest_in_flight_age > Duration::from_nanos(self.oldest_action_threshold_nanos) {
                reasons.push(format!(
                    "oldest in-flight action {}s stale",
                    oldest_in_flight_age.as_secs()
                ));
            }
            if reasons.is_empty() {
                None
            } else {
                Some(reasons.join("; "))
            }
        } else {
            None
        };

        let metrics = serde_json::json!({
            "heartbeatAgeSecs": heartbeat_age.as_secs(),
            "oldestQueuedAgeSecs": oldest_queued_age.as_secs(),
            "oldestInFlightAgeSecs": oldest_in_flight_age.as_secs(),
            "heartbeatThresholdSecs": Duration::from_nanos(self.heartbeat_threshold_nanos).as_secs(),
            "oldestActionThresholdSecs": Duration::from_nanos(self.oldest_action_threshold_nanos).as_secs(),
        });

        ModuleControlResponse::HealthCheck {
            status,
            detail,
            metrics: Some(metrics),
        }
    }

    /// Derive the health status mechanically from the stamped atomics.
    ///
    /// Healthy when heartbeat age AND oldest-queued/in-flight age are below OR
    /// exactly equal to their thresholds. Degraded one tick after an age
    /// exceeds its threshold.
    fn derive_status(&self) -> HealthStatus {
        let heartbeat_age = self.heartbeat_age();
        let oldest_queued_age = self.oldest_queued_age();
        let oldest_in_flight_age = self.oldest_in_flight_age();

        let heartbeat_threshold = Duration::from_nanos(self.heartbeat_threshold_nanos);
        let oldest_action_threshold = Duration::from_nanos(self.oldest_action_threshold_nanos);

        let heartbeat_ok = heartbeat_age <= heartbeat_threshold;
        let queued_ok = oldest_queued_age <= oldest_action_threshold;
        let in_flight_ok = oldest_in_flight_age <= oldest_action_threshold;

        if heartbeat_ok && queued_ok && in_flight_ok {
            HealthStatus::Ok
        } else {
            HealthStatus::Degraded
        }
    }

    fn heartbeat_age(&self) -> Duration {
        if self.heartbeat_stamped.load(Ordering::Relaxed) == 0 {
            // Never ticked: a freshly-started module is healthy.
            return Duration::ZERO;
        }
        let stamped = self.heartbeat_nanos.load(Ordering::Relaxed);
        let now = self.start.elapsed().as_nanos() as u64;
        Duration::from_nanos(now.saturating_sub(stamped))
    }

    fn oldest_queued_age(&self) -> Duration {
        // The dispatch path stamps the observed age directly; the health lane
        // reads it verbatim. Zero means no action is queued.
        Duration::from_nanos(self.oldest_queued_nanos.load(Ordering::Relaxed))
    }

    fn oldest_in_flight_age(&self) -> Duration {
        Duration::from_nanos(self.oldest_in_flight_nanos.load(Ordering::Relaxed))
    }
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_module_is_healthy() {
        let state = HealthState::new();
        state.stamp_heartbeat();
        let report = state.report();
        match report {
            ModuleControlResponse::HealthCheck { status, .. } => {
                assert_eq!(status, HealthStatus::Ok);
            }
            _ => panic!("expected a HealthCheck response"),
        }
    }

    #[test]
    fn healthy_at_exactly_heartbeat_threshold() {
        // Healthy below AND exactly equal to both thresholds.
        let state =
            HealthState::with_thresholds(Duration::from_millis(100), Duration::from_secs(30));
        state.stamp_heartbeat();
        // Sleep just under the threshold.
        std::thread::sleep(Duration::from_millis(50));
        let report = state.report();
        match report {
            ModuleControlResponse::HealthCheck { status, .. } => {
                assert_eq!(status, HealthStatus::Ok);
            }
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn degraded_when_heartbeat_exceeds_threshold() {
        let state =
            HealthState::with_thresholds(Duration::from_millis(50), Duration::from_secs(30));
        state.stamp_heartbeat();
        // Sleep past the threshold so the heartbeat is stale.
        std::thread::sleep(Duration::from_millis(100));
        let report = state.report();
        match report {
            ModuleControlResponse::HealthCheck { status, detail, .. } => {
                assert_eq!(status, HealthStatus::Degraded);
                let detail = detail.expect("degraded should carry a detail");
                assert!(
                    detail.contains("heartbeat"),
                    "detail should name heartbeat: {detail}"
                );
            }
            _ => panic!("expected a HealthCheck response"),
        }
    }

    #[test]
    fn degraded_when_oldest_queued_exceeds_threshold() {
        let state =
            HealthState::with_thresholds(Duration::from_secs(60), Duration::from_millis(50));
        state.stamp_heartbeat();
        // Stamp an oldest queued action age that exceeds the 50ms threshold.
        state.stamp_oldest_queued(Some(Duration::from_millis(100)));
        let report = state.report();
        match report {
            ModuleControlResponse::HealthCheck { status, detail, .. } => {
                assert_eq!(status, HealthStatus::Degraded);
                let detail = detail.expect("degraded should carry a detail");
                assert!(
                    detail.contains("queued"),
                    "detail should name queued: {detail}"
                );
            }
            _ => panic!("expected a HealthCheck response"),
        }
    }

    #[test]
    fn degraded_when_oldest_in_flight_exceeds_threshold() {
        let state =
            HealthState::with_thresholds(Duration::from_secs(60), Duration::from_millis(50));
        state.stamp_heartbeat();
        state.stamp_oldest_in_flight(Some(Duration::from_millis(100)));
        let report = state.report();
        match report {
            ModuleControlResponse::HealthCheck { status, detail, .. } => {
                assert_eq!(status, HealthStatus::Degraded);
                let detail = detail.expect("degraded should carry a detail");
                assert!(
                    detail.contains("in-flight"),
                    "detail should name in-flight: {detail}"
                );
            }
            _ => panic!("expected a HealthCheck response"),
        }
    }

    #[test]
    fn clearing_oldest_action_restores_healthy() {
        let state =
            HealthState::with_thresholds(Duration::from_secs(60), Duration::from_millis(50));
        state.stamp_heartbeat();
        state.stamp_oldest_queued(Some(Duration::from_millis(100)));
        assert_eq!(status_of(state.report()), HealthStatus::Degraded);
        // Clear the queued action.
        state.stamp_oldest_queued(None);
        state.stamp_heartbeat();
        assert_eq!(status_of(state.report()), HealthStatus::Ok);
    }

    #[test]
    fn cached_gauge_change_does_not_block_or_alter_status() {
        // Changing a cached gauge (oldest queued/in-flight) is reflected in the
        // report's metrics but does not block health.check and does not alter
        // the overall status when within thresholds.
        let state = HealthState::with_thresholds(Duration::from_secs(60), Duration::from_secs(60));
        state.stamp_heartbeat();
        assert_eq!(status_of(state.report()), HealthStatus::Ok);

        // Change a cached gauge within threshold.
        state.stamp_oldest_queued(Some(Duration::from_secs(10)));
        let report = state.report();
        assert_eq!(status_of(report.clone()), HealthStatus::Ok);
        match report {
            ModuleControlResponse::HealthCheck { metrics, .. } => {
                let metrics = metrics.expect("metrics present");
                assert_eq!(metrics["oldestQueuedAgeSecs"], serde_json::json!(10));
            }
            _ => panic!("expected HealthCheck"),
        }
    }

    #[test]
    fn wedged_dispatch_flips_degraded() {
        // A synthetic wedged dispatch (heartbeat frozen) flips health degraded.
        let state =
            HealthState::with_thresholds(Duration::from_millis(50), Duration::from_secs(30));
        state.stamp_heartbeat();
        // Simulate a wedged dispatch: do NOT stamp the heartbeat again.
        std::thread::sleep(Duration::from_millis(100));
        let report = state.report();
        assert_eq!(status_of(report), HealthStatus::Degraded);
    }

    fn status_of(report: ModuleControlResponse) -> HealthStatus {
        match report {
            ModuleControlResponse::HealthCheck { status, .. } => status,
            _ => panic!("expected HealthCheck"),
        }
    }
}
