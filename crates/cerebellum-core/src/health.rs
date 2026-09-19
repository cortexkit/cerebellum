//! The insulated `health.check` execution lane.
//!
//! Health-Path-Rule-v2: `health.check` rides an insulated lane; status is
//! derived mechanically from atomics stamped by the dispatch path (heartbeat,
//! oldest-queued-age, oldest-in-flight-age). The insulated lane reads only
//! those atomics plus cached gauges, never a live probe. Cached gauges never
//! block `health.check` and never alter overall dispatch status.
//!
//! Status ladder:
//! - **healthy** when heartbeat age AND oldest-queued/in-flight age are below
//!   OR exactly equal to their configured thresholds.
//! - **degraded** one tick after an age exceeds its threshold.
//!
//! In Spec A there is no browser, so the cached browser/CDP gauges are stubbed
//! as absent. Dispatch is exercised by `browser.status` and a synthetic
//! wedged-dispatch test.
//!
//! This module is the integration point between the frozen configuration
//! surface ([`crate::config::HealthConfig`]), the monotonic clock abstraction
//! ([`crate::clock`]), and the dispatch timing state
//! ([`crate::dispatch::DispatchTimingState`]). [`HealthState`] owns all three
//! and exposes the API the wire handler in `lib.rs` consumes
//! ([`HealthState::new`], [`HealthState::stamp_heartbeat`],
//! [`HealthState::report`]). The wire-visible report shape
//! (`ModuleControlResponse::HealthCheck { status, detail, metrics }`) and its
//! metric keys are preserved per Spec A.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use subc_protocol::session::{HealthStatus, ModuleControlResponse};

use crate::clock::{MonotonicClock, SystemClock};
use crate::config::HealthConfig;
use crate::dispatch::DispatchTimingState;

/// The insulated health state: a clock, a frozen config, and the dispatch
/// timing atomics. The health lane reads only the atomics (via one clock
/// sample) and performs no browser probe, CDP round trip, dispatch enqueue,
/// gauge read, or lock acquisition that can wait behind an action.
///
/// `HealthState` is the single integration point the wire handler consumes.
/// Construction stamps the initial heartbeat so it is set before registration
/// completes (the caller constructs this before making the module externally
/// visible).
#[derive(Debug)]
pub struct HealthState {
    /// The monotonic clock shared by the dispatch path and the health lane.
    clock: SystemClock,
    /// The frozen health configuration (thresholds).
    config: HealthConfig,
    /// The dispatch timing atomics: heartbeat, oldest queued, oldest
    /// in-flight.
    timing: std::sync::Arc<DispatchTimingState>,
    /// Whether the dispatch loop has ever stamped a heartbeat (0 = no, 1 =
    /// yes). A module that has never ticked is healthy (it just started and
    /// the heartbeat was initialized at construction).
    heartbeat_stamped: AtomicU8,
}

impl HealthState {
    /// Create the health state with default thresholds and the platform
    /// monotonic clock. The heartbeat is stamped at construction so it is set
    /// before registration completes.
    pub fn new() -> Self {
        Self::with_config(HealthConfig::DEFAULT)
    }

    /// Create the health state with a custom [`HealthConfig`] (parsed from the
    /// config file at boot). The heartbeat is stamped at construction.
    pub fn with_config(config: HealthConfig) -> Self {
        let clock = SystemClock::new();
        let timing = std::sync::Arc::new(DispatchTimingState::new(&clock));
        Self {
            clock,
            config,
            timing,
            heartbeat_stamped: AtomicU8::new(0),
        }
    }

    /// Create a health state with custom thresholds (convenience for tests
    /// that predate the config surface). Equivalent to
    /// `with_config(HealthConfig { ... })`.
    pub fn with_thresholds(
        heartbeat_threshold: Duration,
        oldest_action_threshold: Duration,
    ) -> Self {
        Self::with_config(HealthConfig {
            dispatch_heartbeat_stale_ms: heartbeat_threshold.as_millis() as u64,
            queue_age_stale_ms: oldest_action_threshold.as_millis() as u64,
            in_flight_age_stale_ms: oldest_action_threshold.as_millis() as u64,
        })
    }

    /// The frozen health configuration.
    pub fn config(&self) -> HealthConfig {
        self.config
    }

    /// The monotonic clock this state uses internally to age the heartbeat.
    /// Exposed so the dispatch loop can stamp the heartbeat with the SAME clock
    /// the insulated health lane reads, keeping stamped instants and computed
    /// ages on a single epoch (instants from different clock epochs are not
    /// comparable).
    pub fn clock(&self) -> &SystemClock {
        &self.clock
    }

    /// Hold this guard for the entire route request, including writing its reply.
    pub fn enter_request(&self) -> crate::dispatch::InFlightGuard {
        self.timing.enter(&self.clock)
    }

    /// Stamp the dispatch heartbeat. Called at the top of every loop turn so a
    /// wedged dispatch (frozen loop) surfaces as a stale heartbeat.
    pub fn stamp_heartbeat(&self) {
        self.timing.refresh_heartbeat(&self.clock);
        self.heartbeat_stamped.store(1, Ordering::SeqCst);
    }

    /// Publish the enqueue instant of the oldest queued action. Pass `None`
    /// when the queue becomes empty. The dispatch path records the instant the
    /// oldest action was enqueued; the health lane computes the age from one
    /// clock sample.
    pub fn stamp_oldest_queued(&self, instant: Option<crate::clock::MonoInstant>) {
        self.timing.set_oldest_queued(instant);
    }

    /// Publish the start instant of the oldest in-flight action. Pass `None`
    /// when nothing is in-flight.
    pub fn stamp_oldest_in_flight(&self, instant: Option<crate::clock::MonoInstant>) {
        self.timing.set_oldest_in_flight(instant);
    }

    /// Read the current heartbeat instant. Exposed for the deterministic test
    /// harness and for dispatch-path introspection; the wire handler uses
    /// [`Self::report`] which reads this internally.
    pub fn heartbeat_instant(&self) -> crate::clock::MonoInstant {
        self.timing.heartbeat()
    }

    /// Read the oldest queued-action enqueue instant, or `None` if the queue
    /// is empty. Exposed for the deterministic test harness.
    pub fn oldest_queued_instant(&self) -> Option<crate::clock::MonoInstant> {
        self.timing.oldest_queued()
    }

    /// Read the oldest in-flight action start instant, or `None` if nothing
    /// is in-flight. Exposed for the deterministic test harness.
    pub fn oldest_in_flight_instant(&self) -> Option<crate::clock::MonoInstant> {
        self.timing.oldest_in_flight()
    }

    /// Refresh the heartbeat using a custom monotonic clock (for the
    /// deterministic test harness). The wire handler uses
    /// [`Self::stamp_heartbeat`] which uses the internal system clock.
    pub fn stamp_heartbeat_with_clock(&self, clock: &impl crate::clock::MonotonicClock) {
        self.timing.refresh_heartbeat(clock);
        self.heartbeat_stamped.store(1, Ordering::SeqCst);
    }

    /// Build the insulated health report: a mechanical mapper over the stamped
    /// atomics. This never blocks on a lock and never forms its own opinion.
    /// The wire-visible response is `ModuleControlResponse::HealthCheck {
    /// status, detail, metrics }`, and `metrics` retains the established keys
    /// (`heartbeatAgeSecs`, `oldestQueuedAgeSecs`, `oldestInFlightAgeSecs`,
    /// `heartbeatThresholdSecs`, `queueAgeThresholdSecs`, `inFlightAgeThresholdSecs`) expected by
    /// health-check clients.
    pub fn report(&self) -> ModuleControlResponse {
        self.report_ages(self.compute_ages())
    }

    fn report_ages(&self, ages: HealthAges) -> ModuleControlResponse {
        let status = classify(&ages, &self.config);

        let detail = if status == HealthStatus::Degraded {
            let mut reasons = Vec::new();
            if ages.heartbeat_age > self.config.heartbeat_threshold() {
                reasons.push(format!(
                    "dispatch heartbeat {}s stale",
                    ages.heartbeat_age.as_secs()
                ));
            }
            if let Some(q) = ages.oldest_queued_age {
                if q > self.config.queue_age_threshold() {
                    reasons.push(format!("oldest queued action {}s stale", q.as_secs()));
                }
            }
            if let Some(f) = ages.oldest_in_flight_age {
                if f > self.config.in_flight_age_threshold() {
                    reasons.push(format!("oldest in-flight action {}s stale", f.as_secs()));
                }
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
            "inFlightActions": self.timing.in_flight(),
            "awaitingConsent": self.timing.awaiting_consent(),
            "heartbeatAgeSecs": ages.heartbeat_age.as_secs(),
            "oldestQueuedAgeSecs": ages.oldest_queued_age.map(|d| d.as_secs()).unwrap_or(0),
            "oldestInFlightAgeSecs": ages.oldest_in_flight_age.map(|d| d.as_secs()).unwrap_or(0),
            "heartbeatThresholdSecs": self.config.heartbeat_threshold().as_secs(),
            "queueAgeThresholdSecs": self.config.queue_age_threshold().as_secs(),
            "inFlightAgeThresholdSecs": self.config.in_flight_age_threshold().as_secs(),
        });

        ModuleControlResponse::HealthCheck {
            status,
            detail,
            metrics: Some(metrics),
        }
    }

    /// Compute the per-gauge ages at the moment of the health check, from one
    /// monotonic clock sample. Each age is `Some(duration)` when the gauge is
    /// present, or `None` when the set is empty (and so contributes no stale
    /// age). Ages saturate at zero if the clock has not advanced past the
    /// instant.
    fn compute_ages(&self) -> HealthAges {
        let heartbeat_age = if self.heartbeat_stamped.load(Ordering::SeqCst) == 0 {
            // Never explicitly stamped: a freshly-started module is healthy.
            // The heartbeat was initialized at construction, so the age is
            // ~0; treat it as zero to avoid racing construction vs first
            // stamp.
            Duration::ZERO
        } else {
            self.clock.age_since(self.timing.heartbeat())
        };
        let oldest_queued_age = self.timing.oldest_queued().map(|i| self.clock.age_since(i));
        let oldest_in_flight_age = self
            .timing
            .oldest_in_flight()
            .map(|i| self.clock.age_since(i));

        HealthAges {
            heartbeat_age,
            oldest_queued_age,
            oldest_in_flight_age,
        }
    }
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

/// The per-gauge ages at the moment of the health check, for observability.
/// Each age is `Some(duration)` when the gauge is present, or `None` when the
/// set is empty (and so contributes no stale age).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthAges {
    pub heartbeat_age: Duration,
    pub oldest_queued_age: Option<Duration>,
    pub oldest_in_flight_age: Option<Duration>,
}

/// The result of an insulated health check against a custom clock: the status
/// and the ages it was derived from. Used by the deterministic test harness
/// ([`health_check_with_clock`]) which drives the lane with a fake clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub ages: HealthAges,
}

/// Run an insulated health check against a [`HealthState`] using a custom
/// monotonic clock (for deterministic tests). Takes one clock sample and
/// computes each applicable age as `now - instant`, saturating at zero if the
/// clock has not advanced past the instant. Reads only the three published
/// instants from the state's timing; performs no browser probe, CDP round
/// trip, dispatch enqueue, gauge read, or lock acquisition that can wait
/// behind an action.
///
/// A blocked dispatch future cannot prevent this from completing: the
/// dispatch loop's only contribution to health is the three atomics, which
/// are read without waiting.
pub fn health_check_with_clock(state: &HealthState, clock: &impl MonotonicClock) -> HealthReport {
    let heartbeat_age = if state.heartbeat_stamped.load(Ordering::SeqCst) == 0 {
        Duration::ZERO
    } else {
        clock.age_since(state.timing.heartbeat())
    };
    let oldest_queued_age = state.timing.oldest_queued().map(|i| clock.age_since(i));
    let oldest_in_flight_age = state.timing.oldest_in_flight().map(|i| clock.age_since(i));

    let ages = HealthAges {
        heartbeat_age,
        oldest_queued_age,
        oldest_in_flight_age,
    };
    let status = classify(&ages, &state.config);
    HealthReport { status, ages }
}

/// Classify health from the computed ages and the configured thresholds.
///
/// Healthy exactly when every applicable age is `<=` its threshold; degraded
/// when any applicable age is `>` its threshold. Absent queued/in-flight ages
/// are not applicable and never degrade health.
pub fn classify(ages: &HealthAges, config: &HealthConfig) -> HealthStatus {
    let heartbeat_threshold = config.heartbeat_threshold();
    let action_threshold = config.queue_age_threshold();

    if ages.heartbeat_age > heartbeat_threshold {
        return HealthStatus::Degraded;
    }
    if let Some(q) = ages.oldest_queued_age {
        if q > action_threshold {
            return HealthStatus::Degraded;
        }
    }
    if let Some(f) = ages.oldest_in_flight_age {
        if f > config.in_flight_age_threshold() {
            return HealthStatus::Degraded;
        }
    }
    HealthStatus::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;

    #[test]
    fn queue_and_in_flight_ages_have_separate_thresholds() {
        let state = HealthState::with_config(HealthConfig {
            queue_age_stale_ms: 10_000,
            in_flight_age_stale_ms: 50_000,
            ..HealthConfig::default()
        });
        for (queued, flight, expected, reason) in [
            (
                11,
                40,
                HealthStatus::Degraded,
                Some("oldest queued action 11s stale"),
            ),
            (
                9,
                51,
                HealthStatus::Degraded,
                Some("oldest in-flight action 51s stale"),
            ),
            (9, 40, HealthStatus::Ok, None),
        ] {
            let ModuleControlResponse::HealthCheck { status, detail, .. } =
                state.report_ages(HealthAges {
                    heartbeat_age: Duration::ZERO,
                    oldest_queued_age: Some(Duration::from_secs(queued)),
                    oldest_in_flight_age: Some(Duration::from_secs(flight)),
                })
            else {
                panic!("health report")
            };
            assert_eq!(status, expected);
            assert_eq!(detail.as_deref(), reason);
        }
    }

    fn metrics(state: &HealthState) -> serde_json::Value {
        let ModuleControlResponse::HealthCheck {
            metrics: Some(metrics),
            ..
        } = state.report()
        else {
            panic!("health report")
        };
        metrics
    }

    #[derive(Clone, Default)]
    struct SharedClock(std::sync::Arc<std::sync::atomic::AtomicU64>);
    impl MonotonicClock for SharedClock {
        fn now(&self) -> crate::clock::MonoInstant {
            crate::clock::MonoInstant::from_nanos(self.0.load(Ordering::SeqCst))
        }
    }

    #[test]
    fn a_request_parked_on_consent_leaves_the_busy_gauge() {
        let state = HealthState::new();
        let clock = SharedClock::default();
        let first = state.timing.enter(&clock);
        let second = state.timing.enter(&clock);
        clock.0.store(10, Ordering::SeqCst);
        let park_time = clock.now();
        let parked = first.park_on_consent();
        assert_eq!(metrics(&state)["inFlightActions"], 1);
        assert_eq!(metrics(&state)["awaitingConsent"], 1);
        clock.0.store(100, Ordering::SeqCst);
        drop(parked);
        assert_eq!(metrics(&state)["inFlightActions"], 2);
        assert_eq!(metrics(&state)["awaitingConsent"], 0);
        // The older second request still owns the oldest age after the first resumes.
        assert_eq!(state.oldest_in_flight_instant().unwrap().as_nanos(), 0);
        drop(second);
        assert!(state.oldest_in_flight_instant().unwrap() > park_time);
        drop(first);
        assert_eq!(metrics(&state)["inFlightActions"], 0);
    }

    #[test]
    fn a_request_parked_on_consent_does_not_age_the_in_flight_gauge() {
        let state = HealthState::new();
        let mut clock = FakeClock::new();
        let guard = state.timing.enter(&clock);
        let _parked = guard.park_on_consent();
        clock.advance(Duration::from_secs(301));
        let report = health_check_with_clock(&state, &clock);
        assert_eq!(report.status, HealthStatus::Ok);
        assert_eq!(report.ages.oldest_in_flight_age, None);
    }

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
        // Healthy below AND exactly equal to both thresholds. Use a fake
        // clock for determinism (no real sleeps).
        let cfg = HealthConfig {
            dispatch_heartbeat_stale_ms: 100,
            queue_age_stale_ms: 30000,
            in_flight_age_stale_ms: 30000,
        };
        let clock = FakeClock::new();
        let state = HealthState::with_config(cfg);
        // Stamp the heartbeat at epoch zero via the fake clock.
        state.stamp_heartbeat_with_clock(&clock);
        // Advance to exactly the threshold (100ms): healthy.
        let mut clock2 = clock.clone();
        clock2.advance(Duration::from_millis(100));
        let report = health_check_with_clock(&state, &clock2);
        assert_eq!(report.status, HealthStatus::Ok);
        assert_eq!(report.ages.heartbeat_age, Duration::from_millis(100));
    }

    #[test]
    fn degraded_when_heartbeat_exceeds_threshold() {
        let cfg = HealthConfig {
            dispatch_heartbeat_stale_ms: 50,
            queue_age_stale_ms: 30000,
            in_flight_age_stale_ms: 30000,
        };
        let clock = FakeClock::new();
        let state = HealthState::with_config(cfg);
        state.stamp_heartbeat_with_clock(&clock);
        let mut clock2 = clock.clone();
        clock2.advance(Duration::from_millis(100));
        let report = health_check_with_clock(&state, &clock2);
        assert_eq!(report.status, HealthStatus::Degraded);
    }

    #[test]
    fn degraded_when_oldest_queued_exceeds_threshold() {
        let cfg = HealthConfig {
            dispatch_heartbeat_stale_ms: 60000,
            queue_age_stale_ms: 50,
            in_flight_age_stale_ms: 50,
        };
        let clock = FakeClock::new();
        let state = HealthState::with_config(cfg);
        state.stamp_heartbeat_with_clock(&clock);
        // Publish a queued instant at epoch zero, then advance past the 50ms
        // threshold.
        state.stamp_oldest_queued(Some(clock.now()));
        let mut clock2 = clock.clone();
        clock2.advance(Duration::from_millis(100));
        state.stamp_heartbeat_with_clock(&clock2);
        let report = health_check_with_clock(&state, &clock2);
        assert_eq!(report.status, HealthStatus::Degraded);
        // The degradation is from the queued age.
        assert!(report.ages.oldest_queued_age.is_some());
    }

    #[test]
    fn degraded_when_oldest_in_flight_exceeds_threshold() {
        let cfg = HealthConfig {
            dispatch_heartbeat_stale_ms: 60000,
            queue_age_stale_ms: 50,
            in_flight_age_stale_ms: 50,
        };
        let clock = FakeClock::new();
        let state = HealthState::with_config(cfg);
        state.stamp_heartbeat_with_clock(&clock);
        state.stamp_oldest_in_flight(Some(clock.now()));
        let mut clock2 = clock.clone();
        clock2.advance(Duration::from_millis(100));
        state.stamp_heartbeat_with_clock(&clock2);
        let report = health_check_with_clock(&state, &clock2);
        assert_eq!(report.status, HealthStatus::Degraded);
        assert!(report.ages.oldest_in_flight_age.is_some());
    }

    #[test]
    fn clearing_oldest_action_restores_healthy() {
        let cfg = HealthConfig {
            dispatch_heartbeat_stale_ms: 60000,
            queue_age_stale_ms: 50,
            in_flight_age_stale_ms: 50,
        };
        let clock = FakeClock::new();
        let state = HealthState::with_config(cfg);
        state.stamp_heartbeat_with_clock(&clock);
        state.stamp_oldest_queued(Some(clock.now()));
        let mut clock2 = clock.clone();
        clock2.advance(Duration::from_millis(100));
        state.stamp_heartbeat_with_clock(&clock2);
        assert_eq!(
            health_check_with_clock(&state, &clock2).status,
            HealthStatus::Degraded
        );
        // Clear the queued action.
        state.stamp_oldest_queued(None);
        assert_eq!(
            health_check_with_clock(&state, &clock2).status,
            HealthStatus::Ok
        );
    }

    #[test]
    fn cached_gauge_change_does_not_block_or_alter_status() {
        // Changing a cached gauge (oldest queued/in-flight) is reflected in the
        // report's metrics but does not block health.check and does not alter
        // the overall status when within thresholds.
        let cfg = HealthConfig {
            dispatch_heartbeat_stale_ms: 60000,
            queue_age_stale_ms: 60000,
            in_flight_age_stale_ms: 60000,
        };
        let clock = FakeClock::new();
        let state = HealthState::with_config(cfg);
        state.stamp_heartbeat_with_clock(&clock);
        assert_eq!(
            health_check_with_clock(&state, &clock).status,
            HealthStatus::Ok
        );

        // Change a cached gauge within threshold: publish a queued instant at
        // epoch zero and advance 10s (under the 60s threshold).
        state.stamp_oldest_queued(Some(clock.now()));
        let mut clock2 = clock.clone();
        clock2.advance(Duration::from_secs(10));
        let report = health_check_with_clock(&state, &clock2);
        assert_eq!(report.status, HealthStatus::Ok);
        assert_eq!(report.ages.oldest_queued_age, Some(Duration::from_secs(10)));
    }

    #[test]
    fn wedged_dispatch_flips_degraded() {
        // A synthetic wedged dispatch (heartbeat frozen) flips health
        // degraded. Use a fake clock: stamp the heartbeat, then advance past
        // the threshold without re-stamping.
        let cfg = HealthConfig {
            dispatch_heartbeat_stale_ms: 50,
            queue_age_stale_ms: 30000,
            in_flight_age_stale_ms: 30000,
        };
        let clock = FakeClock::new();
        let state = HealthState::with_config(cfg);
        state.stamp_heartbeat_with_clock(&clock);
        let mut clock2 = clock.clone();
        clock2.advance(Duration::from_millis(100));
        let report = health_check_with_clock(&state, &clock2);
        assert_eq!(report.status, HealthStatus::Degraded);
    }

    #[test]
    fn report_carries_pinned_metric_keys() {
        // The wire-visible report must carry the metric keys the conformance
        // fixture pins.
        let state = HealthState::new();
        state.stamp_heartbeat();
        let report = state.report();
        match report {
            ModuleControlResponse::HealthCheck { metrics, .. } => {
                let metrics = metrics.expect("metrics present");
                let obj = metrics.as_object().expect("metrics is an object");
                for key in [
                    "heartbeatAgeSecs",
                    "oldestQueuedAgeSecs",
                    "oldestInFlightAgeSecs",
                    "heartbeatThresholdSecs",
                    "queueAgeThresholdSecs",
                    "inFlightAgeThresholdSecs",
                    "awaitingConsent",
                ] {
                    assert!(obj.contains_key(key), "metrics include {key}");
                }
            }
            _ => panic!("expected HealthCheck response"),
        }
    }
}
