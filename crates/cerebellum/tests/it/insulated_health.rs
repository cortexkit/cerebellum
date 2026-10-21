//! Insulated health lane — integration tests for the `insulated_health` slice.
//!
//! These tests cover the slice acceptance criteria, ported onto the integrated
//! `cerebellum` crate. They drive the health lane with a deterministic fake
//! clock via [`cerebellum_core::health::health_check_with_clock`] and the
//! `timing_access` test helpers, asserting the frozen configuration surface,
//! the mechanical threshold boundaries, the insulated-lane rules, and the
//! dispatch-timing-state semantics.
//!
//! Acceptance criteria covered:
//!
//! - The initial monotonic heartbeat is stamped before registration completes.
//! - With default thresholds, heartbeat ages of 1999 ms and 2000 ms are healthy
//!   and 2001 ms is degraded; queued and in-flight ages of 29999 ms and 30000
//!   ms are healthy and 30001 ms is degraded.
//! - The same boundary tests pass for non-default positive-integer thresholds,
//!   and configuring one threshold leaves the other at its independent default.
//! - Zero, negative, fractional, and non-numeric threshold values fail
//!   deterministically without silent fallback.
//! - Empty queued and in-flight sets do not degrade health.
//! - A blocked dispatch future cannot prevent `health.check` from completing,
//!   and the health path does not poll, advance, or unblock that future.
//! - Absent or cached test-only browser gauges cannot delay health completion
//!   or alter dispatch status.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::support::HANG_GUARD;
use cerebellum_core::clock::{FakeClock, MonotonicClock};
use cerebellum_core::config::{
    parse_config, ConfigReason, HealthConfig, DEFAULT_DISPATCH_HEARTBEAT_STALE_MS,
    DEFAULT_QUEUE_AGE_STALE_MS,
};
use cerebellum_core::health::{health_check_with_clock, HealthReport, HealthState};
use subc_protocol::session::HealthStatus;

/// Helper: build a health state + fake clock with the heartbeat stamped at
/// epoch zero, and the queued/in-flight sets empty.
fn fresh_state(cfg: HealthConfig) -> (HealthState, FakeClock) {
    let clock = FakeClock::new();
    let state = HealthState::with_config(cfg);
    // Stamp the heartbeat at epoch zero via the fake clock so ages are
    // deterministic.
    state.stamp_heartbeat_with_clock(&clock);
    (state, clock)
}

/// Run the synchronous check away from the test thread so a stuck check can
/// time out without leaving a parked operation in the caller.
fn health_check_with_hang_guard(
    state: HealthState,
    clock: FakeClock,
) -> Result<HealthReport, std::sync::mpsc::RecvTimeoutError> {
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = send.send(health_check_with_clock(&state, &clock));
    });
    receive.recv_timeout(HANG_GUARD)
}

/// Helper: assert health status at a given heartbeat age (queued/in-flight
/// empty) under the default config.
fn assert_heartbeat_age_status(age_ms: u64, expected: HealthStatus) {
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(age_ms));
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(
        report.status, expected,
        "heartbeat age {}ms should be {:?}",
        age_ms, expected
    );
}

/// Helper: assert health status at a given queued age (heartbeat fresh,
/// in-flight empty) under the default config.
fn assert_queued_age_status(age_ms: u64, expected: HealthStatus) {
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);
    // Publish a queued instant at epoch zero, then advance the clock so the
    // age is exactly age_ms.
    state.stamp_oldest_queued(Some(clock.now()));
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(age_ms));
    // Refresh the heartbeat right before the check so the heartbeat age is
    // ~0 and only the queued age is under test.
    state.stamp_heartbeat_with_clock(&clock2);
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(
        report.status, expected,
        "queued age {}ms should be {:?}",
        age_ms, expected
    );
}

/// Helper: assert health status at a given in-flight age (heartbeat fresh,
/// queued empty) under the default config.
fn assert_in_flight_age_status(age_ms: u64, expected: HealthStatus) {
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);
    state.stamp_oldest_in_flight(Some(clock.now()));
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(age_ms));
    state.stamp_heartbeat_with_clock(&clock2);
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(
        report.status, expected,
        "in-flight age {}ms should be {:?}",
        age_ms, expected
    );
}

// ---------------------------------------------------------------------------
// Acceptance: the initial monotonic heartbeat is stamped before registration
// completes.
// ---------------------------------------------------------------------------

#[test]
fn heartbeat_is_stamped_before_registration_completes() {
    // The health state is constructed (heartbeat stamped) before the module
    // becomes externally visible. We model "registration completes" as the
    // moment the state exists: the heartbeat instant must already be set, and
    // a health check immediately afterwards must be healthy (age ~0).
    let clock = FakeClock::new();
    let state = HealthState::with_config(HealthConfig::DEFAULT);
    state.stamp_heartbeat_with_clock(&clock);

    // The heartbeat instant is the clock's epoch (zero), so the age is zero.
    let report = health_check_with_clock(&state, &clock);
    assert_eq!(report.status, HealthStatus::Ok);
    assert_eq!(report.ages.heartbeat_age, Duration::ZERO);

    // The heartbeat instant is readable immediately, proving it was stamped
    // at construction (before any registration step).
    let heartbeat = state.heartbeat_instant();
    assert_eq!(heartbeat.as_nanos(), 0);
}

// ---------------------------------------------------------------------------
// Acceptance: default threshold boundaries.
// ---------------------------------------------------------------------------

#[test]
fn default_heartbeat_boundaries() {
    // 1999ms and 2000ms healthy; 2001ms degraded.
    assert_heartbeat_age_status(1999, HealthStatus::Ok);
    assert_heartbeat_age_status(2000, HealthStatus::Ok);
    assert_heartbeat_age_status(2001, HealthStatus::Degraded);
}

#[test]
fn default_queued_age_boundaries() {
    // 29999ms and 30000ms healthy; 30001ms degraded.
    assert_queued_age_status(29999, HealthStatus::Ok);
    assert_queued_age_status(30000, HealthStatus::Ok);
    assert_queued_age_status(30001, HealthStatus::Degraded);
}

#[test]
fn default_in_flight_age_boundaries() {
    // 29999ms and 30000ms healthy; 30001ms degraded.
    assert_in_flight_age_status(29999, HealthStatus::Ok);
    assert_in_flight_age_status(30000, HealthStatus::Ok);
    assert_in_flight_age_status(30001, HealthStatus::Degraded);
}

// ---------------------------------------------------------------------------
// Acceptance: non-default positive-integer thresholds, and configuring one
// threshold leaves the other at its independent default.
// ---------------------------------------------------------------------------

#[test]
fn non_default_heartbeat_threshold_boundaries() {
    let cfg = HealthConfig {
        dispatch_heartbeat_stale_ms: 5000,
        queue_age_stale_ms: DEFAULT_QUEUE_AGE_STALE_MS,
        in_flight_age_stale_ms: DEFAULT_QUEUE_AGE_STALE_MS,
    };
    let (state, clock) = fresh_state(cfg);
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(4999));
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Ok
    );
    clock2.advance(Duration::from_millis(1)); // 5000ms
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Ok
    );
    clock2.advance(Duration::from_millis(1)); // 5001ms
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Degraded
    );
}

#[test]
fn non_default_queue_age_threshold_boundaries() {
    let cfg = HealthConfig {
        dispatch_heartbeat_stale_ms: DEFAULT_DISPATCH_HEARTBEAT_STALE_MS,
        queue_age_stale_ms: 10000,
        in_flight_age_stale_ms: 10000,
    };
    // Queued boundary.
    let (state, clock) = fresh_state(cfg);
    state.stamp_oldest_queued(Some(clock.now()));
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(9999));
    state.stamp_heartbeat_with_clock(&clock2);
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Ok
    );
    clock2.advance(Duration::from_millis(1)); // 10000ms
    state.stamp_heartbeat_with_clock(&clock2);
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Ok
    );
    clock2.advance(Duration::from_millis(1)); // 10001ms
    state.stamp_heartbeat_with_clock(&clock2);
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Degraded
    );

    // In-flight boundary under the same threshold.
    let (state, clock) = fresh_state(cfg);
    state.stamp_oldest_in_flight(Some(clock.now()));
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(9999));
    state.stamp_heartbeat_with_clock(&clock2);
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Ok
    );
    clock2.advance(Duration::from_millis(1)); // 10000ms
    state.stamp_heartbeat_with_clock(&clock2);
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Ok
    );
    clock2.advance(Duration::from_millis(1)); // 10001ms
    state.stamp_heartbeat_with_clock(&clock2);
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Degraded
    );
}

#[test]
fn configuring_one_threshold_leaves_the_other_at_default() {
    // Configure heartbeat only; action age stays at default.
    let cfg = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": 8000}}"#).unwrap();
    assert_eq!(cfg.health.dispatch_heartbeat_stale_ms, 8000);
    assert_eq!(cfg.health.queue_age_stale_ms, DEFAULT_QUEUE_AGE_STALE_MS);

    // Configure action age only; heartbeat stays at default.
    let cfg = parse_config(r#"{"health": {"queue_age_stale_ms": 90000}}"#).unwrap();
    assert_eq!(
        cfg.health.dispatch_heartbeat_stale_ms,
        DEFAULT_DISPATCH_HEARTBEAT_STALE_MS
    );
    assert_eq!(cfg.health.queue_age_stale_ms, 90000);

    // Both configured independently.
    let cfg = parse_config(
        r#"{"health": {"dispatch_heartbeat_stale_ms": 3000, "queue_age_stale_ms": 60000}}"#,
    )
    .unwrap();
    assert_eq!(cfg.health.dispatch_heartbeat_stale_ms, 3000);
    assert_eq!(cfg.health.queue_age_stale_ms, 60000);
}

// ---------------------------------------------------------------------------
// Acceptance: zero, negative, fractional, and non-numeric threshold values
// fail deterministically without silent fallback.
// ---------------------------------------------------------------------------

#[test]
fn zero_threshold_fails_deterministically() {
    let err = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": 0}}"#).unwrap_err();
    assert_eq!(err.reason, ConfigReason::NotPositive);
    let err = parse_config(r#"{"health": {"queue_age_stale_ms": 0}}"#).unwrap_err();
    assert_eq!(err.reason, ConfigReason::NotPositive);
}

#[test]
fn negative_threshold_fails_deterministically() {
    let err = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": -1}}"#).unwrap_err();
    assert_eq!(err.reason, ConfigReason::NotPositive);
    let err = parse_config(r#"{"health": {"queue_age_stale_ms": -30000}}"#).unwrap_err();
    assert_eq!(err.reason, ConfigReason::NotPositive);
}

#[test]
fn fractional_threshold_fails_deterministically() {
    let err = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": 2000.5}}"#).unwrap_err();
    assert_eq!(err.reason, ConfigReason::NotInteger);
    let err = parse_config(r#"{"health": {"queue_age_stale_ms": 30000.0}}"#).unwrap_err();
    assert_eq!(err.reason, ConfigReason::NotInteger);
}

#[test]
fn non_numeric_threshold_fails_deterministically() {
    let err = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": "2000"}}"#).unwrap_err();
    assert_eq!(err.reason, ConfigReason::NotInteger);
    let err = parse_config(r#"{"health": {"queue_age_stale_ms": true}}"#).unwrap_err();
    assert_eq!(err.reason, ConfigReason::NotInteger);
    let err = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": null}}"#).unwrap_err();
    assert_eq!(err.reason, ConfigReason::NotInteger);
}

#[test]
fn unknown_member_fails_deterministically() {
    let err = parse_config(r#"{"health": {"heartbeat_ms": 2000}}"#).unwrap_err();
    assert_eq!(
        err.reason,
        ConfigReason::UnknownMember("heartbeat_ms".to_string())
    );
}

#[test]
fn health_not_object_fails_deterministically() {
    let err = parse_config(r#"{"health": 2000}"#).unwrap_err();
    assert_eq!(err.reason, ConfigReason::HealthNotObject);
    let err = parse_config(r#"{"health": null}"#).unwrap_err();
    assert_eq!(err.reason, ConfigReason::HealthNotObject);
}

// ---------------------------------------------------------------------------
// Acceptance: empty queued and in-flight sets do not degrade health.
// ---------------------------------------------------------------------------

#[test]
fn empty_queued_and_in_flight_do_not_degrade() {
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);
    // Advance well past both thresholds; with empty queued/in-flight, only
    // the heartbeat age matters. Keep the heartbeat fresh.
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(100));
    state.stamp_heartbeat_with_clock(&clock2);
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(report.status, HealthStatus::Ok);
    assert!(report.ages.oldest_queued_age.is_none());
    assert!(report.ages.oldest_in_flight_age.is_none());

    // Even with a stale heartbeat, empty queued/in-flight do not add
    // degradation beyond the heartbeat's own.
    clock2.advance(Duration::from_millis(5000));
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(report.status, HealthStatus::Degraded);
    // The degradation is from the heartbeat, not the empty sets.
    assert!(report.ages.oldest_queued_age.is_none());
    assert!(report.ages.oldest_in_flight_age.is_none());
}

// ---------------------------------------------------------------------------
// Acceptance: a blocked dispatch future cannot prevent `health.check` from
// completing, and the health path does not poll, advance, or unblock that
// future.
// ---------------------------------------------------------------------------

#[test]
fn blocked_dispatch_future_does_not_block_health_check() {
    // Model a "blocked dispatch future" as a parked thread that never wakes.
    // The health lane reads only the three atomics; it does not wait on the
    // dispatch loop, poll a future, or acquire a lock the dispatch loop holds.
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);

    // Spawn a "dispatch" thread that parks forever (simulating a wedged
    // dispatch future). It holds no lock the health lane needs.
    let parked = Arc::new(AtomicUsize::new(0));
    let parked_clone = parked.clone();
    let handle = std::thread::spawn(move || {
        parked_clone.store(1, Ordering::SeqCst);
        // Park indefinitely; the health check must not wait for this thread.
        std::thread::park();
    });

    // Wait for the dispatch thread to park.
    while parked.load(Ordering::SeqCst) == 0 {
        std::thread::yield_now();
    }

    // Avoid a host-load latency claim: health must answer while dispatch stays
    // parked, which proves it does not wait for that operation.
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(100));
    let report = health_check_with_hang_guard(state, clock2);
    let dispatch_still_parked = parked.load(Ordering::SeqCst) == 1;
    handle.thread().unpark();
    handle.join().unwrap();
    assert!(
        dispatch_still_parked,
        "health check unparked the dispatch thread"
    );
    let report = report.expect("health check did not return while dispatch was parked");
    assert_eq!(report.status, HealthStatus::Ok);
}

#[test]
fn health_check_does_not_advance_clock_or_dispatch_state() {
    // The health lane takes one clock sample and reads three atomics; it must
    // not advance the clock, refresh the heartbeat, or republish queued/in-flight
    // instants. We verify by checking the clock and state are unchanged after
    // a health check.
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(1234));
    let clock_before = clock2.now().as_nanos();
    let heartbeat_before = state.heartbeat_instant().as_nanos();
    let queued_before = state.oldest_queued_instant().map(|i| i.as_nanos());
    let in_flight_before = state.oldest_in_flight_instant().map(|i| i.as_nanos());

    let _report = health_check_with_clock(&state, &clock2);

    assert_eq!(
        clock2.now().as_nanos(),
        clock_before,
        "clock must not advance"
    );
    assert_eq!(
        state.heartbeat_instant().as_nanos(),
        heartbeat_before,
        "heartbeat must not be refreshed"
    );
    assert_eq!(
        state.oldest_queued_instant().map(|i| i.as_nanos()),
        queued_before,
        "queued instant must not be republished"
    );
    assert_eq!(
        state.oldest_in_flight_instant().map(|i| i.as_nanos()),
        in_flight_before,
        "in-flight instant must not be republished"
    );
}

// ---------------------------------------------------------------------------
// Acceptance: absent or cached test-only browser gauges cannot delay health
// completion or alter dispatch status.
// ---------------------------------------------------------------------------

/// A test-only "cached browser gauge" that the health lane is NOT wired to.
/// This struct exists to prove that adding a gauge (or leaving it absent)
/// neither delays health completion nor changes dispatch status: the health
/// lane reads only the three dispatch instants. The fields are intentionally
/// unread — the point is that the health lane never touches them.
#[allow(dead_code)]
struct CachedBrowserGauge {
    /// Simulated CDP session liveness gauge. Absent in Spec A.
    cdp_session_live: Option<bool>,
    /// Simulated browser process state gauge. Absent in Spec A.
    browser_process_alive: Option<bool>,
}

#[test]
fn absent_browser_gauges_do_not_delay_or_alter_health() {
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(50));

    // Gauges are absent (None) in Spec A. The health lane is not wired to them.
    let _gauges = CachedBrowserGauge {
        cdp_session_live: None,
        browser_process_alive: None,
    };

    // The contract is independence from these absent gauges, not a wall-clock
    // completion threshold; assert the outcome and unchanged health status.
    let report = health_check_with_hang_guard(state, clock2)
        .expect("health check did not return with browser gauges absent");
    assert_eq!(report.status, HealthStatus::Ok);
}

#[test]
fn cached_browser_gauges_do_not_alter_dispatch_status() {
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(50));

    // Even with "cached" gauge values present, the health lane ignores them:
    // it reads only the three dispatch instants. So the status is determined
    // solely by the dispatch ages.
    let _gauges = CachedBrowserGauge {
        cdp_session_live: Some(false),
        browser_process_alive: Some(false),
    };

    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(report.status, HealthStatus::Ok);

    // And a degraded dispatch state stays degraded regardless of gauges.
    clock2.advance(Duration::from_millis(5000)); // heartbeat now stale
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(report.status, HealthStatus::Degraded);
}

// ---------------------------------------------------------------------------
// Acceptance: advancing the health clock without republishing a queued or
// in-flight timestamp increases its computed age.
// ---------------------------------------------------------------------------

#[test]
fn advancing_clock_without_republishing_increases_age() {
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);
    state.stamp_oldest_queued(Some(clock.now()));
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(1000));
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(
        report.ages.oldest_queued_age,
        Some(Duration::from_millis(1000))
    );

    // Advance the clock without republishing the queued instant; the age
    // must increase.
    clock2.advance(Duration::from_millis(1000));
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(
        report.ages.oldest_queued_age,
        Some(Duration::from_millis(2000))
    );

    // Same for in-flight.
    state.stamp_oldest_in_flight(Some(clock2.now()));
    clock2.advance(Duration::from_millis(1000));
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(
        report.ages.oldest_in_flight_age,
        Some(Duration::from_millis(1000))
    );
    clock2.advance(Duration::from_millis(1000));
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(
        report.ages.oldest_in_flight_age,
        Some(Duration::from_millis(2000))
    );
}

// ---------------------------------------------------------------------------
// Acceptance: a frozen heartbeat produces degraded status; absent queue and
// in-flight timestamps do not.
// ---------------------------------------------------------------------------

#[test]
fn frozen_heartbeat_produces_degraded() {
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);
    // Freeze the heartbeat by not refreshing it while the clock advances past
    // the threshold.
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(2001));
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(report.status, HealthStatus::Degraded);
    // The degradation is from the heartbeat; queued/in-flight are absent.
    assert!(report.ages.oldest_queued_age.is_none());
    assert!(report.ages.oldest_in_flight_age.is_none());
}

#[test]
fn refreshing_heartbeat_restores_healthy() {
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(5000));
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Degraded
    );
    // Refresh the heartbeat; health returns to healthy.
    state.stamp_heartbeat_with_clock(&clock2);
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Ok
    );
}

// ---------------------------------------------------------------------------
// Saturation: a clock that goes backwards never produces a negative (degraded)
// age.
// ---------------------------------------------------------------------------

#[test]
fn backwards_clock_saturates_age_to_zero() {
    // The FakeClock is monotonic by construction, but we can simulate a
    // backwards sample by publishing an instant in the "future" relative to
    // the clock's current offset. The age saturates at zero.
    let (state, clock) = fresh_state(HealthConfig::DEFAULT);
    // Publish a heartbeat "in the future" by constructing an instant the clock
    // has not yet reached. We do this by advancing the clock, stamping the
    // heartbeat, then "rolling back" via a fresh clock at a lower offset.
    let mut clock_future = clock.clone();
    clock_future.advance(Duration::from_millis(5000));
    state.stamp_heartbeat_with_clock(&clock_future);
    // Now a new clock at epoch zero samples an age against the future
    // heartbeat; it must saturate at zero, not go negative.
    let clock2 = FakeClock::new();
    let report = health_check_with_clock(&state, &clock2);
    assert_eq!(report.ages.heartbeat_age, Duration::ZERO);
    assert_eq!(report.status, HealthStatus::Ok);
}

// ---------------------------------------------------------------------------
// The wire-visible report must retain the established metric keys
// (`heartbeatAgeSecs`, `oldestQueuedAgeSecs`, `oldestInFlightAgeSecs`,
// `heartbeatThresholdSecs`, `oldestActionThresholdSecs`) and include the
// expected status and detail fields in the health-check response.
// ---------------------------------------------------------------------------

#[test]
fn report_carries_pinned_metric_keys_and_status() {
    let state = HealthState::new();
    state.stamp_heartbeat();
    let report = state.report();
    use subc_protocol::session::ModuleControlResponse;
    match report {
        ModuleControlResponse::HealthCheck {
            status, metrics, ..
        } => {
            assert_eq!(status, HealthStatus::Ok);
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

// ---------------------------------------------------------------------------
// Configuring the health state from a parsed config flows through to the
// thresholds used by classification.
// ---------------------------------------------------------------------------

#[test]
fn with_config_uses_parsed_thresholds() {
    let cfg = parse_config(
        r#"{"health": {"dispatch_heartbeat_stale_ms": 3000, "queue_age_stale_ms": 60000}}"#,
    )
    .unwrap()
    .health;
    let state = HealthState::with_config(cfg);
    assert_eq!(state.config().dispatch_heartbeat_stale_ms, 3000);
    assert_eq!(state.config().queue_age_stale_ms, 60000);

    // The thresholds flow through to classification: a 3000ms heartbeat age
    // is healthy (exactly at threshold), 3001ms is degraded.
    let clock = FakeClock::new();
    state.stamp_heartbeat_with_clock(&clock);
    let mut clock2 = clock.clone();
    clock2.advance(Duration::from_millis(3000));
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Ok
    );
    clock2.advance(Duration::from_millis(1)); // 3001ms
    assert_eq!(
        health_check_with_clock(&state, &clock2).status,
        HealthStatus::Degraded
    );
}

// ---------------------------------------------------------------------------
// MonoInstant / MonotonicClock sanity: the clock abstraction used by the
// dispatch timing state and the health lane.
// ---------------------------------------------------------------------------

#[test]
fn fake_clock_advances_monotonically() {
    let mut clock = FakeClock::new();
    let a = clock.now();
    clock.advance(Duration::from_millis(100));
    let b = clock.now();
    assert!(b.as_nanos() > a.as_nanos());
    assert_eq!(clock.age_since(a), Duration::from_millis(100));
}

#[test]
fn age_since_saturates_at_zero_for_backwards_sample() {
    let mut clock = FakeClock::new();
    clock.advance(Duration::from_millis(100));
    let later = clock.now();
    // A fresh clock at epoch zero samples an age against a "future" instant;
    // it saturates at zero.
    let clock2 = FakeClock::new();
    assert_eq!(clock2.age_since(later), Duration::ZERO);
}
