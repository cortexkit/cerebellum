//! What a health.check reply costs, measured rather than argued.
//!
//! The daemon's prober cannot tell "busy" from "dead": it cancels its waiter at
//! the deadline, and enough misses exhaust a restart budget. A registry
//! deadline therefore has to be chosen against a measured reply cost. aft's
//! incident is the precedent -- its reply was linear in tracked roots, which
//! nobody knew until it was killed fleet-wide.
//!
//! A probe rather than a test: the numbers depend on the machine, so there is
//! no fixed expectation to assert. What it establishes is the SHAPE -- whether
//! the cost grows with what the module is doing.
use std::sync::Arc;
use std::time::Instant;

use cerebellum_core::clock::{MonotonicClock, SystemClock};
use cerebellum_core::health::HealthState;

fn measure(health: &HealthState, runs: u32) -> (std::time::Duration, std::time::Duration) {
    let mut worst = std::time::Duration::ZERO;
    let start = Instant::now();
    for _ in 0..runs {
        let one = Instant::now();
        let _ = health.report();
        worst = worst.max(one.elapsed());
    }
    (start.elapsed() / runs, worst)
}

fn main() {
    let health = Arc::new(HealthState::new());
    let clock = SystemClock::default();
    let runs = 100_000;

    // Warm, so lazy initialisation is not reported as steady-state cost.
    let _ = measure(&health, 1_000);

    let (idle_mean, idle_worst) = measure(&health, runs);
    println!("health.report, idle module:");
    println!("  mean:  {idle_mean:?}");
    println!("  worst: {idle_worst:?}");

    // The shape aft got wrong. This state holds atomics rather than a
    // collection, so cost cannot grow with in-flight work -- printed so the
    // claim is visible rather than asserted.
    health.stamp_oldest_queued(Some(clock.now()));
    health.stamp_oldest_in_flight(Some(clock.now()));
    let (loaded_mean, loaded_worst) = measure(&health, runs);
    println!("health.report, both action gauges live:");
    println!("  mean:  {loaded_mean:?}");
    println!("  worst: {loaded_worst:?}");

    // Degraded takes the branch that formats reason strings, which is the most
    // expensive path the reply has.
    let stale = HealthState::with_thresholds(
        std::time::Duration::from_millis(1),
        std::time::Duration::from_millis(1),
    );
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    stale.stamp_oldest_queued(Some(stale.clock().now()));
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let (degraded_mean, degraded_worst) = measure(&stale, runs);
    println!("health.report, degraded (formats reasons):");
    println!("  mean:  {degraded_mean:?}");
    println!("  worst: {degraded_worst:?}");
    println!();
    println!("reply reaches no browser, no CDP socket, no profile lock:");
    println!("  it reads three atomics and two thresholds, so a wedged browser");
    println!("  cannot slow it and cannot make the prober read the module dead.");
}
