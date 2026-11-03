//! Desk-free access to the native observed-post delegation for composed tests.
//! Only the posting operation is exposed; bracket front/restore operations
//! remain the caller's scripted host, so no operator application is activated.

use super::*;
use crate::dispatch::FrontingBracketHost;

pub use super::pointer::TestPrimitives as PointerPrimitives;

pub fn post_observed_pointer(
    action: &SyntheticAction,
    target: ProcessEventTarget,
    guard: super::super::GlobalPointerGuard,
    started: Instant,
    primitives: PointerPrimitives,
    observation: crate::dispatch::ObservedUnit<'_, cerebellum_macos::SessionEventTap>,
) -> Result<crate::dispatch::UnitPosted, SequencePostFailure> {
    let marker = observation.probe.marker;
    let mut host = MacBracketHost {
        pointer_primitives: Some(primitives),
        started,
        tap: None,
        target,
        heartbeat: HeartbeatPoster {
            marker,
            event: None,
            started,
            our_pid: 99,
        },
        units: vec![Some(
            super::super::macos_synthetic::synthetic_event_steps(action)
                .expect("test action constructs native pointer events"),
        )],
        transport: MacOsPerProcessEventTransport::new(Duration::from_millis(50)),
        pointer: Some(MacPointerUnit {
            guard,
            interval_ms: 50,
            last_post_at: None,
            error: None,
            observed_abort: None,
        }),
    };
    host.post_observed_unit(0, observation)
}
