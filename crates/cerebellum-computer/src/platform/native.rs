//! Turns raw system readings into this plane's permission types.
//!
//! Compiled only on macOS, and containing no unsafe code: the framework calls
//! live in `cerebellum-macos` so this crate can keep `#![forbid(unsafe_code)]`.
//! What is here is the conversion, which is the part worth reading — a reading
//! the system declines to give is reported as absence, never as a value that
//! would satisfy a check.

use super::{PermissionLiveness, PermissionProbeResult, PermissionService};

/// The process this system attributes our permission grants to.
///
/// `None` when the system reports none. The caller must treat that as "no grant
/// can be credited", not as a reason to substitute this process: a module
/// spawned by a daemon holds no grants of its own, so naming itself would
/// discard every real grant it has.
pub fn responsible_process() -> Option<String> {
    cerebellum_macos::responsible_process()
}

/// Read the permission state the system reports for this process.
///
/// Each result carries the attribution read at the moment of the probe, which
/// the caller compares against the attribution established at startup. Both
/// sides must not come from one reading, or the comparison passes by
/// construction; supplying the fresh side here lets it catch an attribution
/// that changed underneath us — a re-signed or replaced launcher, whose grants
/// are not the ones we started with.
///
/// An unresolvable attribution yields no results at all rather than a result
/// naming nothing, because a result naming nothing would be admitted by an
/// expectation that also knows nothing.
pub fn probe_permissions() -> Vec<PermissionProbeResult> {
    // Before any reading, because a capture filter created in a process that
    // has never reached the window server aborts the process instead of
    // failing. Cheap and idempotent, so it is done here rather than at a call
    // site someone has to remember.
    cerebellum_macos::establish_window_server_connection();

    let Some(attributed_to) = responsible_process() else {
        return Vec::new();
    };

    let off_main = cerebellum_macos::is_off_main_thread();

    vec![PermissionProbeResult {
        service: PermissionService::ScreenRecording,
        liveness: if cerebellum_macos::screen_capture_is_permitted() {
            PermissionLiveness::Live
        } else {
            // A denied permission is a state the plane handles, not a failure
            // of the probe.
            PermissionLiveness::Unavailable
        },
        responsible_process: attributed_to,
        off_main,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Probing reports the attribution it read, for the service it read.
    ///
    /// The liveness value is deliberately not asserted: it depends on whether
    /// this machine has granted capture, and demanding one answer would fail
    /// honestly on the other kind of machine.
    #[test]
    fn probing_reports_the_attribution_it_read() {
        let results = probe_permissions();
        let Some(expected) = responsible_process() else {
            assert!(
                results.is_empty(),
                "no attribution resolved, so no result may claim one"
            );
            return;
        };
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].service, PermissionService::ScreenRecording);
        assert_eq!(results[0].responsible_process, expected);
    }

    /// The reading is one the plane's own policy accepts.
    ///
    /// This is the join the whole slice rests on: the probe supplies the
    /// attribution, and the startup policy admits a grant only when the two
    /// agree. Asserting Live specifically — rather than "not unresolved" —
    /// because the failure being guarded against is a truthful reading being
    /// silently discarded, which presents as unresolved.
    #[test]
    fn a_reading_survives_the_policy_that_consumes_it() {
        let Some(attribution) = responsible_process() else {
            return;
        };
        let mut results = probe_permissions();
        // Force the granted case, so the test states a property of the JOIN
        // rather than of this machine's permission settings.
        for result in &mut results {
            result.liveness = PermissionLiveness::Live;
        }

        let report = super::super::macos::PermissionLivenessProbe {
            responsible_process: attribution,
        }
        .run(&results);

        assert_eq!(
            report.state(PermissionService::ScreenRecording),
            PermissionLiveness::Live,
            "a reading taken here was discarded by the policy that consumes it"
        );
    }
}
