//! Turns raw operating-system readings into this plane's types.
//!
//! Compiled only on macOS, and containing no unsafe code: the framework calls
//! live in `cerebellum-macos` so this crate can keep `#![forbid(unsafe_code)]`.
//! What is here is the conversion, which is the part worth reading — a reading
//! the system declines to give is reported as absence, never as a value that
//! would satisfy a check.

use std::time::Duration;

use super::{
    PermissionLiveness, PermissionProbeResult, PermissionService, ProcessGrant, TargetResolution,
};
use crate::capture::{
    BackendError, BackendTeardownProgress, BroadDisplayCaptureRequest, CaptureArtifact,
    CaptureBackend, EnumeratedWindow, WindowCaptureFrame, WindowCaptureRequest, WindowChange,
    WindowChangeKind, WindowFrame,
};

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

    // Both services are read, because the action vocabulary requires different
    // ones per capability: capture needs screen recording, and every capability
    // that acts on an application needs accessibility. Reading only one leaves
    // the other's absence to surface as a runtime failure at the moment an
    // action is attempted, rather than as a capability that was never offered.
    vec![
        PermissionProbeResult {
            service: PermissionService::ScreenRecording,
            liveness: if cerebellum_macos::screen_capture_is_permitted() {
                PermissionLiveness::Live
            } else {
                // A denied permission is a state the plane handles, not a
                // failure of the probe.
                PermissionLiveness::Unavailable
            },
            responsible_process: attributed_to.clone(),
            off_main,
        },
        PermissionProbeResult {
            service: PermissionService::Accessibility,
            // Non-prompting: this asks whether the grant exists rather than
            // requesting it. A probe that raised a system dialog would put a
            // permission prompt in front of the user at module startup, for a
            // capability nobody asked for yet.
            liveness: if cerebellum_macos::accessibility_is_permitted() {
                PermissionLiveness::Live
            } else {
                PermissionLiveness::Unavailable
            },
            responsible_process: attributed_to,
            off_main,
        },
    ]
}

/// Capture the identity of a running process, for later comparison.
///
/// This is the TRUSTED MOMENT the containment check is anchored to. A pid on
/// its own names whoever holds it now, which is exactly the process a later
/// check exists to distinguish from the one that held it when the grant was
/// made; the start time separates them, because a replacement cannot share it.
///
/// `None` when the process cannot be identified — it has exited, or owns no
/// window this system will describe. Absence rather than a grant with empty
/// evidence, since empty evidence would compare equal to other empty evidence
/// and admit any process.
pub fn grant_for_pid(pid: u32, timeout: Duration) -> Option<ProcessGrant> {
    let generation = cerebellum_macos::process_start_time_micros(pid)?;
    let windows = cerebellum_macos::enumerate_windows(timeout).ok()?;
    let bundle_identity = windows
        .iter()
        .find(|window| window.owner_pid == pid)
        .map(|window| window.owner_bundle_identifier.clone())?;

    Some(ProcessGrant {
        pid,
        bundle_identity,
        process_generation_evidence: generation.to_string(),
    })
}

/// Resolve a bundle identity against the windows this system currently reports.
///
/// Thin on purpose: the decision lives in [`TargetResolution::decide`], which is
/// platform-neutral and therefore built and tested on every host. This half only
/// supplies the readings, and it is the half no continuous build compiles.
pub fn resolve_target(bundle_identity: &str, timeout: Duration) -> TargetResolution {
    // A failed reading is passed through as absence rather than converted here,
    // so the decision that a silent window server is not the same as an absent
    // application lives in the platform-neutral half that every host tests. This
    // half only supplies the reading.
    let owners: Option<Vec<(u32, String)>> =
        cerebellum_macos::enumerate_windows(timeout)
            .ok()
            .map(|windows| {
                windows
                    .into_iter()
                    .map(|window| (window.owner_pid, window.owner_bundle_identifier))
                    .collect()
            });

    TargetResolution::decide(bundle_identity, owners.as_deref(), |pid| {
        cerebellum_macos::process_start_time_micros(pid).map(|micros| micros.to_string())
    })
}

/// What a fresh reading of a process says about a grant made for it earlier.
///
/// The failures are kept apart because a caller acts differently on each: a
/// replaced target can be worked with again once a new grant is acquired, an
/// exited one cannot, and a window belonging to another process altogether means
/// the request named the wrong thing. Collapsing them into one answer leaves the
/// caller to guess which happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantVerification {
    /// Same process, same generation: still the thing the grant was made for.
    Current,
    /// The pid is held by a process that started at a different moment, so the
    /// original exited and its pid was reused.
    TargetReplaced,
    /// Nothing holds the pid.
    TargetGone,
    /// The process exists and cannot be inspected from here, so whether it is
    /// still the granted one is unknown. Separate from `TargetGone` because a
    /// target out of reach has not exited, and a caller told it had would stop
    /// rather than escalate.
    TargetUnreadable,
    /// The reading is about a different process than the grant names.
    DifferentProcess,
}

impl GrantVerification {
    pub(crate) fn is_current(self) -> bool {
        self == Self::Current
    }
}

/// Compare a fresh reading of `pid` against a grant made for it earlier.
///
/// The generation is read now rather than carried, because a pid on its own
/// names whoever holds it at this moment — which is exactly the process the
/// check exists to distinguish from the one the grant was made for.
pub(crate) fn verify_grant(pid: u32, grant: &ProcessGrant) -> GrantVerification {
    if pid != grant.pid {
        return GrantVerification::DifferentProcess;
    }
    // Every failure here refuses; they are told apart because the caller and
    // anyone reading the journal afterwards act differently on each. In
    // particular a mismatch between this build and the running kernel would
    // otherwise present as every target having exited at once, which points an
    // investigation at the applications instead of at this module.
    let generation = match cerebellum_macos::process_start_time(pid) {
        cerebellum_macos::ProcessStartTime::Started(generation) => generation,
        cerebellum_macos::ProcessStartTime::NoSuchProcess => return GrantVerification::TargetGone,
        cerebellum_macos::ProcessStartTime::NotPermitted
        | cerebellum_macos::ProcessStartTime::NoStartTime
        | cerebellum_macos::ProcessStartTime::LayoutMismatch => {
            return GrantVerification::TargetUnreadable
        }
    };

    if generation.to_string() == grant.process_generation_evidence {
        GrantVerification::Current
    } else {
        GrantVerification::TargetReplaced
    }
}

fn to_frame(window: &cerebellum_macos::RawWindow) -> WindowFrame {
    WindowFrame {
        x: window.x as i32,
        y: window.y as i32,
        // A negative size is not representable and cannot be produced by a
        // window server, so clamping states that rather than wrapping into a
        // huge unsigned value.
        width: window.width.max(0.0) as u32,
        height: window.height.max(0.0) as u32,
    }
}

/// Serves capture for one target process through ScreenCaptureKit.
pub struct NativeCaptureBackend {
    timeout: Duration,
    /// The window ids seen at the last enumeration, so a change can be
    /// reported. Empty until the first enumeration, which is why
    /// [`Self::poll_window_change`] reports nothing before then rather than
    /// reporting that every window appeared at once.
    last_seen: Option<Vec<String>>,
}

impl NativeCaptureBackend {
    /// No warming step is offered, and the reason is worth stating because the
    /// absence looks like an oversight.
    ///
    /// A process's first capture is what establishes its session with the
    /// window server, and two processes doing that simultaneously block each
    /// other badly. Warming would move that cost to startup — but the only way
    /// to warm is to take a real picture, since creating a filter without
    /// capturing does not complete the setup. That trades a photograph nobody
    /// requested, on every boot, against an occasional refusal the caller can
    /// retry. A first capture otherwise costs about the same as any other.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            last_seen: None,
        }
    }
}

/// Preserve the macOS classification when translating it to the backend layer.
fn map_macos_capture_error(error: cerebellum_macos::CaptureError) -> BackendError {
    match error {
        cerebellum_macos::CaptureError::ScreenLocked => BackendError::ScreenLocked,
        cerebellum_macos::CaptureError::Capture(reason) => BackendError::Capture(reason),
    }
}

/// Whether a captured window may be handed back, given who owned it at capture.
///
/// Separated from the capture call because that call needs a live window
/// server, so the decision would otherwise be reachable only on a machine with
/// a real screen — and this is the check that stops pixels belonging to one
/// process being returned under another's grant. Written here, it is decidable
/// anywhere.
///
/// Each refusal names a different remedy: a replaced target needs a new grant,
/// a gone one needs nothing, an unreadable one is unknown rather than wrong,
/// and a different owner means the window was never the target's.
fn capture_ownership_verdict(
    window_id: u32,
    owner_pid_at_capture: u32,
    target: &ProcessGrant,
    verification: GrantVerification,
) -> Result<(), BackendError> {
    match verification {
        GrantVerification::Current => Ok(()),
        GrantVerification::TargetReplaced => Err(BackendError::Capture(format!(
            "window {window_id} is owned by a process that replaced the granted {} at capture \
             time, so a new grant is needed",
            target.pid
        ))),
        GrantVerification::TargetGone => Err(BackendError::Capture(format!(
            "the granted process {} is gone at capture time",
            target.pid
        ))),
        GrantVerification::TargetUnreadable => Err(BackendError::Capture(format!(
            "the granted process {} cannot be inspected, so whether it is still the granted \
             target is unknown",
            target.pid
        ))),
        GrantVerification::DifferentProcess => Err(BackendError::Capture(format!(
            "window {window_id} is owned by process {owner_pid_at_capture} at capture time, not \
             the granted {}",
            target.pid
        ))),
    }
}

impl CaptureBackend for NativeCaptureBackend {
    fn screen_recording_liveness(&self) -> PermissionLiveness {
        if cerebellum_macos::screen_capture_is_permitted() {
            PermissionLiveness::Live
        } else {
            PermissionLiveness::Unavailable
        }
    }

    /// The target's windows, each carrying whether its owner was verified.
    ///
    /// Filtered to the target here rather than by the caller, so a window
    /// belonging to another process is never handed out at all. Verification is
    /// reported per window rather than gating the list, because "this window
    /// belongs to a process whose identity could not be confirmed" is
    /// information the caller needs and cannot recover from an absence.
    fn enumerate_windows(
        &mut self,
        target: &ProcessGrant,
    ) -> Result<Vec<EnumeratedWindow>, BackendError> {
        let windows =
            cerebellum_macos::enumerate_windows(self.timeout).map_err(BackendError::Enumeration)?;

        let verified = verify_grant(target.pid, target).is_current();

        let mine: Vec<EnumeratedWindow> = windows
            .iter()
            .filter(|window| window.owner_pid == target.pid)
            .map(|window| EnumeratedWindow {
                window_id: window.window_id.to_string(),
                owner_identity: target.clone(),
                // The bundle identifier is supplied by the application, so it
                // agreeing with the grant is not evidence. Only the generation
                // read from the kernel is.
                owner_identity_verified: verified
                    && window.owner_bundle_identifier == target.bundle_identity,
                frame: to_frame(window),
                accessibility_root: None,
            })
            .collect();

        self.last_seen = Some(mine.iter().map(|window| window.window_id.clone()).collect());
        Ok(mine)
    }

    /// Whether the target's window set changed since the last enumeration.
    ///
    /// Reports nothing before the first enumeration: with no previous list,
    /// every window looks new, and a caller cannot distinguish that from the
    /// target having just opened them.
    fn poll_window_change(
        &mut self,
        target: &ProcessGrant,
    ) -> Result<Option<WindowChange>, BackendError> {
        let previous = self.last_seen.clone();
        let current = self.enumerate_windows(target)?;
        let Some(previous) = previous else {
            return Ok(None);
        };

        let current_ids: Vec<String> = current
            .iter()
            .map(|window| window.window_id.clone())
            .collect();
        if current_ids == previous {
            return Ok(None);
        }

        // A window that went away is reported ahead of one that appeared, even
        // when both happened. A capture session is bound to a window that no
        // longer exists; a new window elsewhere does not change that, and
        // reporting the addition would describe the set while hiding the event
        // that invalidates the session.
        let kind = if previous.iter().any(|id| !current_ids.contains(id)) {
            WindowChangeKind::Closed
        } else {
            WindowChangeKind::Created
        };
        Ok(Some(WindowChange {
            kind,
            observed_at_ms: 0,
        }))
    }

    /// Capture one window, re-checking the owner at the moment of capture.
    ///
    /// The window was already filtered to the target during enumeration, and
    /// that is not enough: a window id is reused once its window closes, so
    /// between the list and this call the id may name a window belonging to
    /// someone else. The owner is therefore read again from the capture itself
    /// and compared before the pixels are handed back.
    fn capture_window(
        &mut self,
        request: &WindowCaptureRequest,
    ) -> Result<WindowCaptureFrame, BackendError> {
        let window_id: u32 = request.filter.window_id.parse().map_err(|_| {
            BackendError::Capture(format!("not a window id: {}", request.filter.window_id))
        })?;

        let source_rect = request
            .region
            .map(|region| cerebellum_macos::CaptureSourceRect {
                x: f64::from(region.x_px),
                y: f64::from(region.y_px),
                width: f64::from(region.width_px),
                height: f64::from(region.height_px),
            });
        let capture = cerebellum_macos::capture_window(window_id, self.timeout, source_rect)
            .map_err(map_macos_capture_error)?;

        // Read at capture time by the system, not carried from enumeration.
        capture_ownership_verdict(
            window_id,
            capture.owner_pid_at_capture,
            &request.target,
            verify_grant(capture.owner_pid_at_capture, &request.target),
        )?;

        // Encoded here rather than downstream, because this is the last point
        // that holds raw pixels and everything past it accounts for what it is
        // given. The journal charges an artifact by its size against a
        // retention budget, so admitting ~31MB of raw pixels where ~1MB of PNG
        // would do distorts every eviction decision made afterwards. The wire
        // also refuses an image over 16 MiB outright, which raw pixels for one
        // large window exceed.
        let png = cerebellum_macos::encode_png(&capture.bgra, capture.width, capture.height)
            .map_err(BackendError::Capture)?;

        Ok(WindowCaptureFrame {
            owner_identity: request.target.clone(),
            owner_identity_verified: true,
            frame: WindowFrame {
                x: 0,
                y: 0,
                width: capture.width as u32,
                height: capture.height as u32,
            },
            captured_at_ms: request.captured_at_ms,
            artifact: CaptureArtifact::Bytes(png),
            accessibility_root: None,
        })
    }

    /// Whole-display capture is not served.
    ///
    /// A display capture takes in every application's windows, so it is a
    /// broader grant than anything here establishes. Refused rather than left
    /// unimplemented, so a caller receives a decision instead of discovering
    /// the absence at run time.
    fn capture_display(
        &mut self,
        _request: &BroadDisplayCaptureRequest,
    ) -> Result<CaptureArtifact, BackendError> {
        Err(BackendError::Capture(
            "whole-display capture is not served by this backend".to_string(),
        ))
    }

    /// Nothing is held open to tear down.
    ///
    /// Each capture is a single request that completes before it returns, so
    /// there is no stream to stop and teardown is immediate. The split
    /// begin/poll shape exists for a backend that holds a live stream; honoring
    /// it here costs nothing and keeps the caller's sequence identical across
    /// backends.
    fn begin_teardown(&mut self) -> Result<BackendTeardownProgress, BackendError> {
        self.last_seen = None;
        Ok(BackendTeardownProgress::Complete)
    }

    fn poll_teardown(&mut self, _elapsed_ms: u64) -> Result<BackendTeardownProgress, BackendError> {
        Ok(BackendTeardownProgress::Complete)
    }
}

#[cfg(test)]
mod tests {

    /// Pixels are handed back only when the owner at capture is the granted one.
    ///
    /// This is what stops one process's window contents being returned under
    /// another's grant. A window id is resolved before the capture and the
    /// owner is read during it, so the two can disagree: the process may have
    /// exited and its identifier been reused, or the window may never have
    /// belonged to the target.
    ///
    /// Every verification state is covered, because a mutation that collapsed
    /// any refusal into acceptance would otherwise pass on the cases nobody
    /// wrote.
    #[test]
    fn a_capture_is_returned_only_when_the_owner_is_still_the_granted_process() {
        let target = ProcessGrant {
            pid: 42,
            bundle_identity: "com.example.target".into(),
            process_generation_evidence: "generation-1".into(),
        };

        assert!(
            capture_ownership_verdict(7, 42, &target, GrantVerification::Current).is_ok(),
            "a capture whose owner is the granted process was refused"
        );

        for refused in [
            GrantVerification::TargetReplaced,
            GrantVerification::TargetGone,
            GrantVerification::TargetUnreadable,
            GrantVerification::DifferentProcess,
        ] {
            assert!(
                capture_ownership_verdict(7, 99, &target, refused).is_err(),
                "{refused:?} did not refuse the capture"
            );
        }
    }

    /// Preserve screen-locked captures as a distinct backend error so callers can
    /// recognize the condition and respond by unlocking the screen.
    #[test]
    fn a_locked_screen_maps_to_a_distinct_backend_error() {
        assert_eq!(
            map_macos_capture_error(cerebellum_macos::CaptureError::ScreenLocked),
            BackendError::ScreenLocked
        );
        assert_eq!(
            map_macos_capture_error(cerebellum_macos::CaptureError::Capture(
                "stream stopped".into()
            )),
            BackendError::Capture("stream stopped".into())
        );
    }

    /// Each refusal says something different about what went wrong.
    ///
    /// The remedies differ -- acquire a new grant, stop, or treat the answer as
    /// unknown -- so a caller handed one message for all four cannot choose
    /// between them.
    #[test]
    fn the_capture_refusals_are_distinguishable_from_one_another() {
        let target = ProcessGrant {
            pid: 42,
            bundle_identity: "com.example.target".into(),
            process_generation_evidence: "generation-1".into(),
        };

        let messages: Vec<String> = [
            GrantVerification::TargetReplaced,
            GrantVerification::TargetGone,
            GrantVerification::TargetUnreadable,
            GrantVerification::DifferentProcess,
        ]
        .into_iter()
        .map(|verification| {
            format!(
                "{:?}",
                capture_ownership_verdict(7, 99, &target, verification)
                    .expect_err("this verification refuses")
            )
        })
        .collect();

        let distinct: std::collections::BTreeSet<&String> = messages.iter().collect();
        assert_eq!(
            distinct.len(),
            messages.len(),
            "two capture refusals report the same thing: {messages:?}"
        );
    }

    /// Every service this driver can exercise is probed, and the rest are named.
    ///
    /// A permission that is required but never read leaves its absence to
    /// surface when an action is attempted, which is later and harder to
    /// attribute than a capability that was never offered.
    ///
    /// The vocabulary also requires two permissions for synthetic input, which
    /// has no implementation here: nothing in this driver posts an event or
    /// observes input. They are listed explicitly rather than skipped, so the
    /// list must be shortened deliberately when a path that needs them is
    /// written -- and this test fails if one is probed while still listed,
    /// rather than leaving a stale exemption behind.
    #[test]
    fn every_service_the_vocabulary_requires_is_probed() {
        use std::collections::BTreeSet;

        let probed: BTreeSet<_> = probe_permissions()
            .into_iter()
            .map(|result| result.service)
            .collect();

        // An empty probe means the host process could not be identified at all,
        // so no permission can be attributed to anything and there is no
        // coverage to check. The neighbouring attribution test asserts that
        // this case produces no results rather than results claiming nothing.
        if probed.is_empty() {
            return;
        }

        let mut required = BTreeSet::new();
        for capability in crate::audit::ComputerCapability::ALL {
            let services = crate::platform::vocabulary::required_permission_services(
                capability.capability_id(),
            )
            .expect("the vocabulary lists every frozen capability");
            required.extend(services);
        }

        // Required by capabilities that actuate through synthetic input. No code
        // in this driver posts an event or observes input, so probing for these
        // would ask about a facility that does not exist.
        let unimplemented: BTreeSet<_> = [
            PermissionService::PostEvent,
            PermissionService::InputMonitoring,
        ]
        .into_iter()
        .collect();

        let unprobed: BTreeSet<_> = required.difference(&probed).copied().collect();
        assert_eq!(
            unprobed, unimplemented,
            "the set of required-but-unprobed permissions changed: either a service this driver \
             now exercises is going unprobed, or one listed as unimplemented is being probed and \
             should be removed from that list"
        );
    }
    use super::*;

    /// Serializes the tests that cause a first capture in this process.
    ///
    /// A process's first capture waits for any other process that is capturing,
    /// so two of these at once block each other for as long as the deadline
    /// allows and fail for a reason unrelated to what they assert.
    static FIRST_CAPTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Whether this machine can currently produce window pixels at all.
    ///
    /// Two states prevent it and they are different: capture may not be
    /// permitted, or the screen may be locked. A locked screen still answers
    /// questions about windows while refusing their contents, so a test that
    /// only checks enumeration would proceed and then fail on the picture.
    fn pixels_are_obtainable() -> bool {
        cerebellum_macos::screen_capture_is_permitted()
            && cerebellum_macos::screen_is_locked() != Some(true)
    }

    /// Skip a live capture assertion only when the screen became locked after the test
    /// checked its lock status.
    fn skip_live_capture_when_screen_is_locked(error: &BackendError, test_name: &str) -> bool {
        if matches!(error, BackendError::ScreenLocked) {
            println!("skipping {test_name}: the screen locked during capture");
            true
        } else {
            false
        }
    }

    #[test]
    fn only_a_locked_screen_skips_live_capture_tests() {
        assert!(skip_live_capture_when_screen_is_locked(
            &BackendError::ScreenLocked,
            "test"
        ));
        assert!(
            !skip_live_capture_when_screen_is_locked(
                &BackendError::Capture("capture regression".into()),
                "test"
            ),
            "a capture regression must fail the live test rather than skip it"
        );
    }

    fn timeout() -> Duration {
        Duration::from_secs(10)
    }

    /// Every result reports the attribution that was read.
    ///
    /// The liveness value is deliberately not asserted: it depends on what this
    /// machine has granted, and demanding one answer would fail honestly on a
    /// machine that granted the other.
    ///
    /// Asserted per result rather than against a count, so adding a service
    /// does not require editing a number that carries no meaning. A result
    /// claiming a different attribution than the probe resolved would name the
    /// wrong process as the one a grant belongs to.
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
        assert!(
            !results.is_empty(),
            "an attribution resolved, so at least one service must be reported"
        );
        for result in &results {
            assert_eq!(
                result.responsible_process, expected,
                "{:?} claims an attribution the probe did not resolve",
                result.service
            );
        }
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

    /// A grant made for this process verifies against this process.
    #[test]
    fn a_grant_verifies_against_the_process_it_was_made_for() {
        let pid = std::process::id();
        let Some(generation) = cerebellum_macos::process_start_time_micros(pid) else {
            return;
        };
        let grant = ProcessGrant {
            pid,
            bundle_identity: "irrelevant to generation".to_string(),
            process_generation_evidence: generation.to_string(),
        };
        assert_eq!(verify_grant(pid, &grant), GrantVerification::Current);
    }

    /// A grant carrying another process's generation does not verify.
    ///
    /// This is the pid-reuse case with the timing removed: same pid, different
    /// generation, which is exactly what a replacement process presents.
    #[test]
    fn a_grant_from_a_different_generation_does_not_verify() {
        let pid = std::process::id();
        let Some(generation) = cerebellum_macos::process_start_time_micros(pid) else {
            return;
        };
        let grant = ProcessGrant {
            pid,
            bundle_identity: "irrelevant to generation".to_string(),
            // One microsecond earlier: a process that started at a different
            // moment, which is what a reused pid holds.
            process_generation_evidence: (generation - 1).to_string(),
        };
        assert_eq!(
            verify_grant(pid, &grant),
            GrantVerification::TargetReplaced,
            "a pid held by a process that started at a different moment is a REPLACED target, \
             which a caller can act on by acquiring a new grant"
        );
    }

    /// A grant for a process that does not exist does not verify.
    #[test]
    fn a_grant_for_a_departed_process_does_not_verify() {
        let grant = ProcessGrant {
            pid: u32::MAX - 1,
            bundle_identity: "gone".to_string(),
            process_generation_evidence: "1".to_string(),
        };
        assert_eq!(
            verify_grant(u32::MAX - 1, &grant),
            GrantVerification::TargetGone
        );
    }

    /// A target that cannot be inspected is not reported as one that has gone.
    ///
    /// The first process is root-owned, so it exists and this one may not read
    /// it — the same answer a kernel-layout mismatch would produce, and the
    /// reason both must stay separate from absence. A caller told a target had
    /// exited stops; one told it is unreadable can escalate.
    #[test]
    fn an_uninspectable_target_is_not_reported_as_gone() {
        let grant = ProcessGrant {
            pid: 1,
            bundle_identity: "root-owned".to_string(),
            process_generation_evidence: "1".to_string(),
        };
        assert_eq!(verify_grant(1, &grant), GrantVerification::TargetUnreadable);
    }

    /// A reading about some other process is not a verdict about the grant.
    ///
    /// The fourth outcome, and the one a caller acts on differently from the
    /// rest: the other three say something about the granted process, while this
    /// says the reading was about something else entirely and the request named
    /// the wrong thing.
    #[test]
    fn a_reading_about_another_process_is_reported_as_such() {
        let pid = std::process::id();
        let Some(generation) = cerebellum_macos::process_start_time_micros(pid) else {
            return;
        };
        let grant = ProcessGrant {
            pid,
            bundle_identity: "irrelevant to generation".to_string(),
            process_generation_evidence: generation.to_string(),
        };
        // A pid the grant does not name, checked against that grant.
        assert_eq!(
            verify_grant(pid.wrapping_add(1), &grant),
            GrantVerification::DifferentProcess
        );
    }

    /// Enumeration returns only the target's windows.
    ///
    /// Skipped where capture is not granted: with no window list there is
    /// nothing to filter, and the test would pass over an empty result without
    /// exercising the filter at all.
    #[test]
    fn enumeration_returns_only_the_targets_windows() {
        let _serialized = FIRST_CAPTURE.lock();
        let Ok(all) = cerebellum_macos::enumerate_windows(timeout()) else {
            return;
        };
        // A process that actually owns windows, so the filter has something to
        // exclude as well as something to keep.
        let Some(sample) = all.iter().find(|window| window.on_screen) else {
            return;
        };
        assert!(
            all.iter()
                .any(|window| window.owner_pid != sample.owner_pid),
            "every window has one owner, so this proves nothing about filtering"
        );

        let Some(grant) = grant_for_pid(sample.owner_pid, timeout()) else {
            return;
        };
        let mut backend = NativeCaptureBackend::new(timeout());
        let mine = backend.enumerate_windows(&grant).expect("enumerate");

        // The expectation is computed from the system's own list rather than
        // from the returned windows. Every returned window carries the target's
        // identity because that field is copied from the grant, so asserting on
        // it would compare the grant with itself and hold however the list was
        // filtered.
        let expected: Vec<String> = all
            .iter()
            .filter(|window| window.owner_pid == sample.owner_pid)
            .map(|window| window.window_id.to_string())
            .collect();
        let returned: Vec<String> = mine.iter().map(|window| window.window_id.clone()).collect();

        assert!(!expected.is_empty(), "the target owns at least one window");
        assert!(
            expected.len() < all.len(),
            "the target owns every window here, so filtering cannot be observed"
        );
        assert_eq!(
            returned, expected,
            "the backend returned a different window set than the target owns"
        );
    }

    /// A grant whose generation is wrong yields windows marked unverified.
    ///
    /// The windows are still returned, because the caller needs to know they
    /// exist; what changes is the claim attached to them. A backend that
    /// dropped the check entirely would mark these verified.
    #[test]
    fn windows_of_an_unverifiable_owner_are_returned_unverified() {
        let _serialized = FIRST_CAPTURE.lock();
        let Ok(all) = cerebellum_macos::enumerate_windows(timeout()) else {
            return;
        };
        let Some(sample) = all.iter().find(|window| window.on_screen) else {
            return;
        };
        let Some(mut grant) = grant_for_pid(sample.owner_pid, timeout()) else {
            return;
        };
        // The same process, claimed to have started at a different moment.
        grant.process_generation_evidence = "0".to_string();

        let mut backend = NativeCaptureBackend::new(timeout());
        let mine = backend.enumerate_windows(&grant).expect("enumerate");
        assert!(!mine.is_empty());
        for window in &mine {
            assert!(
                !window.owner_identity_verified,
                "a window was marked verified for a grant whose generation does not match"
            );
        }
    }

    /// Capturing through the backend yields the target's pixels.
    #[test]
    fn capturing_through_the_backend_yields_pixels() {
        if !pixels_are_obtainable() {
            return;
        }
        let _serialized = FIRST_CAPTURE.lock();
        let Ok(all) = cerebellum_macos::enumerate_windows(timeout()) else {
            return;
        };
        let Some(sample) = all
            .iter()
            .find(|window| window.on_screen && window.width >= 64.0 && window.height >= 64.0)
        else {
            return;
        };
        let Some(grant) = grant_for_pid(sample.owner_pid, timeout()) else {
            return;
        };

        let mut backend = NativeCaptureBackend::new(timeout());
        let frame = match backend.capture_window(&WindowCaptureRequest {
            target: grant.clone(),
            filter: crate::capture::DesktopIndependentWindowFilter::new(
                sample.window_id.to_string(),
            ),
            captured_at_ms: 1234,
            region: None,
        }) {
            Ok(frame) => frame,
            Err(error)
                if skip_live_capture_when_screen_is_locked(
                    &error,
                    "capturing_through_the_backend_yields_pixels",
                ) =>
            {
                return;
            }
            Err(error) => panic!("capture the sampled window: {error}"),
        };

        assert_eq!(frame.owner_identity, grant);
        assert!(frame.owner_identity_verified);
        assert_eq!(frame.captured_at_ms, 1234);
        assert!(frame.frame.width > 0 && frame.frame.height > 0);
        // A PNG rather than raw pixels, asserted by its signature: everything
        // downstream accounts for what it is handed, and raw pixels for one
        // large window exceed the wire's own image limit before any budget is
        // consulted.
        match &frame.artifact {
            CaptureArtifact::Bytes(bytes) => {
                assert_eq!(
                    &bytes[..8],
                    &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
                    "the backend handed over something that is not a PNG"
                );
                assert!(
                    bytes.len() < frame.frame.width as usize * frame.frame.height as usize * 4,
                    "the encoded image is not smaller than the pixels it came from"
                );
            }
            CaptureArtifact::Reference(_) => panic!("this backend returns pixels, not a reference"),
        }
    }

    /// Capturing with a grant for a different process refuses.
    ///
    /// The window belongs to the process named by the filter, and the grant
    /// names another; the capture-time owner check is the only thing that can
    /// tell, since the window id alone is a valid id.
    #[test]
    fn capturing_a_window_owned_by_another_process_refuses() {
        if !pixels_are_obtainable() {
            return;
        }
        let _serialized = FIRST_CAPTURE.lock();
        let Ok(all) = cerebellum_macos::enumerate_windows(timeout()) else {
            return;
        };
        let Some(sample) = all
            .iter()
            .find(|window| window.on_screen && window.width >= 64.0)
        else {
            return;
        };
        // A grant naming a process that is not the window's owner.
        let Some(other) = all
            .iter()
            .find(|window| window.owner_pid != sample.owner_pid)
        else {
            return;
        };
        let Some(grant) = grant_for_pid(other.owner_pid, timeout()) else {
            return;
        };

        let mut backend = NativeCaptureBackend::new(timeout());
        let result = backend.capture_window(&WindowCaptureRequest {
            target: grant,
            filter: crate::capture::DesktopIndependentWindowFilter::new(
                sample.window_id.to_string(),
            ),
            captured_at_ms: 0,
            region: None,
        });

        // The refusal must name the ownership mismatch. A capture that failed
        // for any other reason also produces an error, and would satisfy a bare
        // "this failed" while proving nothing about the owner check.
        let reason = match result {
            Err(error)
                if skip_live_capture_when_screen_is_locked(
                    &error,
                    "capturing_a_window_owned_by_another_process_refuses",
                ) =>
            {
                return;
            }
            Err(BackendError::Capture(reason)) => reason,
            Ok(_) => panic!("captured a window owned by a process the grant does not name"),
            Err(error) => panic!("refused for an unrelated error: {error}"),
        };
        assert!(
            reason.contains("at capture time"),
            "refused for an unrelated reason: {reason}"
        );
    }

    /// Whole-display capture is refused rather than served.
    #[test]
    fn whole_display_capture_is_refused() {
        let mut backend = NativeCaptureBackend::new(timeout());
        let result = backend.capture_display(&BroadDisplayCaptureRequest {
            include_cursor: false,
            captured_at_ms: 0,
        });
        let Err(BackendError::Capture(reason)) = result else {
            panic!("whole-display capture was served");
        };
        assert!(reason.contains("not served"), "unexpected reason: {reason}");
    }
}
