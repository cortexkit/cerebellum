//! Turns raw operating-system readings into this plane's types.
//!
//! Compiled only on macOS, and containing no unsafe code: the framework calls
//! live in `cerebellum-macos` so this crate can keep `#![forbid(unsafe_code)]`.
//! What is here is the conversion, which is the part worth reading — a reading
//! the system declines to give is reported as absence, never as a value that
//! would satisfy a check.

use std::time::Duration;

use super::{PermissionLiveness, PermissionProbeResult, PermissionService, ProcessGrant};
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

/// Whether the process holding `pid` right now is the one the grant was made
/// for.
///
/// Reads the generation fresh and compares it against the grant's. A process
/// that cannot be read is NOT verified: an unreadable process is either gone or
/// not ours to inspect, and neither is evidence of a match.
fn owner_is_the_granted_process(pid: u32, grant: &ProcessGrant) -> bool {
    if pid != grant.pid {
        return false;
    }
    cerebellum_macos::process_start_time_micros(pid)
        .is_some_and(|generation| generation.to_string() == grant.process_generation_evidence)
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
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            last_seen: None,
        }
    }

    /// Perform this process's first capture while nothing is competing for it.
    ///
    /// A process's first capture sets up its session with the window server,
    /// and that setup contends system-wide: while another process is capturing,
    /// it does not proceed. Two processes starting together have blocked each
    /// other past 60 seconds on different windows. Doing it at startup means a
    /// later request waits for the work rather than for whatever else the
    /// machine happened to be doing when the request arrived.
    ///
    /// Returns the error rather than swallowing it, so a caller can decide
    /// whether a module that cannot capture should come up at all.
    pub fn warm(&mut self) -> Result<(), BackendError> {
        let windows =
            cerebellum_macos::enumerate_windows(self.timeout).map_err(BackendError::Enumeration)?;
        let Some(window) = windows.iter().find(|window| window.on_screen) else {
            // Nothing to capture is not a failure to capture. The session stays
            // cold, and the first real request pays for it.
            return Ok(());
        };
        cerebellum_macos::capture_window(window.window_id, self.timeout)
            .map(|_| ())
            .map_err(BackendError::Capture)
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

        let verified = owner_is_the_granted_process(target.pid, target);

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

        let capture = cerebellum_macos::capture_window(window_id, self.timeout)
            .map_err(BackendError::Capture)?;

        // Read at capture time by the system, not carried from enumeration.
        if !owner_is_the_granted_process(capture.owner_pid_at_capture, &request.target) {
            return Err(BackendError::Capture(format!(
                "window {window_id} is owned by process {} at capture time, not the granted {}",
                capture.owner_pid_at_capture, request.target.pid
            )));
        }

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
            artifact: CaptureArtifact::Bytes(capture.bgra),
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

    fn timeout() -> Duration {
        Duration::from_secs(10)
    }

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
        assert!(owner_is_the_granted_process(pid, &grant));
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
        assert!(
            !owner_is_the_granted_process(pid, &grant),
            "a grant from a different generation was accepted for the same pid"
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
        assert!(!owner_is_the_granted_process(u32::MAX - 1, &grant));
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
        let frame = backend
            .capture_window(&WindowCaptureRequest {
                target: grant.clone(),
                filter: crate::capture::DesktopIndependentWindowFilter::new(
                    sample.window_id.to_string(),
                ),
                captured_at_ms: 1234,
            })
            .expect("capture the sampled window");

        assert_eq!(frame.owner_identity, grant);
        assert!(frame.owner_identity_verified);
        assert_eq!(frame.captured_at_ms, 1234);
        assert!(frame.frame.width > 0 && frame.frame.height > 0);
        match &frame.artifact {
            CaptureArtifact::Bytes(bytes) => assert!(!bytes.is_empty()),
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
        });

        // The refusal must name the ownership mismatch. A capture that failed
        // for any other reason also produces an error, and would satisfy a bare
        // "this failed" while proving nothing about the owner check.
        let Err(BackendError::Capture(reason)) = result else {
            panic!("captured a window owned by a process the grant does not name");
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
