//! Window selection, lifetime binding and release of one Windows picture.

use super::app_state::{windows, WindowsAppStateSource};
use super::fronting::Binding;
use super::{
    validate_vocabulary_digests, ImmutableReleaseInputs, PermissionLiveness,
    PermissionLivenessReport, PermissionProbeResult, PermissionService, ProcessGrant,
    WindowsElevation,
};
use crate::app_state::image::{ImageUnavailable, WindowImageCapture};
use crate::capture::AcquisitionFence;
use cerebellum_windows::{FrameReadError, WindowCaptureProperties};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

pub fn startup_permissions(
    inputs: &ImmutableReleaseInputs,
    elevation: WindowsElevation,
) -> PermissionLivenessReport {
    startup_permissions_from(
        inputs,
        elevation,
        cerebellum_windows::capture_support,
        WindowsAppStateSource::client_available,
    )
}

fn startup_permissions_from(
    inputs: &ImmutableReleaseInputs,
    elevation: WindowsElevation,
    capture_support: impl FnOnce() -> Option<bool>,
    uia_available: impl FnOnce() -> bool,
) -> PermissionLivenessReport {
    let app_state = inputs.windows_app_identity_review_revision.is_some()
        && inputs.windows_app_state_review_revision.is_some()
        && common_keys(inputs, elevation);
    let result = |service, liveness| PermissionProbeResult {
        service,
        liveness,
        responsible_process: "ck-cerebellum".into(),
        off_main: true,
    };
    if !app_state {
        return PermissionLivenessReport::default();
    }
    let accessible = if uia_available() {
        PermissionLiveness::Live
    } else {
        PermissionLiveness::Unavailable
    };
    let recording = if inputs.windows_capture_review_revision.is_some() {
        match capture_support() {
            Some(true) => PermissionLiveness::Live,
            Some(false) => PermissionLiveness::Unavailable,
            None => PermissionLiveness::Unresolved,
        }
    } else {
        PermissionLiveness::Unresolved
    };
    PermissionLivenessReport::from_results([
        result(PermissionService::Accessibility, accessible),
        result(PermissionService::ScreenRecording, recording),
    ])
}

pub(super) fn common_keys(inputs: &ImmutableReleaseInputs, elevation: WindowsElevation) -> bool {
    inputs.release_signing_topology_revision.is_some()
        && elevation == WindowsElevation::Medium
        && validate_vocabulary_digests(&inputs.vocabulary_digests).is_ok()
}

/// The bracket, app-use, pointer and preview flags, respectively. A Windows
/// review never admits leaving an app in the foreground by design.
pub fn fronting_flags(
    inputs: &ImmutableReleaseInputs,
    elevation: WindowsElevation,
) -> (bool, bool, bool, bool) {
    let fronting = super::fronting::background_restore_admitted(inputs, elevation);
    let bracket = fronting && inputs.windows_input_bracket_review_revision.is_some();
    let pointer = bracket && inputs.windows_takeover_review_revision.is_some();
    let preview = fronting && inputs.windows_capture_review_revision.is_some();
    (bracket, false, pointer, preview)
}

thread_local! {
    static FRONTED_WINDOW: RefCell<Option<Binding>> = const { RefCell::new(None) };
}

/// The bracket and its synchronous capture callback must name the same HWND.
/// Copy the retained proof to the capture worker rather than reselecting there.
pub(super) fn with_fronted_window(binding: &Binding, read: &mut dyn FnMut()) {
    struct Reset(Option<Binding>);
    impl Drop for Reset {
        fn drop(&mut self) {
            FRONTED_WINDOW.replace(self.0.take());
        }
    }
    let _reset = Reset(FRONTED_WINDOW.replace(Some(binding.clone())));
    read();
}

// D3D readback and COM teardown are synchronous OS calls. If one of them
// stalls, the caller can still return its tree at the deadline, but another
// capture must not start compounding the stuck native work.
static CAPTURING: AtomicBool = AtomicBool::new(false);

struct CaptureSlot;

impl CaptureSlot {
    fn try_take() -> Option<Self> {
        CAPTURING
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for CaptureSlot {
    fn drop(&mut self) {
        CAPTURING.store(false, Ordering::Release);
    }
}

pub(super) fn capture(
    target: &ProcessGrant,
    deadline: Instant,
    may_acquire: &AcquisitionFence,
) -> Result<WindowImageCapture, ImageUnavailable> {
    let failed = ImageUnavailable::CaptureFailed;
    check_deadline(deadline, may_acquire)?;
    let slot = CaptureSlot::try_take().ok_or(failed)?;
    let (ready, wait) = std::sync::mpsc::sync_channel(1);
    let target = target.clone();
    let fence = may_acquire.clone();
    let fronted = FRONTED_WINDOW.with(|slot| slot.borrow().clone());
    std::thread::Builder::new()
        .name("windows-window-picture".into())
        .spawn(move || {
            let result = capture_on_worker(&target, deadline, &fence, fronted.as_ref());
            drop(slot);
            let _ = ready.send(result);
        })
        .map_err(|_| failed)?;
    let result = wait
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| failed)?;
    check_deadline(deadline, may_acquire)?;
    result
}

fn check_deadline(
    deadline: Instant,
    may_acquire: &AcquisitionFence,
) -> Result<(), ImageUnavailable> {
    if Instant::now() >= deadline || !may_acquire() {
        Err(ImageUnavailable::CaptureFailed)
    } else {
        Ok(())
    }
}

fn window_properties(reading: WindowCaptureProperties) -> Result<(), ImageUnavailable> {
    // The Win32 window display-affinity constants. An unreadable setting cannot
    // authorize either capture or a front to try to obtain the same pixels.
    match (reading.minimized, reading.display_affinity) {
        (true, _) => Err(ImageUnavailable::NoWindowCaptured),
        (false, Some(0)) => Ok(()),
        (false, Some(1 | 0x11)) => Err(ImageUnavailable::CaptureExcluded),
        (false, _) => Err(ImageUnavailable::CaptureUnavailable),
    }
}

pub(super) fn permits_picture_front(number: u32) -> bool {
    window_properties(cerebellum_windows::window_capture_properties(number)).is_ok()
}

fn capture_on_worker(
    target: &ProcessGrant,
    deadline: Instant,
    may_acquire: &AcquisitionFence,
    fronted: Option<&Binding>,
) -> Result<WindowImageCapture, ImageUnavailable> {
    let failed = ImageUnavailable::CaptureFailed;
    if !cerebellum_windows::per_monitor_v2() {
        return Err(ImageUnavailable::CaptureUnavailable);
    }
    let generation = target
        .process_generation_evidence
        .parse()
        .map_err(|_| failed)?;
    let retained = windows::retain(target.pid, generation).map_err(|_| failed)?;
    let chosen = if let Some(binding) = fronted {
        windows::bound_window(&retained, target.pid, binding.number)
            .map_err(|_| failed)?
            .filter(|window| window.proof == binding.proof && binding.is_foreground())
            .ok_or(failed)?
    } else {
        let candidates = windows::windows(&retained, target.pid, deadline).map_err(|_| failed)?;
        windows::image_window(&candidates)
            .map_err(|_| failed)?
            .cloned()
            .ok_or(ImageUnavailable::NoWindowCaptured)?
    };
    let hwnd = chosen.root.number;
    let frame = windows::frame(chosen.state.bounds);
    let confirm = || {
        if !windows::is_default_desktop() || fronted.is_some_and(|binding| !binding.is_foreground())
        {
            return Err(failed);
        }
        windows::current(&retained, generation).map_err(|_| failed)?;
        let bound = windows::bound_window(&retained, target.pid, hwnd)
            .map_err(|_| failed)?
            .ok_or(failed)?;
        if bound.proof != chosen.proof
            || bound.root.tid != chosen.root.tid
            || bound.root.class != chosen.root.class
            || windows::frame(bound.state.bounds) != frame
        {
            return Err(failed);
        }
        window_properties(cerebellum_windows::window_capture_properties(hwnd))
    };
    confirm()?;
    check_deadline(deadline, may_acquire)?;
    let mut prepared = Err(failed);
    let jpeg =
        cerebellum_windows::first_window_jpeg(hwnd, deadline, may_acquire.as_ref(), |source| {
            prepared = (|| {
                // A frame sampled during a resize or a DPI transition need not
                // describe the window's composition bounds. Do not issue coordinates for it.
                if source.received_at >= deadline
                    || (f64::from(source.width), f64::from(source.height)) != (frame[2], frame[3])
                {
                    return Err(failed);
                }
                confirm()?;
                check_deadline(deadline, may_acquire)?;
                let size =
                    cerebellum_core::vision::fit_within_vision_limits(source.width, source.height)
                        .ok_or(ImageUnavailable::ImageNotScalable)?;
                Ok(((source.width, source.height), size))
            })();
            prepared.ok().map(|(_, size)| size)
        })
        .map_err(|error| match error {
            FrameReadError::CursorPropertyMissing => ImageUnavailable::CaptureUnavailable,
            FrameReadError::Windows(error) => {
                super::wgc_failure_reason(error.code().0 as u32, || {
                    check_deadline(deadline, may_acquire)?;
                    confirm()
                })
            }
            FrameReadError::Encode(_) => failed,
        })?;
    let (captured_px, _) = prepared?;
    let jpeg = jpeg.ok_or(failed)?;
    confirm()?;
    check_deadline(deadline, may_acquire)?;
    Ok(WindowImageCapture {
        window_id: hwnd.to_string(),
        owning_pid: target.pid,
        window_origin: (frame[0], frame[1]),
        window_points: (frame[2], frame[3]),
        captured_px,
        exact_axes: true,
        jpeg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{VocabularyDigestInputs, COMPUTER_ACTION_VOCABULARY_SHA256};

    fn reviewed() -> ImmutableReleaseInputs {
        let pin = || Some(COMPUTER_ACTION_VOCABULARY_SHA256.into());
        ImmutableReleaseInputs {
            windows_app_identity_review_revision: Some("identity".into()),
            windows_app_state_review_revision: Some("state".into()),
            windows_capture_review_revision: Some("capture".into()),
            release_signing_topology_revision: Some("signing".into()),
            vocabulary_digests: VocabularyDigestInputs {
                manifest_digest: pin(),
                source_lock_digest: pin(),
                computed_artifact_digest: pin(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn screen_recording_is_live_only_with_the_picture_keys_and_positive_wgc() {
        let review = reviewed();
        for (reading, expected) in [
            (Some(true), PermissionLiveness::Live),
            (Some(false), PermissionLiveness::Unavailable),
            (None, PermissionLiveness::Unresolved),
        ] {
            let report =
                startup_permissions_from(&review, WindowsElevation::Medium, || reading, || true);
            assert_eq!(report.state(PermissionService::ScreenRecording), expected);
            assert_eq!(
                report.state(PermissionService::Accessibility),
                PermissionLiveness::Live
            );
        }
        for removed in 0..7 {
            let mut inputs = review.clone();
            let mut elevation = WindowsElevation::Medium;
            match removed {
                0 => inputs.windows_capture_review_revision = None,
                1 => inputs.windows_app_state_review_revision = None,
                2 => inputs.windows_app_identity_review_revision = None,
                3 => inputs.release_signing_topology_revision = None,
                4 => inputs.vocabulary_digests.manifest_digest = None,
                5 => elevation = WindowsElevation::ElevatedOrAboveMedium,
                _ => elevation = WindowsElevation::UnreadableOrBelowMedium,
            }
            let report = startup_permissions_from(
                &inputs,
                elevation,
                || panic!("unadmitted WGC probe"),
                || true,
            );
            assert_ne!(
                report.state(PermissionService::ScreenRecording),
                PermissionLiveness::Live
            );
        }
    }

    #[test]
    fn windows_fronting_flags_do_not_read_macos_reviews_or_admit_app_use_foreground() {
        let mut reviews = reviewed();
        reviews.app_use_fronting_review_revision = Some("macOS app-use".into());
        reviews.takeover_dispatch_review_revision = Some("macOS bracket".into());
        reviews.takeover_pointer_fronting_review_revision = Some("macOS pointer".into());
        reviews.capture_review_revision = Some("macOS capture".into());
        reviews.windows_capture_review_revision = None;
        let medium = WindowsElevation::Medium;
        assert_eq!(
            fronting_flags(&reviews, medium),
            (false, false, false, false)
        );
        reviews.windows_capture_review_revision = Some("Windows capture".into());
        reviews.windows_fronting_review_revision = Some("Windows fronting".into());
        assert_eq!(
            fronting_flags(&reviews, medium),
            (false, false, false, true)
        );
        reviews.windows_input_bracket_review_revision = Some("Windows input bracket".into());
        assert_eq!(fronting_flags(&reviews, medium), (true, false, false, true));
        reviews.windows_takeover_review_revision = Some("Windows takeover".into());
        assert_eq!(fronting_flags(&reviews, medium), (true, false, true, true));
    }

    #[test]
    fn known_affinity_exclusion_minimization_and_unreadable_affinity_are_terminals() {
        let properties = |minimized, display_affinity| {
            window_properties(WindowCaptureProperties {
                minimized,
                display_affinity,
            })
        };
        assert_eq!(properties(false, Some(0)), Ok(()));
        assert_eq!(
            properties(false, Some(1)),
            Err(ImageUnavailable::CaptureExcluded)
        );
        assert_eq!(
            properties(false, Some(0x11)),
            Err(ImageUnavailable::CaptureExcluded)
        );
        assert_eq!(
            properties(true, Some(0)),
            Err(ImageUnavailable::NoWindowCaptured)
        );
        assert_eq!(
            properties(false, None),
            Err(ImageUnavailable::CaptureUnavailable)
        );
    }
}
