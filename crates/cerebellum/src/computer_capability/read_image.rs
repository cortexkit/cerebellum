//! Image reads borrow the keys bracket only under an already-held takeover grant.

use cerebellum_computer::app_state::image::{
    ImageDecision, ImageFronting, ImageUnavailable, WindowImageCapture,
};
use cerebellum_computer::app_state::ImageReadEvidence;
use cerebellum_computer::capture::{
    CaptureBackend, CaptureError, ScopedCaptureController, SingleWindowCaptureError,
};
use cerebellum_computer::dispatch::{BracketStop, RestoreStatus};
use cerebellum_computer::platform::{PermissionLiveness, PlatformDriver, ProcessGrant};

use super::image_freshness::{image_freshness_decision, ImageFreshnessSource};

#[derive(Default)]
pub(super) struct ImageReadPlan {
    pub requested: bool,
    pub bring_to_front: bool,
    pub takeover: bool,
    pub bracket_admitted: bool,
    pub cancel: Option<crate::CancelHandle>,
    pub now_ms: u64,
}

pub(super) fn capture<B: CaptureBackend, D: PlatformDriver>(
    backend: B,
    driver: &mut D,
    freshness: &dyn ImageFreshnessSource,
    grant: &ProcessGrant,
    plan: &ImageReadPlan,
    evidence: &std::cell::RefCell<ImageReadEvidence>,
) -> Result<WindowImageCapture, ImageUnavailable> {
    let now_ms = plan.now_ms;
    if !plan.bring_to_front {
        return capture_visible(backend, freshness, grant, evidence, false, now_ms);
    }
    let (_, _, decision) = freshness.inspect_decision(grant, None);
    evidence.borrow_mut().decision = Some(decision);
    if !plan.takeover {
        return Err(ImageUnavailable::ImageNeedsTakeover);
    }
    if !plan.bracket_admitted {
        return Err(ImageUnavailable::FrontingUnavailable);
    }
    let bound = cerebellum_computer::platform::vocabulary::frozen_row_bound_ms(
        "computer.keys",
        "maximum_fronting_bracket_interval_ms",
    )
    .unwrap_or(100);
    let mut backend = Some(backend);
    let mut captured = Err(ImageUnavailable::FrontingUnavailable);
    let report = driver
        .read_fronted(
            grant,
            bound,
            &|| plan.cancel.as_ref().is_some_and(|c| c.is_cancelled()),
            &mut || {
                // Even a backend panic must return through the bracket's restore.
                captured = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    capture_visible(
                        backend.take().expect("one bracket read"),
                        freshness,
                        grant,
                        evidence,
                        true,
                        now_ms,
                    )
                }))
                .unwrap_or(Err(ImageUnavailable::CaptureFailed));
            },
        )
        .map_err(|_| ImageUnavailable::FrontingUnavailable)?;
    evidence.borrow_mut().fronting = Some(ImageFronting::from(&report));
    if matches!(report.restore, RestoreStatus::Failed { .. }) {
        return Err(ImageUnavailable::RestoreFailed);
    }
    if report.longest_fronted_interval_ms > bound || report.stop == Some(BracketStop::BoundExceeded)
    {
        return Err(ImageUnavailable::FrontingBoundExceeded);
    }
    if !report.held(bound) {
        return Err(ImageUnavailable::FrontingUnavailable);
    }
    if captured.is_ok() && report.previous_frontmost != Some(grant.pid) {
        evidence.borrow_mut().decision = Some(ImageDecision::FrontedThenVisible);
    }
    captured
}

fn capture_visible<B: CaptureBackend>(
    backend: B,
    freshness: &dyn ImageFreshnessSource,
    grant: &ProcessGrant,
    evidence: &std::cell::RefCell<ImageReadEvidence>,
    fronted: bool,
    now_ms: u64,
) -> Result<WindowImageCapture, ImageUnavailable> {
    if backend.screen_recording_liveness() != PermissionLiveness::Live {
        return Err(ImageUnavailable::ScreenRecordingNotLive);
    }
    let check = |window_id: Option<&str>| {
        let (repaints, visibility, decision) = freshness.inspect_decision(grant, window_id);
        evidence.borrow_mut().decision = Some(decision);
        // A fronted read is never captured while still covered, even for an
        // engine with measured background repainting.
        image_freshness_decision(repaints && !fronted, visibility)?;
        Ok(())
    };
    check(None)?;
    let mut controller = ScopedCaptureController::with_v1_bounds(backend, grant.clone())
        .map_err(|_| ImageUnavailable::CaptureUnavailable)?;
    let captured = controller
        .capture_frontmost_window_for_vision(now_ms)
        .map_err(|error| match error {
            SingleWindowCaptureError::NoWindow => ImageUnavailable::NoWindowCaptured,
            SingleWindowCaptureError::Capture(
                CaptureError::PermissionUnavailable | CaptureError::PermissionPendingRelaunch,
            ) => ImageUnavailable::ScreenRecordingNotLive,
            SingleWindowCaptureError::Capture(CaptureError::UnsupportedOnPlatform) => {
                ImageUnavailable::CaptureUnavailable
            }
            SingleWindowCaptureError::Capture(_) => ImageUnavailable::CaptureFailed,
        })?;
    // Selection and capture can race a cover; certify the exact captured window.
    check(Some(&captured.window.window_id))?;
    Ok(WindowImageCapture {
        window_id: captured.window.window_id.clone(),
        owning_pid: grant.pid,
        window_origin: (
            f64::from(captured.window.frame.x),
            f64::from(captured.window.frame.y),
        ),
        window_points: (
            f64::from(captured.window.frame.width),
            f64::from(captured.window.frame.height),
        ),
        captured_px: (
            captured.frame.captured_width_px,
            captured.frame.captured_height_px,
        ),
        jpeg: captured.frame.jpeg,
    })
}
