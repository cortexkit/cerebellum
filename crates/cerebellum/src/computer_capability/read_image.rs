//! Image reads borrow the keys bracket only under an already-held takeover grant.

use cerebellum_computer::app_state::image::{
    ImageDecision, ImageFronting, ImageUnavailable, WindowImageCapture,
};
use cerebellum_computer::app_state::ImageReadEvidence;
use cerebellum_computer::capture::{
    CaptureBackend, CaptureError, ScopedCaptureController, SingleWindowCapture,
    SingleWindowCaptureError,
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
    /// The call's dispatch gate. Fronting the target is a mutation, so it
    /// must still be open immediately before the bracket.
    pub gate: Option<std::sync::Arc<dyn cerebellum_computer::dispatch::MutationGate>>,
    /// Set when the read fronts under the fronting lock and the call's
    /// restore obligation; the driver then runs its bracket through them.
    pub hooks: Option<super::fronting::CellHooks>,
    /// What the read's row records of the front, as known before the image.
    pub fronting: Option<super::fronting::Fronting>,
}

pub(super) fn capture<B: CaptureBackend, D: PlatformDriver>(
    backend: B,
    driver: &mut D,
    freshness: &dyn ImageFreshnessSource,
    grant: &ProcessGrant,
    plan: &ImageReadPlan,
    evidence: &std::cell::RefCell<ImageReadEvidence>,
    after_fronting: &mut dyn FnMut(),
) -> Result<WindowImageCapture, ImageUnavailable> {
    let now_ms = plan.now_ms;
    if !plan.bring_to_front {
        return capture_visible(backend, freshness, grant, evidence, now_ms);
    }
    let (_, _, decision) = freshness.inspect_decision(grant, None);
    evidence.borrow_mut().decision = Some(decision);
    if !plan.takeover {
        return Err(ImageUnavailable::ImageNeedsTakeover);
    }
    if !plan.bracket_admitted {
        return Err(ImageUnavailable::FrontingUnavailable);
    }
    let hooks = plan
        .hooks
        .as_ref()
        .ok_or(ImageUnavailable::FrontingUnavailable)?;
    // The declared 300 ms read bound is provisional pending a live measurement
    // by the placed module. Keys retain their independently sized 100 ms bound.
    let bound = cerebellum_computer::platform::vocabulary::frozen_row_bound_ms(
        "computer.read_state",
        "maximum_fronting_read_interval_ms",
    )
    .ok_or(ImageUnavailable::FrontingUnavailable)?;
    if backend.screen_recording_liveness() != PermissionLiveness::Live {
        return Err(ImageUnavailable::ScreenRecordingNotLive);
    }
    let mut controller = ScopedCaptureController::with_v1_bounds(backend, grant.clone())
        .map_err(|_| ImageUnavailable::CaptureUnavailable)?;
    let mut captured = Err(ImageUnavailable::FrontingUnavailable);
    // Bringing the target forward changes which application has the person's
    // focus, so it is a mutation: the call's gate must still be open.
    let gate = plan.gate.as_deref();
    if gate.is_some_and(|gate| !gate.begin_mutation()) {
        return Err(ImageUnavailable::FrontingUnavailable);
    }
    if !driver.accept_fronted_dispatch_hooks(super::fronting::boxed_hooks(hooks)) {
        return Err(ImageUnavailable::FrontingUnavailable);
    }
    let bracket = driver.read_fronted(
        grant,
        bound,
        &|| {
            plan.cancel.as_ref().is_some_and(|c| c.is_cancelled())
                || gate.is_some_and(|gate| gate.stopped())
        },
        &mut || {
            // Even a backend panic must return through the bracket's restore.
            captured = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                check_visibility(freshness, grant, evidence, None, false)?;
                let pending = controller
                    .capture_frontmost_window_unencoded_for_vision(now_ms)
                    .map_err(image_capture_error)?;
                check_visibility(
                    freshness,
                    grant,
                    evidence,
                    Some(&pending.window.window_id),
                    false,
                )?;
                Ok(pending)
            }))
            .unwrap_or(Err(ImageUnavailable::CaptureFailed));
        },
    );
    // The heartbeat's own-input bookkeeping must not hide input that arrives
    // while the previous app is back in front and the JPEG is being encoded.
    after_fronting();
    let report = bracket.map_err(|_| ImageUnavailable::FrontingUnavailable)?;
    evidence.borrow_mut().fronting = Some(ImageFronting::from(&report));
    if let Some(hooks) = &plan.hooks {
        // The bracket ran the call's restore decision through the hooks, so
        // the row can say how the front ended before it is finalized.
        let mode = plan
            .fronting
            .map_or(cerebellum_core::config::AppUse::Background, |fronting| {
                fronting.mode
            });
        evidence.borrow_mut().fronting_record = super::fronting::hooked_fronting(
            mode,
            super::fronting::Purpose::BringToFront,
            &hooks.peek(),
        )
        .row_record();
    }
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
    let pending = captured?;
    // The app is restored before any scaling or JPEG encoding. Encoding never
    // recaptures: pixels remain the snapshot certified while the app was visible.
    let captured = controller
        .encode_window_for_vision(pending)
        .map_err(image_capture_error)?;
    if report.previous_frontmost != Some(grant.pid) {
        evidence.borrow_mut().decision = Some(ImageDecision::FrontedThenVisible);
    }
    Ok(window_image(captured, grant))
}

fn capture_visible<B: CaptureBackend>(
    backend: B,
    freshness: &dyn ImageFreshnessSource,
    grant: &ProcessGrant,
    evidence: &std::cell::RefCell<ImageReadEvidence>,
    now_ms: u64,
) -> Result<WindowImageCapture, ImageUnavailable> {
    if backend.screen_recording_liveness() != PermissionLiveness::Live {
        return Err(ImageUnavailable::ScreenRecordingNotLive);
    }
    check_visibility(freshness, grant, evidence, None, true)?;
    let mut controller = ScopedCaptureController::with_v1_bounds(backend, grant.clone())
        .map_err(|_| ImageUnavailable::CaptureUnavailable)?;
    let captured = controller
        .capture_frontmost_window_for_vision(now_ms)
        .map_err(image_capture_error)?;
    // Selection and capture can race a cover; certify the exact captured window.
    check_visibility(
        freshness,
        grant,
        evidence,
        Some(&captured.window.window_id),
        true,
    )?;
    Ok(window_image(captured, grant))
}

fn check_visibility(
    freshness: &dyn ImageFreshnessSource,
    grant: &ProcessGrant,
    evidence: &std::cell::RefCell<ImageReadEvidence>,
    window_id: Option<&str>,
    allow_covered_repainting: bool,
) -> Result<(), ImageUnavailable> {
    let (repaints, visibility, decision) = freshness.inspect_decision(grant, window_id);
    evidence.borrow_mut().decision = Some(decision);
    // Fronted reads never capture a still-covered window, even for a measured engine.
    image_freshness_decision(repaints && allow_covered_repainting, visibility)
}

fn image_capture_error(error: SingleWindowCaptureError) -> ImageUnavailable {
    match error {
        SingleWindowCaptureError::NoWindow => ImageUnavailable::NoWindowCaptured,
        SingleWindowCaptureError::Capture(
            CaptureError::PermissionUnavailable | CaptureError::PermissionPendingRelaunch,
        ) => ImageUnavailable::ScreenRecordingNotLive,
        SingleWindowCaptureError::Capture(CaptureError::UnsupportedOnPlatform) => {
            ImageUnavailable::CaptureUnavailable
        }
        SingleWindowCaptureError::Capture(_) => ImageUnavailable::CaptureFailed,
    }
}

fn window_image(captured: SingleWindowCapture, grant: &ProcessGrant) -> WindowImageCapture {
    WindowImageCapture {
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
    }
}
