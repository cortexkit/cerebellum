//! Budget and admission for target-bound background pictures.

use super::{fronting, read_image::ImageReadTrace};
use crate::CancelHandle;
use cerebellum_computer::app_state::image::{ImageUnavailable, WindowImageCapture};
use cerebellum_computer::capture::{AcquisitionFence, CaptureBackend};
use cerebellum_computer::dispatch::{FrontingStop, MutationGate};
use cerebellum_computer::platform::ProcessGrant;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) struct PicturePlan {
    end: Instant,
    fallback: Option<Result<(), FrontingStop>>,
}

impl PicturePlan {
    pub(super) fn new(end: Instant, fallback: Option<Result<(), FrontingStop>>) -> Self {
        Self { end, fallback }
    }

    fn background_end(&self) -> Instant {
        if self.fallback.is_none() {
            return self.end;
        }
        // Leave the full bracket and a small handoff allowance. Waiting right
        // up to the reserve would leave less than a bracket by the time the
        // timeout is observed and admission is checked.
        const HANDOFF: Duration = Duration::from_millis(25);
        self.end
            .checked_sub(Duration::from_millis(crate::budgets::FRONTING_READ_MS) + HANDOFF)
            .unwrap_or_else(Instant::now)
    }

    fn fallback_stop(&self, now: Instant) -> Option<FrontingStop> {
        let admission = self.fallback?;
        if self.end.saturating_duration_since(now)
            < Duration::from_millis(crate::budgets::FRONTING_READ_MS)
        {
            return None;
        }
        // No Windows capture front has an input observer and bound HWND
        // restore host yet. Admission alone must not activate a window.
        Some(admission.err().unwrap_or(FrontingStop::ObserverUnavailable))
    }
}

pub(super) fn capture<B: CaptureBackend>(
    mut backend: B,
    grant: &ProcessGrant,
    plan: &PicturePlan,
    cancel: Option<CancelHandle>,
    gate: Option<Arc<dyn MutationGate>>,
    trace: &ImageReadTrace,
) -> Result<WindowImageCapture, ImageUnavailable> {
    let active: AcquisitionFence = Arc::new(move || {
        !cancel.as_ref().is_some_and(|cancel| cancel.is_cancelled())
            && !gate.as_ref().is_some_and(|gate| gate.stopped())
    });
    let background_end = plan.background_end();
    if Instant::now() >= background_end || !active() {
        return Err(ImageUnavailable::CaptureFailed);
    }
    let captured = backend.capture_background_picture(grant, background_end, &active);
    if !active() {
        return Err(ImageUnavailable::CaptureFailed);
    }
    match captured {
        // An already reported terminal (affinity, cursor property or no
        // window) can never lead to an attempt to reveal the same pixels.
        Err(reason) if reason != ImageUnavailable::CaptureFailed => return Err(reason),
        Ok(image) if Instant::now() < background_end => return Ok(image),
        _ => (),
    }
    if let Some(stop) = plan.fallback_stop(Instant::now()) {
        let fronting = fronting::Fronting::stopped(
            cerebellum_core::config::AppUse::Background,
            fronting::Purpose::NeedsFront,
            stop,
        );
        trace.background_fronting.set(Some(fronting));
        trace.evidence.borrow_mut().fronting_record = fronting.row_record();
        return Err(ImageUnavailable::FrontingUnavailable);
    }
    Err(ImageUnavailable::CaptureFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_must_have_the_full_remaining_read_bracket() {
        let end = Instant::now() + Duration::from_secs(1);
        let plan = PicturePlan::new(end, Some(Ok(())));
        assert_eq!(
            plan.fallback_stop(plan.background_end()),
            Some(FrontingStop::ObserverUnavailable)
        );
        assert_eq!(
            plan.fallback_stop(end - Duration::from_millis(crate::budgets::FRONTING_READ_MS - 1)),
            None
        );
    }
}
