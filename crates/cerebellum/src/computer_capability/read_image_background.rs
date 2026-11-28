//! Budget and admission for target-bound background pictures.

use super::{fronting, read_image::ImageReadTrace};
use crate::CancelHandle;
use cerebellum_computer::app_state::image::{ImageUnavailable, WindowImageCapture};
use cerebellum_computer::capture::{AcquisitionFence, CaptureBackend};
use cerebellum_computer::dispatch::{FrontingStop, MutationGate};
use cerebellum_computer::platform::{PlatformDriver, ProcessGrant};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) struct PicturePlan {
    end: Instant,
    fallback: Option<Result<(), FrontingStop>>,
    #[cfg(windows)]
    hooks: Option<fronting::CellHooks>,
}

impl PicturePlan {
    pub(super) fn new(end: Instant, fallback: Option<Result<(), FrontingStop>>) -> Self {
        Self {
            end,
            fallback,
            #[cfg(windows)]
            hooks: None,
        }
    }

    #[cfg(windows)]
    pub(super) fn prepare(
        &mut self,
        prepared: Result<fronting::ObligationParts, fronting::PrepareStop>,
    ) {
        match prepared {
            Ok(parts) => self.hooks = Some(fronting::CellHooks::new(parts)),
            Err(refusal) => self.fallback = Some(Err(refusal.stop)),
        }
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
        // Admission alone is not proof that an observer is live.
        Some(admission.err().unwrap_or(FrontingStop::ObserverUnavailable))
    }
}

pub(super) fn capture<B: CaptureBackend, D: PlatformDriver>(
    mut backend: B,
    grant: &ProcessGrant,
    plan: &PicturePlan,
    cancel: Option<CancelHandle>,
    gate: Option<Arc<dyn MutationGate>>,
    trace: &ImageReadTrace,
    _make_driver: &dyn Fn() -> D,
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
        #[cfg(windows)]
        if let Some(hooks) = &plan.hooks {
            return capture_fronted(backend, grant, plan.end, hooks, active, trace, _make_driver);
        }
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

#[cfg(windows)]
fn capture_fronted<B: CaptureBackend, D: PlatformDriver>(
    mut backend: B,
    grant: &ProcessGrant,
    end: Instant,
    hooks: &fronting::CellHooks,
    active: AcquisitionFence,
    trace: &ImageReadTrace,
    make_driver: &dyn Fn() -> D,
) -> Result<WindowImageCapture, ImageUnavailable> {
    use cerebellum_computer::app_state::image::ImageFronting;
    use cerebellum_computer::dispatch::{BracketStop, RestoreStatus};
    use cerebellum_core::config::AppUse;

    let bound = crate::budgets::FRONTING_READ_MS;
    trace.fronting_bound_ms.set(Some(bound));
    let mut driver = make_driver();
    if !driver.accept_fronted_dispatch_hooks(fronting::boxed_hooks(hooks)) {
        let refused = fronting::Fronting::stopped(
            AppUse::Background,
            fronting::Purpose::NeedsFront,
            FrontingStop::ObserverUnavailable,
        );
        trace.background_fronting.set(Some(refused));
        trace.evidence.borrow_mut().fronting_record = refused.row_record();
        return Err(ImageUnavailable::FrontingUnavailable);
    }
    let mut captured = Err(ImageUnavailable::CaptureFailed);
    let picture_hooks = hooks.clone();
    let picture_active = Arc::clone(&active);
    let fence: AcquisitionFence = Arc::new(move || {
        picture_active() && Instant::now() < end && picture_hooks.picture_may_acquire()
    });
    let report = driver
        .read_fronted(
            grant,
            bound,
            &|| !active() || Instant::now() >= end,
            &mut || {
                let Some(_lock) = hooks.hold_lock_for_read() else {
                    return;
                };
                let Some(until) = hooks.picture_wait_until() else {
                    return;
                };
                let deadline = end.min(until);
                if Instant::now() < deadline && fence() {
                    captured = backend.capture_background_picture(grant, deadline, &fence);
                    if Instant::now() >= deadline || !fence() {
                        captured = Err(ImageUnavailable::FrontingBoundExceeded);
                    }
                }
            },
        )
        .map_err(|_| ImageUnavailable::FrontingUnavailable)?;
    trace.evidence.borrow_mut().fronting = Some(ImageFronting::from(&report));
    let ending = hooks.peek();
    let fronting =
        fronting::hooked_fronting(AppUse::Background, fronting::Purpose::NeedsFront, &ending);
    trace.background_fronting.set(Some(fronting));
    trace.evidence.borrow_mut().fronting_record = fronting.row_record();
    if report.stop == Some(BracketStop::BoundExceeded)
        || (ending.refusal != Some(FrontingStop::FrontFailed)
            && (hooks.cutoff_fired()
                || report.restore_started_by_cutoff
                || report.longest_fronted_interval_ms > bound))
    {
        return Err(ImageUnavailable::FrontingBoundExceeded);
    }
    if matches!(report.restore, RestoreStatus::Failed { .. }) {
        return Err(ImageUnavailable::RestoreFailed);
    }
    if !report.held(bound) {
        return Err(ImageUnavailable::FrontingUnavailable);
    }
    captured
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
