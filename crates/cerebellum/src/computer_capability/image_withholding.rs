//! Identify a stale-cover refusal without changing the image decision or audit row.

use std::collections::BTreeMap;
use std::sync::Mutex;

use cerebellum_computer::app_state::image::ImageUnavailable;
use serde_json::{json, Value};

#[derive(Clone, Copy)]
pub(super) enum ImageWithholding {
    BeforeCapture,
    AfterCapture,
    #[cfg(target_os = "macos")]
    DockWitness,
    #[cfg(target_os = "macos")]
    PrepareFailed(cerebellum_macos::FrontedVisibilityPrepareError),
}

impl ImageWithholding {
    fn stage(self) -> &'static str {
        match self {
            Self::BeforeCapture => "covered_before_capture",
            Self::AfterCapture => "covered_after_capture",
            #[cfg(target_os = "macos")]
            Self::DockWitness => "dock_witness",
            #[cfg(target_os = "macos")]
            Self::PrepareFailed(_) => "prepare_failed",
        }
    }

    fn prepare_error(self) -> Option<&'static str> {
        match self {
            #[cfg(target_os = "macos")]
            Self::PrepareFailed(error) => Some(error.as_str()),
            _ => None,
        }
    }

    pub(super) fn detail(self) -> Value {
        let mut detail = json!({"stage": self.stage()});
        if let Some(error) = self.prepare_error() {
            detail["prepare_error"] = json!(error);
        }
        detail
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Counts {
    by_stage: BTreeMap<&'static str, u64>,
    by_prepare_error: BTreeMap<&'static str, u64>,
}

impl Counts {
    const fn new() -> Self {
        Self {
            by_stage: BTreeMap::new(),
            by_prepare_error: BTreeMap::new(),
        }
    }

    fn record(
        &mut self,
        reason: ImageUnavailable,
        withholding: Option<ImageWithholding>,
    ) -> Option<ImageWithholding> {
        // A failed restore or expired cutoff can supersede a visibility
        // refusal. Count only the final reason.
        let withholding =
            withholding.filter(|_| reason == ImageUnavailable::WindowCoveredMayBeStale)?;
        let count = self.by_stage.entry(withholding.stage()).or_default();
        *count = count.saturating_add(1);
        if let Some(error) = withholding.prepare_error() {
            let count = self.by_prepare_error.entry(error).or_default();
            *count = count.saturating_add(1);
        }
        Some(withholding)
    }
}

static COUNTS: Mutex<Counts> = Mutex::new(Counts::new());

pub(super) fn record(
    reason: ImageUnavailable,
    withholding: Option<ImageWithholding>,
) -> Option<ImageWithholding> {
    COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .record(reason, withholding)
}

/// Cumulative stale-cover refusals since process start. Missing keys are zero.
pub(crate) fn image_withholding_counts() -> Value {
    json!(*COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_the_diagnostic_for_the_final_unavailable_reason() {
        let mut counts = Counts::new();
        let stage = Some(ImageWithholding::BeforeCapture);
        assert!(counts
            .record(ImageUnavailable::RestoreFailed, stage)
            .is_none());
        assert!(counts
            .record(ImageUnavailable::FrontingBoundExceeded, stage)
            .is_none());
        assert!(counts
            .record(ImageUnavailable::WindowCoveredMayBeStale, stage)
            .is_some());
        assert_eq!(
            json!(counts),
            json!({
                "byStage": {"covered_before_capture": 1}, "byPrepareError": {}
            })
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn prepare_diagnostic_counts_one_closed_stage_and_error_kind() {
        let mut counts = Counts::new();
        let diagnostic = ImageWithholding::PrepareFailed(
            cerebellum_macos::FrontedVisibilityPrepareError::DockCaptureLookup,
        );
        let observed = counts
            .record(ImageUnavailable::WindowCoveredMayBeStale, Some(diagnostic))
            .unwrap();
        assert_eq!(
            observed.detail(),
            json!({"stage": "prepare_failed", "prepare_error": "dock_capture_lookup"})
        );
        assert_eq!(
            json!(counts),
            json!({
                "byStage": {"prepare_failed": 1}, "byPrepareError": {"dock_capture_lookup": 1}
            })
        );
    }
}
