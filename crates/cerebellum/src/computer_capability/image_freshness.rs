//! Covered pixels are not evidence of current state without measured repainting.

/// Add an app only after a desk measurement shows its covered window repainting.
const COVERED_WINDOW_REPAINTING_APPS: &[&str] = &[];

fn repaints_while_covered(bundle_identity: &str) -> bool {
    COVERED_WINDOW_REPAINTING_APPS.contains(&bundle_identity)
}

use cerebellum_computer::app_state::image::{ImageDecision, ImageUnavailable};
use cerebellum_computer::platform::ProcessGrant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowVisibility {
    FullyVisible,
    Covered,
    Unknown,
}

/// Missing visibility cannot certify fresh pixels for an unmeasured engine.
pub fn image_freshness_decision(
    repaints_while_covered: bool,
    visibility: WindowVisibility,
) -> Result<(), ImageUnavailable> {
    if !repaints_while_covered && visibility != WindowVisibility::FullyVisible {
        Err(ImageUnavailable::WindowCoveredMayBeStale)
    } else {
        Ok(())
    }
}

/// Read facts before capture and again for the exact window whose pixels were taken.
/// Tests supply facts without depending on the desktop running the suite.
/// The boolean certifies measured repainting while covered, not an engine guess.
pub trait ImageFreshnessSource: Send + Sync {
    fn inspect(&self, target: &ProcessGrant, window_id: Option<&str>) -> (bool, WindowVisibility);

    /// Sources without a deciding rule cannot distinguish a cover from an
    /// off-screen or absent window. Only report a rule the source established.
    fn inspect_decision(
        &self,
        target: &ProcessGrant,
        window_id: Option<&str>,
    ) -> (bool, WindowVisibility, ImageDecision) {
        let (repaints, visibility) = self.inspect(target, window_id);
        let decision = match visibility {
            WindowVisibility::FullyVisible => ImageDecision::FullyVisible,
            WindowVisibility::Covered | WindowVisibility::Unknown => ImageDecision::Unknown,
        };
        (repaints, visibility, decision)
    }

    #[cfg(target_os = "macos")]
    fn prepare_fronted(
        &self,
        _target: &ProcessGrant,
        _window_id: &str,
    ) -> Result<Option<cerebellum_macos::PreparedFrontedVisibility>, ImageUnavailable> {
        Ok(None)
    }
}

pub(super) struct NativeImageFreshnessSource;

impl ImageFreshnessSource for NativeImageFreshnessSource {
    fn inspect(&self, target: &ProcessGrant, window_id: Option<&str>) -> (bool, WindowVisibility) {
        let (repaints, visibility, _) = self.inspect_decision(target, window_id);
        (repaints, visibility)
    }

    fn inspect_decision(
        &self,
        target: &ProcessGrant,
        window_id: Option<&str>,
    ) -> (bool, WindowVisibility, ImageDecision) {
        #[cfg(target_os = "macos")]
        {
            let id = match window_id {
                Some(id) => id.parse::<u32>().ok(),
                None => cerebellum_macos::frontmost_window_id(target.pid),
            };
            let visibility =
                id.map(|id| cerebellum_macos::window_visibility_decision(target.pid, id));
            let (visibility, decision) = map_native_visibility(visibility);
            (
                repaints_while_covered(&target.bundle_identity),
                visibility,
                decision,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = window_id;
            (
                repaints_while_covered(&target.bundle_identity),
                WindowVisibility::Unknown,
                ImageDecision::Unknown,
            )
        }
    }

    #[cfg(target_os = "macos")]
    fn prepare_fronted(
        &self,
        target: &ProcessGrant,
        window_id: &str,
    ) -> Result<Option<cerebellum_macos::PreparedFrontedVisibility>, ImageUnavailable> {
        let generation = target
            .process_generation_evidence
            .parse()
            .map_err(|_| ImageUnavailable::FrontingUnavailable)?;
        let window_id = window_id
            .parse()
            .map_err(|_| ImageUnavailable::NoWindowCaptured)?;
        cerebellum_macos::PreparedFrontedVisibility::prepare(target.pid, generation, window_id)
            .map(Some)
            .map_err(|_| ImageUnavailable::WindowCoveredMayBeStale)
    }
}

#[cfg(target_os = "macos")]
pub(super) fn map_native_visibility(
    visibility: Option<(
        cerebellum_macos::WindowVisibility,
        cerebellum_macos::VisibilityRule,
    )>,
) -> (WindowVisibility, ImageDecision) {
    use cerebellum_macos::{VisibilityRule as Rule, WindowVisibility as Native};
    (
        match visibility {
            Some((Native::FullyVisible, _)) => WindowVisibility::FullyVisible,
            Some((Native::Covered, _)) => WindowVisibility::Covered,
            Some((Native::Unknown, _)) | None => WindowVisibility::Unknown,
        },
        match visibility.map(|(_, rule)| rule) {
            Some(Rule::TargetAbsent) => ImageDecision::TargetAbsent,
            Some(Rule::TargetTransparent) => ImageDecision::TargetTransparent,
            Some(Rule::OutsideDisplays) => ImageDecision::OutsideDisplays,
            Some(Rule::OverlappingWindow) => ImageDecision::CoveredByWindow,
            Some(Rule::HigherLayerUnionCoverage) => ImageDecision::FullyOverlaid,
            Some(Rule::NoLayerZeroOverlap) => ImageDecision::FullyVisible,
            Some(Rule::MissingData) | None => ImageDecision::Unknown,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmeasured_engines_withhold_covered_and_unknown_windows() {
        for app in [
            "com.example.Unknown",
            "com.apple.TextEdit",
            "com.google.Chrome",
        ] {
            for visibility in [WindowVisibility::Covered, WindowVisibility::Unknown] {
                assert_eq!(
                    image_freshness_decision(repaints_while_covered(app), visibility),
                    Err(ImageUnavailable::WindowCoveredMayBeStale),
                    "{app}: {visibility:?}"
                );
            }
        }
    }

    #[test]
    fn fully_visible_windows_allow_images_for_every_engine() {
        for repaints in [false, true] {
            assert_eq!(
                image_freshness_decision(repaints, WindowVisibility::FullyVisible),
                Ok(())
            );
        }
    }
}
