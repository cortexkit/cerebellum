//! Covered pixels are not evidence of current state without measured repainting.

/// Add an app only after a desk measurement shows its covered window repainting.
const COVERED_WINDOW_REPAINTING_APPS: &[&str] = &[];

fn repaints_while_covered(bundle_identity: &str) -> bool {
    COVERED_WINDOW_REPAINTING_APPS.contains(&bundle_identity)
}

use cerebellum_computer::app_state::image::ImageUnavailable;
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
}

pub(super) struct NativeImageFreshnessSource;

impl ImageFreshnessSource for NativeImageFreshnessSource {
    fn inspect(&self, target: &ProcessGrant, window_id: Option<&str>) -> (bool, WindowVisibility) {
        #[cfg(target_os = "macos")]
        {
            let id = match window_id {
                Some(id) => id.parse::<u32>().ok(),
                None => cerebellum_macos::frontmost_window_id(target.pid),
            };
            let visibility = id.map(|id| cerebellum_macos::window_visibility(target.pid, id));
            use cerebellum_macos::WindowVisibility as Native;
            (
                repaints_while_covered(&target.bundle_identity),
                match visibility {
                    Some(Native::FullyVisible) => WindowVisibility::FullyVisible,
                    Some(Native::Covered) => WindowVisibility::Covered,
                    Some(Native::Unknown) | None => WindowVisibility::Unknown,
                },
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = window_id;
            (
                repaints_while_covered(&target.bundle_identity),
                WindowVisibility::Unknown,
            )
        }
    }
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
