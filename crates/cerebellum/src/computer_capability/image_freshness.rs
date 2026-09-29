//! Accessibility remains current while covered Chromium windows stop painting.

use cerebellum_computer::app_state::image::ImageUnavailable;
use cerebellum_computer::platform::ProcessGrant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowVisibility {
    FullyVisible,
    Covered,
    Unknown,
}

/// A missing visibility reading cannot certify that Chromium repainted.
pub fn image_freshness_decision(
    is_chromium: bool,
    visibility: WindowVisibility,
) -> Result<(), ImageUnavailable> {
    if is_chromium && visibility != WindowVisibility::FullyVisible {
        Err(ImageUnavailable::WindowCoveredMayBeStale)
    } else {
        Ok(())
    }
}

/// Read facts before capture and again for the exact window whose pixels were taken.
/// Tests supply facts without depending on the desktop running the suite.
pub trait ImageFreshnessSource: Send + Sync {
    fn inspect(&self, target: &ProcessGrant, window_id: Option<&str>) -> (bool, WindowVisibility);
}

pub(super) struct NativeImageFreshnessSource;

impl ImageFreshnessSource for NativeImageFreshnessSource {
    fn inspect(&self, target: &ProcessGrant, window_id: Option<&str>) -> (bool, WindowVisibility) {
        #[cfg(target_os = "macos")]
        {
            if !cerebellum_macos::process_uses_chromium(target.pid, &target.bundle_identity) {
                return (false, WindowVisibility::Unknown);
            }
            let id = match window_id {
                Some(id) => id.parse::<u32>().ok(),
                None => cerebellum_macos::frontmost_window_id(target.pid),
            };
            let visibility = id.map(|id| cerebellum_macos::window_visibility(target.pid, id));
            use cerebellum_macos::WindowVisibility as Native;
            (
                true,
                match visibility {
                    Some(Native::FullyVisible) => WindowVisibility::FullyVisible,
                    Some(Native::Covered) => WindowVisibility::Covered,
                    Some(Native::Unknown) | None => WindowVisibility::Unknown,
                },
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (target, window_id);
            (false, WindowVisibility::Unknown)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_chromium_visibility_refuses_image() {
        assert_eq!(
            image_freshness_decision(true, WindowVisibility::Unknown),
            Err(ImageUnavailable::WindowCoveredMayBeStale)
        );
    }

    #[test]
    fn covered_chromium_refuses_but_visible_chromium_and_native_apps_allow_images() {
        assert_eq!(
            image_freshness_decision(true, WindowVisibility::Covered),
            Err(ImageUnavailable::WindowCoveredMayBeStale)
        );
        assert_eq!(
            image_freshness_decision(true, WindowVisibility::FullyVisible),
            Ok(())
        );
        for visibility in [
            WindowVisibility::FullyVisible,
            WindowVisibility::Covered,
            WindowVisibility::Unknown,
        ] {
            assert_eq!(image_freshness_decision(false, visibility), Ok(()));
        }
    }
}
