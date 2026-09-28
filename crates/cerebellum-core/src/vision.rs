//! The size limits a vision model reads an image under, as arithmetic over
//! pixel dimensions.
//!
//! Shared here because two planes size images for the same readers: the
//! browser asks Chrome to render a page screenshot at the fitting size, and
//! the computer plane resamples a window capture to it. Both must agree on the
//! size, or a coordinate a model reads off one image is interpreted in the
//! space of another; one function means there is nothing to agree about.

/// Claude's standard tier uses 1568 for two different limits: the longest
/// side of an image, and the visual-token budget where an image costs
/// `ceil(width / 28) * ceil(height / 28)` tokens. The high-resolution tier
/// (Claude 4.7 and later) allows 2576 px and 4784 tokens. This module cannot
/// know which model will read a capture. Undershooting costs a high-resolution
/// consumer some detail; overshooting makes the API downscale again, so the
/// model produces coordinates in a smaller space than we report. That is the
/// mismatch a pixel-addressed click exists to prevent. Standard is the bound
/// that keeps every consumer correct.
pub const VISION_LONG_EDGE_PX: u32 = 1568;

/// Pixel size of one visual-token patch.
pub const VISION_PATCH_PX: u32 = 28;

/// Standard-tier visual-token cap. Equal to [`VISION_LONG_EDGE_PX`] on the
/// standard tier; a distinct constant because an image can satisfy the edge
/// limit while still costing more tokens than this.
pub const VISION_TOKEN_CAP: u32 = 1568;

/// Largest aspect-preserving width, in pixels, that satisfies both
/// standard-tier vision limits.
///
/// Tokens are counted on a grid of [`VISION_PATCH_PX`] squares, so feasible
/// sizes are `patch_w` by `patch_h` rectangles with `patch_w * patch_h` at
/// most [`VISION_TOKEN_CAP`] and each side at most [`VISION_LONG_EDGE_PX`].
/// The largest size on the native aspect line is the right edge of the best
/// such rectangle.
pub fn max_vision_width_px(native_width: f64, native_height: f64) -> f64 {
    let patch = f64::from(VISION_PATCH_PX);
    let max_patches = VISION_LONG_EDGE_PX / VISION_PATCH_PX;
    let aspect = native_height / native_width;
    let mut best_width: f64 = 0.0;
    for patch_w in 1..=max_patches {
        for patch_h in 1..=max_patches {
            if patch_w.saturating_mul(patch_h) > VISION_TOKEN_CAP {
                continue;
            }
            // Half-open pixel box for this patch pair: width in
            // ((patch_w-1)*patch, patch_w*patch], same for height. Intersect
            // the aspect line with that box and keep the largest width.
            let width_lo =
                (f64::from(patch_w - 1) * patch).max(f64::from(patch_h - 1) * patch / aspect);
            let width_hi = (f64::from(patch_w) * patch).min(f64::from(patch_h) * patch / aspect);
            if width_hi > width_lo {
                best_width = best_width.max(width_hi);
            }
        }
    }
    best_width.min(native_width)
}

/// The visual-token cost of an image of these whole-pixel dimensions.
pub fn vision_tokens(width_px: u32, height_px: u32) -> u64 {
    u64::from(width_px.div_ceil(VISION_PATCH_PX)) * u64::from(height_px.div_ceil(VISION_PATCH_PX))
}

/// Whole-pixel dimensions an image of `width_px` by `height_px` is resampled
/// to so a vision model reads it without resizing it again: scaled down,
/// aspect preserved, until it satisfies both limits, and never scaled up.
///
/// `None` for an image with no area, which has no size to fit.
///
/// Rounding goes down on both sides, so the result can only shrink from the
/// fitting size [`max_vision_width_px`] computes and therefore still fits: a
/// side rounded up could cross into the next token patch.
pub fn fit_within_vision_limits(width_px: u32, height_px: u32) -> Option<(u32, u32)> {
    if width_px == 0 || height_px == 0 {
        return None;
    }
    if width_px <= VISION_LONG_EDGE_PX
        && height_px <= VISION_LONG_EDGE_PX
        && vision_tokens(width_px, height_px) <= u64::from(VISION_TOKEN_CAP)
    {
        return Some((width_px, height_px));
    }
    let native_width = f64::from(width_px);
    let native_height = f64::from(height_px);
    let target_width = max_vision_width_px(native_width, native_height);
    let scale = target_width / native_width;
    let width = ((native_width * scale).floor() as u32).clamp(1, width_px);
    let height = ((native_height * scale).floor() as u32).clamp(1, height_px);
    Some((width, height))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fits(width: u32, height: u32) -> bool {
        width <= VISION_LONG_EDGE_PX
            && height <= VISION_LONG_EDGE_PX
            && vision_tokens(width, height) <= u64::from(VISION_TOKEN_CAP)
    }

    #[test]
    fn a_fitting_image_keeps_its_size_and_is_never_scaled_up() {
        assert_eq!(fit_within_vision_limits(640, 480), Some((640, 480)));
        assert_eq!(fit_within_vision_limits(1, 1), Some((1, 1)));
    }

    #[test]
    fn an_image_with_no_area_has_no_fitting_size() {
        assert_eq!(fit_within_vision_limits(0, 480), None);
        assert_eq!(fit_within_vision_limits(640, 0), None);
    }

    /// Every size across the shapes a window takes fits both limits after
    /// fitting, keeps its aspect up to rounding, and is no larger than the
    /// original on either side.
    #[test]
    fn every_fitted_size_satisfies_both_limits_without_growing() {
        for (width, height) in [
            (2880, 1800),
            (3456, 2234),
            (5120, 2880),
            (1920, 1080),
            (1569, 1569),
            (1200, 1200),
            (8000, 300),
            (300, 8000),
            (1568, 1569),
            (1100, 1100),
        ] {
            let (fitted_width, fitted_height) = fit_within_vision_limits(width, height).unwrap();
            assert!(fits(fitted_width, fitted_height), "{width}x{height}");
            assert!(fitted_width <= width && fitted_height <= height);
            // Both sides are the original scaled by one factor and rounded
            // down, so their ratios to the original differ by at most one
            // pixel's worth of the shorter side.
            let width_ratio = f64::from(fitted_width) / f64::from(width);
            let height_ratio = f64::from(fitted_height) / f64::from(height);
            let tolerance = 1.0 / f64::from(width.min(height));
            assert!(
                (width_ratio - height_ratio).abs() <= tolerance,
                "{width}x{height} became {fitted_width}x{fitted_height}"
            );
        }
    }
}
