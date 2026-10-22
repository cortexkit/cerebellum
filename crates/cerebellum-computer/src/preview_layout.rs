//! Where a background-mode preview is drawn, and where a point of the window
//! it shows lands inside it.
//!
//! Two programs need the same numbers. The module times the agent badge's
//! glides inside a preview by their length in the thumbnail's points, and the
//! helper process draws the preview and places the badge in it. This one
//! file is compiled into both crates: `cerebellum-computer` declares it as a
//! module, and `cerebellum-macos` (the helper's crate, which cannot depend on
//! `cerebellum-computer`) includes it by path, as it does `cursor_timeline.rs`.
//! Keep it free of `use crate::...` and of dependencies, so it compiles the
//! same in either crate. It is plain arithmetic in top-down points: slot
//! origins are global screen points, while a layout's rectangles and a mapped
//! thumbnail point are relative to the preview's own top-left corner.

/// How many previews show at once, one per agent, stacked top-down from the
/// top-right corner of the screen.
pub const PREVIEW_SLOTS: u8 = 3;

/// The preview's width, in points.
pub const PREVIEW_WIDTH: f64 = 280.0;

/// The tallest a preview is, in points. A window too tall to fit at the
/// preview's width is letterboxed: drawn narrower, centred, at its own shape.
pub const PREVIEW_MAX_HEIGHT: f64 = 360.0;

/// Space between the preview's edge and the thumbnail, all round.
pub const PREVIEW_INSET: f64 = 6.0;

/// The strip under the thumbnail that holds the agent's avatar chip, the
/// application's name and the action's label.
pub const PREVIEW_CAPTION_HEIGHT: f64 = 34.0;

/// Clear space between a preview and the screen's right edge, and between
/// the top preview and the menu bar.
pub const PREVIEW_MARGIN: f64 = 12.0;

/// Space between two stacked previews.
pub const PREVIEW_GAP: f64 = 10.0;

/// The preview's corner radius. The thumbnail's corners follow it, less the
/// inset, so the two curves stay parallel.
pub const PREVIEW_CORNER_RADIUS: f64 = 16.0;

/// The lowest thumbnail a preview is given on a very short screen, so a
/// preview never collapses to nothing.
const MIN_THUMBNAIL_HEIGHT: f64 = 40.0;

/// A rectangle in top-down points: `x`, `y` is its top-left corner.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PreviewRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl PreviewRect {
    pub const fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn right(self) -> f64 {
        self.x + self.width
    }

    pub fn bottom(self) -> f64 {
        self.y + self.height
    }

    fn valid(self) -> bool {
        [self.x, self.y, self.width, self.height]
            .iter()
            .all(|v| v.is_finite())
            && self.width > 0.0
            && self.height > 0.0
    }
}

/// One preview's parts, each relative to the preview's own top-left corner.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PreviewLayout {
    /// The preview's width and height.
    pub size: [f64; 2],
    /// The area the thumbnail is fitted into: the preview's width less the
    /// inset, and as tall as the thumbnail.
    pub thumbnail_box: PreviewRect,
    /// The window's picture at the window's own shape. It fills the box's
    /// width, or, when letterboxed, its height, centred across it.
    pub thumbnail: PreviewRect,
    /// The strip under the thumbnail for the chip, the name and the label.
    pub caption: PreviewRect,
}

/// The preview for a window of `aspect` (its width and height, any unit),
/// at most `max_height` tall (never more than `PREVIEW_MAX_HEIGHT`), or
/// `None` for a malformed shape. On a screen so short that `max_height`
/// leaves less than a 40-point thumbnail, the thumbnail keeps that minimum
/// and the preview is taller than `max_height`.
pub fn preview_layout(aspect: [f64; 2], max_height: f64) -> Option<PreviewLayout> {
    let [width, height] = aspect;
    if !(width.is_finite() && height.is_finite() && width > 0.0 && height > 0.0) {
        return None;
    }
    let max_height = if max_height.is_finite() {
        max_height.min(PREVIEW_MAX_HEIGHT)
    } else {
        PREVIEW_MAX_HEIGHT
    };
    let box_width = PREVIEW_WIDTH - 2.0 * PREVIEW_INSET;
    let tallest =
        (max_height - 2.0 * PREVIEW_INSET - PREVIEW_CAPTION_HEIGHT).max(MIN_THUMBNAIL_HEIGHT);
    let natural = box_width * height / width;
    let (thumb_width, thumb_height) = if natural <= tallest {
        (box_width, natural)
    } else {
        (tallest * width / height, tallest)
    };
    let thumbnail_box = PreviewRect::new(PREVIEW_INSET, PREVIEW_INSET, box_width, thumb_height);
    let thumbnail = PreviewRect::new(
        PREVIEW_INSET + (box_width - thumb_width) / 2.0,
        PREVIEW_INSET,
        thumb_width,
        thumb_height,
    );
    let caption = PreviewRect::new(
        PREVIEW_INSET,
        thumbnail_box.bottom(),
        box_width,
        PREVIEW_CAPTION_HEIGHT,
    );
    let layout = PreviewLayout {
        size: [PREVIEW_WIDTH, caption.bottom() + PREVIEW_INSET],
        thumbnail_box,
        thumbnail,
        caption,
    };
    (thumbnail.valid() && caption.valid()).then_some(layout)
}

/// The thumbnail's width and height in points for a window of `aspect`, at
/// the full `PREVIEW_MAX_HEIGHT`: what the module measures a glide inside the
/// preview in. A screen too short for three full-height previews draws them
/// shorter (see `slot_max_height`), which only shortens a letterboxed
/// thumbnail; the badge still lands on the same spot of the window.
pub fn thumbnail_size(aspect: [f64; 2]) -> Option<[f64; 2]> {
    preview_layout(aspect, PREVIEW_MAX_HEIGHT)
        .map(|layout| [layout.thumbnail.width, layout.thumbnail.height])
}

/// The height each preview slot allows on a screen whose usable area (below
/// the menu bar, beside the Dock) is `visible_height` tall:
/// `PREVIEW_MAX_HEIGHT`, or less when that many full-height previews would
/// not fit one above the other. On a very short screen a preview can still
/// be taller than this, to keep its minimum thumbnail height.
pub fn slot_max_height(visible_height: f64) -> f64 {
    let slots = f64::from(PREVIEW_SLOTS);
    let fits = (visible_height - 2.0 * PREVIEW_MARGIN - (slots - 1.0) * PREVIEW_GAP) / slots;
    if fits.is_finite() {
        fits.min(PREVIEW_MAX_HEIGHT)
    } else {
        PREVIEW_MAX_HEIGHT
    }
}

/// The top-left corner of the preview in `slot` on a screen whose usable
/// area is `visible`, or `None` for a slot past the last. Each slot has a
/// fixed place, one full-height preview below the one before it, so a
/// freed slot leaves a gap rather than moving the previews under it.
pub fn slot_origin(visible: PreviewRect, slot: u8) -> Option<[f64; 2]> {
    if slot >= PREVIEW_SLOTS || !visible.valid() {
        return None;
    }
    let pitch = slot_max_height(visible.height) + PREVIEW_GAP;
    Some([
        visible.right() - PREVIEW_MARGIN - PREVIEW_WIDTH,
        visible.y + PREVIEW_MARGIN + f64::from(slot) * pitch,
    ])
}

/// Where a point of the previewed window lands in its thumbnail, relative to
/// the preview's top-left corner. `normalized` is the point's place in the
/// window, each coordinate from 0 (left or top) to 1 (right or bottom);
/// anything outside that, or not finite, lands nowhere.
pub fn thumbnail_point(thumbnail: PreviewRect, normalized: [f64; 2]) -> Option<[f64; 2]> {
    if !thumbnail.valid()
        || !normalized
            .iter()
            .all(|v| v.is_finite() && (0.0..=1.0).contains(v))
    {
        return None;
    }
    Some([
        thumbnail.x + normalized[0] * thumbnail.width,
        thumbnail.y + normalized[1] * thumbnail.height,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCREEN: PreviewRect = PreviewRect::new(0.0, 25.0, 1512.0, 920.0);

    #[test]
    fn a_landscape_window_fills_the_width_at_its_own_shape() {
        let layout = preview_layout([1600.0, 1000.0], PREVIEW_MAX_HEIGHT).unwrap();
        assert_eq!(layout.size[0], PREVIEW_WIDTH);
        let thumb = layout.thumbnail;
        assert_eq!(thumb.width, PREVIEW_WIDTH - 2.0 * PREVIEW_INSET);
        assert!((thumb.width / thumb.height - 1.6).abs() < 1e-9);
        assert_eq!(thumb, layout.thumbnail_box);
        assert_eq!(layout.caption.y, thumb.bottom());
        assert_eq!(
            layout.size[1],
            thumb.height + PREVIEW_CAPTION_HEIGHT + 2.0 * PREVIEW_INSET
        );
        assert!(layout.size[1] <= PREVIEW_MAX_HEIGHT);
    }

    #[test]
    fn a_tall_window_is_letterboxed_so_the_preview_is_at_most_360_points() {
        let layout = preview_layout([400.0, 2000.0], PREVIEW_MAX_HEIGHT).unwrap();
        assert_eq!(layout.size, [PREVIEW_WIDTH, PREVIEW_MAX_HEIGHT]);
        let thumb = layout.thumbnail;
        assert!((thumb.width / thumb.height - 0.2).abs() < 1e-9);
        // Centred across the full-width box, the same height as it.
        assert_eq!(thumb.height, layout.thumbnail_box.height);
        assert!(
            ((thumb.x - layout.thumbnail_box.x) - (layout.thumbnail_box.right() - thumb.right()))
                .abs()
                < 1e-9
        );
        // A screen too short for three full previews makes them shorter.
        let short = preview_layout([400.0, 2000.0], 200.0).unwrap();
        assert_eq!(short.size[1], 200.0);
        assert_eq!(
            thumbnail_size([400.0, 2000.0]),
            Some([thumb.width, thumb.height])
        );
    }

    #[test]
    fn a_malformed_shape_has_no_preview() {
        for aspect in [
            [0.0, 10.0],
            [10.0, -1.0],
            [f64::NAN, 10.0],
            [10.0, f64::INFINITY],
        ] {
            assert_eq!(
                preview_layout(aspect, PREVIEW_MAX_HEIGHT),
                None,
                "{aspect:?}"
            );
            assert_eq!(thumbnail_size(aspect), None);
        }
    }

    #[test]
    fn slots_stack_down_from_the_top_right_below_the_menu_bar_and_never_overlap() {
        let origins: Vec<[f64; 2]> = (0..PREVIEW_SLOTS)
            .map(|slot| slot_origin(SCREEN, slot).unwrap())
            .collect();
        assert_eq!(
            origins[0],
            [
                SCREEN.right() - PREVIEW_MARGIN - PREVIEW_WIDTH,
                25.0 + PREVIEW_MARGIN
            ]
        );
        let tallest = slot_max_height(SCREEN.height);
        for pair in origins.windows(2) {
            assert_eq!(pair[0][0], pair[1][0]);
            assert_eq!(pair[1][1] - pair[0][1], tallest + PREVIEW_GAP);
        }
        // The last slot's tallest preview still ends on the screen.
        assert!(origins[2][1] + tallest <= SCREEN.bottom() - PREVIEW_MARGIN + 1e-9);
        assert_eq!(slot_origin(SCREEN, PREVIEW_SLOTS), None);
        // A tall screen gives every slot the full height.
        assert_eq!(slot_max_height(2000.0), PREVIEW_MAX_HEIGHT);
    }

    #[test]
    fn a_window_point_lands_at_the_same_place_in_the_thumbnail() {
        let thumb = PreviewRect::new(10.0, 6.0, 200.0, 100.0);
        assert_eq!(thumbnail_point(thumb, [0.0, 0.0]), Some([10.0, 6.0]));
        assert_eq!(thumbnail_point(thumb, [1.0, 1.0]), Some([210.0, 106.0]));
        assert_eq!(thumbnail_point(thumb, [0.25, 0.5]), Some([60.0, 56.0]));
        for outside in [[-0.01, 0.5], [0.5, 1.01], [f64::NAN, 0.5]] {
            assert_eq!(thumbnail_point(thumb, outside), None, "{outside:?}");
        }
    }
}
