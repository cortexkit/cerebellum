//! Host-neutral geometry for the agent cursor picture: the pointer's shape,
//! where the avatar chip and label pill sit, and where the panel must go so
//! that the pointer's tip lands exactly on the target.
//!
//! Unless a name says otherwise, coordinates are global top-down screen points,
//! the space accessibility frames and CoreGraphics window bounds use: the origin
//! is the primary display's top-left corner and y grows downward. AppKit window
//! origins are bottom-up from the primary display's bottom-left corner; the two
//! conversion functions here are the only place that flip happens.

/// A rectangle with its origin at the top-left corner.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Rect {
    pub(crate) const fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub(crate) fn right(self) -> f64 {
        self.x + self.width
    }

    pub(crate) fn bottom(self) -> f64 {
        self.y + self.height
    }

    pub(crate) fn offset(self, by: [f64; 2]) -> Self {
        Self {
            x: self.x + by[0],
            y: self.y + by[1],
            ..self
        }
    }

    /// Strict overlap: rectangles that only share an edge do not intersect.
    pub(crate) fn intersects(self, other: Self) -> bool {
        self.x < other.right()
            && other.x < self.right()
            && self.y < other.bottom()
            && other.y < self.bottom()
    }

    pub(crate) fn contains_rect(self, inner: Self) -> bool {
        inner.x >= self.x
            && inner.y >= self.y
            && inner.right() <= self.right()
            && inner.bottom() <= self.bottom()
    }

    pub(crate) fn contains_point(self, p: [f64; 2]) -> bool {
        p[0] >= self.x && p[0] < self.right() && p[1] >= self.y && p[1] < self.bottom()
    }

    fn union(self, other: Self) -> Self {
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        Self::new(
            x,
            y,
            self.right().max(other.right()) - x,
            self.bottom().max(other.bottom()) - y,
        )
    }

    fn valid(self) -> bool {
        [self.x, self.y, self.width, self.height]
            .iter()
            .all(|v| v.is_finite())
            && self.width > 0.0
            && self.height > 0.0
    }
}

/// The pointer, relative to its tip at (0, 0), y downward: a broad, stubby
/// arrowhead with no stem, drawn filled in the agent's accent colour with
/// rounded back corners. The system pointer is a slim black arrow with a stem,
/// so this shape and its colour cannot be mistaken for it. It is symmetric
/// about the diagonal, pointing up and to the left like a map's location
/// arrow, where the system pointer has a vertical left edge. The vertices
/// are, in order: the tip, the lower wing, the notch in the back, the upper
/// wing. Only the tip stays sharp, so the target point is unambiguous.
pub(crate) const POINTER: [[f64; 2]; 4] = [[0.0, 0.0], [6.5, 21.0], [9.0, 9.0], [21.0, 6.5]];
/// How round each back corner is, in points, in `POINTER` order (the tip
/// has none).
pub(crate) const POINTER_CORNER: [f64; 4] = [0.0, 3.0, 2.0, 3.0];
/// The white outline drawn around the coloured fill, in points: it keeps the
/// pointer legible on dark backgrounds, where the accent alone is too dim.
pub(crate) const OUTLINE: f64 = 1.5;
/// The avatar chip sits further along the pointer's axis, just touching the
/// back of the arrowhead, so pointer and avatar read as one marker.
pub(crate) const CHIP_CENTER: [f64; 2] = [22.5, 22.5];
/// Large enough for the avatar to be recognisable at a glance.
pub(crate) const CHIP_DIAMETER: f64 = 32.0;
/// The accent ring just inside the chip's edge.
pub(crate) const CHIP_RING: f64 = 2.5;
/// The white rim just outside the chip's edge: like the pointer's outline,
/// it separates the chip from a dark background.
pub(crate) const CHIP_RIM: f64 = 1.5;
pub(crate) const LABEL_HEIGHT: f64 = 24.0;
pub(crate) const LABEL_MAX_WIDTH: f64 = 220.0;
pub(crate) const LABEL_PADDING: f64 = 10.0;
/// Clear space between the label and whatever it must not cover.
const LABEL_GAP: f64 = 6.0;
/// Room around the drawing for the soft drop shadow.
const SHADOW_MARGIN: f64 = 8.0;
/// The label must not touch the area right around a bare point either, so a
/// pointed-at pixel with no element frame still gets this much clear space.
const POINT_TARGET: f64 = 12.0;

/// What the pointer and chip cover, relative to the tip, outline and rim
/// included.
pub(crate) fn badge_bounds() -> Rect {
    let outer = CHIP_DIAMETER + 2.0 * CHIP_RIM;
    let chip = Rect::new(
        CHIP_CENTER[0] - outer / 2.0,
        CHIP_CENTER[1] - outer / 2.0,
        outer,
        outer,
    );
    let (mut right, mut bottom) = (0.0_f64, 0.0_f64);
    for [x, y] in POINTER {
        right = right.max(x);
        bottom = bottom.max(y);
    }
    Rect::new(
        -OUTLINE,
        -OUTLINE,
        right + 2.0 * OUTLINE,
        bottom + 2.0 * OUTLINE,
    )
    .union(chip)
}

/// One display, already converted to global top-down points.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Display {
    pub frame: Rect,
    /// The frame minus the menu bar and Dock: the label stays inside this.
    pub visible: Rect,
    /// Device pixels per point (2 on a Retina display).
    pub scale: f64,
}

/// The display showing `point`, or the nearest one when the point is in a gap
/// between displays. `None` only when no display was readable.
pub(crate) fn display_at(point: [f64; 2], displays: &[Display]) -> Option<Display> {
    let distance = |frame: Rect| {
        let dx = (frame.x - point[0]).max(point[0] - frame.right()).max(0.0);
        let dy = (frame.y - point[1]).max(point[1] - frame.bottom()).max(0.0);
        dx.hypot(dy)
    };
    displays
        .iter()
        .find(|display| display.frame.contains_point(point))
        .or_else(|| {
            displays
                .iter()
                .min_by(|a, b| distance(a.frame).total_cmp(&distance(b.frame)))
        })
        .copied()
}

/// Put the tip on the corner of the device pixel that contains `point`, so the
/// tip pixel is exactly the requested one and the pointer's edges stay crisp
/// instead of smearing across two pixels.
pub(crate) fn snap_tip(point: [f64; 2], scale: f64) -> [f64; 2] {
    let scale = if scale.is_finite() && scale >= 1.0 {
        scale
    } else {
        1.0
    };
    [
        (point[0] * scale).floor() / scale,
        (point[1] * scale).floor() / scale,
    ]
}

/// What the label must stay off: the element's frame, or a small square around
/// a bare point.
pub(crate) fn target_rect(tip: [f64; 2], frame: Option<[f64; 4]>) -> Rect {
    frame
        .map(|[x, y, width, height]| Rect::new(x, y, width, height))
        .filter(|frame| frame.valid())
        .unwrap_or(Rect::new(
            tip[0] - POINT_TARGET / 2.0,
            tip[1] - POINT_TARGET / 2.0,
            POINT_TARGET,
            POINT_TARGET,
        ))
}

/// Where the label pill goes, in global points, or `None` when no candidate
/// fits. The pill never covers the target or the pointer and chip, and stays
/// inside the screen's visible area. It prefers the side next to the chip, then
/// the other side of the tip, then below or above the target.
pub(crate) fn label_rect(
    tip: [f64; 2],
    size: [f64; 2],
    target: Rect,
    screen: Rect,
) -> Option<Rect> {
    let [width, height] = size;
    if !(width.is_finite() && height.is_finite() && width > 0.0 && height > 0.0) {
        return None;
    }
    let badge = badge_bounds().offset(tip);
    let beside_y = tip[1] + CHIP_CENTER[1] - height / 2.0;
    let along_x = (tip[0] + LABEL_GAP).clamp(screen.x, (screen.right() - width).max(screen.x));
    let candidates = [
        Rect::new(badge.right() + LABEL_GAP, beside_y, width, height),
        Rect::new(
            tip[0] - OUTLINE - LABEL_GAP - width,
            beside_y,
            width,
            height,
        ),
        Rect::new(
            along_x,
            target.bottom().max(badge.bottom()) + LABEL_GAP,
            width,
            height,
        ),
        Rect::new(
            along_x,
            target.y.min(badge.y) - LABEL_GAP - height,
            width,
            height,
        ),
    ];
    candidates.into_iter().find(|label| {
        screen.contains_rect(*label) && !label.intersects(target) && !label.intersects(badge)
    })
}

/// Everything the picture draws, relative to the tip. The panel is aligned to
/// whole points around the tip, so a tip on the device-pixel grid gives a panel
/// origin on the same grid.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Layout {
    pub panel: Rect,
    pub label: Option<Rect>,
}

pub(crate) fn layout(
    tip: [f64; 2],
    target: Rect,
    label_size: Option<[f64; 2]>,
    screen: Rect,
) -> Layout {
    let label = label_size
        .and_then(|size| label_rect(tip, size, target, screen))
        .map(|label| label.offset([-tip[0], -tip[1]]));
    let drawn = label.map_or(badge_bounds(), |label| badge_bounds().union(label));
    let x = (drawn.x - SHADOW_MARGIN).floor();
    let y = (drawn.y - SHADOW_MARGIN).floor();
    Layout {
        panel: Rect::new(
            x,
            y,
            (drawn.right() + SHADOW_MARGIN).ceil() - x,
            (drawn.bottom() + SHADOW_MARGIN).ceil() - y,
        ),
        label,
    }
}

/// The AppKit (bottom-up) window origin that puts the pointer's tip on `tip`.
/// `primary_height` is the primary display's height: AppKit's y axis starts at
/// that display's bottom edge, the top-down one at its top edge, on every
/// display alike.
pub(crate) fn panel_origin_for_tip(tip: [f64; 2], panel: Rect, primary_height: f64) -> [f64; 2] {
    let frame = panel.offset(tip);
    [frame.x, primary_height - frame.bottom()]
}

/// A point given relative to the tip, in the panel view's own bottom-up space.
pub(crate) fn view_point(panel: Rect, relative: [f64; 2]) -> [f64; 2] {
    [relative[0] - panel.x, panel.bottom() - relative[1]]
}

/// An AppKit (bottom-up) screen rectangle in global top-down points.
pub(crate) fn appkit_rect_to_global(
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    primary_height: f64,
) -> Rect {
    Rect::new(x, primary_height - (y + height), width, height)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY_HEIGHT: f64 = 1117.0;

    fn displays() -> [Display; 2] {
        [
            // A Retina laptop panel as the primary display.
            Display {
                frame: appkit_rect_to_global(0.0, 0.0, 1728.0, PRIMARY_HEIGHT, PRIMARY_HEIGHT),
                visible: appkit_rect_to_global(0.0, 0.0, 1728.0, 1084.0, PRIMARY_HEIGHT),
                scale: 2.0,
            },
            // A 1x monitor to the left of and above it: negative x, and in
            // AppKit terms its bottom edge is above the primary's top edge.
            Display {
                frame: appkit_rect_to_global(-1920.0, 1117.0, 1920.0, 1080.0, PRIMARY_HEIGHT),
                visible: appkit_rect_to_global(-1920.0, 1117.0, 1920.0, 1055.0, PRIMARY_HEIGHT),
                scale: 1.0,
            },
        ]
    }

    /// Run the whole chain the overlay runs, then read the tip back the way the
    /// window server would: AppKit origin plus the tip's spot in the view,
    /// flipped back to top-down.
    fn landed_tip(requested: [f64; 2], frame: Option<[f64; 4]>) -> ([f64; 2], f64) {
        let display = display_at(requested, &displays()).unwrap();
        let tip = snap_tip(requested, display.scale);
        let layout = layout(
            tip,
            target_rect(tip, frame),
            Some([120.0, LABEL_HEIGHT]),
            display.visible,
        );
        let origin = panel_origin_for_tip(tip, layout.panel, PRIMARY_HEIGHT);
        let in_view = view_point(layout.panel, [0.0, 0.0]);
        let appkit = [origin[0] + in_view[0], origin[1] + in_view[1]];
        // The window server places windows on the device-pixel grid; an origin
        // off it would shift the whole picture by a fraction of a pixel.
        for v in origin {
            assert_eq!((v * display.scale).fract(), 0.0, "origin {origin:?}");
        }
        ([appkit[0], PRIMARY_HEIGHT - appkit[1]], display.scale)
    }

    fn assert_tip_pixel_holds(requested: [f64; 2], frame: Option<[f64; 4]>) {
        let (tip, scale) = landed_tip(requested, frame);
        let pixel = 1.0 / scale;
        for axis in 0..2 {
            assert!(
                tip[axis] <= requested[axis] && requested[axis] < tip[axis] + pixel,
                "requested {requested:?} but the tip pixel starts at {tip:?} (scale {scale})"
            );
        }
    }

    #[test]
    fn tip_lands_on_the_requested_point_on_a_scaled_display() {
        assert_eq!(landed_tip([400.0, 300.0], None).0, [400.0, 300.0]);
        assert_eq!(landed_tip([400.75, 300.25], None).0, [400.5, 300.0]);
        for requested in [[400.3, 300.7], [1.0, 1.0], [1727.9, 1116.6]] {
            assert_tip_pixel_holds(requested, None);
            assert_tip_pixel_holds(requested, Some([300.0, 280.0, 220.0, 28.0]));
        }
    }

    #[test]
    fn tip_lands_on_the_requested_point_on_a_secondary_display_with_negative_origin() {
        let secondary = displays()[1];
        assert_eq!(secondary.frame, Rect::new(-1920.0, -1080.0, 1920.0, 1080.0));
        assert_eq!(display_at([-1000.0, -100.0], &displays()), Some(secondary));
        assert_eq!(landed_tip([-1000.0, -100.0], None).0, [-1000.0, -100.0]);
        for requested in [[-1000.4, -100.6], [-1919.0, -1079.5], [-0.5, -0.5]] {
            assert_tip_pixel_holds(requested, None);
        }
    }

    #[test]
    fn a_point_in_a_gap_between_displays_uses_the_nearest_one() {
        assert_eq!(display_at([100.0, -10.0], &displays()), Some(displays()[0]));
        assert_eq!(display_at([-5.0, -500.0], &displays()), Some(displays()[1]));
        assert_eq!(display_at([0.0, 0.0], &[]), None);
    }

    #[test]
    fn the_tip_is_the_pointer_s_first_vertex_and_the_chip_touches_its_back() {
        // The tip is the first vertex and has no rounding, so the requested
        // point is the pointer's exact corner.
        assert_eq!(POINTER[0], [0.0, 0.0]);
        assert_eq!(POINTER_CORNER[0], 0.0);
        // Every other vertex lies below and to the right of the tip, so the
        // tip is the extreme corner and nothing is drawn beyond it but the
        // outline.
        for [x, y] in &POINTER[1..] {
            assert!(*x > 0.0 && *y > 0.0, "vertex ({x}, {y})");
        }
        let badge = badge_bounds();
        assert_eq!(badge.x, -OUTLINE);
        assert_eq!(badge.y, -OUTLINE);
        // A chip of about 28-36 points, big enough to recognise the avatar.
        assert!((28.0..=36.0).contains(&CHIP_DIAMETER));
        // Both wings touch the chip (within the outline's width), so pointer
        // and avatar read as one marker rather than two loose shapes.
        for wing in [POINTER[1], POINTER[3]] {
            let gap =
                (wing[0] - CHIP_CENTER[0]).hypot(wing[1] - CHIP_CENTER[1]) - CHIP_DIAMETER / 2.0;
            assert!((0.0..=OUTLINE).contains(&gap), "wing to chip gap {gap}");
        }
        // The back's notch stays clear of the chip, so the arrowhead's shape
        // is not swallowed by it.
        let notch = POINTER[2];
        let notch_gap =
            (notch[0] - CHIP_CENTER[0]).hypot(notch[1] - CHIP_CENTER[1]) - CHIP_DIAMETER / 2.0;
        assert!(notch_gap > OUTLINE, "notch to chip gap {notch_gap}");
    }

    fn screen() -> Rect {
        Rect::new(0.0, 25.0, 1728.0, 1059.0)
    }

    #[test]
    fn label_never_covers_the_target_and_stays_on_screen() {
        let size = [150.0, LABEL_HEIGHT];
        let mut placed = 0;
        // Targets of every shape, near every edge: list rows, a whole text
        // area, tiny buttons, and bare points.
        for (tip, frame) in [
            ([110.0, 300.0], Some([20.0, 286.0, 180.0, 28.0])),
            ([600.0, 500.0], Some([200.0, 200.0, 800.0, 600.0])),
            ([1700.0, 1070.0], Some([1690.0, 1060.0, 30.0, 20.0])),
            ([5.0, 30.0], Some([0.0, 25.0, 12.0, 12.0])),
            ([864.0, 540.0], None),
            ([1725.0, 600.0], None),
            ([2.0, 1080.0], None),
            ([864.0, 26.0], Some([0.0, 25.0, 1728.0, 1059.0])),
        ] {
            let tip = snap_tip(tip, 2.0);
            let target = target_rect(tip, frame);
            let Some(label) = label_rect(tip, size, target, screen()) else {
                // No room anywhere is allowed (the target fills the screen);
                // covering it is not.
                continue;
            };
            placed += 1;
            assert!(!label.intersects(target), "{label:?} covers {target:?}");
            assert!(
                !label.intersects(badge_bounds().offset(tip)),
                "{label:?} covers the pointer"
            );
            assert!(screen().contains_rect(label), "{label:?} leaves the screen");
        }
        assert_eq!(placed, 7, "only the full-screen target leaves no room");
    }

    #[test]
    fn label_prefers_beside_the_chip_then_the_side_with_room() {
        let size = [150.0, LABEL_HEIGHT];
        let tip = [600.0, 400.0];
        let beside = label_rect(tip, size, target_rect(tip, None), screen()).unwrap();
        assert_eq!(beside.x, tip[0] + badge_bounds().right() + 6.0);
        assert_eq!(beside.y + beside.height / 2.0, tip[1] + CHIP_CENTER[1]);
        // Against the right edge, the label moves to the tip's left.
        let tip = [1700.0, 400.0];
        let left = label_rect(tip, size, target_rect(tip, None), screen()).unwrap();
        assert!(left.right() < tip[0], "{left:?}");
        // A tall list row near the left edge blocks both sides; the label
        // drops below the row and the chip rather than covering the row.
        let tip = [110.0, 300.0];
        let row = target_rect(tip, Some([20.0, 278.0, 180.0, 44.0]));
        let below = label_rect(tip, size, row, screen()).unwrap();
        assert!(below.y >= row.bottom() && below.y >= tip[1] + badge_bounds().bottom());
    }

    #[test]
    fn panel_encloses_the_drawing_and_its_shadow() {
        let tip = [600.0, 400.0];
        let with_label = layout(tip, target_rect(tip, None), Some([150.0, 20.0]), screen());
        let label = with_label.label.unwrap();
        assert!(with_label.panel.contains_rect(label));
        assert!(with_label.panel.contains_rect(badge_bounds()));
        let bare = layout(tip, target_rect(tip, None), None, screen());
        assert_eq!(bare.label, None);
        assert!(bare.panel.contains_rect(badge_bounds()));
        assert!(bare.panel.width < with_label.panel.width);
        for v in [
            bare.panel.x,
            bare.panel.y,
            bare.panel.width,
            bare.panel.height,
        ] {
            assert_eq!(
                v.fract(),
                0.0,
                "panel {:?} is not point-aligned",
                bare.panel
            );
        }
    }

    #[test]
    fn malformed_frames_fall_back_to_the_point() {
        let tip = [50.0, 60.0];
        let point = Rect::new(44.0, 54.0, 12.0, 12.0);
        assert_eq!(target_rect(tip, Some([0.0, 0.0, 0.0, 10.0])), point);
        assert_eq!(target_rect(tip, Some([f64::NAN, 0.0, 5.0, 10.0])), point);
        assert_eq!(label_rect(tip, [f64::NAN, 20.0], point, screen()), None);
        assert_eq!(snap_tip([10.3, 10.6], f64::NAN), [10.0, 10.0]);
    }
}
