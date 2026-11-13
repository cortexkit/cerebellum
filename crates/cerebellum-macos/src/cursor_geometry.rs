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
/// The avatar chip's diameter. Large enough for the avatar to be recognised
/// at a glance next to a full-size pointer. The avatar itself is drawn inside
/// the accent ring, 36 - 2 x 2.5 = 31 points across, which is 62 pixels on a
/// Retina display: the module's 64-pixel avatar raster is scaled down a
/// little, never up, so it stays sharp.
pub(crate) const CHIP_DIAMETER: f64 = 36.0;
/// Clear space between the pointer's white outline and the chip's white rim.
/// With no space the two run together into one blob and the pointer's shape
/// is lost; four points reads as two separate marks (where, and who) that
/// still plainly belong together. `CHIP_CENTER` is chosen to leave this
/// gap, and a test holds it to it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const CHIP_GAP: f64 = 4.0;
/// The avatar chip sits on the pointer's diagonal axis, behind the
/// arrowhead, as close to it as `CHIP_GAP` allows. The pointer's nearest
/// points to this centre are the two wing tips, (6.5, 21) and (21, 6.5), each
/// about 25.2 points away; the chip's rim reaches 18 + 1.5 = 19.5 points out
/// and the pointer's outline 1.5, leaving just over the 4-point gap. The tip
/// stays at (0, 0), so moving the chip never moves where the badge points.
pub(crate) const CHIP_CENTER: [f64; 2] = [30.0, 30.0];
/// How large the chip is when a badge first appears, as a multiple of its
/// resting size. The entry shows the avatar alone first, centred on the
/// target, then shrinks it onto its resting place behind the pointer; at
/// twice the size it reads as "this agent has started working here" rather
/// than as an ordinary move.
pub(crate) const ENTRY_CHIP_SCALE: f64 = 2.0;
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

/// Where the chip's centre is and how large it is, relative to the tip, for
/// an entry progress in [0, 1]: at 0 it is `ENTRY_CHIP_SCALE` times its
/// resting size and centred on the tip itself, at 1 it is at rest. Both move
/// together, linearly in the progress, so every intermediate chip lies inside
/// the bounding box of the two ends.
pub(crate) fn chip_at(progress: f64) -> ([f64; 2], f64) {
    let p = if progress.is_finite() {
        progress.clamp(0.0, 1.0)
    } else {
        1.0
    };
    (
        [CHIP_CENTER[0] * p, CHIP_CENTER[1] * p],
        CHIP_DIAMETER * (ENTRY_CHIP_SCALE + (1.0 - ENTRY_CHIP_SCALE) * p),
    )
}

/// What the chip covers, rim included, at an entry progress.
fn chip_bounds(progress: f64) -> Rect {
    let (centre, diameter) = chip_at(progress);
    let outer = diameter + 2.0 * CHIP_RIM;
    Rect::new(
        centre[0] - outer / 2.0,
        centre[1] - outer / 2.0,
        outer,
        outer,
    )
}

/// What the pointer and the resting chip cover, relative to the tip, outline
/// and rim included.
pub(crate) fn badge_bounds() -> Rect {
    let chip = chip_bounds(1.0);
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

/// Where the label pill goes, in global points. The window and the screen
/// bound it, but the badge alone anchors it: a large accessibility element
/// must not push the label away from the badge. A narrow window truncates the
/// label, and a window too small for a pill shows none.
pub(crate) fn label_rect(
    tip: [f64; 2],
    size: [f64; 2],
    window: Rect,
    screen: Rect,
) -> Option<Rect> {
    let [width, height] = size;
    if !(width.is_finite() && height.is_finite() && width > 0.0 && height > 0.0) {
        return None;
    }
    let bounds = Rect::new(
        window.x.max(screen.x),
        window.y.max(screen.y),
        window.right().min(screen.right()) - window.x.max(screen.x),
        window.bottom().min(screen.bottom()) - window.y.max(screen.y),
    );
    if !bounds.valid() || bounds.height < height || !bounds.contains_point(tip) {
        return None;
    }
    let width = width.min(bounds.width);
    if width <= 2.0 * LABEL_PADDING {
        return None;
    }
    let badge = badge_bounds().offset(tip);
    let beside_y =
        (tip[1] + CHIP_CENTER[1] - height / 2.0).clamp(bounds.y, bounds.bottom() - height);
    let along_x = (badge.x + LABEL_GAP).clamp(bounds.x, bounds.right() - width);
    let candidates = [
        Rect::new(badge.right() + LABEL_GAP, beside_y, width, height),
        Rect::new(
            tip[0] - OUTLINE - LABEL_GAP - width,
            beside_y,
            width,
            height,
        ),
        Rect::new(along_x, badge.bottom() + LABEL_GAP, width, height),
        Rect::new(along_x, badge.y - LABEL_GAP - height, width, height),
    ];
    candidates
        .into_iter()
        .find(|label| bounds.contains_rect(*label) && !label.intersects(badge))
}

/// Everything the picture draws, relative to the tip. The panel is aligned to
/// whole points around the tip, so a tip on the device-pixel grid gives a panel
/// origin on the same grid.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Layout {
    pub panel: Rect,
    pub label: Option<Rect>,
}

/// `entering` makes the panel large enough for the whole entry, whose chip
/// starts at twice its size around the tip; the label is placed for the
/// resting badge either way, since it only fades in as the chip settles.
pub(crate) fn layout(
    tip: [f64; 2],
    window: Rect,
    label_size: Option<[f64; 2]>,
    screen: Rect,
    entering: bool,
) -> Layout {
    let label = label_size
        .and_then(|size| label_rect(tip, size, window, screen))
        .map(|label| label.offset([-tip[0], -tip[1]]));
    let badge = if entering {
        badge_bounds().union(chip_bounds(0.0))
    } else {
        badge_bounds()
    };
    let drawn = label.map_or(badge, |label| badge.union(label));
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

/// How far the pointer's tip is from the chip's centre in the resting badge.
/// While the window under a badge is being dragged, the chip holds still and
/// the pointer swings around it like a clock's hand, its tip on a circle of
/// this radius, so the badge keeps its shape and size the whole time.
pub(crate) fn hand_radius() -> f64 {
    CHIP_CENTER[0].hypot(CHIP_CENTER[1])
}

/// The direction, in radians, from the chip's centre to the pointer's tip in
/// the resting badge, measured like `atan2` in top-down points (0 is to the
/// right, a quarter turn is straight down). The chip sits below and to the
/// right of the tip, so this points up and to the left.
pub(crate) fn rest_angle() -> f64 {
    (-CHIP_CENTER[1]).atan2(-CHIP_CENTER[0])
}

/// An angle brought into (-pi, pi], so a pointer turning back to rest from
/// it takes the short way round.
pub(crate) fn wrap_angle(angle: f64) -> f64 {
    use std::f64::consts::{PI, TAU};
    let wrapped = (angle + PI).rem_euclid(TAU) - PI;
    // rem_euclid maps an angle of exactly pi to -pi; keep it at +pi so the
    // range is half-open on the negative side.
    if wrapped == -PI {
        PI
    } else {
        wrapped
    }
}

/// The turn from `from` to `to` that goes the short way round: at most half
/// a turn either way. A pointer pointing just past straight left that must
/// point just short of it turns a few degrees, not almost a whole circle.
pub(crate) fn shortest_turn(from: f64, to: f64) -> f64 {
    wrap_angle(to - from)
}

/// How far to turn the pointer about the chip's centre, from its resting
/// direction, so that it points from a chip centred on `chip` toward
/// `target` (both global top-down points). `None` when the direction is
/// undefined: the target is on the chip's centre or a value is not finite.
pub(crate) fn aim_rotation(chip: [f64; 2], target: [f64; 2]) -> Option<f64> {
    let (dx, dy) = (target[0] - chip[0], target[1] - chip[1]);
    if !(dx.is_finite() && dy.is_finite()) || dx.hypot(dy) < f64::EPSILON {
        return None;
    }
    Some(wrap_angle(dy.atan2(dx) - rest_angle()))
}

/// Where a point drawn relative to the resting tip goes once the pointer has
/// turned by `rotation` about the chip's centre. A rotation of exactly 0 is
/// the resting badge and leaves every point exactly where it was.
pub(crate) fn turn_point(point: [f64; 2], rotation: f64) -> [f64; 2] {
    if rotation == 0.0 || !rotation.is_finite() {
        return point;
    }
    let (sin, cos) = rotation.sin_cos();
    let (dx, dy) = (point[0] - CHIP_CENTER[0], point[1] - CHIP_CENTER[1]);
    [
        CHIP_CENTER[0] + dx * cos - dy * sin,
        CHIP_CENTER[1] + dx * sin + dy * cos,
    ]
}

/// The panel a swinging pointer needs: `panel` (a resting layout's) grown to
/// hold the pointer at every angle around the chip, outline and shadow
/// included. Every pointer point lies within `hand_radius` of the chip's
/// centre (the tip is the farthest), so a square of that half-size around
/// the centre holds them all.
pub(crate) fn swing_panel(panel: Rect) -> Rect {
    let reach = hand_radius() + OUTLINE + SHADOW_MARGIN;
    let orbit = Rect::new(
        CHIP_CENTER[0] - reach,
        CHIP_CENTER[1] - reach,
        2.0 * reach,
        2.0 * reach,
    )
    .union(panel);
    // Whole points, like every layout panel, so a tip on the device-pixel
    // grid still gives a panel origin on it.
    let x = orbit.x.floor();
    let y = orbit.y.floor();
    Rect::new(x, y, orbit.right().ceil() - x, orbit.bottom().ceil() - y)
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
        landed_tip_with(requested, frame, false)
    }

    fn landed_tip_with(
        requested: [f64; 2],
        frame: Option<[f64; 4]>,
        entering: bool,
    ) -> ([f64; 2], f64) {
        let display = display_at(requested, &displays()).unwrap();
        let tip = snap_tip(requested, display.scale);
        let layout = layout(
            tip,
            frame.map_or(display.visible, |[x, y, w, h]| Rect::new(x, y, w, h)),
            Some([120.0, LABEL_HEIGHT]),
            display.visible,
            entering,
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
        // The larger panel an entry needs moves the panel's origin, never the
        // tip.
        assert_eq!(
            landed_tip_with([400.75, 300.25], None, true).0,
            [400.5, 300.0]
        );
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

    /// The shortest distance from `point` to the pointer's (sharp-cornered)
    /// outline polygon. Rounding the back corners only pulls the outline
    /// inward, so the real gap is never smaller than one measured here.
    fn distance_to_pointer(point: [f64; 2]) -> f64 {
        (0..POINTER.len())
            .map(|index| {
                let a = POINTER[index];
                let b = POINTER[(index + 1) % POINTER.len()];
                let (dx, dy) = (b[0] - a[0], b[1] - a[1]);
                let t = (((point[0] - a[0]) * dx + (point[1] - a[1]) * dy) / (dx * dx + dy * dy))
                    .clamp(0.0, 1.0);
                (point[0] - (a[0] + t * dx)).hypot(point[1] - (a[1] + t * dy))
            })
            .fold(f64::INFINITY, f64::min)
    }

    #[test]
    fn the_tip_is_the_pointer_s_first_vertex_and_the_chip_stands_clear_of_it() {
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
        // A chip of about 34-40 points, big enough to recognise the avatar,
        // and the avatar inside its ring needs no more pixels on a Retina
        // display than the 64-pixel raster has, so it is never upscaled.
        assert!((34.0..=40.0).contains(&CHIP_DIAMETER));
        const { assert!((CHIP_DIAMETER - 2.0 * CHIP_RING) * 2.0 <= 64.0) };
        // The chip's white rim stays at least `CHIP_GAP` clear of the
        // pointer's white outline, so the two never touch, and not much more,
        // so the avatar still sits with its pointer.
        let gap = distance_to_pointer(CHIP_CENTER) - OUTLINE - (CHIP_DIAMETER / 2.0 + CHIP_RIM);
        assert!(
            (CHIP_GAP..=CHIP_GAP + 1.0).contains(&gap),
            "pointer to chip gap {gap}"
        );
        // So the drawn shapes do not overlap either: the chip's disc is clear
        // of every point of the pointer.
        for vertex in POINTER {
            let to_centre = (vertex[0] - CHIP_CENTER[0]).hypot(vertex[1] - CHIP_CENTER[1]);
            assert!(to_centre > CHIP_DIAMETER / 2.0 + CHIP_RIM + OUTLINE);
        }
        // On the diagonal, so the badge stays symmetric like its pointer.
        assert_eq!(CHIP_CENTER[0], CHIP_CENTER[1]);
    }

    #[test]
    fn the_entry_chip_starts_twice_as_large_on_the_tip_and_the_panel_holds_it() {
        assert_eq!(chip_at(0.0), ([0.0, 0.0], CHIP_DIAMETER * ENTRY_CHIP_SCALE));
        assert_eq!(chip_at(1.0), (CHIP_CENTER, CHIP_DIAMETER));
        assert_eq!(chip_at(f64::NAN), (CHIP_CENTER, CHIP_DIAMETER));
        let tip = [600.0, 400.0];
        let entering = layout(tip, screen(), None, screen(), true);
        let resting = layout(tip, screen(), None, screen(), false);
        for step in 0..=20 {
            let chip = chip_bounds(f64::from(step) / 20.0);
            assert!(
                entering.panel.contains_rect(chip),
                "{chip:?} at step {step} leaves {:?}",
                entering.panel
            );
        }
        // The resting panel stays as tight as before.
        assert!(!resting.panel.contains_rect(chip_bounds(0.0)));
        assert!(resting.panel.contains_rect(badge_bounds()));
    }

    fn screen() -> Rect {
        Rect::new(0.0, 25.0, 1728.0, 1059.0)
    }

    #[test]
    fn label_stays_beside_the_badge_inside_the_window_and_screen() {
        let size = [150.0, LABEL_HEIGHT];
        let mut placed = 0;
        for (tip, window) in [
            ([110.0, 300.0], Rect::new(20.0, 200.0, 500.0, 200.0)),
            ([600.0, 500.0], Rect::new(200.0, 200.0, 800.0, 600.0)),
            ([1700.0, 1070.0], screen()),
            ([5.0, 30.0], screen()),
            ([864.0, 540.0], screen()),
            ([1725.0, 600.0], screen()),
            ([2.0, 1080.0], screen()),
            ([864.0, 26.0], screen()),
        ] {
            let tip = snap_tip(tip, 2.0);
            let label = label_rect(tip, size, window, screen()).expect("room beside the badge");
            placed += 1;
            assert!(
                !label.intersects(badge_bounds().offset(tip)),
                "{label:?} covers the pointer"
            );
            assert!(screen().contains_rect(label), "{label:?} leaves the screen");
            assert!(window.contains_rect(label), "{label:?} leaves the window");
            assert!((label.y - tip[1]).abs() < 60.0, "label detached: {label:?}");
        }
        assert_eq!(placed, 8);
    }

    #[test]
    fn label_prefers_beside_the_chip_then_the_side_with_room() {
        let size = [150.0, LABEL_HEIGHT];
        let tip = [600.0, 400.0];
        let beside = label_rect(tip, size, screen(), screen()).unwrap();
        assert_eq!(beside.x, tip[0] + badge_bounds().right() + 6.0);
        assert_eq!(beside.y + beside.height / 2.0, tip[1] + CHIP_CENTER[1]);
        // Against the right edge, the label moves to the tip's left.
        let tip = [1700.0, 400.0];
        let left = label_rect(tip, size, screen(), screen()).unwrap();
        assert!(left.right() < tip[0], "{left:?}");
        // A narrow window leaves room only under the badge. The label stays
        // local even when the focused accessibility element fills the window.
        let tip = [110.0, 300.0];
        let window = Rect::new(100.0, 250.0, 160.0, 150.0);
        let below = label_rect(tip, size, window, screen()).unwrap();
        assert_eq!(below.y, tip[1] + badge_bounds().bottom() + LABEL_GAP);
        assert!(window.contains_rect(below));
    }

    #[test]
    fn label_flips_at_window_edges_on_a_negative_origin_display() {
        let window = Rect::new(-1800.0, -900.0, 700.0, 500.0);
        let screen = displays()[1].visible;
        let tip = [-1120.0, -880.0];
        let label = label_rect(tip, [220.0, LABEL_HEIGHT], window, screen).unwrap();
        assert!(label.right() < tip[0]);
        assert!(window.contains_rect(label));
        assert!(screen.contains_rect(label));
        assert!((label.y - tip[1]).abs() < 60.0);
    }

    #[test]
    fn panel_encloses_the_drawing_and_its_shadow() {
        let tip = [600.0, 400.0];
        let with_label = layout(tip, screen(), Some([150.0, 20.0]), screen(), false);
        let label = with_label.label.unwrap();
        assert!(with_label.panel.contains_rect(label));
        assert!(with_label.panel.contains_rect(badge_bounds()));
        let bare = layout(tip, screen(), None, screen(), false);
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
    fn malformed_label_sizes_are_omitted_and_scale_falls_back() {
        let tip = [50.0, 60.0];
        let point = Rect::new(44.0, 54.0, 12.0, 12.0);
        assert_eq!(label_rect(tip, [f64::NAN, 20.0], point, screen()), None);
        assert_eq!(
            label_rect(
                [5.0, 50.0],
                [150.0, LABEL_HEIGHT],
                Rect::new(0.0, 25.0, 10.0, 100.0),
                screen()
            ),
            None
        );
        assert_eq!(snap_tip([10.3, 10.6], f64::NAN), [10.0, 10.0]);
    }

    #[test]
    fn the_hand_turns_about_the_chip_on_a_circle_through_the_resting_tip() {
        use std::f64::consts::PI;
        // The resting badge is the hand at rotation 0: every point stays put
        // exactly, so a badge that has turned back lands pixel for pixel.
        for point in POINTER {
            assert_eq!(turn_point(point, 0.0), point);
        }
        // The resting tip is on the circle, up and to the left of the chip.
        assert!((rest_angle() + 3.0 * PI / 4.0).abs() < 1e-12);
        assert!((hand_radius() - 30.0 * 2f64.sqrt()).abs() < 1e-12);
        for step in 0..72 {
            let rotation = f64::from(step) * PI / 36.0 - PI;
            let tip = turn_point([0.0, 0.0], rotation);
            let from_chip = [tip[0] - CHIP_CENTER[0], tip[1] - CHIP_CENTER[1]];
            assert!((from_chip[0].hypot(from_chip[1]) - hand_radius()).abs() < 1e-9);
            // The pointer's notch stays on the line from the chip to the tip,
            // between them: the arrow points away from the avatar.
            let notch = turn_point(POINTER[2], rotation);
            let to_notch = [notch[0] - CHIP_CENTER[0], notch[1] - CHIP_CENTER[1]];
            let cross = from_chip[0] * to_notch[1] - from_chip[1] * to_notch[0];
            let along = from_chip[0] * to_notch[0] + from_chip[1] * to_notch[1];
            assert!(cross.abs() < 1e-9 && along > 0.0, "at {rotation}");
            // Aiming at the turned tip asks for exactly this rotation.
            let aimed = aim_rotation(CHIP_CENTER, tip).unwrap();
            assert!(shortest_turn(aimed, rotation).abs() < 1e-9, "at {rotation}");
        }
        assert_eq!(aim_rotation(CHIP_CENTER, CHIP_CENTER), None);
        assert_eq!(aim_rotation(CHIP_CENTER, [f64::NAN, 0.0]), None);
    }

    #[test]
    fn turns_wrap_the_short_way_round() {
        use std::f64::consts::PI;
        let degrees = |d: f64| d * PI / 180.0;
        // From just short of half a turn one way to just short of it the
        // other way is a small turn across the back, not almost a circle.
        assert!((shortest_turn(degrees(170.0), degrees(-170.0)) - degrees(20.0)).abs() < 1e-12);
        assert!((shortest_turn(degrees(-170.0), degrees(170.0)) + degrees(20.0)).abs() < 1e-12);
        assert!((shortest_turn(degrees(10.0), degrees(50.0)) - degrees(40.0)).abs() < 1e-12);
        for angle in [-7.0, -PI, -1.0, 0.0, 1.0, PI, 7.0, 100.0] {
            let wrapped = wrap_angle(angle);
            assert!(
                wrapped > -PI && wrapped <= PI,
                "{angle} wrapped to {wrapped}"
            );
            assert!(((angle - wrapped) / (2.0 * PI)).fract().abs() < 1e-9);
        }
    }

    #[test]
    fn the_swing_panel_holds_the_pointer_at_every_angle() {
        let tip = [600.0, 400.0];
        let resting = layout(tip, screen(), None, screen(), false).panel;
        let panel = swing_panel(resting);
        assert!(panel.contains_rect(resting));
        for v in [panel.x, panel.y, panel.width, panel.height] {
            assert_eq!(v.fract(), 0.0, "panel {panel:?} is not point-aligned");
        }
        for step in 0..360 {
            let rotation = f64::from(step).to_radians();
            for point in POINTER {
                let [x, y] = turn_point(point, rotation);
                let outlined = Rect::new(x - OUTLINE, y - OUTLINE, 2.0 * OUTLINE, 2.0 * OUTLINE);
                assert!(panel.contains_rect(outlined), "{point:?} at {step} degrees");
            }
        }
    }
}
