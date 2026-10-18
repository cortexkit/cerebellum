//! Main-thread-only pictures in small, click-through, non-key floating panels.
//! This module has no input posting, target-app activation, or capture APIs.
//!
//! The picture is a stubby pointer filled in the agent's accent colour, whose
//! tip sits exactly on the target, the agent's avatar in a large ringed chip
//! behind it, and for actions a label pill in the same colour. Where each part
//! goes is decided in `cursor_geometry`; the motion curves and the colour come
//! in from the caller.

use std::cell::{Cell, RefCell};
use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::Instant;

use crate::cursor_geometry::{
    appkit_rect_to_global, display_at, layout, panel_origin_for_tip, snap_tip, target_rect,
    view_point, Display, Layout, Rect, CHIP_CENTER, CHIP_DIAMETER, CHIP_RIM, CHIP_RING,
    LABEL_HEIGHT, LABEL_MAX_WIDTH, LABEL_PADDING, OUTLINE, POINTER, POINTER_CORNER,
};
use crate::cursor_schedule::{CursorSchedule, PictureStep, Wait};

use objc2::rc::Retained;
use objc2::{define_class, msg_send, AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSBezierPath, NSBitmapFormat,
    NSBitmapImageFileType, NSBitmapImageRep, NSColor, NSCompositingOperation,
    NSDeviceRGBColorSpace, NSEventMask, NSFont, NSFontWeightMedium, NSFontWeightSemibold,
    NSGraphicsContext, NSImage, NSLineBreakMode, NSLineJoinStyle, NSPanel, NSScreen, NSShadow,
    NSTextAlignment, NSTextField, NSView, NSWindowAnimationBehavior, NSWindowCollectionBehavior,
    NSWindowStyleMask, NSWorkspace,
};
use objc2_foundation::{
    NSDate, NSDefaultRunLoopMode, NSDictionary, NSPoint, NSRect, NSSize, NSString,
};

/// The avatar raster's side in pixels: the 32-point chip at a Retina
/// display's two pixels per point. The module renders avatars at this size.
pub const AVATAR_PIXELS: usize = 64;

/// One 60 Hz frame, in ms: how far ahead a picture looks to decide whether its
/// landing motion still needs another frame.
const ONE_FRAME_MS: f64 = 1000.0 / 60.0;

/// What the agent is doing, which decides the label and the landing motion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayGesture {
    Press,
    Type,
    Read,
}

pub struct OverlayEvent {
    pub agent: String,
    pub initial: char,
    /// The agent's accent colour, sRGB in [0, 1]: the pointer, the chip's
    /// ring and the label pill are drawn in it.
    pub accent: [f64; 3],
    /// The tip's destination, global top-down points.
    pub to: [f64; 2],
    /// The acted-on element's frame; the label never covers it.
    pub target: Option<[f64; 4]>,
    /// `to` is only somewhere to appear: a shown cursor stays where it is.
    pub resting: bool,
    pub label: Option<String>,
    pub gesture: OverlayGesture,
    pub serial: u64,
    pub avatar_rgba: Option<Vec<u8>>,
    pub avatar_update: bool,
}

/// One message from the module: a picture to show or move, or one agent's
/// picture to take off the screen now because that agent is done.
pub enum OverlayMessage {
    Show(OverlayEvent),
    Hide { agent: String },
}

/// Motion curves, supplied by the platform-neutral crate where they are
/// tested on every host.
#[derive(Clone, Copy)]
pub struct CursorMotion {
    /// Glide length in ms from the distance and the Reduce Motion setting.
    pub duration_ms: fn(f64, bool) -> f64,
    /// The tip's position for a glide fraction in [0, 1].
    pub position: fn([f64; 2], [f64; 2], f64, bool) -> [f64; 2],
    /// Scale about the tip, from ms since arrival, press or not, Reduce Motion.
    pub settle_scale: fn(f64, bool, bool) -> f64,
    /// Opacity factor for a glide fraction (the Reduce Motion fade-move).
    pub fade_alpha: fn(f64, bool) -> f64,
    /// How long a first appearance takes, in ms.
    pub arrival_ms: f64,
    /// Where a first appearance's glide starts, from the destination and
    /// the Reduce Motion setting.
    pub arrival_start: fn([f64; 2], bool) -> [f64; 2],
    /// Opacity during a first appearance, for a fraction of `arrival_ms`.
    pub arrival_alpha: fn(f64, bool) -> f64,
}

define_class!(
    #[unsafe(super(NSPanel))]
    #[thread_kind = MainThreadOnly]
    struct CursorPanel;
    impl CursorPanel {
        #[unsafe(method(canBecomeKeyWindow))]
        fn can_become_key(&self) -> bool { false }
        #[unsafe(method(canBecomeMainWindow))]
        fn can_become_main(&self) -> bool { false }
    }
);

/// What the badge view draws, in its own bottom-up coordinates.
#[derive(Clone, Copy)]
struct Scene {
    /// The pointer's tip.
    tip: [f64; 2],
    /// The landing animation's scale, applied about the tip.
    scale: f64,
    label: Option<NSRect>,
    accent: [f64; 3],
    /// Only the offscreen gallery draws a backdrop; the live panel is clear.
    backdrop: Option<Backdrop>,
    /// Opacity the gallery draws the badge at. The live panel always draws
    /// at 1 and fades the whole window instead.
    alpha: f64,
}

impl Default for Scene {
    fn default() -> Self {
        Self {
            tip: [0.0, 0.0],
            scale: 1.0,
            label: None,
            accent: [0.427, 0.290, 1.0],
            backdrop: None,
            alpha: 1.0,
        }
    }
}

#[derive(Clone, Copy)]
struct Backdrop {
    dark: bool,
    target: Option<NSRect>,
    point: NSPoint,
}

#[derive(Default)]
struct BadgeIvars {
    scene: Cell<Scene>,
    image: RefCell<Option<Retained<NSImage>>>,
}

define_class!(
    #[unsafe(super(NSView))]
    #[thread_kind = MainThreadOnly]
    #[ivars = BadgeIvars]
    struct Badge;
    impl Badge {
        #[unsafe(method(drawRect:))]
        fn draw(&self, _rect: NSRect) {
            let scene = self.ivars().scene.get();
            if let Some(backdrop) = scene.backdrop {
                draw_backdrop(self.bounds(), backdrop);
            }
            with_group_alpha(scene.alpha, || {
                if let Some(label) = scene.label {
                    draw_pill(label, scene.accent);
                }
                draw_badge(
                    scene.tip,
                    scene.scale,
                    scene.accent,
                    self.ivars().image.borrow().as_deref(),
                );
            });
        }
    }
);

fn rect(x: f64, y: f64, width: f64, height: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(width, height))
}

fn srgb(red: f64, green: f64, blue: f64, alpha: f64) -> Retained<NSColor> {
    NSColor::colorWithSRGBRed_green_blue_alpha(red, green, blue, alpha)
}

/// Draw `body` with a soft shadow under it, without leaving the shadow set
/// for anything drawn afterwards.
fn with_shadow(blur: f64, alpha: f64, body: impl FnOnce()) {
    NSGraphicsContext::saveGraphicsState_class();
    let shadow = NSShadow::new();
    shadow.setShadowColor(Some(&srgb(0.0, 0.0, 0.0, alpha)));
    shadow.setShadowBlurRadius(blur);
    shadow.setShadowOffset(NSSize::new(0.0, -1.0));
    shadow.set();
    body();
    NSGraphicsContext::restoreGraphicsState_class();
}

/// Draw `body` as one group at `alpha`, the way a window fade composites the
/// whole picture, so overlapping parts do not show through each other. Only
/// the gallery's arrival stills use it; at 1 it draws directly.
fn with_group_alpha(alpha: f64, body: impl FnOnce()) {
    use objc2_core_graphics::CGContext;
    if alpha >= 1.0 {
        return body();
    }
    let Some(context) = NSGraphicsContext::currentContext() else {
        return body();
    };
    // SAFETY: `CGContext` returns the current drawing context's CoreGraphics
    // context (not retained), which stays valid for the duration of this draw.
    let cg: *mut CGContext = unsafe { msg_send![&context, CGContext] };
    // SAFETY: non-null was checked; the reference does not outlive the draw.
    let Some(cg) = (unsafe { cg.as_ref() }) else {
        return body();
    };
    NSGraphicsContext::saveGraphicsState_class();
    CGContext::set_alpha(Some(cg), alpha.clamp(0.0, 1.0));
    // SAFETY: no auxiliary dictionary; the layer is ended below, in this draw.
    unsafe { CGContext::begin_transparency_layer(Some(cg), None) };
    body();
    CGContext::end_transparency_layer(Some(cg));
    NSGraphicsContext::restoreGraphicsState_class();
}

fn accent_color(accent: [f64; 3], alpha: f64) -> Retained<NSColor> {
    srgb(accent[0], accent[1], accent[2], alpha)
}

/// The accent mixed toward white: the chip's backdrop behind an avatar, light
/// enough that the creature's own colours read against it.
fn accent_tint(accent: [f64; 3]) -> Retained<NSColor> {
    let mix = |c: f64| c + (1.0 - c) * 0.82;
    srgb(mix(accent[0]), mix(accent[1]), mix(accent[2]), 1.0)
}

fn oval(centre: NSPoint, diameter: f64) -> Retained<NSBezierPath> {
    NSBezierPath::bezierPathWithOvalInRect(rect(
        centre.x - diameter / 2.0,
        centre.y - diameter / 2.0,
        diameter,
        diameter,
    ))
}

/// The pointer's outline through `at`, with its back corners rounded and its
/// tip left sharp so the tip vertex is exactly the target point.
fn pointer_path(at: impl Fn([f64; 2]) -> NSPoint, scale: f64) -> Retained<NSBezierPath> {
    let path = NSBezierPath::bezierPath();
    path.moveToPoint(at(POINTER[0]));
    for index in 1..POINTER.len() {
        let next = POINTER[(index + 1) % POINTER.len()];
        // A line toward this corner, then an arc that turns onto the edge
        // toward the next one.
        path.appendBezierPathWithArcFromPoint_toPoint_radius(
            at(POINTER[index]),
            at(next),
            POINTER_CORNER[index] * scale,
        );
    }
    path.lineToPoint(at(POINTER[0]));
    path.closePath();
    path
}

/// The pointer and the chip. Geometry is top-down relative to the tip; the
/// view is bottom-up, so y flips here, and the landing scale is applied about
/// the tip so the tip itself never moves.
fn draw_badge(tip: [f64; 2], scale: f64, accent: [f64; 3], avatar: Option<&NSImage>) {
    let at = |p: [f64; 2]| NSPoint::new(tip[0] + p[0] * scale, tip[1] - p[1] * scale);

    let centre = at(CHIP_CENTER);
    let diameter = CHIP_DIAMETER * scale;
    let chip = oval(centre, diameter);
    // The white rim, just outside the chip's edge, carries the shadow: it
    // lifts the chip off a light background and outlines it on a dark one.
    let rim = oval(centre, diameter + 2.0 * CHIP_RIM * scale);
    with_shadow(5.0, 0.4, || {
        NSColor::whiteColor().setFill();
        rim.fill();
    });
    match avatar {
        Some(image) => {
            accent_tint(accent).setFill();
            chip.fill();
            NSGraphicsContext::saveGraphicsState_class();
            chip.addClip();
            // Inset by the ring, so the ring frames the avatar rather than
            // covering its edge.
            let inset = oval(centre, diameter - 2.0 * CHIP_RING * scale).bounds();
            image.drawInRect_fromRect_operation_fraction(
                inset,
                NSRect::ZERO,
                NSCompositingOperation::SourceOver,
                1.0,
            );
            NSGraphicsContext::restoreGraphicsState_class();
        }
        None => {
            // The initial is a white text field drawn over this.
            accent_color(accent, 1.0).setFill();
            chip.fill();
        }
    }
    let ring = oval(centre, diameter - CHIP_RING * scale);
    ring.setLineWidth(CHIP_RING * scale);
    accent_color(accent, 1.0).setStroke();
    ring.stroke();

    let pointer = pointer_path(at, scale);
    pointer.setLineJoinStyle(NSLineJoinStyle::Round);
    pointer.setLineWidth(OUTLINE * 2.0 * scale);
    // The white outline (half of the stroke, outside the fill) and the shadow
    // are drawn together, then the coloured body on top without a shadow.
    with_shadow(4.0, 0.45, || {
        NSColor::whiteColor().setFill();
        NSColor::whiteColor().setStroke();
        pointer.fill();
        pointer.stroke();
    });
    accent_color(accent, 1.0).setFill();
    pointer.fill();
}

fn draw_pill(label: NSRect, accent: [f64; 3]) {
    let radius = label.size.height / 2.0;
    let pill = NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(label, radius, radius);
    with_shadow(3.0, 0.3, || {
        accent_color(accent, 1.0).setFill();
        pill.fill();
    });
    // A thin white edge, like the pointer's outline, keeps the pill's shape
    // on a background close to the accent.
    srgb(1.0, 1.0, 1.0, 0.85).setStroke();
    pill.setLineWidth(1.0);
    pill.stroke();
}

/// The gallery's stand-in for an app: a plain surface, the element being
/// acted on, and a red hairline cross on the exact target point so a picture
/// shows at a glance whether the tip landed on it.
fn draw_backdrop(bounds: NSRect, backdrop: Backdrop) {
    let (surface, element) = if backdrop.dark {
        (srgb(0.12, 0.12, 0.13, 1.0), srgb(0.22, 0.22, 0.25, 1.0))
    } else {
        (srgb(0.96, 0.96, 0.97, 1.0), srgb(0.86, 0.88, 0.93, 1.0))
    };
    surface.setFill();
    NSBezierPath::fillRect(bounds);
    if let Some(target) = backdrop.target {
        element.setFill();
        NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(target, 6.0, 6.0).fill();
    }
    srgb(0.9, 0.1, 0.1, 1.0).setFill();
    let NSPoint { x, y } = backdrop.point;
    NSBezierPath::fillRect(rect(x - 8.0, y - 0.5, 16.0, 0.5));
    NSBezierPath::fillRect(rect(x, y - 8.0, 0.5, 16.0));
}

/// The label and initial are text fields over the badge view, so AppKit does
/// the text layout and tail truncation.
fn text_field(
    mtm: MainThreadMarker,
    badge: &Badge,
    size: f64,
    weight_semibold: bool,
) -> Retained<NSTextField> {
    let field = NSTextField::labelWithString(&NSString::from_str(""), mtm);
    field.setTextColor(Some(&NSColor::whiteColor()));
    // SAFETY: the weight constants are immutable AppKit statics.
    let weight = unsafe {
        if weight_semibold {
            NSFontWeightSemibold
        } else {
            NSFontWeightMedium
        }
    };
    field.setFont(Some(&NSFont::systemFontOfSize_weight(size, weight)));
    field.setUsesSingleLineMode(true);
    field.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
    field.setHidden(true);
    badge.addSubview(&field);
    field
}

struct Fields {
    badge: Retained<Badge>,
    initial: Retained<NSTextField>,
    label: Retained<NSTextField>,
}

impl Fields {
    fn new(mtm: MainThreadMarker, frame: NSRect) -> Self {
        let badge: Retained<Badge> = unsafe {
            let this = Badge::alloc(mtm).set_ivars(BadgeIvars::default());
            msg_send![super(this), initWithFrame: frame]
        };
        let initial = text_field(mtm, &badge, 15.0, true);
        initial.setAlignment(NSTextAlignment::Center);
        let label = text_field(mtm, &badge, 12.0, false);
        Self {
            badge,
            initial,
            label,
        }
    }

    /// The pill's size for `text`: the text's natural width plus padding,
    /// capped so a long title is ellipsised instead of growing the pill.
    fn measure_label(&self, text: &str) -> [f64; 2] {
        self.label.setStringValue(&NSString::from_str(text));
        self.label.sizeToFit();
        let natural = self.label.frame().size.width;
        [
            (natural + 2.0 * LABEL_PADDING).min(LABEL_MAX_WIDTH).ceil(),
            LABEL_HEIGHT,
        ]
    }

    fn set_initial(&self, initial: char) {
        self.initial
            .setStringValue(&NSString::from_str(&initial.to_string()));
        self.initial.sizeToFit();
    }

    fn set_accent(&self, accent: [f64; 3]) {
        let mut scene = self.ivars_scene();
        scene.accent = accent;
        self.badge.ivars().scene.set(scene);
        self.badge.setNeedsDisplay(true);
    }

    fn set_avatar(&self, pixels: Option<&[u8]>) {
        const SIDE: usize = AVATAR_PIXELS;
        let image = pixels.and_then(|pixels| {
            if pixels.len() != SIDE * SIDE * 4 { return None; }
            // SAFETY: AppKit allocates a SIDE x SIDE, four-channel premultiplied
            // RGBA bitmap. Its buffer of exactly `pixels.len()` bytes is filled
            // before the image is used.
            unsafe {
                let rep = NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bitmapFormat_bytesPerRow_bitsPerPixel(
                    NSBitmapImageRep::alloc(), std::ptr::null_mut(), SIDE as isize, SIDE as isize,
                    8, 4, true, false, NSDeviceRGBColorSpace, NSBitmapFormat::empty(),
                    (SIDE * 4) as isize, 32)?;
                let data = rep.bitmapData();
                if data.is_null() { return None; }
                std::ptr::copy_nonoverlapping(pixels.as_ptr(), data, pixels.len());
                // The raster is two pixels per point at the chip's size, so a
                // Retina display draws it pixel for pixel, with no upscaling.
                let size = NSSize::new(CHIP_DIAMETER, CHIP_DIAMETER);
                rep.setSize(size);
                let image = NSImage::initWithSize(NSImage::alloc(), size);
                image.addRepresentation(&rep);
                Some(image)
            }
        });
        self.initial.setHidden(image.is_some());
        *self.badge.ivars().image.borrow_mut() = image;
        self.badge.setNeedsDisplay(true);
    }

    /// Place the drawing and the text fields for a tip and label given in the
    /// view's bottom-up coordinates.
    fn apply(&self, tip: [f64; 2], label: Option<NSRect>, scale: f64) {
        let mut scene = self.ivars_scene();
        scene.tip = tip;
        scene.label = label;
        scene.scale = scale;
        self.badge.ivars().scene.set(scene);
        let initial = self.initial.frame().size;
        // The initial follows the chip's centre as the chip scales.
        self.initial.setFrame(rect(
            tip[0] + CHIP_CENTER[0] * scale - CHIP_DIAMETER / 2.0,
            tip[1] - CHIP_CENTER[1] * scale - initial.height / 2.0,
            CHIP_DIAMETER,
            initial.height,
        ));
        if let Some(pill) = label {
            let height = self.label.frame().size.height;
            self.label.setFrame(rect(
                pill.origin.x + LABEL_PADDING,
                pill.origin.y + (pill.size.height - height) / 2.0,
                pill.size.width - 2.0 * LABEL_PADDING,
                height,
            ));
        }
        self.label.setHidden(label.is_none());
        self.badge.setNeedsDisplay(true);
    }

    fn ivars_scene(&self) -> Scene {
        self.badge.ivars().scene.get()
    }
}

/// A rectangle given relative to the tip, in the panel view's coordinates.
fn view_rect(panel: Rect, relative: Rect) -> NSRect {
    let [x, y] = view_point(panel, [relative.x, relative.bottom()]);
    rect(x, y, relative.width, relative.height)
}

/// Every display in global top-down points, and the primary display's height
/// that AppKit's flipped y axis is measured from.
fn read_displays(mtm: MainThreadMarker) -> (Vec<Display>, f64) {
    let screens = NSScreen::screens(mtm);
    let primary_height = screens
        .firstObject()
        .map_or(0.0, |screen| screen.frame().size.height);
    let displays = screens
        .iter()
        .map(|screen| {
            let (frame, visible) = (screen.frame(), screen.visibleFrame());
            let global = |r: NSRect| {
                appkit_rect_to_global(
                    r.origin.x,
                    r.origin.y,
                    r.size.width,
                    r.size.height,
                    primary_height,
                )
            };
            Display {
                frame: global(frame),
                visible: global(visible),
                scale: screen.backingScaleFactor(),
            }
        })
        .collect();
    (displays, primary_height)
}

struct Picture {
    panel: Retained<CursorPanel>,
    fields: Fields,
    from: [f64; 2],
    to: [f64; 2],
    current: [f64; 2],
    duration_ms: f64,
    reduce: bool,
    press: bool,
    serial: u64,
    /// Whether this picture has been placed on screen at least once.
    shown: bool,
    /// While the first appearance is still fading up: how far into it the
    /// picture was when its latest event arrived, in ms. Kept across events,
    /// so a second action during the arrival does not snap the opacity.
    arrival_base_ms: Option<f64>,
    /// The last frame's ms since the latest event.
    last_elapsed_ms: f64,
    layout: Layout,
    displays: Vec<Display>,
    primary_height: f64,
    /// Last values handed to AppKit. A settled picture changes nothing, so
    /// its ticks cost no window-server or drawing work.
    last_origin: Option<[f64; 2]>,
    last_scale: f64,
    last_alpha: f64,
}

impl Picture {
    fn new(mtm: MainThreadMarker) -> Self {
        // SAFETY: AppKit initialization is on the main thread. Borderless and
        // non-activating; the subclass additionally refuses both key and main.
        let panel: Retained<CursorPanel> = unsafe {
            msg_send![CursorPanel::alloc(mtm), initWithContentRect: rect(0.0, 0.0, 48.0, 48.0),
                styleMask: NSWindowStyleMask::Borderless | NSWindowStyleMask::NonactivatingPanel,
                backing: NSBackingStoreType::Buffered, defer: false]
        };
        // SAFETY: `remove` closes the panel while this struct still owns it
        // through `Retained`; AppKit must not also release it on close, or
        // the drop that follows would release it a second time.
        unsafe { panel.setReleasedWhenClosed(false) };
        // No system animation when the panel is ordered in or out. AppKit runs
        // that animation (a fade of about a quarter of a second) from the main
        // run loop, and the helper stops turning the run loop as soon as no
        // picture needs frames: an order-out animation started just before
        // that froze part way, and left a faint, never-removed husk of the
        // badge on screen. Without it, an order-out is immediate.
        panel.setAnimationBehavior(NSWindowAnimationBehavior::None);
        panel.setLevel(3); // NSFloatingWindowLevel, never the normal layer (0).
        panel.setIgnoresMouseEvents(true);
        // The view draws its own soft shadow; a window shadow would outline
        // the whole transparent panel.
        panel.setHasShadow(false);
        panel.setOpaque(false);
        panel.setBackgroundColor(Some(&NSColor::clearColor()));
        panel.setCollectionBehavior(
            NSWindowCollectionBehavior::CanJoinAllSpaces
                | NSWindowCollectionBehavior::FullScreenAuxiliary
                | NSWindowCollectionBehavior::Stationary,
        );
        panel.setRestorable(false);
        let fields = Fields::new(mtm, rect(0.0, 0.0, 48.0, 48.0));
        panel.setContentView(Some(&fields.badge));
        Self {
            panel,
            fields,
            from: [0.0, 0.0],
            to: [0.0, 0.0],
            current: [0.0, 0.0],
            duration_ms: 0.0,
            reduce: false,
            press: false,
            serial: 0,
            shown: false,
            arrival_base_ms: None,
            last_elapsed_ms: 0.0,
            layout: Layout {
                panel: Rect::new(0.0, 0.0, 48.0, 48.0),
                label: None,
            },
            displays: Vec::new(),
            primary_height: 0.0,
            last_origin: None,
            last_scale: 1.0,
            last_alpha: 1.0,
        }
    }

    fn update(&mut self, mtm: MainThreadMarker, event: OverlayEvent, motion: CursorMotion) {
        self.serial = event.serial;
        self.fields.set_accent(event.accent);
        self.fields.set_avatar(event.avatar_rgba.as_deref());
        self.fields.set_initial(event.initial);
        self.reduce = NSWorkspace::sharedWorkspace().accessibilityDisplayShouldReduceMotion();
        self.press = event.gesture == OverlayGesture::Press;
        (self.displays, self.primary_height) = read_displays(mtm);
        // A read with nothing to aim at leaves a shown cursor where it is.
        let to = if event.resting && self.shown {
            self.current
        } else {
            event.to
        };
        self.to = to;
        if self.shown {
            self.from = self.current;
            self.duration_ms = (motion.duration_ms)(
                (self.to[0] - self.from[0]).hypot(self.to[1] - self.from[1]),
                self.reduce,
            );
            // An arrival still fading up carries on from where it was.
            self.arrival_base_ms = self.arrival_base_ms.map(|base| base + self.last_elapsed_ms);
        } else {
            // A first appearance glides in from a little way off while it
            // fades up, so the badge reads as the agent arriving here.
            self.from = (motion.arrival_start)(to, self.reduce);
            self.duration_ms = motion.arrival_ms;
            self.arrival_base_ms = Some(0.0);
        }
        self.last_elapsed_ms = 0.0;

        let display = display_at(to, &self.displays);
        let tip = snap_tip(to, display.map_or(1.0, |d| d.scale));
        let screen = display.map_or(Rect::new(-1e6, -1e6, 2e6, 2e6), |d| d.visible);
        let label = event
            .label
            .filter(|text| event.gesture != OverlayGesture::Read && !text.is_empty());
        let label_size = label.as_deref().map(|text| self.fields.measure_label(text));
        self.layout = layout(tip, target_rect(tip, event.target), label_size, screen);
        self.panel.setContentSize(NSSize::new(
            self.layout.panel.width,
            self.layout.panel.height,
        ));
        self.last_origin = None;
        self.last_scale = 1.0;
        self.fields.apply(
            view_point(self.layout.panel, [0.0, 0.0]),
            self.layout
                .label
                .map(|label| view_rect(self.layout.panel, label)),
            1.0,
        );
        self.place(self.from);
        if !self.shown {
            // Ordered in fully transparent; the first frame starts the fade.
            let alpha = (motion.arrival_alpha)(0.0, self.reduce);
            self.last_alpha = alpha;
            self.panel.setAlphaValue(alpha);
        }
        self.shown = true;
        self.panel.orderFrontRegardless();
    }

    /// Move the panel so the tip sits on `point`, snapped to the device-pixel
    /// grid of the display under it.
    fn place(&mut self, point: [f64; 2]) {
        let scale = display_at(point, &self.displays).map_or(1.0, |d| d.scale);
        let origin = panel_origin_for_tip(
            snap_tip(point, scale),
            self.layout.panel,
            self.primary_height,
        );
        if self.last_origin != Some(origin) {
            self.panel
                .setFrameOrigin(NSPoint::new(origin[0], origin[1]));
            self.last_origin = Some(origin);
        }
    }

    /// Draw one frame and answer whether the picture is still arriving,
    /// gliding or settling. A picture at rest needs no further frames.
    fn tick(&mut self, elapsed: f64, alpha: f64, motion: CursorMotion) -> bool {
        self.last_elapsed_ms = elapsed;
        let fraction = if self.duration_ms <= 0.0 {
            1.0
        } else {
            elapsed / self.duration_ms
        };
        self.current = (motion.position)(self.from, self.to, fraction, self.reduce);
        self.place(self.current);
        let scale = (motion.settle_scale)(elapsed - self.duration_ms, self.press, self.reduce);
        if scale != self.last_scale {
            let scene = self.fields.ivars_scene();
            self.fields.apply(scene.tip, scene.label, scale);
            self.last_scale = scale;
        }
        let mut alpha = alpha * (motion.fade_alpha)(fraction, self.reduce);
        if let Some(base) = self.arrival_base_ms {
            let arrival = if motion.arrival_ms <= 0.0 {
                1.0
            } else {
                (base + elapsed) / motion.arrival_ms
            };
            alpha *= (motion.arrival_alpha)(arrival, self.reduce);
            if arrival >= 1.0 {
                self.arrival_base_ms = None;
            }
        }
        if alpha != self.last_alpha {
            self.panel.setAlphaValue(alpha);
            self.last_alpha = alpha;
        }
        // Still moving while arriving, while the glide runs, while the landing
        // scale is off 1, or while it will be off 1 one frame from now: the
        // settle starts at exactly 1, so the arrival frame alone cannot tell.
        let since_arrival = elapsed - self.duration_ms;
        self.arrival_base_ms.is_some()
            || fraction < 1.0
            || scale != 1.0
            || (motion.settle_scale)(since_arrival + ONE_FRAME_MS, self.press, self.reduce) != 1.0
    }

    /// Take the picture off the screen for good, now. Hidden means the window
    /// is gone, not merely transparent or waiting to be ordered out.
    fn remove(&mut self) {
        self.panel.setAlphaValue(0.0);
        self.panel.orderOut(None);
        self.panel.close();
        commit_window_changes(self.panel.mtm());
    }
}

/// Hand every pending window change to the window server now.
///
/// AppKit sends window ordering, placement and opacity changes to the window
/// server when the main thread next fetches an event. This helper's main
/// thread does not sit in AppKit's event loop: with nothing left to animate it
/// blocks on its event channel. Measured with this panel: right after an
/// order-out the window was still in the window server's on-screen list (and
/// stayed there for as long as no event was fetched), and it left the list on
/// the next fetch. So a badge hidden just before that block stayed on screen
/// indefinitely. Asking AppKit for an event without waiting sends the changes
/// before the thread can block.
fn commit_window_changes(mtm: MainThreadMarker) {
    // A date in the past never waits, and nothing is dequeued: an event that
    // is waiting stays queued for the helper's loop to handle as usual.
    let _ = NSApplication::sharedApplication(mtm).nextEventMatchingMask_untilDate_inMode_dequeue(
        NSEventMask::Any,
        Some(&NSDate::distantPast()),
        unsafe { NSDefaultRunLoopMode },
        false,
    );
}

/// What the window server reported around one hide, for the macOS test that
/// checks a hidden picture's window is really gone.
#[doc(hidden)]
#[derive(Debug)]
pub struct HideProbe {
    /// The window server listed the picture's window as on screen once shown.
    pub listed_while_shown: bool,
    /// It still listed the window right after the hide, before the run loop
    /// turned again.
    pub listed_after_hide: bool,
    /// AppKit still called the window visible after the hide.
    pub visible_after_hide: bool,
}

/// Show one picture through the helper's own `update`, then hide it through
/// the same `remove` the helper uses on an end or a finished fade, and read
/// the window server's on-screen list on both sides. Must run on the main
/// thread. The picture is shown fully transparent (its arrival's first
/// frame) and never animated, so nothing appears on the desk.
#[doc(hidden)]
pub fn probe_cursor_hide(motion: CursorMotion) -> Result<HideProbe, String> {
    let mtm = MainThreadMarker::new().ok_or("the hide probe must run on the main thread")?;
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    app.finishLaunching();
    let (displays, _) = read_displays(mtm);
    let screen = displays.first().ok_or("no display is readable")?.visible;
    let mut picture = Picture::new(mtm);
    picture.update(
        mtm,
        OverlayEvent {
            agent: "hide-probe".into(),
            initial: 'P',
            accent: [0.4, 0.3, 1.0],
            to: [
                screen.x + screen.width / 2.0,
                screen.y + screen.height / 2.0,
            ],
            target: None,
            resting: true,
            label: None,
            gesture: OverlayGesture::Read,
            serial: 1,
            avatar_rgba: None,
            avatar_update: false,
        },
        motion,
    );
    // The helper's loop sends window changes between frames; do the same
    // once so the window server has really received the shown window.
    commit_window_changes(mtm);
    let number = picture.panel.windowNumber();
    let listed_while_shown = window_listed_on_screen(number);
    picture.remove();
    // Read at once, with no run-loop turn in between: the helper may block
    // right after a hide, so the hide must take effect on its own.
    let listed_after_hide = window_listed_on_screen(number);
    Ok(HideProbe {
        listed_while_shown,
        listed_after_hide,
        visible_after_hide: picture.panel.isVisible(),
    })
}

/// Whether the window server's on-screen list holds window `number` of this
/// process.
fn window_listed_on_screen(number: isize) -> bool {
    use objc2_core_foundation::{CFArray, CFDictionary, CFNumber, CFString, CFType};
    use objc2_core_graphics::{CGWindowListCopyWindowInfo, CGWindowListOption};
    let Some(windows) = CGWindowListCopyWindowInfo(CGWindowListOption::OptionOnScreenOnly, 0)
    else {
        return false;
    };
    // SAFETY: CoreGraphics documents this result as an array of string-keyed
    // dictionaries; the cast only names that element type for reading.
    let windows: &CFArray<CFDictionary<CFString, CFType>> = unsafe { windows.cast_unchecked() };
    let number_key = CFString::from_static_str("kCGWindowNumber");
    let owner_key = CFString::from_static_str("kCGWindowOwnerPID");
    let pid = f64::from(std::process::id());
    (0..windows.len()).any(|index| {
        let Some(window) = windows.get(index) else {
            return false;
        };
        let value = |key: &CFString| -> Option<f64> {
            window.get(key)?.downcast::<CFNumber>().ok()?.as_f64()
        };
        value(&owner_key) == Some(pid) && value(&number_key) == Some(number as f64)
    })
}

/// Run only in the hidden helper mode, before any asynchronous runtime exists.
/// EOF closes the channel and ends the main-thread run loop without saving state.
pub fn run_agent_cursor(events: Receiver<OverlayMessage>, motion: CursorMotion) {
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    app.disableRelaunchOnLogin();
    app.finishLaunching();
    let mut pictures = CursorSchedule::<Picture>::new();
    let mut pending = None;
    loop {
        let wait = objc2::rc::autoreleasepool(|_| {
            // Bounded by the producer's queue; animation still gets a turn when
            // a noisy agent is continuously sending events.
            for _ in 0..32 {
                match pending.take().map_or_else(|| events.try_recv(), Ok) {
                    Ok(OverlayMessage::Hide { agent }) => {
                        pictures.end(&agent, |picture, _| picture.remove());
                    }
                    Ok(OverlayMessage::Show(event)) => {
                        if !event.to.iter().all(|v| v.is_finite()) {
                            continue;
                        }
                        if event.avatar_update {
                            if let Some(picture) = pictures.picture_for_update(&event.agent) {
                                if picture.serial == event.serial {
                                    picture.fields.set_avatar(event.avatar_rgba.as_deref());
                                }
                            }
                            continue;
                        }
                        if let Some(picture) =
                            pictures.picture_for_event(event.agent.clone(), Instant::now(), || {
                                Picture::new(mtm)
                            })
                        {
                            picture.update(mtm, event, motion);
                        }
                    }
                    Err(TryRecvError::Disconnected) => return None,
                    Err(TryRecvError::Empty) => break,
                }
            }
            let wait = pictures.advance(Instant::now(), |picture, step| match step {
                PictureStep::Draw { elapsed_ms, alpha } => picture.tick(elapsed_ms, alpha, motion),
                PictureStep::Hide => {
                    picture.remove();
                    false
                }
            });
            if let Wait::Frame(interval) = wait {
                let date = NSDate::dateWithTimeIntervalSinceNow(interval.as_secs_f64());
                // Only live pictures need AppKit's timed pump; it never posts input.
                if let Some(event) = app.nextEventMatchingMask_untilDate_inMode_dequeue(
                    NSEventMask::Any,
                    Some(&date),
                    unsafe { NSDefaultRunLoopMode },
                    true,
                ) {
                    app.sendEvent(&event);
                }
            } else {
                // About to block outside the run loop, until the next event
                // or a fade is due. Handle whatever AppKit already queued and
                // let the run loop turn once, so it commits this pass's window
                // changes (above all an order-out) instead of leaving them
                // pending while the thread sleeps; never blocks.
                for _ in 0..16 {
                    let Some(event) = app.nextEventMatchingMask_untilDate_inMode_dequeue(
                        NSEventMask::Any,
                        Some(&NSDate::distantPast()),
                        unsafe { NSDefaultRunLoopMode },
                        true,
                    ) else {
                        break;
                    };
                    app.sendEvent(&event);
                }
            }
            // Flush the final draw or orderOut before sleeping.
            app.updateWindows();
            commit_window_changes(mtm);
            Some(wait)
        });
        match wait {
            None => break,
            Some(Wait::Event) => {
                // The stdin reader already runs in the background. Receiving here
                // wakes immediately on new pictures or EOF, without an idle timer
                // or a synthetic AppKit event that could carry input authority.
                match events.recv() {
                    Ok(event) => pending = Some(event),
                    Err(_) => break,
                }
            }
            Some(Wait::Timed(until_fade)) => {
                // Every picture is resting. Sleep until the next event or until
                // the oldest one is due to fade, with no frames in between, so
                // a badge left on screen costs no CPU while its agent thinks.
                match events.recv_timeout(until_fade) {
                    Ok(event) => pending = Some(event),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            Some(Wait::Frame(_)) => {}
        }
    }
}

/// One still of the picture for the offscreen gallery: a stand-in app surface
/// with the cursor drawn exactly as the live panel draws it.
pub struct GalleryShot<'a> {
    pub gesture: OverlayGesture,
    pub label: Option<&'a str>,
    pub initial: char,
    pub accent: [f64; 3],
    pub avatar_rgba: Option<&'a [u8]>,
    pub dark: bool,
    /// The scene's size in points; it stands in for the screen.
    pub size: [f64; 2],
    /// The requested tip point, top-down within the scene.
    pub point: [f64; 2],
    /// The element being acted on, top-down within the scene.
    pub target: Option<[f64; 4]>,
    /// The landing animation's scale (1 at rest, 0.9 mid-tap, 1.04 mid-settle).
    pub scale: f64,
    /// Where the tip is relative to `point`: zero at rest, and part of the
    /// way along the arrival glide for an arrival still.
    pub tip_offset: [f64; 2],
    /// The picture's opacity (below 1 only part way into an arrival).
    pub alpha: f64,
}

/// Render `shot` at 2x into a PNG at `path`, entirely offscreen: no window is
/// created, nothing is shown, and the process never becomes active. The scene
/// stands in for one Retina display, so the same layout and snapping as the
/// live panel decide where everything goes. Returns the PNG's pixel size.
#[doc(hidden)]
pub fn render_cursor_gallery_png(
    shot: &GalleryShot<'_>,
    path: &Path,
) -> Result<[usize; 2], String> {
    const SCALE: f64 = 2.0;
    let mtm = MainThreadMarker::new().ok_or("the gallery must render on the main thread")?;
    // Text needs the shared application object; Prohibited keeps it out of
    // the Dock and unable to take focus.
    NSApplication::sharedApplication(mtm)
        .setActivationPolicy(NSApplicationActivationPolicy::Prohibited);
    let [width, height] = shot.size;
    let fields = Fields::new(mtm, rect(0.0, 0.0, width, height));
    fields.set_initial(shot.initial);
    fields.set_avatar(shot.avatar_rgba);
    let point = snap_tip(shot.point, SCALE);
    let tip = snap_tip(
        [
            shot.point[0] + shot.tip_offset[0],
            shot.point[1] + shot.tip_offset[1],
        ],
        SCALE,
    );
    let label = shot
        .label
        .filter(|text| shot.gesture != OverlayGesture::Read && !text.is_empty())
        .map(|text| fields.measure_label(text));
    let screen = Rect::new(0.0, 0.0, width, height);
    let placed = layout(tip, target_rect(tip, shot.target), label, screen);
    // The scene itself is the "panel": a rectangle relative to the tip that
    // covers the whole scene.
    let scene = Rect::new(-tip[0], -tip[1], width, height);
    let flip = |r: [f64; 4]| rect(r[0], height - r[1] - r[3], r[2], r[3]);
    fields.badge.ivars().scene.set(Scene {
        backdrop: Some(Backdrop {
            dark: shot.dark,
            target: shot.target.map(flip),
            point: NSPoint::new(point[0], height - point[1]),
        }),
        accent: shot.accent,
        alpha: shot.alpha,
        ..Scene::default()
    });
    // The text fields are drawn after the badge view's own drawing, outside
    // its group opacity, so they take the same opacity themselves.
    fields.initial.setAlphaValue(shot.alpha);
    fields.label.setAlphaValue(shot.alpha);
    fields.apply(
        view_point(scene, [0.0, 0.0]),
        placed.label.map(|label| view_rect(scene, label)),
        shot.scale,
    );
    let pixels = [(width * SCALE) as usize, (height * SCALE) as usize];
    // SAFETY: AppKit allocates and owns the bitmap; it is only read back
    // through AppKit's own PNG encoder.
    let rep = unsafe {
        NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bitmapFormat_bytesPerRow_bitsPerPixel(
            NSBitmapImageRep::alloc(), std::ptr::null_mut(), pixels[0] as isize, pixels[1] as isize,
            8, 4, true, false, NSDeviceRGBColorSpace, NSBitmapFormat::empty(), 0, 0)
    }
    .ok_or("could not allocate the bitmap")?;
    rep.setSize(NSSize::new(width, height));
    fields
        .badge
        .cacheDisplayInRect_toBitmapImageRep(fields.badge.bounds(), &rep);
    // SAFETY: an empty property dictionary is valid for every file type.
    let png = unsafe {
        rep.representationUsingType_properties(NSBitmapImageFileType::PNG, &NSDictionary::new())
    }
    .ok_or("the PNG encoder returned nothing")?;
    std::fs::write(path, png.to_vec()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(pixels)
}
