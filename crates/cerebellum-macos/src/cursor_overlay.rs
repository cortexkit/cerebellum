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
use std::time::{Duration, Instant};

use crate::cursor_geometry::{
    appkit_rect_to_global, chip_at, display_at, layout_frame, panel_origin_for_tip, snap_tip,
    swing_panel, turn_point, view_point, BodySide, Display, Layout, Rect, CHIP_DIAMETER, CHIP_RIM,
    CHIP_RING, LABEL_HEIGHT, LABEL_MAX_WIDTH, LABEL_PADDING, OUTLINE, POINTER, POINTER_CORNER,
};
use crate::cursor_schedule::{
    avatar_change, begin_picture, entry_frame, sooner_wait, ActivityChange, ActivityGate,
    Appearance, BadgeMotion, ColourFade, Colours, CursorSchedule, EntryFrame, PictureAim,
    PictureNeed, PictureStep, Wait,
};
pub use crate::cursor_schedule::{CursorMotion, PictureTiming};
use crate::preview_schedule::{OverlayFrame, OverlayPreview, OverlayPreviewMotion, Previews};

#[cfg(feature = "desk-probe")]
mod capture_probe;
#[cfg(feature = "desk-probe")]
pub use capture_probe::{
    prepare_app_use_desk_probe, probe_overlay_capture_exclusion, with_app_use_desk_probe_run_loop,
};
// The preview's window: a child module, so it draws the badge and its chip
// with the same private drawing code as the badge's own panel.
mod preview_window;
use preview_window::{primary_visible_area, PreviewWindow};

use objc2::rc::Retained;
use objc2::{define_class, msg_send, AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSBezierPath, NSBitmapFormat,
    NSBitmapImageFileType, NSBitmapImageRep, NSColor, NSCompositingOperation,
    NSDeviceRGBColorSpace, NSEventMask, NSFont, NSFontWeightMedium, NSFontWeightSemibold,
    NSGraphicsContext, NSImage, NSLineBreakMode, NSLineJoinStyle, NSPanel, NSScreen, NSShadow,
    NSTextAlignment, NSTextField, NSView, NSWindowAnimationBehavior, NSWindowCollectionBehavior,
    NSWindowSharingType, NSWindowStyleMask, NSWorkspace,
};
use objc2_foundation::{
    NSActivityOptions, NSDate, NSDefaultRunLoopMode, NSDictionary, NSObjectProtocol, NSPoint,
    NSProcessInfo, NSRect, NSSize, NSString,
};

/// The avatar raster's side in pixels. The avatar is drawn 31 points across
/// inside the chip's ring, 62 pixels on a Retina display, so a raster of 64
/// is only ever scaled down. The module renders avatars at this size.
pub const AVATAR_PIXELS: usize = 64;

/// The initial letter's font size in a resting chip; it grows with the chip
/// during an entry.
const INITIAL_FONT_SIZE: f64 = 17.0;

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
    /// The agent's colours for Light and Dark mode; the helper draws the set
    /// for the appearance it sees.
    pub accent: OverlayAccent,
    /// `accent` is the agent's own colour, read from its avatar. When false
    /// it is the neutral colour, which a badge already showing the agent's
    /// colour keeps rather than going back to grey. An avatar update always
    /// sets the colour it carries.
    pub accent_known: bool,
    /// The tip's destination, global top-down points.
    pub to: [f64; 2],
    /// The acted-on element's frame. Label layout deliberately does not use it.
    pub target: Option<[f64; 4]>,
    /// The target window bounds, in global top-down points.
    pub window: Option<[f64; 4]>,
    /// `to` is only somewhere to appear: a shown cursor stays where it is.
    pub resting: bool,
    pub label: Option<String>,
    pub gesture: OverlayGesture,
    pub serial: u64,
    pub avatar_rgba: Option<Vec<u8>>,
    pub avatar_update: bool,
    /// How the badge reaches `to` and how long that takes, as the module
    /// chose it. The helper follows it exactly.
    pub motion: PictureTiming,
}

/// The colours a badge is drawn in for one system appearance, sRGB in [0, 1].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OverlayColours {
    /// The pointer's fill and the chip's ring.
    pub accent: [f64; 3],
    /// The label pill, under white text.
    pub pill: [f64; 3],
}

/// An agent's colours for Light and for Dark mode.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OverlayAccent {
    pub light: OverlayColours,
    pub dark: OverlayColours,
}

/// One message from the module: a picture to show or move, one agent's
/// picture to take off the screen now because that agent is done, or the
/// window under one agent's picture having moved.
pub enum OverlayMessage {
    /// A no-drawing barrier acknowledged after AppKit initialization.
    Ready {
        reply: std::sync::mpsc::SyncSender<()>,
    },
    /// Query on this AppKit application's main thread, never the pipe reader.
    PointerWindow {
        point: [f64; 2],
        reply: std::sync::mpsc::SyncSender<Option<u32>>,
    },
    /// Boxed: a picture is far larger than the other messages.
    Show(Box<OverlayEvent>),
    Hide {
        agent: String,
    },
    /// The element the picture of event `serial` points at has moved by
    /// `offset` points in total since that event, because its window was
    /// moved or resized. A report for an older event is ignored: the badge
    /// has moved on to another target since.
    Follow {
        agent: String,
        serial: u64,
        offset: [f64; 2],
        window: Option<[f64; 4]>,
    },
    /// Show or retarget one agent's background-mode preview. It takes the
    /// agent's badge off the real screen: in background mode the badge moves
    /// inside the preview.
    Preview(Box<OverlayPreview>),
    /// A captured frame of the window an agent's preview shows.
    Frame(Box<OverlayFrame>),
    /// The badge's motion inside an agent's preview.
    PreviewMotion(Box<OverlayPreviewMotion>),
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
    side: BodySide,
    chip_shift: [f64; 2],
    /// The landing animation's scale, applied about the tip.
    scale: f64,
    /// Where a first appearance is: the chip's size and place, and how far
    /// the pointer and label have come in.
    entry: EntryFrame,
    /// How far the pointer is turned about the chip's centre from its
    /// resting direction, while the window under the badge is dragged.
    rotation: f64,
    /// The pointer's own opacity: Reduce Motion hides it during a drag.
    pointer_alpha: f64,
    label: Option<NSRect>,
    accent: [f64; 3],
    /// The label pill's fill.
    pill: [f64; 3],
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
            side: BodySide::default(),
            chip_shift: [0.0; 2],
            scale: 1.0,
            entry: EntryFrame::REST,
            rotation: 0.0,
            pointer_alpha: 1.0,
            label: None,
            accent: [0.427, 0.290, 1.0],
            pill: [0.427, 0.290, 1.0],
            backdrop: None,
            alpha: 1.0,
        }
    }
}

impl Scene {
    fn colours(&self) -> Colours {
        [self.accent, self.pill]
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
                    with_group_alpha(scene.entry.pointer, || draw_pill(label, scene.pill));
                }
                draw_badge(&scene, self.ivars().image.borrow().as_deref());
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
/// whole picture, so overlapping parts do not show through each other. Used
/// for the gallery's entry stills and, live, for the pointer and label while
/// an entry fades them in; at 1 it draws directly.
fn with_group_alpha(alpha: f64, body: impl FnOnce()) {
    use objc2_core_graphics::CGContext;
    if alpha >= 1.0 {
        return body();
    }
    if alpha <= 0.0 {
        return;
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
/// the tip so the tip itself never moves. During an entry the chip is larger
/// and nearer the tip, and the pointer grows and fades in on top of it. While
/// the window under the badge is dragged, the pointer is turned about the
/// chip's centre and the chip stays where it is.
fn draw_badge(scene: &Scene, avatar: Option<&NSImage>) {
    let (tip, scale, entry, accent) = (scene.tip, scene.scale, scene.entry, scene.accent);
    let at = |p: [f64; 2]| NSPoint::new(tip[0] + p[0] * scale, tip[1] - p[1] * scale);

    let (chip_centre, chip_diameter) = chip_at(entry.chip);
    // The rim and ring keep their proportion to the chip as it grows.
    let chip_scale = scale * chip_diameter / CHIP_DIAMETER;
    let chip_centre = scene.side.point(chip_centre);
    draw_chip(
        at([
            chip_centre[0] + scene.chip_shift[0],
            chip_centre[1] + scene.chip_shift[1],
        ]),
        chip_scale,
        accent,
        avatar,
    );

    // The pointer grows about the tip as it comes in, so the tip stays put.
    let pointer_scale = scale * entry.pointer_scale();
    let rotation = scene.rotation;
    let at = |p: [f64; 2]| {
        let p = scene.side.point(turn_point(p, rotation));
        NSPoint::new(tip[0] + p[0] * pointer_scale, tip[1] - p[1] * pointer_scale)
    };
    with_group_alpha(entry.pointer * scene.pointer_alpha, || {
        let pointer = pointer_path(at, pointer_scale);
        pointer.setLineJoinStyle(NSLineJoinStyle::Round);
        pointer.setLineWidth(OUTLINE * 2.0 * pointer_scale);
        // The white outline (half of the stroke, outside the fill) and the
        // shadow are drawn together, then the coloured body on top without a
        // shadow.
        with_shadow(4.0, 0.45, || {
            NSColor::whiteColor().setFill();
            NSColor::whiteColor().setStroke();
            pointer.fill();
            pointer.stroke();
        });
        accent_color(accent, 1.0).setFill();
        pointer.fill();
    });
}

/// The avatar chip with its centre at `centre`, at `chip_scale` times its
/// resting size: the white rim, the avatar (or the plain accent, under the
/// initial's text field) and the accent ring. The badge draws it behind its
/// pointer; a preview also draws one beside the application's name.
fn draw_chip(centre: NSPoint, chip_scale: f64, accent: [f64; 3], avatar: Option<&NSImage>) {
    let diameter = CHIP_DIAMETER * chip_scale;
    let chip = oval(centre, diameter);
    // The white rim, just outside the chip's edge, carries the shadow: it
    // lifts the chip off a light background and outlines it on a dark one.
    let rim = oval(centre, diameter + 2.0 * CHIP_RIM * chip_scale);
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
            let inset = oval(centre, diameter - 2.0 * CHIP_RING * chip_scale).bounds();
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
    let ring = oval(centre, diameter - CHIP_RING * chip_scale);
    ring.setLineWidth(CHIP_RING * chip_scale);
    accent_color(accent, 1.0).setStroke();
    ring.stroke();
}

fn draw_pill(label: NSRect, fill: [f64; 3]) {
    let radius = label.size.height / 2.0;
    let pill = NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(label, radius, radius);
    with_shadow(3.0, 0.3, || {
        accent_color(fill, 1.0).setFill();
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
    /// The initial's current font size; it changes only while an entry
    /// grows or shrinks the chip.
    initial_font: Cell<f64>,
    avatar_pixels: RefCell<Option<Vec<u8>>>,
}

impl Fields {
    fn new(mtm: MainThreadMarker, frame: NSRect) -> Self {
        let badge: Retained<Badge> = unsafe {
            let this = Badge::alloc(mtm).set_ivars(BadgeIvars::default());
            msg_send![super(this), initWithFrame: frame]
        };
        let initial = text_field(mtm, &badge, INITIAL_FONT_SIZE, true);
        initial.setHidden(false);
        initial.setAlignment(NSTextAlignment::Center);
        let label = text_field(mtm, &badge, 12.0, false);
        Self {
            badge,
            initial,
            label,
            initial_font: Cell::new(INITIAL_FONT_SIZE),
            avatar_pixels: RefCell::new(None),
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

    fn set_colours(&self, colours: Colours) {
        let mut scene = self.ivars_scene();
        [scene.accent, scene.pill] = colours;
        self.badge.ivars().scene.set(scene);
        self.badge.setNeedsDisplay(true);
    }

    fn set_avatar(&self, pixels: Option<&[u8]>) {
        let known = self.avatar_pixels.borrow();
        let Some(pixels) = avatar_change(known.as_deref(), pixels) else {
            return;
        };
        let Some(image) = avatar_image(pixels) else {
            return;
        };
        drop(known);
        *self.avatar_pixels.borrow_mut() = Some(pixels.to_vec());
        self.initial.setHidden(true);
        *self.badge.ivars().image.borrow_mut() = Some(image);
        self.badge.setNeedsDisplay(true);
    }

    /// Place the drawing and the text fields for a tip and label given in the
    /// view's bottom-up coordinates, at a landing scale and an entry frame.
    fn apply(&self, tip: [f64; 2], label: Option<NSRect>, scale: f64, entry: EntryFrame) {
        let mut scene = self.ivars_scene();
        scene.tip = tip;
        scene.label = label;
        scene.scale = scale;
        scene.entry = entry;
        self.badge.ivars().scene.set(scene);
        let (centre, diameter) = chip_at(entry.chip);
        let centre = scene.side.point(centre);
        let centre = [
            centre[0] + scene.chip_shift[0],
            centre[1] + scene.chip_shift[1],
        ];
        let chip_scale = scale * diameter / CHIP_DIAMETER;
        // The initial grows and shrinks with the chip, and only an entry
        // changes the chip's size, so the font is rarely set.
        let font = (INITIAL_FONT_SIZE * chip_scale * 2.0).round() / 2.0;
        if font != self.initial_font.get() {
            // SAFETY: the weight constant is an immutable AppKit static.
            let weight = unsafe { NSFontWeightSemibold };
            self.initial
                .setFont(Some(&NSFont::systemFontOfSize_weight(font, weight)));
            self.initial.sizeToFit();
            self.initial_font.set(font);
        }
        let initial = self.initial.frame().size;
        let width = CHIP_DIAMETER * chip_scale;
        // The initial follows the chip's centre as the chip moves and scales.
        self.initial.setFrame(rect(
            tip[0] + centre[0] * scale - width / 2.0,
            tip[1] - centre[1] * scale - initial.height / 2.0,
            width,
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
        // The label text comes in with its pill and the pointer.
        self.label.setAlphaValue(entry.pointer);
        self.label.setHidden(label.is_none());
        self.badge.setNeedsDisplay(true);
    }

    fn ivars_scene(&self) -> Scene {
        self.badge.ivars().scene.get()
    }

    /// Turn the pointer about the chip and set its own opacity.
    fn set_hand(&self, rotation: f64, pointer_alpha: f64) {
        let mut scene = self.ivars_scene();
        scene.rotation = rotation;
        scene.pointer_alpha = pointer_alpha;
        self.badge.ivars().scene.set(scene);
        self.badge.setNeedsDisplay(true);
    }
}

/// The avatar as an image the chip draws, from the module's
/// `AVATAR_PIXELS`-square, four-channel premultiplied RGBA raster; `None` for
/// a raster of any other size.
fn avatar_image(pixels: &[u8]) -> Option<Retained<NSImage>> {
    const SIDE: usize = AVATAR_PIXELS;
    if pixels.len() != SIDE * SIDE * 4 {
        return None;
    }
    // SAFETY: AppKit allocates a SIDE x SIDE, four-channel premultiplied
    // RGBA bitmap. Its buffer of exactly `pixels.len()` bytes is filled
    // before the image is used.
    unsafe {
        let rep = NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bitmapFormat_bytesPerRow_bitsPerPixel(
            NSBitmapImageRep::alloc(), std::ptr::null_mut(), SIDE as isize, SIDE as isize,
            8, 4, true, false, NSDeviceRGBColorSpace, NSBitmapFormat::empty(),
            (SIDE * 4) as isize, 32)?;
        let data = rep.bitmapData();
        if data.is_null() {
            return None;
        }
        std::ptr::copy_nonoverlapping(pixels.as_ptr(), data, pixels.len());
        // The image is the resting chip's size; AppKit scales the
        // 64-pixel raster into the avatar's circle when it draws.
        let size = NSSize::new(CHIP_DIAMETER, CHIP_DIAMETER);
        rep.setSize(size);
        let image = NSImage::initWithSize(NSImage::alloc(), size);
        image.addRepresentation(&rep);
        Some(image)
    }
}

/// A rectangle given relative to the tip, in the panel view's coordinates.
fn view_rect(panel: Rect, relative: Rect) -> NSRect {
    let [x, y] = view_point(panel, [relative.x, relative.bottom()]);
    rect(x, y, relative.width, relative.height)
}

/// Whether the system is in Dark mode, as this process sees it. The helper
/// never sets an appearance of its own, so its application's appearance is
/// the system's.
fn system_is_dark(mtm: MainThreadMarker) -> bool {
    use objc2_app_kit::{NSAppearanceNameAqua, NSAppearanceNameDarkAqua};
    use objc2_foundation::NSArray;
    let appearance = NSApplication::sharedApplication(mtm).effectiveAppearance();
    // SAFETY: the appearance names are immutable AppKit string constants.
    let (light, dark) = unsafe { (NSAppearanceNameAqua, NSAppearanceNameDarkAqua) };
    appearance
        .bestMatchFromAppearancesWithNames(&NSArray::from_slice(&[light, dark]))
        .is_some_and(|best| &*best == dark)
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

/// Who an agent's badge is drawn as.
struct BadgeIdentity {
    initial: char,
    accent: Option<OverlayAccent>,
    avatar: Option<Retained<NSImage>>,
}

struct Picture {
    panel: Retained<CursorPanel>,
    fields: Fields,
    serial: u64,
    /// The agent's initial, shown on the chip until its avatar arrives.
    initial: char,
    /// Whether it has appeared yet, and its entry while it is appearing.
    appearance: Appearance,
    /// Where it is, where it is going, and what its pointer is doing.
    motion: BadgeMotion,
    /// The agent's colours this picture is drawn in, once set by an event.
    accent: Option<OverlayAccent>,
    /// The colours shown, cross-fading to new ones when they change.
    colours: ColourFade,
    /// The resting badge's layout for the latest event.
    layout: Layout,
    label_size: Option<[f64; 2]>,
    window: Option<[f64; 4]>,
    /// The panel in use: the resting layout's, or a larger one that holds a
    /// pointer swinging around the chip.
    panel_rect: Rect,
    /// `panel_rect` is the larger panel for a swinging pointer.
    hand_panel: bool,
    displays: Vec<Display>,
    primary_height: f64,
    /// Last values handed to AppKit. A settled picture changes nothing, so
    /// its ticks cost no window-server or drawing work.
    last_origin: Option<[f64; 2]>,
    last_scale: f64,
    last_entry: EntryFrame,
    last_alpha: f64,
    last_hand: (f64, f64),
    last_colours: Colours,
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
        // Keep the badge out of screen sharing, recordings and screenshots,
        // like the preview panel: its label describes what the agent is
        // doing, which a shared screen should not reveal either.
        panel.setSharingType(NSWindowSharingType::None);
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
            serial: 0,
            initial: ' ',
            appearance: Appearance::default(),
            motion: BadgeMotion::new(Instant::now()),
            accent: None,
            colours: ColourFade::new(Scene::default().colours()),
            layout: Layout {
                panel: Rect::new(0.0, 0.0, 48.0, 48.0),
                label: None,
                side: Default::default(),
                chip_shift: [0.0; 2],
            },
            label_size: None,
            window: None,
            panel_rect: Rect::new(0.0, 0.0, 48.0, 48.0),
            hand_panel: false,
            displays: Vec::new(),
            primary_height: 0.0,
            last_origin: None,
            last_scale: 1.0,
            last_entry: EntryFrame::REST,
            last_alpha: 1.0,
            last_hand: (0.0, 1.0),
            last_colours: Scene::default().colours(),
        }
    }

    /// Draw this picture in `accent`, the set for the system's current
    /// appearance: at once for a badge only now appearing, otherwise by a
    /// short cross-fade, so a colour that arrives after the badge appeared
    /// eases in rather than snapping.
    fn recolour(&mut self, mtm: MainThreadMarker, accent: OverlayAccent, now: Instant, fade: bool) {
        self.accent = Some(accent);
        let colours = if system_is_dark(mtm) {
            accent.dark
        } else {
            accent.light
        };
        self.colours.set([colours.accent, colours.pill], now, fade);
        if !fade {
            let (shown, _) = self.colours.frame(now);
            self.fields.set_colours(shown);
            self.last_colours = shown;
        }
    }

    fn update(&mut self, mtm: MainThreadMarker, event: OverlayEvent, now: Instant) {
        self.serial = event.serial;
        self.initial = event.initial;
        if let Some(pixels) = event.avatar_rgba.as_deref() {
            self.fields.set_avatar(Some(pixels));
        }
        self.fields.set_initial(event.initial);
        (self.displays, self.primary_height) = read_displays(mtm);
        // The module's motion, from wherever this badge really is: its entry
        // or glide ends exactly when the module sends the action.
        let (_, first) = begin_picture(
            &mut self.appearance,
            &mut self.motion,
            PictureAim {
                to: event.to,
                resting: event.resting,
                press: event.gesture == OverlayGesture::Press,
                timing: event.motion,
            },
            now,
        );
        // The agent's own colour replaces whatever is shown; the neutral one
        // only stands in until that is known, so it never replaces it. The
        // appearance is read again either way, so a switch between Light and
        // Dark mode shows on the next event.
        let accent = match self.accent {
            Some(known) if !event.accent_known => known,
            _ => event.accent,
        };
        self.recolour(mtm, accent, now, !first);

        let label = event
            .label
            .filter(|text| event.gesture != OverlayGesture::Read && !text.is_empty());
        let label_size = label.as_deref().map(|text| self.fields.measure_label(text));
        self.label_size = label_size;
        self.window = event.window;
        self.last_scale = 1.0;
        // An action during an entry keeps the entry where it is.
        let entry = self.appearance.frame(now);
        self.last_entry = entry;
        self.relayout(self.motion.current(), entry, self.last_scale);
        self.fit_panel(self.motion.hand(), entry);
        self.place(self.motion.current());
        if first {
            // Ordered in fully transparent; the first frames fade it up.
            self.last_alpha = entry.alpha;
            self.panel.setAlphaValue(entry.alpha);
        }
        self.panel.orderFrontRegardless();
    }

    /// Size the panel for the resting badge, or, while the pointer is off its
    /// resting place, for a pointer at any angle around the chip; then lay
    /// the drawing out in it. The label is hidden while the pointer swings:
    /// the pointer would sweep across it, and it names an action on an
    /// element the pointer has left. It comes back when the badge lands.
    fn fit_panel(&mut self, hand: bool, entry: EntryFrame) {
        self.hand_panel = hand;
        self.panel_rect = if hand {
            self.layout
                .side
                .rect(swing_panel(self.layout.side.rect(self.layout.panel)))
        } else {
            self.layout.panel
        };
        self.panel
            .setContentSize(NSSize::new(self.panel_rect.width, self.panel_rect.height));
        // The panel's origin depends on its size, so it must be set again.
        self.last_origin = None;
        let label = if hand { None } else { self.layout.label };
        let mut scene = self.fields.ivars_scene();
        scene.side = self.layout.side;
        scene.chip_shift = self.layout.chip_shift;
        self.fields.badge.ivars().scene.set(scene);
        self.fields.apply(
            view_point(self.panel_rect, [0.0, 0.0]),
            label.map(|label| view_rect(self.panel_rect, label)),
            self.last_scale,
            entry,
        );
    }

    /// The window under this picture's target moved. During its entry the
    /// badge moves with the window at once; otherwise the chip holds still
    /// and the pointer turns toward where the element now is, and the next
    /// frame draws that.
    fn follow(&mut self, serial: u64, offset: [f64; 2], window: Option<[f64; 4]>, now: Instant) {
        if serial != self.serial {
            return;
        }
        if let Some(window) = window {
            self.window = Some(window);
        }
        if self
            .motion
            .on_follow(offset, now, self.appearance.entering())
        {
            if self.relayout(self.motion.current(), self.last_entry, self.last_scale) {
                self.fit_panel(self.motion.hand(), self.last_entry);
            }
            self.place(self.motion.current());
        }
    }

    /// Use the same side decision at the current tip for events, every glide
    /// frame, and window-follow reports. The destination never pre-flips a
    /// badge that is still at the start of its flight.
    fn relayout(&mut self, point: [f64; 2], entry: EntryFrame, scale: f64) -> bool {
        let display = display_at(point, &self.displays);
        let tip = snap_tip(point, display.map_or(1.0, |d| d.scale));
        let screen = display.map_or(Rect::new(-1e6, -1e6, 2e6, 2e6), |d| d.visible);
        let placed = layout_frame(
            tip,
            self.window
                .map_or(screen, |[x, y, w, h]| Rect::new(x, y, w, h)),
            self.label_size,
            screen,
            entry.chip,
            scale,
            self.layout.side,
        );
        let changed = placed != self.layout;
        self.layout = placed;
        self.motion.set_body_side(placed.side);
        changed
    }

    /// Move the panel so the tip sits on `point`, snapped to the device-pixel
    /// grid of the display under it.
    fn place(&mut self, point: [f64; 2]) {
        let scale = display_at(point, &self.displays).map_or(1.0, |d| d.scale);
        let origin =
            panel_origin_for_tip(snap_tip(point, scale), self.panel_rect, self.primary_height);
        if self.last_origin != Some(origin) {
            self.panel
                .setFrameOrigin(NSPoint::new(origin[0], origin[1]));
            self.last_origin = Some(origin);
        }
    }

    /// Draw the frame for `now` and answer what the picture still needs:
    /// frames while it is entering, gliding, settling or turning its pointer,
    /// a later wake-up while it waits for a dragged window to keep still, and
    /// nothing at rest. `alpha` is the schedule's idle-fade opacity.
    fn tick(&mut self, now: Instant, alpha: f64, motion: CursorMotion) -> PictureNeed {
        let frame = self.motion.frame(now, &motion);
        let entry = self.appearance.frame(now);
        let changed = self.relayout(frame.tip, entry, frame.scale);
        if changed || frame.hand != self.hand_panel {
            self.last_scale = frame.scale;
            self.last_entry = entry;
            self.fit_panel(frame.hand, entry);
        }
        self.place(frame.tip);
        if frame.scale != self.last_scale || entry != self.last_entry {
            let scene = self.fields.ivars_scene();
            self.fields
                .apply(scene.tip, scene.label, frame.scale, entry);
            self.last_scale = frame.scale;
            self.last_entry = entry;
        }
        let hand = (self.motion.rotation(), frame.pointer_alpha);
        if hand != self.last_hand {
            self.fields.set_hand(hand.0, hand.1);
            self.last_hand = hand;
        }
        let alpha = alpha * frame.alpha * entry.alpha;
        if alpha != self.last_alpha {
            self.panel.setAlphaValue(alpha);
            self.last_alpha = alpha;
        }
        let (colours, recolouring) = self.colours.frame(now);
        if colours != self.last_colours {
            self.fields.set_colours(colours);
            self.last_colours = colours;
        }
        if self.appearance.entering() || recolouring {
            PictureNeed::Frames
        } else {
            frame.need
        }
    }

    /// Who this badge is drawn as: what a preview taking the badge off the
    /// screen carries on, so the agent looks the same inside it.
    fn identity(&self) -> BadgeIdentity {
        BadgeIdentity {
            initial: self.initial,
            accent: self.accent,
            avatar: self.fields.badge.ivars().image.borrow().clone(),
        }
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
/// thread. The picture is shown fully transparent (its entry's first
/// frame) and never animated, so nothing appears on the desk.
#[doc(hidden)]
pub fn probe_cursor_hide(motion: CursorMotion) -> Result<HideProbe, String> {
    // A picture's motion now comes on its event, and this one never moves,
    // so the curves are not needed; the parameter keeps the probe's callers
    // unchanged.
    let _ = motion;
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
            accent: PROBE_ACCENT,
            accent_known: true,
            to: [
                screen.x + screen.width / 2.0,
                screen.y + screen.height / 2.0,
            ],
            target: None,
            window: None,
            resting: true,
            label: None,
            gesture: OverlayGesture::Read,
            serial: 1,
            avatar_rgba: None,
            avatar_update: false,
            motion: PictureTiming {
                entry: true,
                duration_ms: crate::cursor_schedule::ENTRY_MS,
                reduce_motion: false,
            },
        },
        Instant::now(),
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

/// What the window server and AppKit reported about one background-mode
/// preview's window around its hide, for the macOS test that checks the
/// window's kind and that a hidden preview is really gone.
#[doc(hidden)]
#[derive(Debug)]
pub struct PreviewHideProbe {
    /// The window server listed the preview's window as on screen once shown.
    pub listed_while_shown: bool,
    /// It still listed the window right after the hide, before the run loop
    /// turned again.
    pub listed_after_hide: bool,
    /// AppKit still called the window visible after the hide.
    pub visible_after_hide: bool,
    pub can_become_key: bool,
    pub can_become_main: bool,
    /// Clicks fall through it to the window underneath.
    pub ignores_mouse: bool,
    /// Its style mask includes `NonactivatingPanel`, so showing it does not
    /// activate the helper.
    pub non_activating: bool,
    /// It floats above normal windows (whose level is 0).
    pub level: isize,
    /// Its sharing type is `NSWindowSharingNone`. Actual pixel exclusion is
    /// checked separately by the manual display-capture probe.
    pub hidden_from_capture: bool,
    /// The badge panel also requests `NSWindowSharingNone`.
    pub badge_hidden_from_capture: bool,
    /// Its frosted pane is the system's Liquid Glass view.
    pub liquid_glass: bool,
    /// This macOS has a Liquid Glass view at all (macOS 26 and later).
    pub liquid_glass_available: bool,
}

/// Show one preview through the helper's own preview code, then hide it
/// through the same `hide` the helper uses for an agent's end, and read the
/// window server's on-screen list on both sides. Must run on the main
/// thread. The preview is shown fully transparent, so nothing appears on the
/// desk.
#[doc(hidden)]
pub fn probe_preview_hide() -> Result<PreviewHideProbe, String> {
    const AGENT: &str = "preview-probe";
    let mtm = MainThreadMarker::new().ok_or("the preview probe must run on the main thread")?;
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    app.finishLaunching();
    let mut previews = Previews::<PreviewWindow>::new();
    let badge = Picture::new(mtm);
    let shown = previews.on_preview(
        OverlayPreview {
            agent: AGENT.into(),
            generation: 1,
            slot: 0,
            window: 1,
            app: "Preview probe".into(),
            aspect: [1600.0, 1000.0],
            label: Some("Pressing Send".into()),
            fallback: None,
            icon_path: None,
        },
        primary_visible_area(mtm),
        Instant::now(),
        || {
            let mut window = PreviewWindow::new(mtm);
            // Transparent before it is first ordered in.
            crate::preview_schedule::PreviewSurface::draw(&mut window, None, 0.0);
            window
        },
    );
    if !shown {
        return Err("no display is readable, so the preview has no place".into());
    }
    commit_window_changes(mtm);
    let facts = previews
        .surface_for_update(AGENT)
        .map(|window| window.facts())
        .ok_or("the shown preview is missing")?;
    let panel = &facts.panel;
    let number = panel.windowNumber();
    let listed_while_shown = window_listed_on_screen(number);
    previews.hide(AGENT);
    // Read at once, with no run-loop turn in between, as for the badge.
    let listed_after_hide = window_listed_on_screen(number);
    Ok(PreviewHideProbe {
        listed_while_shown,
        listed_after_hide,
        visible_after_hide: panel.isVisible(),
        can_become_key: panel.canBecomeKeyWindow(),
        can_become_main: panel.canBecomeMainWindow(),
        ignores_mouse: panel.ignoresMouseEvents(),
        non_activating: panel
            .styleMask()
            .contains(NSWindowStyleMask::NonactivatingPanel),
        level: panel.level(),
        hidden_from_capture: panel.sharingType() == NSWindowSharingType::None,
        badge_hidden_from_capture: badge.panel.sharingType() == NSWindowSharingType::None,
        liquid_glass: facts.liquid_glass,
        liquid_glass_available: objc2::runtime::AnyClass::get(c"NSGlassEffectView").is_some(),
    })
}

/// Whether the person has asked macOS to reduce motion. Only the module reads
/// it: it chooses each picture's motion and sends that, Reduce Motion or not,
/// on the picture line, so the helper never reads the setting itself. The
/// module process runs no AppKit event loop, so this may keep answering the
/// value it first read after the person changes the setting; since the line
/// carries the value, the module and the helper still agree on it.
pub fn reduce_motion() -> bool {
    NSWorkspace::sharedWorkspace().accessibilityDisplayShouldReduceMotion()
}

/// Run only in the hidden helper mode, before any asynchronous runtime exists.
/// EOF closes the channel and ends the main-thread run loop without saving state.
pub fn run_agent_cursor(events: Receiver<OverlayMessage>, motion: CursorMotion) {
    run_cursor_loop(events, motion, None);
}

/// While it animates, the helper tells macOS that it is doing latency-critical
/// work the person asked for, and stops saying so the moment it rests.
///
/// The helper is a background process: never frontmost, with no Dock icon,
/// and between turns it has no window on screen at all. macOS treats such a
/// process as one it may nap (App Nap) and whose timers it may coalesce, so
/// its 60 Hz frame wake-ups can arrive late, by hundreds of milliseconds for a
/// napped process (the `cursor_motion` test measures it). A glide is only a
/// third of a second long, so a late first wake drew the badge at its start
/// and then straight at its end. An activity begun with
/// these options is the documented way to opt out while it is held: "user
/// initiated" keeps the process out of App Nap, and "latency critical" asks
/// for precise timers. It does not keep the Mac awake, and it is ended as soon
/// as no picture needs frames, so a resting badge holds nothing.
struct AnimationActivity {
    gate: ActivityGate,
    token: Option<Retained<objc2::runtime::ProtocolObject<dyn NSObjectProtocol>>>,
    /// Off only in the motion probe's comparison run, to show the throttling
    /// the activity prevents.
    enabled: bool,
}

impl AnimationActivity {
    fn before_wait(&mut self, wait: Wait) {
        match self.gate.before_wait(wait) {
            Some(ActivityChange::Begin) if self.enabled => {
                let info = NSProcessInfo::processInfo();
                self.token = Some(info.beginActivityWithOptions_reason(
                    NSActivityOptions::UserInitiatedAllowingIdleSystemSleep
                        | NSActivityOptions::LatencyCritical,
                    &NSString::from_str("Animating the agent cursor"),
                ));
            }
            Some(ActivityChange::End) => {
                if let Some(token) = self.token.take() {
                    // SAFETY: the token is the object `beginActivity` returned,
                    // ended exactly once.
                    unsafe { NSProcessInfo::processInfo().endActivity(&token) };
                }
            }
            _ => {}
        }
    }

    fn held(&self) -> bool {
        self.token.is_some()
    }
}

fn run_cursor_loop(
    events: Receiver<OverlayMessage>,
    motion: CursorMotion,
    mut probe: Option<&mut LoopRecord>,
) {
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    app.disableRelaunchOnLogin();
    app.finishLaunching();
    let mut pictures = CursorSchedule::<Picture>::new();
    let mut previews = Previews::<PreviewWindow>::new();
    let mut activity = AnimationActivity {
        gate: ActivityGate::default(),
        token: None,
        enabled: probe.as_ref().is_none_or(|probe| probe.hold_activity),
    };
    let mut pending = None;
    loop {
        let wait = objc2::rc::autoreleasepool(|_| {
            // Bounded by the producer's queue; animation still gets a turn when
            // a noisy agent is continuously sending events.
            for _ in 0..32 {
                match pending.take().map_or_else(|| events.try_recv(), Ok) {
                    Ok(OverlayMessage::Ready { reply }) => {
                        let _ = reply.try_send(());
                    }
                    Ok(OverlayMessage::PointerWindow { point, reply }) => {
                        let _ = reply.try_send(crate::pointer_window_at(point[0], point[1]));
                    }
                    Ok(OverlayMessage::Hide { agent }) => {
                        // The agent's badge and its preview go together.
                        pictures.end(&agent, |picture, _| picture.remove());
                        previews.hide(&agent);
                    }
                    Ok(OverlayMessage::Preview(preview)) => {
                        let agent = preview.agent.clone();
                        let shown = previews.on_preview(
                            *preview,
                            primary_visible_area(mtm),
                            Instant::now(),
                            || PreviewWindow::new(mtm),
                        );
                        if shown {
                            // In background mode the badge moves inside the
                            // preview; the one on the real screen would point
                            // at whatever window covers the app. The agent
                            // keeps its look there.
                            let mut identity = None;
                            pictures.end(&agent, |picture, _| {
                                identity = Some(picture.identity());
                                picture.remove();
                            });
                            if let (Some(identity), Some(window)) =
                                (identity, previews.surface_for_update(&agent))
                            {
                                window.set_identity(mtm, identity);
                            }
                        }
                    }
                    Ok(OverlayMessage::Frame(frame)) => {
                        // Never creates or revives a preview, and never
                        // restarts its idle clock.
                        previews.on_frame(*frame);
                    }
                    Ok(OverlayMessage::PreviewMotion(motion)) => {
                        previews.on_motion(*motion, Instant::now());
                    }
                    Ok(OverlayMessage::Follow {
                        agent,
                        serial,
                        offset,
                        window,
                    }) => {
                        // Never creates or revives a picture, and never
                        // restarts its idle clock: the agent did nothing.
                        if let Some(picture) = pictures.picture_for_update(&agent) {
                            picture.follow(serial, offset, window, Instant::now());
                        }
                    }
                    Ok(OverlayMessage::Show(event)) => {
                        if !event.to.iter().all(|v| v.is_finite()) {
                            continue;
                        }
                        if event.avatar_update {
                            // The agent's look, wherever its badge is: on
                            // the screen, or inside its preview.
                            if let Some(window) = previews.surface_for_update(&event.agent) {
                                window.set_identity(
                                    mtm,
                                    BadgeIdentity {
                                        initial: event.initial,
                                        accent: Some(event.accent),
                                        avatar: event.avatar_rgba.as_deref().and_then(avatar_image),
                                    },
                                );
                            }
                            if let Some(picture) = pictures.picture_for_update(&event.agent) {
                                if picture.serial == event.serial {
                                    picture.fields.set_avatar(event.avatar_rgba.as_deref());
                                    // The colour read from that avatar; the
                                    // next frame starts fading to it.
                                    picture.recolour(mtm, event.accent, Instant::now(), true);
                                }
                            }
                            continue;
                        }
                        let now = Instant::now();
                        if let Some(picture) =
                            pictures
                                .picture_for_event(event.agent.clone(), now, || Picture::new(mtm))
                        {
                            picture.update(mtm, *event, now);
                        }
                    }
                    Err(TryRecvError::Disconnected) => return None,
                    Err(TryRecvError::Empty) => break,
                }
            }
            let now = Instant::now();
            let wait = pictures.advance(now, |picture, step| match step {
                PictureStep::Draw { alpha, .. } => picture.tick(now, alpha, motion),
                PictureStep::Hide => {
                    picture.remove();
                    PictureNeed::Rest
                }
            });
            let wait = sooner_wait(wait, previews.advance(now, &motion));
            activity.before_wait(wait);
            if let Some(probe) = probe.as_deref_mut() {
                let tip = pictures
                    .picture_for_update(PROBE_AGENT)
                    .map(|picture| picture.motion.current());
                probe.passes.push(ProbePass {
                    at_ms: now.duration_since(probe.start).as_secs_f64() * 1000.0,
                    frame_wait: matches!(wait, Wait::Frame(_)),
                    activity_held: activity.held(),
                    tip,
                });
            }
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
            Some(Wait::Timed(until)) => {
                // Every picture is resting. Sleep until the next event, until
                // the oldest one is due to fade, or until a dragged window
                // has been still long enough for its badge to fly back, with
                // no frames in between, so a badge left on screen costs no
                // CPU while its agent thinks or its window is being dragged.
                match events.recv_timeout(until) {
                    Ok(event) => pending = Some(event),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            Some(Wait::Frame(_)) => {}
        }
    }
    // The helper is exiting; leave no activity behind it.
    activity.before_wait(Wait::Event);
}

/// The agent the motion probe drives.
const PROBE_AGENT: &str = "motion-probe";

/// The colours the probes draw their badge in: a violet with a darker pill.
const PROBE_ACCENT: OverlayAccent = OverlayAccent {
    light: OverlayColours {
        accent: [0.427, 0.290, 1.0],
        pill: [0.33, 0.22, 0.78],
    },
    dark: OverlayColours {
        accent: [0.427, 0.290, 1.0],
        pill: [0.33, 0.22, 0.78],
    },
};

/// What the helper's loop did on one pass, for the motion probe.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct ProbePass {
    /// When the pass drew, in ms since the probe started.
    pub at_ms: f64,
    /// The loop then waited one frame for the next pass, rather than for an
    /// event or the idle-fade deadline.
    pub frame_wait: bool,
    /// The animation activity was held during that wait.
    pub activity_held: bool,
    /// The live picture's resting-tip anchor, not the swinging pointer's tip.
    pub tip: Option<[f64; 2]>,
}

/// Every pass of the helper's loop during one motion probe.
struct LoopRecord {
    start: Instant,
    hold_activity: bool,
    passes: Vec<ProbePass>,
}

/// What the motion probe did, and what the helper's loop recorded meanwhile.
#[doc(hidden)]
#[derive(Debug)]
pub struct MotionProbe {
    pub passes: Vec<ProbePass>,
    /// When the first event (the entry) was sent, ms since the start.
    pub entry_sent_ms: f64,
    /// When the second event (a glide from `from` to `to`) was sent.
    pub glide_sent_ms: f64,
    pub from: [f64; 2],
    pub to: [f64; 2],
    /// When a window-follow report of `follow_offset` was sent.
    pub follow_sent_ms: f64,
    pub follow_offset: [f64; 2],
    /// How long the window must stay still before the return glide starts.
    pub follow_quiet_ms: f64,
    /// When the picture was hidden.
    pub hide_sent_ms: f64,
}

/// Drive the helper's own loop, exactly as the helper runs it, through one
/// appearance: `idle` with nothing on screen (long enough for macOS to treat
/// the process as idle in the background, as the real helper is between
/// turns), an entry, a 400-point glide, a window-follow report and a hide.
/// Every pass of the loop is recorded, so the caller can read the real frame
/// intervals and where the badge was drawn. Must run on the main thread. A
/// badge is visible on the main display for about four seconds; it never
/// takes focus and ignores the mouse, like the real one.
///
/// `hold_activity: false` runs without the animation activity, to show what
/// macOS does to the frames without it.
#[doc(hidden)]
pub fn probe_cursor_motion(
    motion: CursorMotion,
    idle: Duration,
    hold_activity: bool,
) -> Result<MotionProbe, String> {
    let mtm = MainThreadMarker::new().ok_or("the motion probe must run on the main thread")?;
    let (displays, _) = read_displays(mtm);
    let screen = displays.first().ok_or("no display is readable")?.visible;
    let centre = [
        screen.x + screen.width / 2.0,
        screen.y + screen.height / 2.0,
    ];
    let from = [centre[0] - 200.0, centre[1] - 50.0];
    let to = [centre[0] + 120.0, centre[1] + 190.0];
    let follow_offset: [f64; 2] = [40.0, 30.0];
    // The probe stands in for the module: the entry at its usual length, and
    // the glide at the length the supplied curve gives for that distance.
    let glide_ms = (motion.duration_ms)((to[0] - from[0]).hypot(to[1] - from[1]), false);
    let follow_ms = (motion.duration_ms)(follow_offset[0].hypot(follow_offset[1]), false);
    // A follow first swings the pointer around the stationary avatar. Leave
    // time for the window's quiet period and the return flight, then a margin
    // for scheduling, so hiding the picture cannot cut that flight short.
    let follow_wait = crate::cursor_schedule::WINDOW_QUIET
        + Duration::from_secs_f64(follow_ms / 1000.0)
        + Duration::from_millis(500);
    let event = move |serial: u64, at: [f64; 2]| {
        OverlayMessage::Show(Box::new(OverlayEvent {
            agent: PROBE_AGENT.into(),
            initial: 'P',
            accent: PROBE_ACCENT,
            accent_known: true,
            to: at,
            target: None,
            window: None,
            resting: false,
            label: None,
            gesture: OverlayGesture::Read,
            serial,
            avatar_rgba: None,
            avatar_update: false,
            motion: PictureTiming {
                entry: serial == 1,
                duration_ms: if serial == 1 {
                    crate::cursor_schedule::ENTRY_MS
                } else {
                    glide_ms
                },
                reduce_motion: false,
            },
        }))
    };
    let start = Instant::now();
    let (sender, receiver) = std::sync::mpsc::sync_channel(32);
    let script = std::thread::spawn(move || {
        let since = |at: Instant| at.duration_since(start).as_secs_f64() * 1000.0;
        std::thread::sleep(idle);
        let entry_sent_ms = since(Instant::now());
        sender.send(event(1, from)).ok()?;
        std::thread::sleep(Duration::from_millis(1200));
        let glide_sent_ms = since(Instant::now());
        sender.send(event(2, to)).ok()?;
        std::thread::sleep(Duration::from_millis(1200));
        let follow_sent_ms = since(Instant::now());
        sender
            .send(OverlayMessage::Follow {
                agent: PROBE_AGENT.into(),
                serial: 2,
                offset: follow_offset,
                window: None,
            })
            .ok()?;
        std::thread::sleep(follow_wait);
        let hide_sent_ms = since(Instant::now());
        sender
            .send(OverlayMessage::Hide {
                agent: PROBE_AGENT.into(),
            })
            .ok()?;
        Some([entry_sent_ms, glide_sent_ms, follow_sent_ms, hide_sent_ms])
    });
    let mut record = LoopRecord {
        start,
        hold_activity,
        passes: Vec::new(),
    };
    // Returns once the script drops its sender.
    run_cursor_loop(receiver, motion, Some(&mut record));
    let [entry_sent_ms, glide_sent_ms, follow_sent_ms, hide_sent_ms] = script
        .join()
        .ok()
        .flatten()
        .ok_or("the helper's loop stopped before the probe's script finished")?;
    Ok(MotionProbe {
        passes: record.passes,
        entry_sent_ms,
        glide_sent_ms,
        from,
        to,
        follow_sent_ms,
        follow_offset,
        follow_quiet_ms: crate::cursor_schedule::WINDOW_QUIET.as_secs_f64() * 1000.0,
        hide_sent_ms,
    })
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
    /// For a still of a first appearance: how far into its entry, in ms.
    pub entry_ms: Option<f64>,
    /// Reduce Motion is on, which turns an entry into a plain fade.
    pub reduce_motion: bool,
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
    let tip = point;
    let entry = shot
        .entry_ms
        .and_then(|ms| entry_frame(ms, shot.reduce_motion))
        .unwrap_or(EntryFrame::REST);
    let label = shot
        .label
        .filter(|text| shot.gesture != OverlayGesture::Read && !text.is_empty())
        .map(|text| fields.measure_label(text));
    let screen = Rect::new(0.0, 0.0, width, height);
    let placed = layout_frame(
        tip,
        screen,
        label,
        screen,
        entry.chip,
        shot.scale,
        BodySide::default(),
    );
    // The scene itself is the "panel": a rectangle relative to the tip that
    // covers the whole scene.
    let scene = Rect::new(-tip[0], -tip[1], width, height);
    let flip = |r: [f64; 4]| rect(r[0], height - r[1] - r[3], r[2], r[3]);
    fields.badge.ivars().scene.set(Scene {
        side: placed.side,
        chip_shift: placed.chip_shift,
        backdrop: Some(Backdrop {
            dark: shot.dark,
            target: shot.target.map(flip),
            point: NSPoint::new(point[0], height - point[1]),
        }),
        accent: shot.accent,
        // The stills show the pill in the accent itself.
        pill: shot.accent,
        alpha: entry.alpha,
        ..Scene::default()
    });
    fields.apply(
        view_point(scene, [0.0, 0.0]),
        placed.label.map(|label| view_rect(scene, label)),
        shot.scale,
        entry,
    );
    // The text fields are drawn after the badge view's own drawing, outside
    // its group opacity, so they take the same opacity themselves: the live
    // panel fades the whole window instead.
    fields.initial.setAlphaValue(entry.alpha);
    fields.label.setAlphaValue(entry.alpha * entry.pointer);
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
