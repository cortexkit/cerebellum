//! Main-thread-only pictures in small, click-through, non-key floating panels.
//! This module has no input posting, target-app activation, or capture APIs.
//!
//! The picture is one dark pointer arrow whose tip sits exactly on the target,
//! the agent's avatar in a small chip at the arrow's tail, and for actions a
//! compact label pill. Where each part goes is decided in `cursor_geometry`;
//! the motion curves come in from the caller as `CursorMotion`.

use std::cell::{Cell, RefCell};
use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::Instant;

use crate::cursor_geometry::{
    appkit_rect_to_global, display_at, layout, panel_origin_for_tip, snap_tip, target_rect,
    view_point, Display, Layout, Rect, ARROW, CHIP_CENTER, CHIP_DIAMETER, LABEL_HEIGHT,
    LABEL_MAX_WIDTH, LABEL_PADDING, OUTLINE,
};
use crate::cursor_schedule::{CursorSchedule, PictureStep, Wait};

use objc2::rc::Retained;
use objc2::{define_class, msg_send, AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSBezierPath, NSBitmapFormat,
    NSBitmapImageFileType, NSBitmapImageRep, NSColor, NSDeviceRGBColorSpace, NSEventMask, NSFont,
    NSFontWeightMedium, NSFontWeightSemibold, NSGraphicsContext, NSImage, NSLineBreakMode,
    NSLineJoinStyle, NSPanel, NSScreen, NSShadow, NSTextAlignment, NSTextField, NSView,
    NSWindowCollectionBehavior, NSWindowStyleMask, NSWorkspace,
};
use objc2_foundation::{
    NSDate, NSDefaultRunLoopMode, NSDictionary, NSPoint, NSRect, NSSize, NSString,
};

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
    /// The arrow's tip.
    tip: [f64; 2],
    /// The landing animation's scale, applied about the tip.
    scale: f64,
    label: Option<NSRect>,
    /// Only the offscreen gallery draws a backdrop; the live panel is clear.
    backdrop: Option<Backdrop>,
}

impl Default for Scene {
    fn default() -> Self {
        Self {
            tip: [0.0, 0.0],
            scale: 1.0,
            label: None,
            backdrop: None,
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
            if let Some(label) = scene.label {
                draw_pill(label);
            }
            draw_badge(scene.tip, scene.scale, self.ivars().image.borrow().as_deref());
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

/// The arrow and the chip. Geometry is top-down relative to the tip; the view
/// is bottom-up, so y flips here, and the landing scale is applied about the
/// tip so the tip itself never moves.
fn draw_badge(tip: [f64; 2], scale: f64, avatar: Option<&NSImage>) {
    let at = |p: [f64; 2]| NSPoint::new(tip[0] + p[0] * scale, tip[1] - p[1] * scale);

    let diameter = CHIP_DIAMETER * scale;
    let centre = at(CHIP_CENTER);
    let chip_rect = rect(
        centre.x - diameter / 2.0,
        centre.y - diameter / 2.0,
        diameter,
        diameter,
    );
    let chip = NSBezierPath::bezierPathWithOvalInRect(chip_rect);
    with_shadow(3.0, 0.35, || {
        // A neutral chip; the initial or the avatar goes on top.
        srgb(0.36, 0.38, 0.42, 1.0).setFill();
        chip.fill();
    });
    if let Some(image) = avatar {
        NSGraphicsContext::saveGraphicsState_class();
        chip.addClip();
        image.drawInRect(chip_rect);
        NSGraphicsContext::restoreGraphicsState_class();
    }
    // A hairline ring keeps the chip's edge readable on any avatar colour.
    srgb(1.0, 1.0, 1.0, 0.9).setStroke();
    chip.setLineWidth(1.0);
    chip.stroke();

    let arrow = NSBezierPath::bezierPath();
    arrow.moveToPoint(at(ARROW[0]));
    for vertex in &ARROW[1..] {
        arrow.lineToPoint(at(*vertex));
    }
    arrow.closePath();
    arrow.setLineJoinStyle(NSLineJoinStyle::Round);
    arrow.setLineWidth(OUTLINE * 2.0);
    // The light outline (half of the stroke, outside the fill) and the shadow
    // are drawn together, then the dark body on top without a shadow.
    with_shadow(3.5, 0.4, || {
        NSColor::whiteColor().setFill();
        NSColor::whiteColor().setStroke();
        arrow.fill();
        arrow.stroke();
    });
    srgb(0.11, 0.11, 0.13, 1.0).setFill();
    arrow.fill();
}

fn draw_pill(label: NSRect) {
    let radius = label.size.height / 2.0;
    with_shadow(2.0, 0.25, || {
        srgb(0.08, 0.08, 0.09, 0.82).setFill();
        NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(label, radius, radius).fill();
    });
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
        let initial = text_field(mtm, &badge, 10.0, true);
        initial.setAlignment(NSTextAlignment::Center);
        let label = text_field(mtm, &badge, 11.0, false);
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

    fn set_avatar(&self, pixels: Option<&[u8]>) {
        let image = pixels.and_then(|pixels| {
            if pixels.len() != 32 * 32 * 4 { return None; }
            // SAFETY: AppKit allocates a 32x32, four-channel premultiplied RGBA
            // bitmap. Its 4096-byte buffer is filled before the image is used.
            unsafe {
                let rep = NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bitmapFormat_bytesPerRow_bitsPerPixel(
                    NSBitmapImageRep::alloc(), std::ptr::null_mut(), 32, 32, 8, 4, true, false,
                    NSDeviceRGBColorSpace, NSBitmapFormat::empty(), 32 * 4, 32)?;
                let data = rep.bitmapData();
                if data.is_null() { return None; }
                std::ptr::copy_nonoverlapping(pixels.as_ptr(), data, pixels.len());
                let image = NSImage::initWithSize(NSImage::alloc(), NSSize::new(32.0, 32.0));
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
        self.from = if self.shown { self.current } else { to };
        self.to = to;
        self.duration_ms = (motion.duration_ms)(
            (self.to[0] - self.from[0]).hypot(self.to[1] - self.from[1]),
            self.reduce,
        );

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
            self.last_alpha = 1.0;
            self.panel.setAlphaValue(1.0);
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

    /// Draw one frame and answer whether the picture is still gliding or
    /// settling. A picture at rest needs no further frames until it fades.
    fn tick(&mut self, elapsed: f64, alpha: f64, motion: CursorMotion) -> bool {
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
        let alpha = alpha * (motion.fade_alpha)(fraction, self.reduce);
        if alpha != self.last_alpha {
            self.panel.setAlphaValue(alpha);
            self.last_alpha = alpha;
        }
        // Still moving while the glide runs, while the landing scale is off
        // 1, or while it will be off 1 one frame from now: the settle starts
        // at exactly 1, so the arrival frame alone cannot tell.
        let since_arrival = elapsed - self.duration_ms;
        fraction < 1.0
            || scale != 1.0
            || (motion.settle_scale)(since_arrival + ONE_FRAME_MS, self.press, self.reduce) != 1.0
    }
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
                        pictures.end(&agent, |picture, _| picture.panel.orderOut(None));
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
                    picture.panel.orderOut(None);
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
            }
            if let Wait::Timed(_) = wait {
                // About to sleep for up to the idle fade time with panels on
                // screen. Handle whatever AppKit already queued so it is not
                // left waiting that long; never blocks.
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
    let tip = snap_tip(shot.point, SCALE);
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
            point: NSPoint::new(tip[0], height - tip[1]),
        }),
        ..Scene::default()
    });
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
