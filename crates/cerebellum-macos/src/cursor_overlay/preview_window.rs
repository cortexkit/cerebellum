//! The background-mode preview's window, on the main thread only.
//!
//! One more kind of helper window beside the badge's panel, with the same
//! guarantees: a borderless, non-activating panel that refuses to become key
//! or main, ignores the mouse (clicks fall through to whatever is under it),
//! never takes focus and floats above normal windows. Like the badge, it is
//! a window of the helper process, and the module leaves every window of the
//! registered helper generation out of its occlusion and front-window
//! readings; the helper posts no input, so nothing it does can look like the
//! person's. This module has no input posting, activation or capture calls:
//! the frames it draws were captured by the module and arrive on the pipe.
//!
//! The preview is a frosted pane in the top-right corner of the screen: the
//! system's Liquid Glass view on macOS 26 and later, looked up by class name
//! at run time so the build does not depend on that binding, and the
//! older visual-effect blur otherwise. On it sit the window's thumbnail (or
//! the application's icon and a reason when there is no frame to show), the
//! agent's avatar chip, the application's name and the action's label, and
//! the agent's badge moving inside the thumbnail.

use std::cell::{Cell, RefCell};

use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject};
use objc2::{
    define_class, msg_send, sel, AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly,
};
use objc2_app_kit::{
    NSBackingStoreType, NSBezierPath, NSColor, NSCompositingOperation, NSFont, NSFontWeightRegular,
    NSFontWeightSemibold, NSGraphicsContext, NSImage, NSLineBreakMode, NSTextAlignment,
    NSTextField, NSView, NSVisualEffectBlendingMode, NSVisualEffectMaterial, NSVisualEffectState,
    NSVisualEffectView, NSWindowAnimationBehavior, NSWindowCollectionBehavior, NSWindowStyleMask,
    NSWorkspace,
};
use objc2_foundation::{NSData, NSObjectProtocol, NSPoint, NSRect, NSSize, NSString};

use super::{
    commit_window_changes, draw_badge, draw_chip, read_displays, rect, srgb, system_is_dark,
    with_group_alpha, BadgeIdentity, CursorPanel, OverlayAccent, Scene,
};
use crate::cursor_geometry::CHIP_DIAMETER;
use crate::preview_layout::{PreviewLayout, PreviewRect, PREVIEW_CORNER_RADIUS, PREVIEW_INSET};
use crate::preview_schedule::{
    BadgeDraw, OverlayFrame, OverlayPreview, PreviewFallback, PreviewSurface,
};

/// The badge inside a preview is drawn at this fraction of its size on the
/// screen, so it stays in proportion to the thumbnail.
const BADGE_SCALE: f64 = 0.6;

/// The caption's avatar chip, in points across.
const CAPTION_CHIP: f64 = 22.0;

/// Space between the caption's chip and its text, and around both.
const CAPTION_SPACE: f64 = 6.0;

/// The largest the application's icon is drawn in place of a frame.
const ICON_SIDE: f64 = 64.0;

/// What the preview view draws, in the preview's own top-down points; the
/// view flips each rectangle into its bottom-up coordinates as it draws.
#[derive(Clone, Copy, Debug, PartialEq)]
struct PreviewScene {
    /// The preview's height, which a top-down `y` is flipped about.
    height: f64,
    thumbnail_box: PreviewRect,
    thumbnail: PreviewRect,
    caption: PreviewRect,
    /// The application's icon is shown in place of a frame.
    shows_icon: bool,
    badge: Option<BadgeDraw>,
    /// The agent's accent: the badge's fill and the chip's ring.
    accent: [f64; 3],
}

#[derive(Default)]
struct PreviewIvars {
    scene: Cell<Option<PreviewScene>>,
    /// The latest captured frame of the window shown.
    frame: RefCell<Option<Retained<NSImage>>>,
    /// The application's icon, while there is no frame to show.
    icon: RefCell<Option<Retained<NSImage>>>,
    avatar: RefCell<Option<Retained<NSImage>>>,
}

define_class!(
    #[unsafe(super(NSView))]
    #[thread_kind = MainThreadOnly]
    #[name = "CerebellumAgentPreviewView"]
    #[ivars = PreviewIvars]
    struct PreviewView;
    impl PreviewView {
        #[unsafe(method(drawRect:))]
        fn draw(&self, _rect: NSRect) {
            draw_preview(self.ivars());
        }
    }
);

/// A top-down rectangle in a view `height` points tall, in the view's
/// bottom-up coordinates.
fn flip(r: PreviewRect, height: f64) -> NSRect {
    rect(r.x, height - r.bottom(), r.width, r.height)
}

/// Where the application's icon goes in a thumbnail box: centred, a little
/// above the middle to leave room for the reason under it.
fn icon_rect(thumbnail_box: PreviewRect) -> PreviewRect {
    let side = ICON_SIDE.min(thumbnail_box.height * 0.6).max(0.0);
    PreviewRect::new(
        thumbnail_box.x + (thumbnail_box.width - side) / 2.0,
        thumbnail_box.y + (thumbnail_box.height - side) / 2.0 - 8.0,
        side,
        side,
    )
}

/// The caption chip's centre, top-down.
fn caption_chip_centre(caption: PreviewRect) -> [f64; 2] {
    [
        caption.x + CAPTION_SPACE / 2.0 + CAPTION_CHIP / 2.0,
        caption.y + caption.height / 2.0,
    ]
}

fn draw_preview(ivars: &PreviewIvars) {
    let Some(scene) = ivars.scene.get() else {
        return;
    };
    let height = scene.height;
    let boxed = flip(scene.thumbnail_box, height);
    let radius = (PREVIEW_CORNER_RADIUS - PREVIEW_INSET).max(0.0);
    NSGraphicsContext::saveGraphicsState_class();
    NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(boxed, radius, radius).addClip();
    // A dim well under the picture: the letterbox bars beside a narrow
    // window, and the whole box until the first frame arrives.
    srgb(0.0, 0.0, 0.0, 0.18).setFill();
    NSBezierPath::fillRect(boxed);
    let image = |image: &NSImage, to: NSRect| {
        image.drawInRect_fromRect_operation_fraction(
            to,
            NSRect::ZERO,
            NSCompositingOperation::SourceOver,
            1.0,
        );
    };
    if scene.shows_icon {
        if let Some(icon) = ivars.icon.borrow().as_deref() {
            image(icon, flip(icon_rect(scene.thumbnail_box), height));
        }
    } else if let Some(frame) = ivars.frame.borrow().as_deref() {
        image(frame, flip(scene.thumbnail, height));
    }
    // The badge stays inside the thumbnail, clipped at its edge.
    if let Some(badge) = scene.badge {
        let badge_scene = Scene {
            tip: [badge.tip[0], height - badge.tip[1]],
            scale: BADGE_SCALE * badge.scale,
            entry: badge.entry,
            accent: scene.accent,
            pill: scene.accent,
            ..Scene::default()
        };
        with_group_alpha(badge.alpha, || {
            draw_badge(&badge_scene, ivars.avatar.borrow().as_deref());
        });
    }
    NSGraphicsContext::restoreGraphicsState_class();
    let [x, y] = caption_chip_centre(scene.caption);
    draw_chip(
        NSPoint::new(x, height - y),
        CAPTION_CHIP / CHIP_DIAMETER,
        scene.accent,
        ivars.avatar.borrow().as_deref(),
    );
}

/// A text field for the caption or the fallback's reason, added to `view`.
fn caption_field(
    mtm: MainThreadMarker,
    view: &NSView,
    size: f64,
    semibold: bool,
    colour: &NSColor,
) -> Retained<NSTextField> {
    let field = NSTextField::labelWithString(&NSString::from_str(""), mtm);
    field.setTextColor(Some(colour));
    // SAFETY: the weight constants are immutable AppKit statics.
    let weight = unsafe {
        if semibold {
            NSFontWeightSemibold
        } else {
            NSFontWeightRegular
        }
    };
    field.setFont(Some(&NSFont::systemFontOfSize_weight(size, weight)));
    field.setUsesSingleLineMode(true);
    field.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
    field.setHidden(true);
    view.addSubview(&field);
    field
}

/// The system's Liquid Glass view holding `content`, where this macOS has
/// one (macOS 26 and later). The class is looked up by name at run time, so
/// the build needs no binding for it and an older macOS simply has none.
fn liquid_glass(content: &NSView, frame: NSRect) -> Option<Retained<NSView>> {
    let class = AnyClass::get(c"NSGlassEffectView")?;
    // SAFETY: `new` on a class allocates and initializes one instance and
    // returns it retained, or nil.
    let glass: Option<Retained<AnyObject>> = unsafe { msg_send![class, new] };
    // Checked to be a view before anything else is sent to it.
    let glass = glass?.downcast::<NSView>().ok()?;
    if !(glass.respondsToSelector(sel!(setContentView:))
        && glass.respondsToSelector(sel!(setCornerRadius:)))
    {
        return None;
    }
    glass.setFrame(frame);
    // SAFETY: both are documented NSGlassEffectView properties, checked
    // above to exist: a CGFloat corner radius and the view it holds.
    unsafe {
        let _: () = msg_send![&*glass, setCornerRadius: PREVIEW_CORNER_RADIUS];
        let _: () = msg_send![&*glass, setContentView: content];
    }
    Some(glass)
}

/// The frosted pane holding `content`: Liquid Glass where the system has
/// it, otherwise the visual-effect blur with its corners rounded.
fn glass_pane(mtm: MainThreadMarker, content: &NSView, frame: NSRect) -> Retained<NSView> {
    if let Some(glass) = liquid_glass(content, frame) {
        return glass;
    }
    let pane = NSVisualEffectView::initWithFrame(NSVisualEffectView::alloc(mtm), frame);
    pane.setMaterial(NSVisualEffectMaterial::HUDWindow);
    pane.setBlendingMode(NSVisualEffectBlendingMode::BehindWindow);
    // Always drawn as active: the helper is never the active application.
    pane.setState(NSVisualEffectState::Active);
    pane.setWantsLayer(true);
    // SAFETY: a layer-backed view's `layer` is its Core Animation layer, or
    // nil; corner radius (a CGFloat) and masking are documented properties
    // of that layer.
    unsafe {
        let layer: Option<Retained<AnyObject>> = msg_send![&*pane, layer];
        if let Some(layer) = layer {
            let _: () = msg_send![&*layer, setCornerRadius: PREVIEW_CORNER_RADIUS];
            let _: () = msg_send![&*layer, setMasksToBounds: true];
        }
    }
    pane.addSubview(content);
    Retained::into_super(pane)
}

/// The usable area of the display with the menu bar (below the menu bar,
/// beside the Dock), in global top-down points; empty when no display can
/// be read, which places no preview.
pub(super) fn primary_visible_area(mtm: MainThreadMarker) -> PreviewRect {
    let (displays, _) = read_displays(mtm);
    displays
        .first()
        .map_or(PreviewRect::new(0.0, 0.0, 0.0, 0.0), |display| {
            let visible = display.visible;
            PreviewRect::new(visible.x, visible.y, visible.width, visible.height)
        })
}

/// One agent's preview window.
pub(super) struct PreviewWindow {
    panel: Retained<CursorPanel>,
    pane: Retained<NSView>,
    view: Retained<PreviewView>,
    name: Retained<NSTextField>,
    label: Retained<NSTextField>,
    initial: Retained<NSTextField>,
    reason: Retained<NSTextField>,
    /// The agent's colours, once known; the neutral ones until then.
    accent: Option<OverlayAccent>,
    /// Last values handed to AppKit, so a preview at rest costs no drawing.
    last_alpha: f64,
    last_badge: Option<BadgeDraw>,
}

impl PreviewWindow {
    pub(super) fn new(mtm: MainThreadMarker) -> Self {
        let frame = rect(0.0, 0.0, 280.0, 200.0);
        // SAFETY: AppKit initialization is on the main thread. Borderless and
        // non-activating; the subclass additionally refuses both key and main.
        let panel: Retained<CursorPanel> = unsafe {
            msg_send![CursorPanel::alloc(mtm), initWithContentRect: frame,
                styleMask: NSWindowStyleMask::Borderless | NSWindowStyleMask::NonactivatingPanel,
                backing: NSBackingStoreType::Buffered, defer: false]
        };
        // SAFETY: `remove` closes the panel while this struct still owns it
        // through `Retained`; AppKit must not also release it on close.
        unsafe { panel.setReleasedWhenClosed(false) };
        // Ordered in and out at once, as the badge's panel is: a system fade
        // would freeze part way when the helper's run loop stops turning.
        panel.setAnimationBehavior(NSWindowAnimationBehavior::None);
        panel.setLevel(3); // NSFloatingWindowLevel, never the normal layer (0).
        panel.setIgnoresMouseEvents(true);
        panel.setHasShadow(true);
        panel.setOpaque(false);
        panel.setBackgroundColor(Some(&NSColor::clearColor()));
        panel.setCollectionBehavior(
            NSWindowCollectionBehavior::CanJoinAllSpaces
                | NSWindowCollectionBehavior::FullScreenAuxiliary
                | NSWindowCollectionBehavior::Stationary,
        );
        panel.setRestorable(false);
        let view: Retained<PreviewView> = unsafe {
            let this = PreviewView::alloc(mtm).set_ivars(PreviewIvars::default());
            msg_send![super(this), initWithFrame: frame]
        };
        let pane = glass_pane(mtm, &view, frame);
        panel.setContentView(Some(&pane));
        let name = caption_field(mtm, &view, 12.0, true, &NSColor::labelColor());
        let label = caption_field(mtm, &view, 11.0, false, &NSColor::secondaryLabelColor());
        let reason = caption_field(mtm, &view, 11.0, false, &NSColor::secondaryLabelColor());
        reason.setAlignment(NSTextAlignment::Center);
        let initial = caption_field(mtm, &view, 11.0, true, &NSColor::whiteColor());
        initial.setAlignment(NSTextAlignment::Center);
        Self {
            panel,
            pane,
            view,
            name,
            label,
            initial,
            reason,
            accent: None,
            last_alpha: 1.0,
            last_badge: None,
        }
    }

    fn scene(&self) -> Option<PreviewScene> {
        self.view.ivars().scene.get()
    }

    fn set_scene(&self, scene: PreviewScene) {
        self.view.ivars().scene.set(Some(scene));
        self.view.setNeedsDisplay(true);
    }

    /// Draw the agent as its badge is drawn: its avatar, or its initial on
    /// its accent until the avatar arrives.
    pub(super) fn set_identity(&mut self, mtm: MainThreadMarker, identity: BadgeIdentity) {
        if identity.accent.is_some() {
            self.accent = identity.accent;
        }
        self.initial
            .setStringValue(&NSString::from_str(&identity.initial.to_string()));
        self.initial.setHidden(identity.avatar.is_some());
        *self.view.ivars().avatar.borrow_mut() = identity.avatar;
        if let Some(mut scene) = self.scene() {
            scene.accent = self.accent_now(mtm);
            self.set_scene(scene);
        }
        self.view.setNeedsDisplay(true);
    }

    /// The accent for the system's current appearance.
    fn accent_now(&self, mtm: MainThreadMarker) -> [f64; 3] {
        match self.accent {
            Some(accent) if system_is_dark(mtm) => accent.dark.accent,
            Some(accent) => accent.light.accent,
            None => Scene::default().accent,
        }
    }

    /// Lay the text fields out for `scene`, with the label shown or not.
    fn place_text(&self, scene: &PreviewScene, label: bool, reason: bool) {
        let height = scene.height;
        let caption = scene.caption;
        let text_x = caption.x + CAPTION_SPACE + CAPTION_CHIP + CAPTION_SPACE;
        let text_width = (caption.right() - CAPTION_SPACE - text_x).max(0.0);
        let (name_y, name_height, label_height) = (caption.y + 2.0, 16.0, 14.0);
        let name_top = if label {
            name_y
        } else {
            caption.y + (caption.height - name_height) / 2.0
        };
        self.name.setFrame(flip(
            PreviewRect::new(text_x, name_top, text_width, name_height),
            height,
        ));
        self.label.setFrame(flip(
            PreviewRect::new(text_x, name_y + name_height, text_width, label_height),
            height,
        ));
        self.label.setHidden(!label);
        let [chip_x, chip_y] = caption_chip_centre(caption);
        self.initial.setFrame(flip(
            PreviewRect::new(
                chip_x - CAPTION_CHIP / 2.0,
                chip_y - 7.5,
                CAPTION_CHIP,
                15.0,
            ),
            height,
        ));
        let icon = icon_rect(scene.thumbnail_box);
        self.reason.setFrame(flip(
            PreviewRect::new(
                scene.thumbnail_box.x + CAPTION_SPACE,
                icon.bottom() + 4.0,
                (scene.thumbnail_box.width - 2.0 * CAPTION_SPACE).max(0.0),
                14.0,
            ),
            height,
        ));
        self.reason.setHidden(!reason);
    }
}

impl PreviewSurface for PreviewWindow {
    fn show(
        &mut self,
        preview: &OverlayPreview,
        layout: &PreviewLayout,
        origin: [f64; 2],
        window_changed: bool,
    ) {
        let mtm = self.panel.mtm();
        let [width, height] = layout.size;
        self.panel.setContentSize(NSSize::new(width, height));
        // AppKit places a window by its bottom-left corner, measured up from
        // the bottom of the display with the menu bar.
        let (_, primary_height) = read_displays(mtm);
        self.panel
            .setFrameOrigin(NSPoint::new(origin[0], primary_height - origin[1] - height));
        let bounds = rect(0.0, 0.0, width, height);
        self.pane.setFrame(bounds);
        self.view.setFrame(bounds);
        let ivars = self.view.ivars();
        if window_changed {
            // The old window's frame no longer belongs here.
            *ivars.frame.borrow_mut() = None;
        }
        let fallback = preview.fallback;
        *ivars.icon.borrow_mut() = fallback
            .and(preview.icon_path.as_deref())
            .map(|path| NSWorkspace::sharedWorkspace().iconForFile(&NSString::from_str(path)));
        self.reason
            .setStringValue(&NSString::from_str(match fallback {
                Some(PreviewFallback::Minimized) => "Window minimized",
                Some(PreviewFallback::CaptureRefused) | None => "No preview available",
            }));
        self.name.setStringValue(&NSString::from_str(&preview.app));
        self.label.setStringValue(&NSString::from_str(
            preview.label.as_deref().unwrap_or_default(),
        ));
        let scene = PreviewScene {
            height,
            thumbnail_box: layout.thumbnail_box,
            thumbnail: layout.thumbnail,
            caption: layout.caption,
            shows_icon: fallback.is_some(),
            badge: if window_changed {
                None
            } else {
                self.scene().and_then(|scene| scene.badge)
            },
            accent: self.accent_now(mtm),
        };
        if window_changed {
            self.last_badge = None;
        }
        self.place_text(&scene, preview.label.is_some(), fallback.is_some());
        self.name.setHidden(false);
        self.set_scene(scene);
        self.panel.invalidateShadow();
        self.panel.orderFrontRegardless();
    }

    fn frame(&mut self, frame: OverlayFrame) {
        let data = NSData::with_bytes(&frame.jpeg);
        let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) else {
            return;
        };
        *self.view.ivars().frame.borrow_mut() = Some(image);
        // A frame of the window is shown in place of the icon.
        if let Some(mut scene) = self.scene() {
            scene.shows_icon = false;
            self.reason.setHidden(true);
            self.set_scene(scene);
        }
    }

    fn draw(&mut self, badge: Option<BadgeDraw>, alpha: f64) {
        if alpha != self.last_alpha {
            self.panel.setAlphaValue(alpha);
            self.last_alpha = alpha;
        }
        if badge != self.last_badge {
            self.last_badge = badge;
            if let Some(mut scene) = self.scene() {
                scene.badge = badge;
                self.set_scene(scene);
            }
        }
    }

    fn remove(&mut self) {
        // Gone at once, with no fade: the window is ordered out and closed
        // and the change is sent to the window server before the helper's
        // loop can block, as the badge's panel is.
        self.panel.setAlphaValue(0.0);
        self.panel.orderOut(None);
        self.panel.close();
        commit_window_changes(self.panel.mtm());
    }
}

/// What a probe reads off one preview window.
pub(super) struct PreviewFacts {
    pub(super) panel: Retained<CursorPanel>,
    /// Its frosted pane is the system's Liquid Glass view.
    pub(super) liquid_glass: bool,
}

impl PreviewWindow {
    pub(super) fn facts(&self) -> PreviewFacts {
        PreviewFacts {
            panel: self.panel.clone(),
            liquid_glass: AnyClass::get(c"NSGlassEffectView")
                .is_some_and(|class| self.pane.isKindOfClass(class)),
        }
    }
}
