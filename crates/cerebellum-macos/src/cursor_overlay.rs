//! Main-thread-only pictures in small, click-through, non-key floating panels.
//! This module has no input posting, target-app activation, or capture APIs.

use std::cell::Cell;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Instant;

use crate::cursor_schedule::{CursorSchedule, PictureStep, Wait};

use objc2::rc::Retained;
use objc2::{define_class, msg_send, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSBezierPath, NSColor,
    NSEventMask, NSFont, NSPanel, NSScreen, NSTextField, NSView, NSWindowCollectionBehavior,
    NSWindowStyleMask, NSWorkspace,
};
use objc2_foundation::{NSDate, NSDefaultRunLoopMode, NSPoint, NSRect, NSSize, NSString};

pub struct OverlayEvent {
    pub agent: String,
    pub initial: char,
    pub to: [f64; 2],
    pub width: f64,
    pub label: Option<String>,
    pub reading: bool,
}

pub type GlideDuration = fn(f64, f64, bool) -> f64;
pub type GlidePosition = fn([f64; 2], [f64; 2], f64, bool) -> [f64; 2];

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

#[derive(Default)]
struct BadgeIvars {
    pulse: Cell<f64>,
}

define_class!(
    #[unsafe(super(NSView))]
    #[thread_kind = MainThreadOnly]
    #[ivars = BadgeIvars]
    struct Badge;
    impl Badge {
        #[unsafe(method(drawRect:))]
        fn draw(&self, _rect: NSRect) {
            let radius = 12.0 + self.ivars().pulse.get() * 4.0;
            NSColor::colorWithCalibratedRed_green_blue_alpha(0.24, 0.45, 0.95, 0.85).setFill();
            NSBezierPath::bezierPathWithOvalInRect(rect(42.0-radius, 32.0-radius, radius*2.0, radius*2.0)).fill();
        }
    }
);

fn rect(x: f64, y: f64, width: f64, height: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(width, height))
}

struct Picture {
    panel: Retained<CursorPanel>,
    badge: Retained<Badge>,
    initial: Retained<NSTextField>,
    label: Retained<NSTextField>,
    glyph: Retained<NSTextField>,
    from: [f64; 2],
    to: [f64; 2],
    current: [f64; 2],
    duration_ms: f64,
    reduce: bool,
}

impl Picture {
    fn new(mtm: MainThreadMarker, to: [f64; 2]) -> Self {
        // SAFETY: AppKit initialization is on the main thread. Borderless and
        // non-activating; the subclass additionally refuses both key and main.
        let panel: Retained<CursorPanel> = unsafe {
            msg_send![CursorPanel::alloc(mtm), initWithContentRect: rect(0.0, 0.0, 120.0, 48.0),
                styleMask: NSWindowStyleMask::Borderless | NSWindowStyleMask::NonactivatingPanel,
                backing: NSBackingStoreType::Buffered, defer: false]
        };
        panel.setLevel(3); // NSFloatingWindowLevel, never the normal layer (0).
        panel.setIgnoresMouseEvents(true);
        panel.setHasShadow(false);
        panel.setOpaque(false);
        panel.setBackgroundColor(Some(&NSColor::clearColor()));
        panel.setCollectionBehavior(
            NSWindowCollectionBehavior::CanJoinAllSpaces
                | NSWindowCollectionBehavior::FullScreenAuxiliary
                | NSWindowCollectionBehavior::Stationary,
        );
        panel.setRestorable(false);
        let badge: Retained<Badge> = unsafe {
            let this = Badge::alloc(mtm).set_ivars(BadgeIvars::default());
            msg_send![super(this), initWithFrame: rect(0.0, 0.0, 120.0, 48.0)]
        };
        panel.setContentView(Some(&badge));
        let text = |value: &str, frame: NSRect, size: f64| {
            let field = NSTextField::labelWithString(&NSString::from_str(value), mtm);
            field.setFrame(frame);
            field.setTextColor(Some(&NSColor::whiteColor()));
            field.setFont(Some(&NSFont::boldSystemFontOfSize(size)));
            badge.addSubview(&field);
            field
        };
        // A cursor glyph, not the operator's mouse. The label has its own row.
        let glyph = text("↖", rect(0.0, 18.0, 24.0, 30.0), 26.0);
        let initial = text("", rect(36.0, 21.0, 20.0, 22.0), 16.0);
        let label = text("", rect(0.0, 0.0, 120.0, 18.0), 10.0);
        Self {
            panel,
            badge,
            initial,
            label,
            glyph,
            from: to,
            to,
            current: to,
            duration_ms: 0.0,
            reduce: false,
        }
    }

    fn update(&mut self, event: OverlayEvent, duration: GlideDuration) {
        self.glyph.setHidden(event.reading);
        self.initial
            .setStringValue(&NSString::from_str(&event.initial.to_string()));
        self.label
            .setStringValue(&NSString::from_str(event.label.as_deref().unwrap_or("")));
        self.reduce = NSWorkspace::sharedWorkspace().accessibilityDisplayShouldReduceMotion();
        self.from = self.current;
        self.to = event.to;
        self.duration_ms = if event.reading {
            0.0
        } else {
            duration(
                (self.to[0] - self.from[0]).hypot(self.to[1] - self.from[1]),
                event.width,
                self.reduce,
            )
        };
        self.panel.setAlphaValue(1.0);
        self.panel.orderFrontRegardless();
    }

    fn tick(&mut self, elapsed: f64, alpha: f64, desktop_top: f64, position: GlidePosition) {
        let fraction = if self.duration_ms <= 0.0 {
            1.0
        } else {
            elapsed / self.duration_ms
        };
        self.current = position(self.from, self.to, fraction, self.reduce);
        // AX/CG points are top-down; AppKit window origins are bottom-up.
        self.panel.setFrameOrigin(NSPoint::new(
            self.current[0],
            desktop_top - self.current[1] - 48.0,
        ));
        let since_arrival = elapsed - self.duration_ms;
        let pulse = if !self.reduce && (0.0..250.0).contains(&since_arrival) {
            (since_arrival / 250.0 * std::f64::consts::PI).sin()
        } else {
            0.0
        };
        self.badge.ivars().pulse.set(pulse);
        self.badge.setNeedsDisplay(true);
        self.panel.setAlphaValue(alpha);
    }
}

/// Run only in the hidden helper mode, before any asynchronous runtime exists.
/// EOF closes the channel and ends the main-thread run loop without saving state.
pub fn run_agent_cursor(
    events: Receiver<OverlayEvent>,
    duration: GlideDuration,
    position: GlidePosition,
) {
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    app.disableRelaunchOnLogin();
    app.finishLaunching();
    let desktop_top = NSScreen::screens(mtm)
        .firstObject()
        .map_or(0.0, |screen| screen.frame().size.height);
    let mut pictures = CursorSchedule::<Picture>::new();
    let mut pending = None;
    loop {
        let wait = objc2::rc::autoreleasepool(|_| {
            // Bounded by the producer's queue; animation still gets a turn when
            // a noisy agent is continuously sending events.
            for _ in 0..32 {
                match pending.take().map_or_else(|| events.try_recv(), Ok) {
                    Ok(event) => {
                        if !event.to.iter().all(|v| v.is_finite()) {
                            continue;
                        }
                        if let Some(picture) =
                            pictures.picture_for_event(event.agent.clone(), Instant::now(), || {
                                Picture::new(mtm, event.to)
                            })
                        {
                            picture.update(event, duration);
                        }
                    }
                    Err(TryRecvError::Disconnected) => return None,
                    Err(TryRecvError::Empty) => break,
                }
            }
            let wait = pictures.advance(Instant::now(), |picture, step| match step {
                PictureStep::Draw { elapsed_ms, alpha } => {
                    picture.tick(elapsed_ms, alpha, desktop_top, position);
                }
                PictureStep::Hide => picture.panel.orderOut(None),
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
            // Flush the final orderOut before sleeping without any live panels.
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
            Some(Wait::Frame(_)) => {}
        }
    }
}
