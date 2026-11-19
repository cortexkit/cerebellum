use std::sync::mpsc::{self, Receiver, SendError, SyncSender, TrySendError};

use objc2::rc::Retained;
use objc2::MainThreadMarker;
use objc2_app_kit::{NSApplication, NSEvent, NSEventMask, NSEventModifierFlags, NSEventType};
use objc2_core_foundation::{
    kCFRunLoopDefaultMode, CFRetained, CFRunLoop, CFRunLoopSource, CFRunLoopSourceContext,
};
use objc2_foundation::{NSDate, NSDefaultRunLoopMode, NSPoint};

use super::{OverlayMessage, Wait};

/// The channel bound is also the number of messages we handle before giving
/// AppKit and the animation another turn.
pub(super) const MESSAGE_BUDGET: usize = 32;

/// Application-defined subtype reserved for waking this private AppKit loop.
const OVERLAY_WAKE: i16 = 0x434b;

/// The stdin reader uses this bounded queue. Successful enqueues signal the
/// AppKit run loop; failed lossy sends have nothing to signal.
pub struct OverlaySender {
    // Drop the channel endpoint before signaling EOF, so the receiver cannot
    // wake, observe an empty but connected queue, and sleep forever.
    messages: Option<SyncSender<OverlayMessage>>,
    wake: Wake,
}

struct Wake {
    run_loop: CFRetained<CFRunLoop>,
    source: CFRetained<CFRunLoopSource>,
}

// SAFETY: CF's retain/release, source signaling and run-loop wakeup may be
// called from any thread. Only the main thread installs the source or runs
// the loop, and the source callback has no context shared with the reader.
unsafe impl Send for Wake {}

impl OverlaySender {
    pub fn send(&self, message: OverlayMessage) -> Result<(), SendError<OverlayMessage>> {
        self.messages.as_ref().unwrap().send(message)?;
        self.wake();
        Ok(())
    }

    pub fn try_send(&self, message: OverlayMessage) -> Result<(), TrySendError<OverlayMessage>> {
        self.messages.as_ref().unwrap().try_send(message)?;
        self.wake();
        Ok(())
    }

    fn wake(&self) {
        // Repeated signals before the callback runs coalesce in Core Foundation.
        self.wake.source.signal();
        self.wake.run_loop.wake_up();
    }

    pub(super) fn run_loop(&self) -> &CFRunLoop {
        &self.wake.run_loop
    }
}

impl Drop for OverlaySender {
    fn drop(&mut self) {
        drop(self.messages.take());
        self.wake();
    }
}

pub(super) struct OverlayReceiver {
    pub(super) messages: Receiver<OverlayMessage>,
    source: CFRetained<CFRunLoopSource>,
}

impl Drop for OverlayReceiver {
    fn drop(&mut self) {
        self.source.invalidate();
    }
}

pub(super) fn channel(_mtm: MainThreadMarker) -> Option<(OverlaySender, OverlayReceiver)> {
    let run_loop = CFRunLoop::current()?;
    let mut context = CFRunLoopSourceContext {
        version: 0,
        info: std::ptr::null_mut(),
        retain: None,
        release: None,
        copyDescription: None,
        equal: None,
        hash: None,
        schedule: None,
        cancel: None,
        perform: Some(post_wake),
    };
    // SAFETY: Core Foundation copies this version-zero context. The callback
    // has no data pointer and is only installed on the main thread's run loop.
    let source = unsafe { CFRunLoopSource::new(None, 0, &mut context) }?;
    // SAFETY: the mode is a process-lifetime Core Foundation constant.
    run_loop.add_source(Some(&source), unsafe { kCFRunLoopDefaultMode });
    let (sender, receiver) = mpsc::sync_channel(MESSAGE_BUDGET);
    Some((
        OverlaySender {
            messages: Some(sender),
            wake: Wake {
                run_loop,
                source: source.clone(),
            },
        },
        OverlayReceiver {
            messages: receiver,
            source,
        },
    ))
}

extern "C-unwind" fn post_wake(_: *mut std::ffi::c_void) {
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    let event = NSEvent::otherEventWithType_location_modifierFlags_timestamp_windowNumber_context_subtype_data1_data2(
        NSEventType::ApplicationDefined,
        NSPoint::ZERO,
        NSEventModifierFlags::empty(),
        0.0,
        0,
        None,
        OVERLAY_WAKE,
        0,
        0,
    );
    if let Some(event) = event {
        // Queue locally, behind any AppKit events already waiting. This is
        // never posted to WindowServer and has no window or input authority.
        app.postEvent_atStart(&event, false);
    }
}

pub(super) fn deadline(wait: Wait, batch_full: bool) -> Retained<NSDate> {
    if batch_full {
        // One wake can cover the whole batch, including messages enqueued
        // during the drain. Give AppKit a turn, but do not sleep on that batch.
        return NSDate::distantPast();
    }
    match wait {
        Wait::Event => NSDate::distantFuture(),
        Wait::Frame(after) | Wait::Timed(after) => {
            NSDate::dateWithTimeIntervalSinceNow(after.as_secs_f64())
        }
    }
}

pub(super) fn pump(app: &NSApplication, deadline: &NSDate) {
    // SAFETY: this references the lifetime-long default mode exported by Foundation.
    let mode = unsafe { NSDefaultRunLoopMode };
    while objc2::rc::autoreleasepool(|_| {
        let Some(event) = app.nextEventMatchingMask_untilDate_inMode_dequeue(
            NSEventMask::Any,
            Some(deadline),
            mode,
            true,
        ) else {
            return false;
        };
        if event.r#type() == NSEventType::ApplicationDefined && event.subtype().0 == OVERLAY_WAKE {
            // The event is only a return from nextEvent: never dispatch it.
            return false;
        }
        app.sendEvent(&event);
        app.updateWindows();
        // Native traffic does not push the next frame or fade farther out.
        deadline.timeIntervalSinceNow() > 0.0
    }) {}
}
