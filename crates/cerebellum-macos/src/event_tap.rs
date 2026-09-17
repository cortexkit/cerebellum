//! A listen-only session event tap and the numbers it reports.

use std::fmt;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

use crate::input::InputMonitoringAccess;

/// One event as the tap delivered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEvent {
    /// `kCGEventSourceUnixProcessID` from the event's source.
    pub source_unix_process_id: i64,
    /// `CGEventType` as the integer CoreGraphics uses.
    pub event_type: u32,
    /// `kCGEventSourceUserData`, used to recognize an observer heartbeat.
    pub marker_nonce: u64,
    /// The event's own timestamp, nanoseconds on the same clock as
    /// [`uptime_now_ns`]. A consumer that subtracts this from that clock at the
    /// moment it drains the event measures how late it learned of the event
    /// end to end (window server, tap callback, channel, its own loop), which
    /// is the quantity a seize-latency bound is about. Time since some other
    /// instant of the consumer's choosing is not.
    pub timestamp_ns: u64,
}

/// Nanoseconds since boot on the clock CoreGraphics stamps events with
/// (`CLOCK_UPTIME_RAW`; it does not advance while the machine sleeps, and
/// neither does an event timestamp).
#[cfg(target_os = "macos")]
pub fn uptime_now_ns() -> u64 {
    extern "C" {
        fn clock_gettime_nsec_np(clock_id: u32) -> u64;
    }
    // <time.h>: CLOCK_UPTIME_RAW == 8 on every macOS this crate supports.
    const CLOCK_UPTIME_RAW: u32 = 8;
    // SAFETY: a libc call with no pointer arguments.
    unsafe { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) }
}

/// Why a session event tap was not started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEventTapError {
    /// `CGEventTapCreate` returned no tap. The Input Monitoring reading is
    /// attached because that grant is what creation needs; a Granted reading
    /// here means the grant was present and creation still returned nothing.
    NotCreated {
        input_monitoring: InputMonitoringAccess,
    },
    /// The tap existed but `CFMachPortCreateRunLoopSource` returned no source.
    RunLoopSourceUnavailable,
    /// The tap thread has no run loop to attach the source to.
    RunLoopUnavailable,
}

impl fmt::Display for SessionEventTapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCreated { input_monitoring } => write!(
                f,
                "CGEventTapCreate returned no tap (Input Monitoring: {input_monitoring:?})"
            ),
            Self::RunLoopSourceUnavailable => {
                write!(
                    f,
                    "CFMachPortCreateRunLoopSource returned no source for the tap"
                )
            }
            Self::RunLoopUnavailable => write!(f, "the tap thread has no run loop"),
        }
    }
}

impl std::error::Error for SessionEventTapError {}

/// Attach the Input Monitoring reading to a failed tap create.
///
/// Separated from the create call so the mapping can be tested: create needs a
/// real session and the Input Monitoring grant, which is exactly when a
/// regression would be introduced.
fn tap_create_failure(input_monitoring: InputMonitoringAccess) -> SessionEventTapError {
    SessionEventTapError::NotCreated { input_monitoring }
}

/// A bounded channel the tap callback fills and the caller drains.
///
/// Bounded rather than unbounded because an unread tap that grows without limit
/// is a memory leak wearing a queue's clothes. The callback sends and will
/// stall once the bound is full; macOS may then disable the tap, which the
/// enabled reading reports. The seam does not drop events to keep the tap
/// alive, and it does not re-enable a tap macOS disabled.
fn session_event_channel(bound: usize) -> (SyncSender<SessionEvent>, Receiver<SessionEvent>) {
    sync_channel(bound)
}

#[cfg(target_os = "macos")]
mod framework {
    use std::ptr::NonNull;
    use std::sync::mpsc::{Receiver, SyncSender};
    use std::thread::{self, JoinHandle};

    use objc2_core_foundation::{kCFRunLoopCommonModes, CFMachPort, CFRetained, CFRunLoop};
    use objc2_core_graphics::{
        CGEvent, CGEventField, CGEventMask, CGEventTapLocation, CGEventTapOptions,
        CGEventTapPlacement, CGEventTapProxy, CGEventType,
    };

    use super::{session_event_channel, tap_create_failure, SessionEvent, SessionEventTapError};
    use crate::input::input_monitoring_access;

    struct TapCallbackState {
        tx: SyncSender<SessionEvent>,
    }

    /// CoreFoundation objects whose retain counts are atomic. The generated
    /// bindings do not mark them `Send` because the type is pinned; the tap
    /// port is created to run on one dedicated thread, and the run-loop
    /// reference is only used to stop that thread from another.
    struct SendMachPort(CFRetained<CFMachPort>);
    // SAFETY: CFMachPort retain/release is atomic, and this port is only
    // used as a run-loop source on the thread it is sent to.
    unsafe impl Send for SendMachPort {}

    struct SendRunLoop(CFRetained<CFRunLoop>);
    // SAFETY: CFRunLoop retain/release is atomic; this reference is sent
    // once from the tap thread to the owner so Drop can stop that loop.
    unsafe impl Send for SendRunLoop {}

    fn run_tap_loop(
        port: SendMachPort,
        ready_tx: std::sync::mpsc::Sender<Result<SendRunLoop, SessionEventTapError>>,
    ) {
        let SendMachPort(port) = port;
        let Some(source) = CFMachPort::new_run_loop_source(None, Some(&port), 0) else {
            let _ = ready_tx.send(Err(SessionEventTapError::RunLoopSourceUnavailable));
            return;
        };
        let Some(run_loop) = CFRunLoop::current() else {
            let _ = ready_tx.send(Err(SessionEventTapError::RunLoopUnavailable));
            return;
        };
        // SAFETY: CoreFoundation exports this as a process-lifetime CFString
        // used as a run-loop mode.
        let mode = unsafe { kCFRunLoopCommonModes };
        run_loop.add_source(Some(&source), mode);
        let _ = ready_tx.send(Ok(SendRunLoop(run_loop.clone())));
        CFRunLoop::run();
        run_loop.remove_source(Some(&source), mode);
    }

    /// A listen-only session event tap on its own run-loop thread.
    pub struct SessionEventTap {
        events: Receiver<SessionEvent>,
        port: CFRetained<CFMachPort>,
        run_loop: Option<CFRetained<CFRunLoop>>,
        thread: Option<JoinHandle<()>>,
        user_info: *mut TapCallbackState,
    }

    impl SessionEventTap {
        /// Start a session-scoped listen-only tap.
        ///
        /// `unread_bound` is how many events may sit undrained before the
        /// callback stalls. The tap is `kCGSessionEventTap` at
        /// `kCGHeadInsertEventTap` with listen-only options. A tap macOS
        /// disables is reported by [`Self::is_enabled`]; this does not re-enable
        /// it.
        pub fn listen(unread_bound: usize) -> Result<Self, SessionEventTapError> {
            let (tx, rx) = session_event_channel(unread_bound);
            let state = Box::new(TapCallbackState { tx });
            let user_info = Box::into_raw(state);

            // SAFETY: `tap_callback` only reads integer fields from the event
            // and sends a copy of those numbers. `user_info` points at a Box
            // that is freed after the run-loop thread joins, which is after the
            // tap can no longer invoke the callback.
            let port = unsafe {
                CGEvent::tap_create(
                    CGEventTapLocation::SessionEventTap,
                    CGEventTapPlacement::HeadInsertEventTap,
                    CGEventTapOptions::ListenOnly,
                    CGEventMask::MAX,
                    Some(tap_callback),
                    user_info.cast(),
                )
            };
            let Some(port) = port else {
                // SAFETY: create returned no tap, so the callback was never
                // registered and this is the only remaining owner.
                unsafe {
                    drop(Box::from_raw(user_info));
                }
                return Err(tap_create_failure(input_monitoring_access()));
            };

            let port_for_loop = SendMachPort(port.clone());
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let thread = thread::Builder::new()
                .name("session-event-tap".into())
                .spawn(move || run_tap_loop(port_for_loop, ready_tx))
                .expect("the process can spawn a thread");

            match ready_rx.recv() {
                Ok(Ok(SendRunLoop(run_loop))) => Ok(Self {
                    events: rx,
                    port,
                    run_loop: Some(run_loop),
                    thread: Some(thread),
                    user_info,
                }),
                Ok(Err(error)) => {
                    let _ = thread.join();
                    // SAFETY: the thread has exited, so the callback is no
                    // longer reachable.
                    unsafe {
                        drop(Box::from_raw(user_info));
                    }
                    Err(error)
                }
                Err(_) => {
                    let _ = thread.join();
                    unsafe {
                        drop(Box::from_raw(user_info));
                    }
                    Err(SessionEventTapError::RunLoopUnavailable)
                }
            }
        }

        /// The channel the caller drains.
        pub fn events(&self) -> &Receiver<SessionEvent> {
            &self.events
        }

        /// Whether CoreGraphics currently has this tap enabled.
        ///
        /// macOS disables a tap that is slow to respond
        /// (`kCGEventTapDisabledByTimeout`). This reports that state; it does
        /// not re-enable the tap.
        pub fn is_enabled(&self) -> bool {
            CGEvent::tap_is_enabled(&self.port)
        }
    }

    impl Drop for SessionEventTap {
        fn drop(&mut self) {
            CGEvent::tap_enable(&self.port, false);
            self.port.invalidate();
            if let Some(run_loop) = self.run_loop.take() {
                run_loop.stop();
                run_loop.wake_up();
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            // SAFETY: the run-loop thread has joined, so the callback can no
            // longer observe this pointer.
            unsafe {
                drop(Box::from_raw(self.user_info));
            }
        }
    }

    /// # Safety
    ///
    /// Invoked by CoreGraphics with a live event and the `user_info` pointer
    /// passed to `CGEventTapCreate`. The pointer is a `Box<TapCallbackState>`
    /// that outlives every callback.
    unsafe extern "C-unwind" fn tap_callback(
        _proxy: CGEventTapProxy,
        event_type: CGEventType,
        event: NonNull<CGEvent>,
        user_info: *mut std::ffi::c_void,
    ) -> *mut CGEvent {
        // SAFETY: `user_info` is the Box pointer from `listen`, still alive.
        let state = unsafe { &*(user_info as *const TapCallbackState) };
        // SAFETY: `event` is valid for this callback.
        let source_unix_process_id = CGEvent::integer_value_field(
            Some(unsafe { event.as_ref() }),
            CGEventField::EventSourceUnixProcessID,
        );
        let marker_nonce = CGEvent::integer_value_field(
            Some(unsafe { event.as_ref() }),
            CGEventField::EventSourceUserData,
        ) as u64;
        let timestamp_ns = CGEvent::timestamp(Some(unsafe { event.as_ref() }));
        let _ = state.tx.send(SessionEvent {
            source_unix_process_id,
            event_type: event_type.0,
            marker_nonce,
            timestamp_ns,
        });
        event.as_ptr()
    }
}

#[cfg(target_os = "macos")]
pub use framework::SessionEventTap;

#[cfg(test)]
mod tests {
    use super::{session_event_channel, tap_create_failure, SessionEvent, SessionEventTapError};
    use crate::input::InputMonitoringAccess;
    use std::sync::mpsc::TrySendError;

    #[test]
    fn an_unread_event_channel_stops_accepting_at_its_bound() {
        let event = SessionEvent {
            source_unix_process_id: 0,
            event_type: 5,
            marker_nonce: 0,
            timestamp_ns: 0,
        };
        let (tx, rx) = session_event_channel(2);
        assert!(tx.try_send(event).is_ok());
        assert!(tx.try_send(event).is_ok());
        assert!(
            matches!(tx.try_send(event), Err(TrySendError::Full(_))),
            "a third event was accepted into a channel bound at 2"
        );
        assert_eq!(
            rx.try_recv().expect("the first event is still queued"),
            event
        );
        assert!(tx.try_send(event).is_ok());
    }

    #[test]
    fn a_missing_tap_carries_the_input_monitoring_reading() {
        for access in [
            InputMonitoringAccess::Granted,
            InputMonitoringAccess::Denied,
            InputMonitoringAccess::Undetermined,
            InputMonitoringAccess::Unrecognised(9),
        ] {
            assert_eq!(
                tap_create_failure(access),
                SessionEventTapError::NotCreated {
                    input_monitoring: access
                },
                "the Input Monitoring reading {access:?} was not preserved"
            );
        }
    }

    #[test]
    fn tap_failures_are_distinct() {
        let created = SessionEventTapError::NotCreated {
            input_monitoring: InputMonitoringAccess::Denied,
        };
        assert_ne!(created, SessionEventTapError::RunLoopSourceUnavailable);
        assert_ne!(
            SessionEventTapError::RunLoopSourceUnavailable,
            SessionEventTapError::RunLoopUnavailable
        );
        assert_ne!(
            created,
            SessionEventTapError::NotCreated {
                input_monitoring: InputMonitoringAccess::Granted
            }
        );
    }
}
