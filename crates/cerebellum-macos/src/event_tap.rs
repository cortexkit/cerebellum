//! A listen-only session event tap and the numbers it reports.

use std::fmt;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

use crate::input::InputMonitoringAccess;

/// A deliberate act by a person at the hardware: a key press (10), a left,
/// right or other mouse-button press (1, 3, 25), or an active scroll (22).
/// Pointer motion is excluded because it isn't an act on an app. A nonzero
/// source PID means another process synthesised the event. The private source
/// state (`kCGEventSourceStatePrivate`, -1) is excluded because synthetic
/// events posted from a private source can still carry a zero source PID.
fn is_hardware_deliberate(
    pid: i64,
    source_state: i64,
    event_type: u32,
    scroll: Option<(i64, [i64; 3], [i64; 3])>,
) -> bool {
    if pid != 0 || source_state == -1 {
        return false;
    }
    match event_type {
        1 | 3 | 10 | 25 => true,
        22 => match scroll {
            // Momentum continues a completed gesture; zero deltas describe a
            // phase transition or contact, not movement by the person's fingers.
            Some((momentum_phase, line_deltas, point_deltas)) => {
                momentum_phase == 0
                    && line_deltas
                        .into_iter()
                        .chain(point_deltas)
                        .any(|delta| delta != 0)
            }
            None => false,
        },
        _ => false,
    }
}

/// The entire recorded payload of the process-lifetime hardware observer.
/// Scroll phase and deltas are read only to classify a scroll; they are not
/// retained. This payload has no key code, character, flags, coordinates or PID.
#[derive(Debug, Clone, Copy)]
struct HardwareObservation {
    event_type: u32,
    at: std::time::Instant,
}

impl HardwareObservation {
    fn new(event_type: u32, at: std::time::Instant) -> Self {
        Self { event_type, at }
    }
}

#[derive(Default)]
struct HardwareHistory {
    since: Option<std::time::Instant>,
    latest: [Option<std::time::Instant>; 5],
}

impl HardwareHistory {
    fn record(
        &mut self,
        pid: i64,
        source_state: i64,
        observation: HardwareObservation,
        scroll: Option<(i64, [i64; 3], [i64; 3])>,
    ) {
        if self.since.is_none()
            || !is_hardware_deliberate(pid, source_state, observation.event_type, scroll)
        {
            return;
        }
        let slot = match observation.event_type {
            1 => 0,
            3 => 1,
            25 => 2,
            10 => 3,
            22 => 4,
            _ => return,
        };
        self.latest[slot] = self.latest[slot].max(Some(observation.at));
    }

    fn invalidate(&mut self) {
        self.since = None;
        self.latest = [None; 5];
    }
}

const OBSERVER_NOT_STARTED: u8 = 0;
const OBSERVER_RUNNING: u8 = 1;
const OBSERVER_NO_PERMISSION: u8 = 2;
const OBSERVER_UNAVAILABLE: u8 = 3;

struct ObserverHealth {
    state: std::sync::atomic::AtomicU8,
    disabled_reenabled_count: std::sync::atomic::AtomicU64,
}

impl ObserverHealth {
    const fn new() -> Self {
        Self {
            state: std::sync::atomic::AtomicU8::new(OBSERVER_NOT_STARTED),
            disabled_reenabled_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn set_state(&self, state: u8) {
        self.state
            .store(state, std::sync::atomic::Ordering::Relaxed);
    }

    fn snapshot(&self) -> (&'static str, u64) {
        let state = match self.state.load(std::sync::atomic::Ordering::Relaxed) {
            OBSERVER_NOT_STARTED => "not_started",
            OBSERVER_RUNNING => "running",
            OBSERVER_NO_PERMISSION => "unavailable_no_permission",
            _ => "unavailable",
        };
        (
            state,
            self.disabled_reenabled_count
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

fn note_hardware_disable(
    event_type: u32,
    history: &std::sync::Mutex<HardwareHistory>,
    health: &ObserverHealth,
) -> bool {
    if !matches!(event_type, u32::MAX | 0xFFFF_FFFE) {
        return false;
    }
    history
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .invalidate();
    health.set_state(OBSERVER_UNAVAILABLE);
    true
}

trait HardwareTapControl {
    fn is_enabled(&self) -> bool;
    fn enable(&self);
}

/// Re-enable a tap macOS disabled, and restart coverage from now: input that
/// arrived while the tap was off was never seen, so an action whose last read
/// predates the gap must read again rather than be treated as observed.
/// The liveness worker and the injected-disable tests share this function.
fn recover_hardware_observer(
    tap: &impl HardwareTapControl,
    history: &std::sync::Mutex<HardwareHistory>,
    health: &ObserverHealth,
    now: impl FnOnce() -> std::time::Instant,
) {
    {
        let mut state = history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if tap.is_enabled() && state.since.is_some() {
            return;
        }
        state.invalidate();
        health.set_state(OBSERVER_UNAVAILABLE);
    }
    tap.enable();
    let mut state = history
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if tap.is_enabled() {
        state.since = Some(now());
        health
            .disabled_reenabled_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        health.set_state(OBSERVER_RUNNING);
    }
}

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
    /// [`uptime_now_ns`] read inside the tap callback, the moment the platform
    /// handed the event to this process. `timestamp_ns` to here is the
    /// platform's delivery; here to the consumer's drain is the consumer's.
    pub observed_at_ns: u64,
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

    use super::{
        note_hardware_disable, recover_hardware_observer, session_event_channel,
        tap_create_failure, HardwareHistory, HardwareObservation, HardwareTapControl,
        ObserverHealth, SessionEvent, SessionEventTapError, OBSERVER_NO_PERMISSION,
        OBSERVER_RUNNING, OBSERVER_UNAVAILABLE,
    };
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    static HARDWARE: Mutex<HardwareHistory> = Mutex::new(HardwareHistory {
        since: None,
        latest: [None; 5],
    });
    static HARDWARE_STARTED: OnceLock<()> = OnceLock::new();
    static HARDWARE_HEALTH: ObserverHealth = ObserverHealth::new();
    use crate::input::input_monitoring_access;

    struct TapCallbackState {
        tx: SyncSender<SessionEvent>,
        hardware_only: bool,
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
        port: Option<CFRetained<CFMachPort>>,
        run_loop: Option<CFRetained<CFRunLoop>>,
        thread: Option<JoinHandle<()>>,
        user_info: *mut TapCallbackState,
    }

    impl SessionEventTap {
        /// Channel-only test seam: no OS tap, thread, permission query or posts.
        #[cfg(any(test, feature = "test-support"))]
        pub fn from_test_channel(events: Receiver<SessionEvent>) -> Self {
            Self {
                events,
                port: None,
                run_loop: None,
                thread: None,
                user_info: std::ptr::null_mut(),
            }
        }
        /// Start one process-lifetime observer lazily at the first state read.
        /// No permission request is made. Missing access or a disabled tap is
        /// unavailable, never evidence that a person acted. Coverage begins
        /// after the run loop is ready; callers compare it to their read mark.
        /// Its callback records only one timestamp per deliberate event kind.
        /// A worker checks enabled status every 10 ms and re-enables disabled
        /// taps with a new coverage boundary. No event content or PID is kept.
        pub fn hardware_input_snapshot() -> Option<(Instant, Option<Instant>)> {
            HARDWARE_STARTED.get_or_init(|| {
                if input_monitoring_access() != crate::input::InputMonitoringAccess::Granted {
                    HARDWARE_HEALTH.set_state(OBSERVER_NO_PERMISSION);
                    return;
                }
                HARDWARE_HEALTH.set_state(OBSERVER_UNAVAILABLE);
                let (ready_tx, ready_rx) = std::sync::mpsc::channel();
                let spawned = thread::Builder::new()
                    .name("hardware-input-observer".into())
                    .spawn(move || {
                        let Ok(tap) = Self::listen_impl(1, true) else {
                            let _ = ready_tx.send(());
                            return;
                        };
                        {
                            let mut state = HARDWARE
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            state.since = tap.is_enabled().then(Instant::now);
                            if state.since.is_some() {
                                HARDWARE_HEALTH.set_state(OBSERVER_RUNNING);
                            }
                        }
                        let _ = ready_tx.send(());
                        loop {
                            recover_hardware_observer(
                                &tap,
                                &HARDWARE,
                                &HARDWARE_HEALTH,
                                Instant::now,
                            );
                            match tap.events().recv_timeout(Duration::from_millis(10)) {
                                Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                    HARDWARE
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .invalidate();
                                    HARDWARE_HEALTH.set_state(OBSERVER_UNAVAILABLE);
                                    break;
                                }
                            }
                        }
                    });
                if spawned.is_ok() {
                    let _ = ready_rx.recv();
                }
            });
            let state = HARDWARE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Some((state.since?, state.latest.iter().flatten().copied().max()))
        }

        /// Read-only health facts; this neither starts the observer nor asks
        /// for permission, and uses atomics to keep the health lane insulated.
        pub fn hardware_observer_health() -> (&'static str, u64) {
            HARDWARE_HEALTH.snapshot()
        }

        /// Start a session-scoped listen-only tap.
        ///
        /// `unread_bound` is how many events may sit undrained before the
        /// callback stalls. The tap is `kCGSessionEventTap` at
        /// `kCGHeadInsertEventTap` with listen-only options. A tap macOS
        /// disables is reported by [`Self::is_enabled`]; this does not re-enable
        /// it.
        pub fn listen(unread_bound: usize) -> Result<Self, SessionEventTapError> {
            Self::listen_impl(unread_bound, false)
        }

        fn listen_impl(
            unread_bound: usize,
            hardware_only: bool,
        ) -> Result<Self, SessionEventTapError> {
            let (tx, rx) = session_event_channel(unread_bound);
            let state = Box::new(TapCallbackState { tx, hardware_only });
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
                    port: Some(port),
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
            self.port
                .as_ref()
                .map_or(cfg!(any(test, feature = "test-support")), |port| {
                    CGEvent::tap_is_enabled(port)
                })
        }
    }

    impl HardwareTapControl for SessionEventTap {
        fn is_enabled(&self) -> bool {
            SessionEventTap::is_enabled(self)
        }

        fn enable(&self) {
            if let Some(port) = &self.port {
                CGEvent::tap_enable(port, true);
            }
        }
    }

    impl Drop for SessionEventTap {
        fn drop(&mut self) {
            if let Some(port) = &self.port {
                CGEvent::tap_enable(port, false);
                port.invalidate();
            }
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
                if !self.user_info.is_null() {
                    drop(Box::from_raw(self.user_info));
                }
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
        if state.hardware_only {
            let source_state = CGEvent::integer_value_field(
                Some(unsafe { event.as_ref() }),
                CGEventField::EventSourceStateID,
            );
            if note_hardware_disable(event_type.0, &HARDWARE, &HARDWARE_HEALTH) {
                return event.as_ptr();
            }
            let scroll = if event_type.0 == 22 {
                let cg_event = Some(unsafe { event.as_ref() });
                Some((
                    CGEvent::integer_value_field(
                        cg_event,
                        CGEventField::ScrollWheelEventMomentumPhase,
                    ),
                    [
                        CGEvent::integer_value_field(
                            cg_event,
                            CGEventField::ScrollWheelEventDeltaAxis1,
                        ),
                        CGEvent::integer_value_field(
                            cg_event,
                            CGEventField::ScrollWheelEventDeltaAxis2,
                        ),
                        CGEvent::integer_value_field(
                            cg_event,
                            CGEventField::ScrollWheelEventDeltaAxis3,
                        ),
                    ],
                    [
                        CGEvent::integer_value_field(
                            cg_event,
                            CGEventField::ScrollWheelEventPointDeltaAxis1,
                        ),
                        CGEvent::integer_value_field(
                            cg_event,
                            CGEventField::ScrollWheelEventPointDeltaAxis2,
                        ),
                        CGEvent::integer_value_field(
                            cg_event,
                            CGEventField::ScrollWheelEventPointDeltaAxis3,
                        ),
                    ],
                ))
            } else {
                None
            };
            if super::is_hardware_deliberate(
                source_unix_process_id,
                source_state,
                event_type.0,
                scroll,
            ) {
                let timestamp_ns = CGEvent::timestamp(Some(unsafe { event.as_ref() }));
                let observed_at_ns = super::uptime_now_ns();
                let at = Instant::now().checked_sub(Duration::from_nanos(
                    observed_at_ns.saturating_sub(timestamp_ns),
                ));
                if let Some(at) = at {
                    let observation = HardwareObservation::new(event_type.0, at);
                    HARDWARE
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .record(source_unix_process_id, source_state, observation, scroll);
                } else {
                    HARDWARE
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .invalidate();
                    HARDWARE_HEALTH.set_state(OBSERVER_UNAVAILABLE);
                }
            }
            return event.as_ptr();
        }
        let marker_nonce = CGEvent::integer_value_field(
            Some(unsafe { event.as_ref() }),
            CGEventField::EventSourceUserData,
        ) as u64;
        let timestamp_ns = CGEvent::timestamp(Some(unsafe { event.as_ref() }));
        let observed_at_ns = super::uptime_now_ns();
        let _ = state.tx.send(SessionEvent {
            source_unix_process_id,
            event_type: event_type.0,
            marker_nonce,
            timestamp_ns,
            observed_at_ns,
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
            observed_at_ns: 0,
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

#[cfg(test)]
mod hardware_tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    #[test]
    fn hardware_history_excludes_synthetic_private_and_motion_and_records_each_kind() {
        let at = Instant::now();
        let mut history = HardwareHistory {
            since: Some(at),
            ..HardwareHistory::default()
        };
        for (pid, state, kind) in [(42, 1, 10), (0, -1, 10), (0, 1, 5)] {
            history.record(pid, state, HardwareObservation::new(kind, at), None);
        }
        assert_eq!(history.latest, [None; 5]);
        for (slot, kind) in [1, 3, 25, 10, 22].into_iter().enumerate() {
            history.latest = [None; 5];
            let scroll = (kind == 22).then_some((0, [1, 0, 0], [0; 3]));
            history.record(0, 1, HardwareObservation::new(kind, at), scroll);
            let mut expected = [None; 5];
            expected[slot] = Some(at);
            assert_eq!(history.latest, expected);
        }
        history.invalidate();
        history.record(0, 1, HardwareObservation::new(10, at), None);
        assert_eq!(history.latest, [None; 5]);
    }

    #[test]
    fn momentum_phase_scroll_is_not_deliberate() {
        assert!(!is_hardware_deliberate(
            0,
            1,
            22,
            Some((1, [1, 0, 0], [0; 3]))
        ));
    }

    #[test]
    fn zero_delta_scroll_phase_is_not_deliberate() {
        assert!(!is_hardware_deliberate(0, 1, 22, Some((0, [0; 3], [0; 3]))));
    }

    #[test]
    fn real_finger_scroll_with_line_delta_counts() {
        assert!(is_hardware_deliberate(
            0,
            1,
            22,
            Some((0, [0, -1, 0], [0; 3]))
        ));
    }

    #[test]
    fn real_finger_scroll_with_point_delta_only_counts() {
        assert!(is_hardware_deliberate(
            0,
            1,
            22,
            Some((0, [0; 3], [1, 0, 0]))
        ));
    }

    #[test]
    fn discrete_wheel_click_counts() {
        assert!(is_hardware_deliberate(
            0,
            1,
            22,
            Some((0, [1, 0, 0], [0; 3]))
        ));
    }

    #[test]
    fn key_and_button_classification_is_unchanged() {
        for kind in [1, 3, 10, 25] {
            assert!(is_hardware_deliberate(0, 1, kind, None));
        }
        assert!(!is_hardware_deliberate(42, 1, 10, None));
        assert!(!is_hardware_deliberate(0, -1, 10, None));
        assert!(!is_hardware_deliberate(0, 1, 5, None));
    }

    #[test]
    fn hardware_observation_shape_retains_only_kind_and_timestamp() {
        // Pin the recorded payload, not its byte size: adding a content field
        // must fail even if padding would leave the allocation size unchanged.
        let source = include_str!("event_tap.rs");
        let body = source
            .split("struct HardwareObservation {")
            .nth(1)
            .unwrap()
            .split_once('\n')
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        let fields: Vec<_> = body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(fields, ["event_type: u32,", "at: std::time::Instant,"]);
    }

    struct InjectedTap {
        enabled: Cell<bool>,
        enable_calls: Cell<usize>,
        can_enable: bool,
    }

    impl HardwareTapControl for InjectedTap {
        fn is_enabled(&self) -> bool {
            self.enabled.get()
        }
        fn enable(&self) {
            self.enable_calls.set(self.enable_calls.get() + 1);
            self.enabled.set(self.can_enable);
        }
    }

    #[test]
    fn disabled_hardware_observer_reenables_and_restarts_coverage() {
        for disabled_kind in [u32::MAX, u32::MAX - 1] {
            let before = Instant::now();
            let after = before + Duration::from_secs(1);
            let history = Mutex::new(HardwareHistory {
                since: Some(before),
                latest: [Some(before); 5],
            });
            let health = ObserverHealth::new();
            health.set_state(OBSERVER_RUNNING);
            let tap = InjectedTap {
                enabled: Cell::new(false),
                enable_calls: Cell::new(0),
                can_enable: true,
            };
            assert!(note_hardware_disable(disabled_kind, &history, &health));
            assert!(history.lock().unwrap().since.is_none());
            assert_eq!(health.snapshot(), ("unavailable", 0));
            recover_hardware_observer(&tap, &history, &health, || after);
            assert_eq!(tap.enable_calls.get(), 1);
            assert!(tap.enabled.get());
            assert_eq!(history.lock().unwrap().since, Some(after));
            assert_eq!(history.lock().unwrap().latest, [None; 5]);
            assert_eq!(health.snapshot(), ("running", 1));
            // Normal polling must not keep moving the coverage boundary.
            recover_hardware_observer(&tap, &history, &health, Instant::now);
            assert_eq!(tap.enable_calls.get(), 1);
            assert_eq!(history.lock().unwrap().since, Some(after));
            history
                .lock()
                .unwrap()
                .record(0, 1, HardwareObservation::new(10, after), None);
            assert_eq!(history.lock().unwrap().latest[3], Some(after));
        }
    }

    #[test]
    fn failed_hardware_reenable_stays_unavailable_and_does_not_count_success() {
        let history = Mutex::new(HardwareHistory::default());
        let health = ObserverHealth::new();
        let tap = InjectedTap {
            enabled: Cell::new(false),
            enable_calls: Cell::new(0),
            can_enable: false,
        };
        recover_hardware_observer(&tap, &history, &health, Instant::now);
        assert_eq!(tap.enable_calls.get(), 1);
        assert!(history.lock().unwrap().since.is_none());
        assert_eq!(health.snapshot(), ("unavailable", 0));
    }

    #[test]
    fn hardware_observer_health_distinguishes_not_started_permission_and_running() {
        let health = ObserverHealth::new();
        assert_eq!(health.snapshot(), ("not_started", 0));
        health.set_state(OBSERVER_NO_PERMISSION);
        assert_eq!(health.snapshot(), ("unavailable_no_permission", 0));
        health.set_state(OBSERVER_RUNNING);
        assert_eq!(health.snapshot(), ("running", 0));
    }
}
