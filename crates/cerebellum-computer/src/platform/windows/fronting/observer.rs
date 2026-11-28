//! Sequence-local observation of global Windows input.

use super::super::*;
use super::{now_ms, Observer};
use crate::dispatch::{
    HardwareInputSnapshot, HeartbeatMarker, HeartbeatObservation, HeartbeatProbe, SeizeWatcher,
    SourcedInputEvent,
};
use cerebellum_windows::{
    async_key_down, foreground_window_number, input_tick, last_input_tick, post_input, InputHooks,
    RawInputEvent, RawInputPost,
};
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering::*};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub(super) const PUMP_START: Duration = Duration::from_millis(150);
const ECHO_MS: u64 = 30;
const CALLBACK_BUDGET: Duration = Duration::from_millis(2);
const UNASSIGNED: u16 = 0xE8;
const WM_MOUSEMOVE: u32 = 0x0200;
const NEVER: u64 = u64::MAX;

pub(super) const MARKER: RawInputPost = RawInputPost::VirtualKey {
    key: UNASSIGNED,
    up: true,
    extended: false,
};

pub(in crate::platform::windows) fn trial_install() -> bool {
    InputHooks::start(None, PUMP_START, |_| false).is_ok()
}

struct Record {
    tag: usize,
    armed: AtomicBool,
    coverage_start: u64,
    person: AtomicU64,
    first_person: OnceLock<(u32, u32)>,
    payload: AtomicUsize,
    marker: AtomicUsize,
    mouse: AtomicUsize,
    watching_route: AtomicBool,
    route_start: AtomicU32,
    route_changed: AtomicBool,
    route_hwnd: AtomicU32,
    automation_held: AtomicUsize,
    callback_slow: AtomicBool,
}

impl Record {
    fn new() -> Self {
        static NONCE_COUNTER: AtomicUsize = AtomicUsize::new(0);
        let tag = RandomState::new().hash_one(NONCE_COUNTER.fetch_add(1, Relaxed)) as usize | 1;
        Self {
            tag,
            armed: AtomicBool::new(false),
            coverage_start: now_ms(),
            person: AtomicU64::new(NEVER),
            first_person: OnceLock::new(),
            payload: AtomicUsize::new(0),
            marker: AtomicUsize::new(0),
            mouse: AtomicUsize::new(0),
            watching_route: AtomicBool::new(false),
            route_start: AtomicU32::new(0),
            route_changed: AtomicBool::new(false),
            route_hwnd: AtomicU32::new(0),
            automation_held: AtomicUsize::new(0),
            callback_slow: AtomicBool::new(false),
        }
    }

    fn observe(&self, event: RawInputEvent, held: &std::cell::RefCell<Vec<u32>>) -> bool {
        if !self.armed.load(Acquire) {
            return false;
        }
        match event {
            RawInputEvent::Keyboard {
                tag,
                key,
                up,
                injected,
                ..
            } if tag == self.tag && injected => {
                if up && key == u32::from(UNASSIGNED) {
                    self.marker.fetch_add(1, Release);
                    true
                } else {
                    let hwnd = self.route_hwnd.load(Acquire);
                    let same_window = hwnd != 0 && foreground_window_number() == Some(hwnd);
                    if !same_window {
                        self.route_changed.store(true, Release);
                    }
                    let mut held = held.borrow_mut();
                    let pass = if !same_window {
                        false
                    } else if up {
                        held.iter().rposition(|vk| *vk == key).is_some_and(|index| {
                            held.remove(index);
                            true
                        })
                    } else if self.person.load(Acquire) != NEVER || self.route_changed.load(Acquire)
                    {
                        false
                    } else {
                        held.push(key);
                        true
                    };
                    self.automation_held.store(held.len(), Release);
                    self.payload.fetch_add(1, Release);
                    !pass
                }
            }
            RawInputEvent::Mouse {
                tag,
                message,
                injected,
                ..
            } if tag == self.tag && injected => {
                if message == WM_MOUSEMOVE {
                    self.mouse.fetch_add(1, Release);
                    true
                } else {
                    self.payload.fetch_add(1, Release);
                    false
                }
            }
            RawInputEvent::Foreground { event_tick } | RawInputEvent::Focus { event_tick } => {
                if self.watching_route.load(Acquire)
                    && event_tick.wrapping_sub(self.route_start.load(Relaxed)) < (1 << 31)
                {
                    self.route_changed.store(true, Release);
                }
                false
            }
            RawInputEvent::Keyboard { event_tick, .. }
            | RawInputEvent::Mouse { event_tick, .. } => {
                let _ = self
                    .first_person
                    .set((event_tick, input_tick().wrapping_sub(event_tick)));
                self.person.store(now_ms(), Release);
                true
            }
        }
    }
}

pub(super) struct NativeObserver {
    record: Arc<Record>,
    _hooks: InputHooks,
    idle: IdleReading,
    held_at_start: bool,
    echo_at: OnceLock<Option<u64>>,
    lost: AtomicBool,
    drained: AtomicBool,
}

impl NativeObserver {
    pub(super) fn start(pid: u32, floor: impl FnOnce() -> bool) -> Option<Arc<Self>> {
        let record = Arc::new(Record::new());
        let observer = Arc::clone(&record);
        let held = std::cell::RefCell::new(Vec::with_capacity(4));
        let hooks = InputHooks::start(Some(pid), PUMP_START, move |event| {
            let started = Instant::now();
            let swallow = observer.observe(event, &held);
            if started.elapsed() > CALLBACK_BUDGET {
                observer.callback_slow.store(true, Release);
            }
            swallow
        })
        .ok()?;
        if !floor() {
            return None;
        }
        record.armed.store(true, Release);
        let idle = last_input_tick()
            .map(|last| IdleReading::Milliseconds(u64::from(input_tick().wrapping_sub(last))))
            .unwrap_or(IdleReading::Unreadable(IdleUnreadable::TableUnavailable));
        // Mouse buttons use virtual keys 1–6. Reserved keys read as up.
        let held_at_start = (1..=254).any(async_key_down);
        Some(Arc::new(Self {
            record,
            _hooks: hooks,
            idle,
            held_at_start,
            echo_at: OnceLock::new(),
            lost: AtomicBool::new(false),
            drained: AtomicBool::new(false),
        }))
    }

    pub(super) fn person(&self) -> bool {
        self.record.person.load(Acquire) != NEVER
    }

    pub(super) fn held(&self) -> bool {
        self.held_at_start
    }

    pub(super) fn lost(&self) -> bool {
        self.lost.load(Acquire) || self.record.callback_slow.load(Acquire)
    }

    pub(super) fn track_route(&self, hwnd: u32) {
        self.record.watching_route.store(false, Release);
        self.record.route_changed.store(false, Relaxed);
        self.record.route_start.store(input_tick(), Relaxed);
        self.record.route_hwnd.store(hwnd, Release);
        self.record.watching_route.store(true, Release);
    }

    pub(super) fn route_changed(&self) -> bool {
        self.record.route_changed.load(Acquire)
    }

    pub(super) fn automation_held(&self) -> bool {
        self.record.automation_held.load(Acquire) != 0
    }

    pub(super) fn stop_tracking_route(&self) {
        self.record.watching_route.store(false, Release);
        self.record.route_hwnd.store(0, Release);
    }

    pub(super) fn post(&self, events: &[RawInputPost]) -> usize {
        post_input(self.record.tag, events)
    }

    pub(super) fn counts(&self) -> (usize, usize) {
        (
            self.record.marker.load(Acquire),
            self.record.payload.load(Acquire),
        )
    }

    pub(super) fn fence(&self, before: (usize, usize), posted: usize, until_ms: u64) -> bool {
        // The callback for the tagged marker follows routing of the preceding
        // events. Counting payload callbacks alone cannot show that.
        let observed = wait_until(until_ms.min(now_ms().saturating_add(ECHO_MS)), || {
            let (marker, payload) = self.counts();
            marker == before.0 + 1 && payload == before.1 + posted
        });
        if !observed || self.lost() {
            self.lost.store(true, Release);
            return false;
        }
        true
    }
}

fn wait_until(until_ms: u64, read: impl Fn() -> bool) -> bool {
    loop {
        if now_ms() > until_ms {
            return false;
        }
        if read() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

impl Drop for NativeObserver {
    fn drop(&mut self) {
        self.record.armed.store(false, Release);
    }
}

impl Observer for NativeObserver {
    fn may_front(&self) -> bool {
        !self.person() && !self.lost() && !self.held()
    }

    fn idle(&self) -> IdleReading {
        self.idle
    }

    fn drain(&self) -> Vec<SourcedInputEvent> {
        if let Some(&(tick, platform)) = self
            .record
            .first_person
            .get()
            .filter(|_| !self.drained.swap(true, AcqRel))
        {
            vec![SourcedInputEvent {
                source_unix_process_id: 0,
                detection_latency_ms: input_tick().wrapping_sub(tick),
                platform_delivery_latency_ms: Some(platform),
            }]
        } else {
            Vec::new()
        }
    }

    fn probe(&self) -> HeartbeatProbe {
        let stamp = now_ms();
        let marker = HeartbeatMarker::new(self.record.tag as u64);
        let our_pid = i64::from(std::process::id());
        if self.person() {
            return HeartbeatProbe {
                marker,
                posted_at_ms: stamp,
                our_pid,
            };
        }
        let echo = self.echo_at.get_or_init(|| {
            if self.held()
                || self.post(&[RawInputPost::RelativeMouseMove { x: 0, y: 0 }, MARKER]) != 2
            {
                return None;
            }
            wait_until(stamp.saturating_add(ECHO_MS), || {
                self.record.mouse.load(Acquire) == 1 && self.record.marker.load(Acquire) == 1
            })
            .then(now_ms)
        });
        if echo.is_none() {
            self.lost.store(true, Release);
        }
        HeartbeatProbe {
            marker,
            posted_at_ms: echo.unwrap_or(stamp),
            our_pid,
        }
    }

    fn echo(&self, probe: HeartbeatProbe, watcher: &mut SeizeWatcher) -> HeartbeatObservation {
        crate::dispatch::observe_drained_events(watcher, self.drain(), probe.our_pid, 0);
        if self.lost() || !matches!(self.echo_at.get(), Some(Some(_))) {
            HeartbeatObservation::Missed
        } else {
            HeartbeatObservation::Seen {
                marker: probe.marker,
                source_unix_process_id: probe.our_pid,
                observed_at_ms: probe.posted_at_ms,
            }
        }
    }

    fn snapshot(&self) -> Option<HardwareInputSnapshot> {
        (!self.lost()).then(|| {
            let last = self.record.person.load(Acquire);
            HardwareInputSnapshot {
                coverage_start_ms: self.record.coverage_start,
                last_input_ms: (last != NEVER).then_some(last),
            }
        })
    }
}
