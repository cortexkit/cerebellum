use super::*;
use crate::dispatch::{
    BracketPlan, BracketReport, BracketStop, FrontingBracketHost, HardwareInputSnapshot,
    HeartbeatObservation, HeartbeatProbe, RestoreStatus, SeizeWatcher, SourcedInputEvent,
    UnitPosted, UserIdleEstimator,
};
use crate::platform::process_event::{
    HeldStateDisposition, ProcessEventRefusal, SequencePostFailure,
};

#[derive(Default)]
pub(in crate::platform::windows) struct FrontedHookSlot(pub Option<Box<dyn FrontedDispatchHooks>>);

impl Clone for FrontedHookSlot {
    fn clone(&self) -> Self {
        Self(None)
    }
}

impl std::fmt::Debug for FrontedHookSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrontedHookSlot")
            .field(&self.0.is_some())
            .finish()
    }
}

/// A platform observer must be able to prove coverage on the bracket clock.
/// The Windows input implementation will supply an armed observer; a slot
/// with no observer cannot even read the desktop or attempt activation.
trait Observer: Send + Sync {
    fn idle(&self) -> IdleReading;
    fn drain(&self) -> Vec<SourcedInputEvent>;
    fn probe(&self) -> HeartbeatProbe;
    fn echo(&self, probe: HeartbeatProbe, watcher: &mut SeizeWatcher) -> HeartbeatObservation;
    fn snapshot(&self) -> Option<HardwareInputSnapshot>;
}

fn live_observer() -> Option<Arc<dyn Observer>> {
    // No observer or probe writes are available until Windows input delivery
    // supplies both low-level hooks and verifies their echoes.
    None
}

trait Desktop: Send + Sync + 'static {
    type Window: Send + Sync + 'static;
    fn now(&self) -> u64;
    fn pause(&self, ms: u64);
    fn safe(&self) -> bool;
    fn foreground(&self) -> Option<u32>;
    fn bind(&self, number: u32) -> Option<Self::Window>;
    fn number(&self, window: &Self::Window) -> u32;
    fn pid(&self, window: &Self::Window) -> u32;
    fn current(&self, window: &Self::Window) -> bool;
    fn safe_integrity(&self, window: &Self::Window) -> bool;
    fn activate(&self, window: &Self::Window) -> bool;

    fn target_ready(&self, window: &Self::Window) -> bool {
        self.current(window) && self.safe_integrity(window)
    }

    fn is_foreground(&self, window: &Self::Window) -> bool {
        self.foreground() == Some(self.number(window))
            && self.current(window)
            && self.foreground() == Some(self.number(window))
    }
}

struct NativeDesktop {
    // The restore host may outlive the bracket if activation is pending.
    _lane: Option<ForegroundLane>,
    picture: bool,
}

impl Desktop for NativeDesktop {
    type Window = Binding;

    fn now(&self) -> u64 {
        now_ms()
    }
    fn pause(&self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
    fn safe(&self) -> bool {
        desktop_safe()
    }
    fn foreground(&self) -> Option<u32> {
        foreground_window_number()
    }
    fn bind(&self, number: u32) -> Option<Self::Window> {
        Binding::read(number, None)
    }
    fn number(&self, window: &Binding) -> u32 {
        window.number
    }
    fn pid(&self, window: &Binding) -> u32 {
        window.pid()
    }
    fn current(&self, window: &Binding) -> bool {
        window.current()
    }
    fn safe_integrity(&self, window: &Binding) -> bool {
        window.safe_integrity()
    }
    fn activate(&self, window: &Binding) -> bool {
        set_foreground_window(window.number)
    }
    fn target_ready(&self, window: &Binding) -> bool {
        window.current()
            && window.safe_integrity()
            && (!self.picture || super::super::picture::permits_picture_front(window.number))
    }
}

struct WindowsBracketHost<D: Desktop> {
    desk: Arc<D>,
    target: Arc<D::Window>,
    previous: Arc<D::Window>,
    observer: Arc<dyn Observer>,
    bound_ms: u64,
    denied: bool,
}

fn stop(failure: ProcessEventRefusal) -> SequencePostFailure {
    SequencePostFailure {
        refusal: failure,
        posts_returned: 0,
        held_state: HeldStateDisposition::NoneHeld,
    }
}

impl<D: Desktop> WindowsBracketHost<D> {
    fn safe_to_start(&self) -> bool {
        self.desk.safe()
            && self.desk.safe_integrity(&self.previous)
            && self.desk.target_ready(&self.target)
            && self.desk.is_foreground(&self.previous)
    }
}

impl<D: Desktop> FrontingBracketHost for WindowsBracketHost<D> {
    type Tap = Arc<dyn Observer>;

    fn now_ms(&mut self) -> u64 {
        self.desk.now()
    }
    fn pause_ms(&mut self, ms: u64) {
        self.desk.pause(ms);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        if self.desk.is_foreground(&self.target) {
            Some(self.desk.pid(&self.target))
        } else if self.desk.is_foreground(&self.previous) {
            Some(self.desk.pid(&self.previous))
        } else {
            None
        }
    }
    fn request_front(&mut self, pid: u32) -> bool {
        self.request_front_while(pid, &mut || true)
    }
    fn request_front_while(&mut self, pid: u32, permitted: &mut dyn FnMut() -> bool) -> bool {
        self.denied = false;
        if pid != self.desk.pid(&self.target) || !self.safe_to_start() || !permitted() {
            return false;
        }
        let accepted = self.desk.activate(&self.target);
        self.denied = !accepted && self.desk.is_foreground(&self.previous);
        accepted
    }
    fn front_request_definitively_denied(&self) -> bool {
        self.denied
    }
    fn our_pid(&self) -> i64 {
        i64::from(std::process::id())
    }
    fn before_front(&mut self) -> Result<(), SequencePostFailure> {
        self.safe_to_start()
            .then_some(())
            .ok_or_else(|| stop(ProcessEventRefusal::ProcessNotInspectable))
    }
    fn create_tap(&mut self) -> Option<Self::Tap> {
        self.safe_to_start().then(|| Arc::clone(&self.observer))
    }
    fn read_idle(&mut self) -> IdleReading {
        self.observer.idle()
    }
    fn drain(&mut self, tap: &Self::Tap) -> Vec<SourcedInputEvent> {
        tap.drain()
    }
    fn post_heartbeat(&mut self) -> HeartbeatProbe {
        if self.safe_to_start() {
            self.observer.probe()
        } else {
            // A zero source pid can never satisfy the shared echo check.
            HeartbeatProbe {
                marker: crate::dispatch::HeartbeatMarker::new(0),
                posted_at_ms: self.desk.now(),
                our_pid: 0,
            }
        }
    }
    fn observe_heartbeat(
        &mut self,
        tap: &Self::Tap,
        probe: HeartbeatProbe,
        watcher: &mut SeizeWatcher,
    ) -> HeartbeatObservation {
        if probe.our_pid == 0 {
            HeartbeatObservation::Missed
        } else {
            tap.echo(probe, watcher)
        }
    }
    fn post_unit(&mut self, _: usize) -> Result<UnitPosted, SequencePostFailure> {
        // No keyboard or pointer payload is implemented in this driver.
        Err(stop(ProcessEventRefusal::ProcessNotInspectable))
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        self.observer.snapshot()
    }
    fn measured_restore_latency_ms(&mut self) -> Option<u64> {
        // Leave room for the exact-window recheck and the one restore write.
        // This is a reserve for admission, not a native latency measurement.
        Some(self.bound_ms / 4)
    }
    fn record_restore_latency_ms(&mut self, _: u64) {}
}

impl<D: Desktop> RestoreHostSource for WindowsBracketHost<D> {
    fn restore_host(&self) -> Box<dyn FrontingRestoreHost> {
        Box::new(WindowsRestoreHost {
            desk: Arc::clone(&self.desk),
            target: Arc::clone(&self.target),
            previous: Arc::clone(&self.previous),
            observer: Arc::clone(&self.observer),
            remembered: false,
            attempted: false,
        })
    }
}

struct WindowsRestoreHost<D: Desktop> {
    desk: Arc<D>,
    target: Arc<D::Window>,
    previous: Arc<D::Window>,
    observer: Arc<dyn Observer>,
    remembered: bool,
    attempted: bool,
}

impl<D: Desktop> FrontingRestoreHost for WindowsRestoreHost<D> {
    fn now_ms(&mut self) -> u64 {
        self.desk.now()
    }
    fn pause_ms(&mut self, ms: u64) {
        self.desk.pause(ms);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        if self.desk.is_foreground(&self.target) {
            Some(self.desk.pid(&self.target))
        } else if self.desk.is_foreground(&self.previous) {
            Some(self.desk.pid(&self.previous))
        } else {
            // A sibling HWND, even with the same pid, is a third window.
            None
        }
    }
    fn remember_previous(&mut self, pid: u32) -> bool {
        self.remembered |=
            pid == self.desk.pid(&self.previous) && self.desk.is_foreground(&self.previous);
        self.remembered && pid == self.desk.pid(&self.previous)
    }
    fn request_front(&mut self, pid: u32) -> bool {
        struct Permit;
        impl RestoreWriteCheck for Permit {
            fn permit(&mut self) -> bool {
                true
            }
        }
        self.request_front_while(pid, &mut Permit)
    }
    fn request_front_while(&mut self, pid: u32, check: &mut dyn RestoreWriteCheck) -> bool {
        if self.attempted
            || !self.remembered
            || pid != self.desk.pid(&self.previous)
            || !self.desk.safe()
            || !self.desk.safe_integrity(&self.target)
            || !self.desk.current(&self.previous)
            || !self.desk.safe_integrity(&self.previous)
            || !self.desk.is_foreground(&self.target)
            || !check.permit()
        {
            return false;
        }
        self.attempted = true;
        self.desk.activate(&self.previous)
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        self.observer.snapshot()
    }
}

fn refusal(stop: BracketStop) -> BracketReport {
    BracketReport {
        previous_frontmost: None,
        chunks: 0,
        units_posted: 0,
        posts_returned: 0,
        generation_verifications: 0,
        longest_fronted_interval_ms: 0,
        slowest_unit_ms: 0,
        slowest_restore_ms: 0,
        restore: RestoreStatus::NotNeeded,
        stop: Some(stop),
        waiting_out_slow_post: false,
        waiting_out_slow_restore: false,
        restore_calibrated: false,
        restore_started_by_cutoff: false,
    }
}

type WindowRead<'a, W> = &'a mut dyn FnMut(&W);

fn run<D: Desktop>(
    desk: Arc<D>,
    target: impl FnOnce() -> Result<D::Window, DriverError>,
    observer: Option<Arc<dyn Observer>>,
    plan: BracketPlan,
    hooks: &mut dyn FrontedDispatchHooks,
    cancelled: &dyn Fn() -> bool,
    read: Option<WindowRead<'_, D::Window>>,
) -> Result<BracketReport, DriverError> {
    let refused = |hooks: &mut dyn FrontedDispatchHooks, stop| {
        let outcome = crate::dispatch::BracketOutcome {
            report: refusal(stop),
            person_input_during_fronting: false,
            deferred_restore: None,
        };
        hooks.finished(&outcome);
        Ok(outcome.report)
    };
    let Some(observer) = observer else {
        return refused(hooks, BracketStop::ObserverUnavailable);
    };
    if cancelled() {
        return refused(hooks, BracketStop::Cancelled);
    }
    if !desk.safe() {
        return refused(hooks, BracketStop::ObserverUnavailable);
    }
    let Some(previous) = desk.foreground().and_then(|hwnd| desk.bind(hwnd)) else {
        return refused(hooks, BracketStop::PreviousUnknown);
    };
    if !desk.safe_integrity(&previous) {
        return refused(hooks, BracketStop::ObserverUnavailable);
    }
    let target = Arc::new(target()?);
    if desk.pid(&previous) == plan.target_pid && desk.number(&previous) != desk.number(&target) {
        // The shared runner would interpret the sibling's pid as proof the
        // exact addressed window is already frontmost.
        return refused(hooks, BracketStop::PreviousUnknown);
    }
    let mut host = WindowsBracketHost {
        desk: Arc::clone(&desk),
        target: Arc::clone(&target),
        previous: Arc::new(previous),
        observer,
        bound_ms: plan.maximum_interval_ms,
        denied: false,
    };
    let mut read = read.map(|read| {
        let desk = &desk;
        let target = &target;
        move || {
            if !cancelled() && desk.safe() && desk.is_foreground(target) {
                read(target);
            }
        }
    });
    let outcome = run_hooked_fronted(
        &mut host,
        &mut UserIdleEstimator::new(),
        plan,
        cancelled,
        hooks,
        read.as_mut().map(|read| read as &mut dyn FnMut()),
    );
    Ok(outcome.report)
}

pub(in crate::platform::windows) fn run_native(
    target: &ProcessGrant,
    bound: u64,
    seize_latency: u32,
    hooks: &mut dyn FrontedDispatchHooks,
    cancelled: &dyn Fn() -> bool,
    read: Option<&mut dyn FnMut()>,
) -> Result<BracketReport, DriverError> {
    let observer = live_observer();
    // No production action currently has a source of Windows keyboard pieces.
    // Keep dispatch refused even if the observer is installed independently.
    let observer = observer.filter(|_| read.is_some());
    let lane = observer.as_ref().and_then(|_| take_foreground_lane());
    let observer = observer.filter(|_| lane.is_some());
    let picture = read.is_some();
    let select = || {
        let retained = target_process(target)?;
        let deadline = Instant::now() + Duration::from_millis(bound);
        let candidates = windows::windows(&retained, target.pid, deadline)
            .map_err(|_| DriverError::Unsupported("Windows target windows unreadable"))?;
        let selected = if picture {
            windows::image_window(&candidates)
        } else {
            windows::active_window(&candidates).map(|window| window.map(|(window, _)| window))
        };
        let window = selected
            .ok()
            .flatten()
            .ok_or(DriverError::Unsupported("Windows target window unreadable"))?;
        let binding = Binding::read(window.root.number, Some(retained))
            .filter(|binding| binding.proof == window.proof)
            .ok_or(DriverError::Unsupported("Windows target window changed"))?;
        Ok(binding)
    };
    let mut read = read.map(|read| {
        move |binding: &Binding| super::super::picture::with_fronted_window(binding, read)
    });
    run(
        Arc::new(NativeDesktop {
            _lane: lane,
            picture,
        }),
        select,
        observer,
        BracketPlan {
            target_pid: target.pid,
            units: 1,
            maximum_interval_ms: bound,
            maximum_seize_detection_latency_ms: seize_latency,
        },
        hooks,
        cancelled,
        read.as_mut().map(|read| read as &mut dyn FnMut(&Binding)),
    )
}

#[cfg(test)]
mod tests;
