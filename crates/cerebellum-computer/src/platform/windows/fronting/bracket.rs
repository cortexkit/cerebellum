use super::*;
use crate::dispatch::{
    BracketPlan, BracketReport, BracketStop, FrontingBracketHost, HardwareInputSnapshot,
    HeartbeatObservation, HeartbeatProbe, ObservedUnit, RestoreStatus, SeizeWatcher,
    SourcedInputEvent, UnitPosted, UserIdleEstimator,
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

pub(super) trait Observer: Send + Sync {
    fn idle(&self) -> IdleReading;
    fn drain(&self) -> Vec<SourcedInputEvent>;
    fn probe(&self) -> HeartbeatProbe;
    fn echo(&self, probe: HeartbeatProbe, watcher: &mut SeizeWatcher) -> HeartbeatObservation;
    fn snapshot(&self) -> Option<HardwareInputSnapshot>;
    fn may_front(&self) -> bool {
        true
    }
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
    previous: Binding,
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
        (number == self.previous.number && self.previous.is_foreground())
            .then(|| self.previous.clone())
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

type Unit<'a, W> = &'a mut dyn FnMut(
    &W,
    ObservedUnit<'_, Arc<dyn Observer>>,
) -> Result<UnitPosted, SequencePostFailure>;

struct WindowsBracketHost<'a, D: Desktop> {
    desk: Arc<D>,
    target: Arc<D::Window>,
    previous: Arc<D::Window>,
    observer: Arc<dyn Observer>,
    bound_ms: u64,
    denied: bool,
    unit: Option<Unit<'a, D::Window>>,
}

fn stop(failure: ProcessEventRefusal) -> SequencePostFailure {
    SequencePostFailure {
        refusal: failure,
        posts_returned: 0,
        held_state: HeldStateDisposition::NoneHeld,
    }
}

impl<D: Desktop> WindowsBracketHost<'_, D> {
    fn safe_to_start(&self) -> bool {
        self.desk.safe()
            && self.desk.safe_integrity(&self.previous)
            && self.desk.target_ready(&self.target)
            && self.desk.is_foreground(&self.previous)
    }
}

impl<D: Desktop> FrontingBracketHost for WindowsBracketHost<'_, D> {
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
        if pid != self.desk.pid(&self.target)
            || !self.safe_to_start()
            || !permitted()
            || !self.observer.may_front()
        {
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
        Err(stop(ProcessEventRefusal::ProcessNotInspectable))
    }
    fn post_observed_unit(
        &mut self,
        index: usize,
        observation: ObservedUnit<'_, Self::Tap>,
    ) -> Result<UnitPosted, SequencePostFailure> {
        match self.unit.as_mut() {
            Some(unit) => unit(&self.target, observation),
            None => self.post_unit(index),
        }
    }
    fn unit_checks_cutoff(&self) -> bool {
        self.unit.is_some()
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

impl<D: Desktop> RestoreHostSource for WindowsBracketHost<'_, D> {
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

enum Work<'a, W> {
    Read(WindowRead<'a, W>),
    Dispatch(Unit<'a, W>),
}

fn run<D: Desktop>(
    desk: Arc<D>,
    target: impl FnOnce() -> Result<D::Window, DriverError>,
    observer: Option<Arc<dyn Observer>>,
    plan: BracketPlan,
    hooks: &mut dyn FrontedDispatchHooks,
    cancelled: &dyn Fn() -> bool,
    work: Work<'_, D::Window>,
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
    let (read, unit) = match work {
        Work::Read(read) => (Some(read), None),
        Work::Dispatch(unit) => (None, Some(unit)),
    };
    let mut host = WindowsBracketHost {
        desk: Arc::clone(&desk),
        target: Arc::clone(&target),
        previous: Arc::new(previous),
        observer,
        bound_ms: plan.maximum_interval_ms,
        denied: false,
        unit,
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

pub(in crate::platform::windows) enum NativeWork<'a> {
    Read(&'a mut dyn FnMut()),
    Dispatch(&'a crate::platform::synthetic::SyntheticAction),
}

pub(in crate::platform::windows) fn run_native(
    target: &ProcessGrant,
    bound: u64,
    seize_latency: u32,
    hooks: &mut dyn FrontedDispatchHooks,
    cancelled: &dyn Fn() -> bool,
    work: NativeWork<'_>,
) -> Result<BracketReport, DriverError> {
    let refuse = |hooks: &mut dyn FrontedDispatchHooks, stop| {
        let report = refusal(stop);
        report_finished(hooks, &report, false);
        Ok(report)
    };
    if cancelled() {
        return refuse(hooks, BracketStop::Cancelled);
    }
    let Some(lane) = take_foreground_lane() else {
        return refuse(hooks, BracketStop::ObserverUnavailable);
    };
    // Check the input desktop and the current foreground window before
    // subscribing to input or sending probes.
    if !desktop_safe() {
        return refuse(hooks, BracketStop::ObserverUnavailable);
    }
    let Some(previous) = foreground_window_number().and_then(|hwnd| Binding::read(hwnd, None))
    else {
        return refuse(hooks, BracketStop::PreviousUnknown);
    };
    if !previous.safe_integrity() || !previous.is_foreground() {
        return refuse(hooks, BracketStop::ObserverUnavailable);
    }
    let picture = matches!(&work, NativeWork::Read(_));
    let retained = target_process(target)?;
    let end = Instant::now() + Duration::from_millis(bound);
    let candidates = windows::windows(&retained, target.pid, end)
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
    let mut sequence = match &work {
        NativeWork::Read(_) => None,
        NativeWork::Dispatch(action) => {
            match super::pieces::Sequence::prepare(action, &binding, end) {
                Ok(sequence) => Some(sequence),
                Err(reason) => {
                    return refuse(
                        hooks,
                        BracketStop::PostFailed(super::pieces::failure(reason)),
                    )
                }
            }
        }
    };
    let desk = Arc::new(NativeDesktop {
        _lane: Some(lane),
        picture,
        previous,
    });
    let Some(observer) = NativeObserver::start(target.pid, || {
        !cancelled()
            && desk.safe()
            && desk.target_ready(&binding)
            && desk.previous.safe_integrity()
            && desk.previous.is_foreground()
    }) else {
        return refuse(hooks, BracketStop::ObserverUnavailable);
    };
    if observer.held() {
        return refuse(
            hooks,
            BracketStop::PostFailed(super::pieces::failure("held_input_unconfirmed")),
        );
    }
    let plan = BracketPlan {
        target_pid: target.pid,
        units: 1,
        maximum_interval_ms: bound,
        maximum_seize_detection_latency_ms: seize_latency,
    };
    if let NativeWork::Read(read) = work {
        return run(
            Arc::clone(&desk),
            || Ok(binding.clone()),
            Some(observer.clone()),
            plan,
            hooks,
            cancelled,
            Work::Read(&mut |binding| {
                if observer.may_front() {
                    super::super::picture::with_fronted_window(binding, read);
                }
            }),
        );
    }
    let sequence = sequence.as_mut().expect("dispatch has pieces");
    let report = run_pieces(
        sequence.len(),
        hooks,
        || {
            if cancelled() {
                Some(BracketStop::Cancelled)
            } else if observer.lost() {
                Some(BracketStop::PostFailed(super::pieces::failure(
                    "observer_lost",
                )))
            } else if observer.person() {
                Some(BracketStop::PostFailed(super::pieces::failure(
                    "person_active",
                )))
            } else {
                None
            }
        },
        |index, hooks| {
            run(
                Arc::clone(&desk),
                || Ok(binding.clone()),
                Some(observer.clone()),
                plan,
                hooks,
                cancelled,
                Work::Dispatch(&mut |binding, observed| {
                    sequence.post(
                        index,
                        binding,
                        &observer,
                        observed.deadline_ms,
                        observed.cutoff,
                        observed.cancelled,
                    )
                }),
            )
        },
    )?;
    // Publish sequence-wide counts without replacing the most recent
    // piece's release or restore decision.
    hooks.windows_input_progress(WindowsInputProgress {
        confirmed: sequence.confirmed,
        unverified: sequence.unverified,
        uncertain: sequence.uncertain,
        person_input_swallowed: observer.person() && !observer.lost(),
    });
    Ok(report)
}

fn run_pieces(
    count: usize,
    hooks: &mut dyn FrontedDispatchHooks,
    stop: impl Fn() -> Option<BracketStop>,
    mut run_one: impl FnMut(usize, &mut dyn FrontedDispatchHooks) -> Result<BracketReport, DriverError>,
) -> Result<BracketReport, DriverError> {
    let mut report = refusal(BracketStop::Cancelled);
    for index in 0..count {
        if let Some(stop) = stop() {
            report.stop = Some(stop);
            break;
        }
        if index != 0
            && report.restore == RestoreStatus::Restored
            && !hooks.prepare_next_windows_piece()
        {
            report.stop = Some(BracketStop::Cancelled);
            break;
        }
        combine(&mut report, run_one(index, hooks)?);
        if report.stop.is_some() {
            break;
        }
        if !matches!(
            report.restore,
            RestoreStatus::Restored | RestoreStatus::NotNeeded
        ) {
            report.stop = Some(BracketStop::RestoreFailed);
            break;
        }
    }
    Ok(report)
}

fn combine(total: &mut BracketReport, piece: BracketReport) {
    total.previous_frontmost = total.previous_frontmost.or(piece.previous_frontmost);
    total.units_posted += piece.units_posted;
    total.posts_returned += piece.posts_returned;
    total.generation_verifications += piece.generation_verifications;
    total.chunks += piece.chunks;
    total.longest_fronted_interval_ms = total
        .longest_fronted_interval_ms
        .max(piece.longest_fronted_interval_ms);
    total.slowest_unit_ms = total.slowest_unit_ms.max(piece.slowest_unit_ms);
    total.slowest_restore_ms = total.slowest_restore_ms.max(piece.slowest_restore_ms);
    total.restore_started_by_cutoff |= piece.restore_started_by_cutoff;
    if piece.chunks > 0 || total.chunks == 0 {
        total.restore = piece.restore;
    }
    total.stop = piece.stop;
}

fn report_finished(hooks: &mut dyn FrontedDispatchHooks, report: &BracketReport, person: bool) {
    hooks.finished(&crate::dispatch::BracketOutcome {
        report: report.clone(),
        person_input_during_fronting: person,
        deferred_restore: None,
    });
}

pub(in crate::platform::windows) fn query_focus(
    target: &ProcessGrant,
) -> Result<FocusQueryResult, DriverError> {
    let process = target_process(target)?;
    let binding = foreground_window_number().and_then(|hwnd| Binding::read(hwnd, Some(process)));
    Ok(FocusQueryResult {
        matches_target: binding.is_some_and(|binding| {
            binding.safe_integrity()
                && super::pieces::query(&binding, Instant::now() + Duration::from_millis(100))
        }),
    })
}

#[cfg(test)]
mod tests;
