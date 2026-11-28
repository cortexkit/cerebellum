//! Non-fronting Windows takeover: pin the addressed root, then prove each event's route.

use super::{observer::PointerEcho, *};
use crate::dispatch::{
    idle_gate, observe_drained_events, AbortReason, HeartbeatObservation, SeizeWatcher,
};
use crate::platform::process_event::{
    HeldStateDisposition, PostCallFailure, ProcessEventRefusal, SequencePostFailure,
};
use cerebellum_windows::{
    cursor_position, gui_thread_capture, gui_thread_windows, mouse_wheel_routing,
    root_window_number, virtual_screen, window_at_point, window_owner, RawInputPost,
};

const MOVE: u32 = 0x0200; // WM_MOUSEMOVE
const DOWN: u32 = 0x0201; // WM_LBUTTONDOWN
const UP: u32 = 0x0202; // WM_LBUTTONUP
const WHEEL: u32 = 0x020a; // WM_MOUSEWHEEL
const HWHEEL: u32 = 0x020e; // WM_MOUSEHWHEEL
const WHEEL_FOCUS: u32 = 0;
const WHEEL_HOVER: u32 = 2;
const MAX_SEQUENCE: Duration = Duration::from_secs(2);

pub const WINDOWS_DOWN_GESTURE_RECOVERY_MEASURED: bool = false;

type Pixel = (i32, i32);

pub(in crate::platform::windows) fn physical_pointer_pixel((x, y): (f64, f64)) -> Option<Pixel> {
    let pixel = |coordinate: f64| {
        let whole = coordinate.floor();
        (whole >= f64::from(i32::MIN) && whole <= f64::from(i32::MAX)).then_some(whole as i32)
    };
    Some((pixel(x)?, pixel(y)?))
}

fn normalize((x, y): Pixel, [left, top, width, height]: [i32; 4]) -> Option<(u16, u16)> {
    fn axis(pixel: i32, origin: i32, extent: i32) -> Option<u16> {
        let offset = i64::from(pixel) - i64::from(origin);
        let extent = i64::from(extent);
        if !(0..extent).contains(&offset) {
            return None;
        }
        // Target the middle of the pixel's normalized interval. Very wide
        // desktops can have pixels with no representable absolute coordinate.
        let absolute = (2 * offset + 1) * 65_536 / (2 * extent);
        (absolute * extent / 65_536 == offset).then_some(absolute as u16)
    }
    Some((axis(x, left, width)?, axis(y, top, height)?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Move(Pixel),
    Down(Pixel),
    Up,
    Wheel { delta: i32, horizontal: bool },
}

impl Step {
    fn event(
        self,
        point: Pixel,
        screen: [i32; 4],
        release: bool,
    ) -> Option<(RawInputPost, PointerEcho)> {
        let (event, message) = match self {
            Self::Move(_) => {
                let (x, y) = normalize(point, screen)?;
                (RawInputPost::AbsoluteMouseMove { x, y }, MOVE)
            }
            Self::Down(_) => (RawInputPost::LeftMouseButton { up: false }, DOWN),
            Self::Up => (RawInputPost::LeftMouseButton { up: true }, UP),
            Self::Wheel { delta, horizontal } => (
                RawInputPost::MouseWheel { delta, horizontal },
                if horizontal { HWHEEL } else { WHEEL },
            ),
        };
        Some((
            event,
            PointerEcho {
                message,
                point,
                release,
            },
        ))
    }
}

fn plan(action: &SyntheticAction, down_recovery_measured: bool) -> Result<Vec<Step>, DriverError> {
    let pixel = |point: &SyntheticPoint| {
        physical_pointer_pixel((point.x, point.y)).ok_or(DriverError::InvalidRequest(
            "pointer coordinates are not physical desktop pixels",
        ))
    };
    Ok(match action {
        SyntheticAction::MovePointer { point } => vec![Step::Move(pixel(point)?)],
        SyntheticAction::Scroll {
            unit: SyntheticScrollUnit::Line,
            delta,
            axis,
        } if *delta != 0 => {
            vec![Step::Wheel {
                delta: delta
                    .checked_mul(120)
                    .ok_or(DriverError::InvalidRequest("wheel delta overflow"))?,
                horizontal: *axis == SyntheticScrollAxis::Horizontal,
            }]
        }
        SyntheticAction::ClickPointer { point } if down_recovery_measured => {
            let point = pixel(point)?;
            vec![Step::Move(point), Step::Down(point), Step::Up]
        }
        SyntheticAction::DragPointer { from, to } if down_recovery_measured => {
            let from = pixel(from)?;
            vec![
                Step::Move(from),
                Step::Down(from),
                Step::Move(pixel(to)?),
                Step::Up,
            ]
        }
        SyntheticAction::ClickPointer { .. } | SyntheticAction::DragPointer { .. } => {
            return Err(DriverError::StartupRefused(
                "Windows button recovery measurement is not recorded",
            ));
        }
        _ => {
            return Err(DriverError::InvalidRequest(
                "unsupported Windows pointer action",
            ))
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Route,
    Observer,
    Person,
    Cancelled,
    Uncertain,
}

impl Stop {
    fn refusal(self) -> ProcessEventRefusal {
        if self == Self::Cancelled {
            return ProcessEventRefusal::Cancelled;
        }
        ProcessEventRefusal::PostCallFailed(PostCallFailure::new(match self {
            Self::Route => "pointer recipient or sensitivity changed",
            Self::Observer => "observer_lost",
            Self::Person => "state_changed_by_person",
            Self::Uncertain => "pointer post did not return with routing evidence",
            Self::Cancelled => unreachable!(),
        }))
    }
}

#[derive(Clone, Copy)]
struct Post {
    submitted: bool,
    passed_hook: bool,
    result: Result<(), Stop>,
}

trait Transport {
    fn pause(&self, interval: Duration, release: bool);
    fn stopped(&self) -> Result<(), Stop>;
    fn post(&mut self, step: Step, held: bool, release: bool) -> Post;
}

fn run_steps(
    transport: &mut impl Transport,
    steps: &[Step],
    interval: Duration,
) -> Result<u64, SequencePostFailure> {
    let mut posts = 0;
    let mut held = false;
    for (index, &step) in steps.iter().enumerate() {
        if index != 0 {
            transport.pause(interval, false);
        }
        let post = match transport.stopped() {
            Ok(()) => transport.post(step, held, false),
            Err(stop) => Post {
                submitted: false,
                passed_hook: false,
                result: Err(stop),
            },
        };
        posts += u64::from(post.submitted);
        let down = matches!(step, Step::Down(_));
        held |= down && post.passed_hook;
        if let Err(stop) = post.result {
            let held_state = if down && post.submitted && !post.passed_hook {
                // Without an echo we may hold a button, but cannot prove that
                // an up would be paired with one of our own downs.
                HeldStateDisposition::Unknown
            } else if !held {
                HeldStateDisposition::NoneHeld
            } else if post.submitted && step == Step::Up {
                // An up that may already have been routed is never replayed.
                HeldStateDisposition::Unknown
            } else {
                transport.pause(interval, true);
                if transport.post(Step::Up, true, true).result.is_ok() {
                    HeldStateDisposition::Released { posts_returned: 1 }
                } else {
                    HeldStateDisposition::Unknown
                }
            };
            return Err(SequencePostFailure {
                posts_returned: posts,
                refusal: stop.refusal(),
                held_state,
            });
        }
        if step == Step::Up {
            held = false;
        }
    }
    Ok(posts)
}

#[derive(Clone, Copy)]
struct Route {
    root: u32,
    capture: Option<u32>,
    wheel: Option<u32>,
}

impl Route {
    fn recipient(self, step: Step, held: bool) -> Option<u32> {
        match step {
            Step::Wheel { .. } => self
                .wheel
                .filter(|recipient| self.capture.is_none_or(|capture| capture == *recipient)),
            _ if held => self.capture.or(Some(self.root)),
            _ => Some(self.root).filter(|root| self.capture.is_none_or(|capture| capture == *root)),
        }
    }
}

struct Native<'a> {
    target: &'a ProcessGrant,
    window: Binding,
    foreground: Binding,
    observer: &'a NativeObserver,
    scroll_guard: Option<GlobalScrollGuard>,
    deadline: Instant,
    cancelled: &'a dyn Fn() -> bool,
}

impl Native<'_> {
    fn safe_desktop(&self) -> bool {
        desktop_safe()
            && self.foreground.safe_integrity()
            && self.foreground.is_foreground()
            && self.window.current()
            && self.window.safe_integrity()
    }

    fn route(&self, step: Step, point: Pixel) -> Option<Route> {
        let hit = window_at_point(point)?;
        let root = root_window_number(hit)?;
        let (_, owner_thread) = window_owner(self.window.number).ok()?;
        let (_, content_thread) = self.window.proof.content_window_and_thread();
        let mut capture = None;
        for tid in [0, owner_thread, content_thread] {
            if let Some(hwnd) = gui_thread_capture(tid).ok()? {
                if capture
                    .replace(hwnd)
                    .is_some_and(|previous| previous != hwnd)
                {
                    return None;
                }
            }
        }
        let wheel = if matches!(step, Step::Wheel { .. }) {
            match mouse_wheel_routing().ok()? {
                WHEEL_HOVER => Some(hit),
                WHEEL_FOCUS => {
                    let (_, tid) = window_owner(self.foreground.number).ok()?;
                    gui_thread_windows(tid).ok()?.focus
                }
                // The hybrid setting depends on the app. No exact recipient
                // can be established from that setting alone.
                _ => None,
            }
        } else {
            None
        };
        Some(Route {
            root,
            capture,
            wheel,
        })
    }

    fn point(&self, step: Step) -> Option<Pixel> {
        match step {
            Step::Move(point) => Some(point),
            Step::Down(point) => (cursor_position().ok()? == point).then_some(point),
            Step::Up | Step::Wheel { .. } => cursor_position().ok(),
        }
    }

    fn route_matches(&self, step: Step, held: bool, point: Pixel) -> bool {
        self.route(step, point).is_some_and(|route| {
            route.root == self.window.number
                && route.recipient(step, held) == Some(self.window.number)
        })
    }

    fn prepare(
        &self,
        step: Step,
        held: bool,
        release: bool,
    ) -> Option<(RawInputPost, PointerEcho)> {
        // Release is never sent to a sibling or a new foreground recipient,
        // even when that means an automation-held button stays unconfirmed.
        if !self.safe_desktop() || (held && !self.window.is_foreground()) {
            return None;
        }
        let point = self.point(step)?;
        if !self.route_matches(step, held, point) {
            return None;
        }
        let geometry = virtual_screen();
        if matches!(step, Step::Wheel { .. }) && (self.scroll_guard.as_ref()?.0)().is_err() {
            return None;
        }
        super::super::app_state::pointer_safe(
            self.target,
            self.window.number,
            self.window.proof.clone(),
            point,
            self.deadline,
        )
        .ok()?;
        // UIA may block or run a provider. Re-read the recipient and cursor
        // afterwards instead of trusting the checks made before that call.
        if !self.safe_desktop()
            || self.point(step)? != point
            || !self.route_matches(step, held, point)
            || geometry != virtual_screen()
            || Instant::now() >= self.deadline
        {
            return None;
        }
        step.event(point, geometry, release)
    }
}

impl Transport for Native<'_> {
    fn pause(&self, interval: Duration, release: bool) {
        let end = (Instant::now() + interval).min(self.deadline);
        while Instant::now() < end && (release || self.stopped().is_ok()) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn stopped(&self) -> Result<(), Stop> {
        if (self.cancelled)() || Instant::now() >= self.deadline {
            Err(Stop::Cancelled)
        } else if self.observer.lost() {
            Err(Stop::Observer)
        } else if self.observer.person() || self.observer.held() {
            Err(Stop::Person)
        } else {
            Ok(())
        }
    }

    fn post(&mut self, step: Step, held: bool, release: bool) -> Post {
        let before_post = || {
            if release {
                if self.observer.lost() || Instant::now() >= self.deadline {
                    return Err(Stop::Observer);
                }
            } else {
                self.stopped()?;
            }
            let (event, echo) = self.prepare(step, held, release).ok_or(Stop::Route)?;
            if release {
                if self.observer.lost() {
                    return Err(Stop::Observer);
                }
            } else {
                self.stopped()?;
                if self.observer.route_changed() {
                    return Err(Stop::Route);
                }
            }
            Ok((event, echo))
        };
        let (event, echo) = match before_post() {
            Ok(prepared) => prepared,
            Err(stop) => {
                return Post {
                    submitted: false,
                    passed_hook: false,
                    result: Err(stop),
                }
            }
        };
        let before = self.observer.counts();
        let submitted = self.observer.post_pointer(event, echo);
        if !submitted {
            return Post {
                submitted,
                passed_hook: false,
                result: Err(Stop::Uncertain),
            };
        }
        if !self.safe_desktop()
            || !self.route_matches(step, held, echo.point)
            || Instant::now() >= self.deadline
        {
            return Post {
                submitted,
                passed_hook: self.observer.pointer_passed(),
                result: Err(Stop::Route),
            };
        }
        let fenced = self.observer.post(&[super::observer::MARKER]) == 1
            && self.observer.fence(
                before,
                1,
                now_ms().saturating_add(
                    self.deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis() as u64,
                ),
            );
        let result = if !fenced || self.observer.lost() {
            Err(Stop::Observer)
        } else if !release && self.observer.person() {
            Err(Stop::Person)
        } else if !self.observer.pointer_passed()
            || (!release && self.observer.route_changed())
            || cursor_position().ok() != Some(echo.point)
            || !self.route_matches(step, held, echo.point)
        {
            Err(Stop::Route)
        } else {
            Ok(())
        };
        Post {
            submitted,
            passed_hook: self.observer.pointer_passed(),
            result,
        }
    }
}

fn observed_start(
    observer: &NativeObserver,
    watcher: &mut SeizeWatcher,
    steps: usize,
) -> Result<(), DriverError> {
    for _ in 0..steps {
        watcher.queue_post();
    }
    if let Err(refusal) = idle_gate(observer.idle()) {
        watcher.abort(AbortReason::IdleGateRefused(refusal), 0, None);
    } else if observer.held() {
        watcher.abort(AbortReason::UserSeizedControl, 0, None);
    } else {
        let probe = observer.probe();
        let echo = observer.echo(probe, watcher);
        if !matches!(echo, HeartbeatObservation::Seen { .. }) {
            watcher.abort(AbortReason::ObserverUnavailable, 0, None);
        }
        observe_drained_events(watcher, observer.drain(), i64::from(std::process::id()), 0);
    }
    if let Some(abort) = watcher.abort_decision() {
        return Err(DriverError::ObservedDispatchAborted(abort));
    }
    Ok(())
}

fn run_observed(
    observer: &NativeObserver,
    watcher: &mut SeizeWatcher,
    transport: &mut impl Transport,
    steps: &[Step],
    interval: Duration,
) -> Result<u64, DriverError> {
    observed_start(observer, watcher, steps.len())?;
    run_steps(transport, steps, interval).map_err(DriverError::SyntheticDispatchFailed)
}

pub(in crate::platform::windows) fn dispatch_takeover(
    request: GlobalDispatchRequest,
    window: Option<u32>,
    scroll_guard: Option<GlobalScrollGuard>,
    cancelled: &dyn Fn() -> bool,
) -> Result<DispatchResult, DriverError> {
    if !request.action_is_admitted() {
        return Err(DriverError::InvalidRequest(
            "takeover token does not admit this action",
        ));
    }
    let steps = plan(
        &request.synthetic.action,
        WINDOWS_DOWN_GESTURE_RECOVERY_MEASURED,
    )?;
    if !crate::dispatch::seize_latency_fits_inter_post_interval(
        request.maximum_seize_detection_latency_ms,
        request.minimum_inter_post_interval_ms,
    ) {
        return Err(DriverError::InvalidRequest(
            "observed inter-post interval is shorter than the seize-detection bound",
        ));
    }
    if matches!(steps[0], Step::Wheel { .. }) && scroll_guard.is_none() {
        return Err(DriverError::InvalidRequest(
            "Windows scroll requires a cursor guard",
        ));
    }
    let hwnd = window.ok_or(DriverError::InvalidRequest(
        "no addressed Windows pointer window",
    ))?;
    if cancelled() || !desktop_safe() {
        return Err(DriverError::Unsupported(
            "Windows input desktop unavailable",
        ));
    }
    let target = &request.synthetic.target;
    let process = target_process(target)?;
    let window = Binding::read(hwnd, Some(process))
        .filter(Binding::safe_integrity)
        .ok_or(DriverError::Unsupported(
            "Windows pointer target unavailable",
        ))?;
    let foreground = foreground_window_number()
        .and_then(|hwnd| Binding::read(hwnd, None))
        .filter(Binding::safe_integrity)
        .ok_or(DriverError::Unsupported("Windows foreground unavailable"))?;
    let deadline = Instant::now() + MAX_SEQUENCE;
    let floor = || {
        !cancelled()
            && desktop_safe()
            && foreground.is_foreground()
            && foreground.safe_integrity()
            && window.current()
            && window.safe_integrity()
    };
    if !floor() {
        return Err(DriverError::Unsupported(
            "Windows desktop or pointer target changed",
        ));
    }
    let mut watcher = SeizeWatcher::new(request.maximum_seize_detection_latency_ms);
    let Some(observer) = NativeObserver::start(target.pid, floor) else {
        watcher.abort(AbortReason::ObserverUnavailable, 0, None);
        return Err(DriverError::ObservedDispatchAborted(
            watcher.abort_decision().expect("observer refusal"),
        ));
    };
    observer.track_route(foreground.number);
    let mut native = Native {
        target,
        window,
        foreground,
        observer: &observer,
        scroll_guard,
        deadline,
        cancelled,
    };
    // Refuse unsafe recipients before sending even the observer's two harmless liveness probes.
    if native.prepare(steps[0], false, false).is_none() || observer.route_changed() {
        watcher.abort(AbortReason::FocusMismatch, 0, None);
        return Err(DriverError::ObservedDispatchAborted(
            watcher.abort_decision().expect("route refusal"),
        ));
    }
    if !native.safe_desktop() || cancelled() || Instant::now() >= deadline {
        return Err(DriverError::Unsupported(
            "Windows desktop or pointer target changed",
        ));
    }
    let posts = run_observed(
        &observer,
        &mut watcher,
        &mut native,
        &steps,
        Duration::from_millis(u64::from(request.minimum_inter_post_interval_ms)),
    )?;
    Ok(DispatchResult {
        accepted_by_platform: true,
        effect_status: EffectStatus::EffectIndeterminate,
        unreadable_subtrees: 0,
        delivery_posts_returned: posts,
        delivery_generation_verifications: posts,
    })
}

#[cfg(test)]
mod tests;
