use super::{cursor_position, Receiver};
use crate::{post_input, InputHooks, RawInputEvent, RawInputPost};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::ptr::null_mut;
use std::sync::{atomic::AtomicBool, atomic::Ordering, mpsc, Arc};
use std::time::{Duration, Instant};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM},
    System::Threading::{AttachThreadInput, GetCurrentThreadId},
    UI::{Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
};

const POSTS: usize = 50;
const TAG_BASE: usize = 0xC3B2_0000;
const PROBES: [Probe; 5] = [Probe::A, Probe::D, Probe::C, Probe::B, Probe::Control];
const MODES: [&str; 2] = ["swallow", "pass"];
const ROWS: usize = PROBES.len() * MODES.len();
const RESTORE_TAG: usize = TAG_BASE + ROWS * POSTS;
const ECHO_LIMIT: Duration = Duration::from_secs(2);
const PROBE_LIMIT: Duration = Duration::from_millis(30);
const EFFECT_SETTLE: Duration = Duration::from_millis(150);
const HOVER_MS: u32 = 40;
const POLL: Duration = Duration::from_millis(5);
// Client-area hover messages from WinUser.h, not exported by windows-sys.
const WM_MOUSEHOVER: u32 = 0x02A1;
const WM_MOUSELEAVE: u32 = 0x02A3;

#[derive(Clone, Copy, Debug)]
enum Probe {
    A,
    D,
    C,
    B,
    Control,
}

impl Probe {
    fn destination(self, start: POINT) -> Option<POINT> {
        match self {
            Self::C => Some(POINT {
                x: start.x.checked_add(1).expect("cursor x + 1"),
                y: start.y,
            }),
            Self::D => Some(start),
            _ => None,
        }
    }

    fn post(self, tag: usize, absolute: Option<POINT>) -> usize {
        match self {
            Self::A => send_mouse(
                tag,
                MOUSEEVENTF_MOVE | MOUSEEVENTF_MOVE_NOCOALESCE,
                POINT::default(),
            ),
            Self::B => send_mouse(tag, MOUSEEVENTF_WHEEL, POINT::default()),
            Self::C | Self::D => {
                send_absolute(tag, absolute.expect("normalised absolute destination"))
            }
            Self::Control => post_input(tag, &[RawInputPost::RelativeMouseMove { x: 0, y: 0 }]),
        }
    }
}

fn send_mouse(tag: usize, flags: u32, position: POINT) -> usize {
    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: position.x,
                dy: position.y,
                mouseData: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: tag,
            },
        },
    };
    // SAFETY: The initialized INPUT lives through the call.
    unsafe { SendInput(1, &input, std::mem::size_of::<INPUT>() as i32) as usize }
}

fn send_absolute(tag: usize, normalised: POINT) -> usize {
    send_mouse(
        tag,
        MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
        normalised,
    )
}

struct VirtualDesktop {
    origin: POINT,
    extent: POINT,
}

impl VirtualDesktop {
    fn read() -> Self {
        // SAFETY: These system metrics need no pointers or handles.
        unsafe {
            Self {
                origin: POINT {
                    x: GetSystemMetrics(SM_XVIRTUALSCREEN),
                    y: GetSystemMetrics(SM_YVIRTUALSCREEN),
                },
                extent: POINT {
                    x: GetSystemMetrics(SM_CXVIRTUALSCREEN),
                    y: GetSystemMetrics(SM_CYVIRTUALSCREEN),
                },
            }
        }
    }

    fn contains(&self, point: POINT) -> bool {
        let in_axis = |pixel, origin, extent| {
            (0..i64::from(extent)).contains(&(i64::from(pixel) - i64::from(origin)))
        };
        in_axis(point.x, self.origin.x, self.extent.x)
            && in_axis(point.y, self.origin.y, self.extent.y)
    }

    fn normalise(&self, point: POINT) -> POINT {
        assert!(
            self.contains(point),
            "absolute destination must be on the virtual desktop"
        );
        // Aim at the center of the pixel's interval in the 65536-value grid.
        let axis = |pixel, origin, extent| {
            let offset = i64::from(pixel) - i64::from(origin);
            ((offset * 65_536 + 32_768) / i64::from(extent)) as i32
        };
        POINT {
            x: axis(point.x, self.origin.x, self.extent.x),
            y: axis(point.y, self.origin.y, self.extent.y),
        }
    }
}

struct Hook {
    enabled: Arc<AtomicBool>,
    overflow: Arc<AtomicBool>,
    _pump: InputHooks,
}

impl Hook {
    fn new() -> (Self, mpsc::Receiver<(usize, Instant)>) {
        let enabled = Arc::new(AtomicBool::new(true));
        let overflow = Arc::new(AtomicBool::new(false));
        let enabled_in_hook = Arc::clone(&enabled);
        let overflow_in_hook = Arc::clone(&overflow);
        let (send, receive) = mpsc::sync_channel(ROWS * POSTS);
        let pump = InputHooks::start(None, Duration::from_secs(2), move |event| {
            let at = Instant::now();
            let RawInputEvent::Mouse {
                tag,
                injected: true,
                ..
            } = event
            else {
                return false;
            };
            if !enabled_in_hook.load(Ordering::Acquire)
                || !(TAG_BASE..TAG_BASE + ROWS * POSTS).contains(&tag)
            {
                return false;
            }
            if send.try_send((tag, at)).is_err() {
                overflow_in_hook.store(true, Ordering::Release);
            }
            // The first half of the tag range is for the swallowing rows.
            tag < TAG_BASE + ROWS * POSTS / 2
        })
        .expect("install the input hook pump");
        (
            Self {
                enabled,
                overflow,
                _pump: pump,
            },
            receive,
        )
    }
}

impl Drop for Hook {
    fn drop(&mut self) {
        // InputHooks stops asynchronously. Stop swallowing before requesting teardown.
        self.enabled.store(false, Ordering::Release);
    }
}

#[derive(Default)]
struct FixtureTraffic {
    message_ids: BTreeSet<u32>,
    tagged_message: bool,
    other_mouse_ids: BTreeSet<u32>,
    mouse_move: bool,
    mouse_wheel: bool,
    hover_change: bool,
    hover_tracking_failed: bool,
}

thread_local! {
    static TRAFFIC: RefCell<Option<FixtureTraffic>> = const { RefCell::new(None) };
}

fn record_traffic(update: impl FnOnce(&mut FixtureTraffic)) -> bool {
    TRAFFIC.with(|slot| {
        if let Some(traffic) = slot.borrow_mut().as_mut() {
            update(traffic);
            true
        } else {
            false
        }
    })
}

fn track_hover(hwnd: HWND, flags: u32) -> bool {
    let mut request = TRACKMOUSEEVENT {
        cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
        dwFlags: flags | TME_HOVER | TME_LEAVE,
        hwndTrack: hwnd,
        dwHoverTime: HOVER_MS,
    };
    // SAFETY: The request is initialized, and the fixture owns the window.
    unsafe { TrackMouseEvent(&mut request) != 0 }
}

unsafe extern "system" fn fixture_proc(
    hwnd: HWND,
    message: u32,
    key: WPARAM,
    data: LPARAM,
) -> LRESULT {
    let measuring = record_traffic(|traffic| {
        traffic.message_ids.insert(message);
        traffic.mouse_move |= message == WM_MOUSEMOVE;
        traffic.mouse_wheel |= message == WM_MOUSEWHEEL;
        traffic.hover_change |= matches!(message, WM_MOUSEHOVER | WM_MOUSELEAVE);
    });
    // Arm hover tracking in response to a delivered move, not at the start of
    // a trial: otherwise the stationary pointer can generate a hover itself.
    if measuring && message == WM_MOUSEMOVE && !track_hover(hwnd, 0) {
        record_traffic(|traffic| traffic.hover_tracking_failed = true);
    }
    // SAFETY: The default procedure receives the unchanged system message.
    unsafe { DefWindowProcW(hwnd, message, key, data) }
}

fn pump_fixture(window: &Receiver, tag: usize) {
    let mut message = MSG::default();
    for _ in 0..64 {
        // SAFETY: This thread owns the receiver and its queue. Read the extra
        // info for the removed message before DispatchMessage can change it.
        unsafe {
            if PeekMessageW(&mut message, window.0, 0, 0, PM_REMOVE) == 0 {
                break;
            }
            if message.hwnd == window.0 && (WM_MOUSEFIRST..=WM_MOUSELAST).contains(&message.message)
            {
                let extra = GetMessageExtraInfo() as usize;
                record_traffic(|traffic| {
                    if extra == tag {
                        traffic.tagged_message = true;
                    } else {
                        traffic.other_mouse_ids.insert(message.message);
                    }
                });
            }
            DispatchMessageW(&message);
        }
    }
}

fn wait_for_focus(window: &Receiver) -> bool {
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        pump_fixture(window, 0);
        // SAFETY: SetFocus acts only on the confirmed foreground fixture.
        if unsafe { GetForegroundWindow() == window.0 } {
            unsafe { SetFocus(window.0) };
            if unsafe { GetFocus() == window.0 } {
                return true;
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(remaining.min(POLL));
    }
}

fn acquire_foreground(window: &Receiver) -> Option<&'static str> {
    // SAFETY: Activation requests always target our own fixture HWND.
    unsafe { SetForegroundWindow(window.0) };
    if wait_for_focus(window) {
        return Some("direct");
    }
    // SAFETY: Only attach to the current foreground input queue long enough to
    // activate our own HWND. Detach before any test input can be posted.
    let detached = unsafe {
        let foreground = GetForegroundWindow();
        if foreground.is_null() {
            return None;
        }
        let other_thread = GetWindowThreadProcessId(foreground, null_mut());
        let own_thread = GetCurrentThreadId();
        if other_thread == 0
            || other_thread == own_thread
            || AttachThreadInput(own_thread, other_thread, 1) == 0
        {
            return None;
        }
        BringWindowToTop(window.0);
        SetForegroundWindow(window.0);
        AttachThreadInput(own_thread, other_thread, 0) != 0
    };
    (detached && wait_for_focus(window)).then_some("AttachThreadInput")
}

fn cursor_delta(from: POINT, to: POINT) -> u32 {
    from.x.abs_diff(to.x).max(from.y.abs_diff(to.y))
}

fn guard_post(
    window: &Receiver,
    desktop: &VirtualDesktop,
    current: POINT,
    destination: Option<POINT>,
) {
    assert!(
        window.contains_client_point(current),
        "pointer must be inside the owned client"
    );
    if let Some(target) = destination {
        assert!(
            desktop.contains(target),
            "target is outside the virtual desktop"
        );
        // Keep a one-pixel rounding error in either axis inside the fixture.
        for dx in -1..=1 {
            for dy in -1..=1 {
                let point = POINT {
                    x: target.x.saturating_add(dx),
                    y: target.y.saturating_add(dy),
                };
                assert!(!desktop.contains(point) || window.contains_client_point(point),
                    "absolute destination and its rounding margin must stay inside the owned client");
            }
        }
    }
    assert_eq!(
        cursor_delta(current, cursor_position()),
        0,
        "pointer moved during preflight"
    );
    // SAFETY: These calls only query window ownership of input.
    unsafe {
        assert_eq!(
            GetForegroundWindow(),
            window.0,
            "fixture must be foreground before posting"
        );
        assert_eq!(
            GetFocus(),
            window.0,
            "wheel input must target the owned fixture"
        );
        assert!(
            GetCapture().is_null(),
            "fixture thread must not have captured the mouse"
        );
    }
}

#[derive(PartialEq, Eq)]
enum Restore {
    Unneeded,
    Restored,
    OffTarget,
    NotRestored,
}

fn restore_cursor(
    window: &Receiver,
    desktop: &VirtualDesktop,
    probe: Probe,
    original: POINT,
    after: POINT,
    target: Option<POINT>,
) -> Restore {
    if cursor_delta(original, after) == 0 {
        return Restore::Unneeded;
    }
    if matches!(probe, Probe::C) {
        let expected = target.expect("candidate C has an absolute destination");
        if cursor_delta(after, expected) != 0 || cursor_delta(cursor_position(), expected) != 0 {
            return Restore::OffTarget;
        }
        let normalised = desktop.normalise(original);
        guard_post(window, desktop, expected, Some(original));
        assert_eq!(
            send_absolute(RESTORE_TAG, normalised),
            1,
            "SendInput rejected the absolute restore"
        );
    } else {
        guard_post(window, desktop, after, Some(original));
        // SAFETY: Both cursor positions are inside the owned foreground fixture.
        assert_ne!(
            unsafe { SetCursorPos(original.x, original.y) },
            0,
            "restore the fixture pointer"
        );
    }
    let deadline = Instant::now() + EFFECT_SETTLE;
    loop {
        pump_fixture(window, RESTORE_TAG);
        if cursor_delta(original, cursor_position()) == 0 {
            return Restore::Restored;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Restore::NotRestored;
        }
        std::thread::sleep(remaining.min(POLL));
    }
}

struct Effects {
    traffic: FixtureTraffic,
    cursor_delta: u32,
    final_at_start: bool,
    final_at_target: bool,
    restore: Restore,
}

fn measure_post(
    window: &Receiver,
    desktop: &VirtualDesktop,
    events: &mpsc::Receiver<(usize, Instant)>,
    probe: Probe,
    tag: usize,
) -> (Option<Duration>, Effects) {
    // Drain setup and restoration messages before recording the next post.
    pump_fixture(window, tag);
    let original = cursor_position();
    let target = probe.destination(original);
    let absolute = target.map(|point| desktop.normalise(point));
    guard_post(window, desktop, original, target);
    TRAFFIC.with(|slot| *slot.borrow_mut() = Some(FixtureTraffic::default()));
    let started = Instant::now();
    assert_eq!(
        probe.post(tag, absolute),
        1,
        "SendInput rejected {probe:?} (tag {tag:#x})"
    );
    let echo_deadline = started + ECHO_LIMIT;
    let mut echo = None;
    let mut max_delta = 0;
    let after = loop {
        pump_fixture(window, tag);
        let current = cursor_position();
        max_delta = max_delta.max(cursor_delta(original, current));
        for (observed_tag, at) in events.try_iter().take(ROWS * POSTS) {
            if observed_tag == tag && at >= started && at <= echo_deadline {
                echo = Some(echo.map_or(at, |first: Instant| first.min(at)));
            }
        }
        // After an echo, keep pumping so Windows can deliver its effects after
        // the hook returns. Without an echo, observe effects to the full cutoff.
        let deadline = echo.map_or(echo_deadline, |at| at + EFFECT_SETTLE);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break current;
        }
        std::thread::sleep(remaining.min(POLL));
    };
    let traffic = TRAFFIC
        .with(RefCell::take)
        .expect("fixture was recording the post");
    if traffic.mouse_move {
        track_hover(window.0, TME_CANCEL);
    }
    let restore = restore_cursor(window, desktop, probe, original, after, target);
    assert!(
        !traffic.hover_tracking_failed,
        "fixture failed to track hover after a delivered move"
    );
    let effects = Effects {
        traffic,
        cursor_delta: max_delta,
        final_at_start: cursor_delta(original, after) == 0,
        final_at_target: target.is_some_and(|point| cursor_delta(point, after) == 0),
        restore,
    };
    (echo.map(|at| at - started), effects)
}

#[derive(Default)]
struct Summary {
    echoes: Vec<Duration>,
    moved: usize,
    max_delta: u32,
    final_at_start: usize,
    final_at_target: usize,
    any_messages: usize,
    message_ids: BTreeSet<u32>,
    tagged_messages: usize,
    other_mouse_messages: usize,
    other_mouse_ids: BTreeSet<u32>,
    mouse_moves: usize,
    mouse_wheels: usize,
    hover_changes: usize,
    restored: usize,
    restore_off_target: usize,
    not_restored: usize,
}

impl Summary {
    fn record(&mut self, echo: Option<Duration>, effects: Effects) {
        self.echoes.extend(echo);
        self.moved += usize::from(effects.cursor_delta != 0);
        self.max_delta = self.max_delta.max(effects.cursor_delta);
        self.final_at_start += usize::from(effects.final_at_start);
        self.final_at_target += usize::from(effects.final_at_target);
        self.any_messages += usize::from(!effects.traffic.message_ids.is_empty());
        self.message_ids.extend(effects.traffic.message_ids);
        self.tagged_messages += usize::from(effects.traffic.tagged_message);
        self.other_mouse_messages += usize::from(!effects.traffic.other_mouse_ids.is_empty());
        self.other_mouse_ids.extend(effects.traffic.other_mouse_ids);
        self.mouse_moves += usize::from(effects.traffic.mouse_move);
        self.mouse_wheels += usize::from(effects.traffic.mouse_wheel);
        self.hover_changes += usize::from(effects.traffic.hover_change);
        self.restored += usize::from(effects.restore == Restore::Restored);
        self.restore_off_target += usize::from(effects.restore == Restore::OffTarget);
        self.not_restored += usize::from(effects.restore == Restore::NotRestored);
    }

    fn print(mut self, arch: &str, probe: Probe, mode: &str, precision: &str) {
        self.echoes.sort_unstable();
        let n = self.echoes.len();
        let on_time = self
            .echoes
            .partition_point(|&latency| latency <= PROBE_LIMIT);
        let latency = if n == 0 {
            "-/-/-/-".to_owned()
        } else {
            let median = (self.echoes[(n - 1) / 2] + self.echoes[n / 2]) / 2;
            let p95 = self.echoes[(n * 95).div_ceil(100) - 1];
            let [min, median, p95, max] = [self.echoes[0], median, p95, self.echoes[n - 1]]
                .map(|elapsed| elapsed.as_secs_f64() * 1_000.0);
            format!("{min:.3}/{median:.3}/{p95:.3}/{max:.3}")
        };
        let target = if matches!(probe, Probe::C | Probe::D) {
            format!("{}/{POSTS}", self.final_at_target)
        } else {
            "-".to_owned()
        };
        println!(
            "{arch} | {probe:?} | {mode} | {precision} | {on_time}/{POSTS} | {n}/{POSTS} | {latency} | {}/{POSTS} | {} | {}/{POSTS} | {target} | {}/{}/{}/{}/{}/{} | {} | {} | {}/{}/{}",
            self.moved, self.max_delta, self.final_at_start, self.any_messages, self.tagged_messages,
            self.other_mouse_messages, self.mouse_moves, self.mouse_wheels, self.hover_changes,
            fixture_ids(&self.message_ids), fixture_ids(&self.other_mouse_ids), self.restored,
            self.restore_off_target, self.not_restored,
        );
    }
}

fn fixture_ids(ids: &BTreeSet<u32>) -> String {
    if ids.is_empty() {
        "-".to_owned()
    } else {
        ids.iter()
            .map(|id| format!("{id:#06x}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn pointer_precision() -> String {
    let mut mouse = [0_i32; 3];
    // SAFETY: SPI_GETMOUSE writes exactly three integers into the supplied array.
    if unsafe { SystemParametersInfoW(SPI_GETMOUSE, 0, mouse.as_mut_ptr().cast(), 0) } == 0 {
        return "unavailable".to_owned();
    }
    let [threshold_1, threshold_2, acceleration] = mouse;
    let precision = match acceleration {
        0 => "off",
        1 | 2 => "on",
        _ => "unknown",
    };
    format!("{precision} ({threshold_1}/{threshold_2}/{acceleration})")
}

#[test]
#[ignore = "requires the GitHub-hosted Windows desktop; run alone"]
fn github_hosted_mouse_hook_probe_measurement() {
    let arch = std::env::var("RUNNER_ARCH").unwrap_or_default();
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
        || !matches!(arch.as_str(), "X64" | "ARM64")
    {
        return;
    }
    assert_eq!(crate::input_desktop_name().as_deref().unwrap(), "Default");
    let window = Receiver::create(fixture_proc);
    let Some(activation) = acquire_foreground(&window) else {
        println!("{arch} | no foreground on this runner | no probes posted (direct activation and AttachThreadInput unavailable)");
        return;
    };
    println!("{arch} | owned foreground fixture acquired | {activation}");
    let desktop = VirtualDesktop::read();
    let precision = pointer_precision();
    let (hook, events) = Hook::new();
    println!(
        "Mouse probe measurement: A=zero move + NOCOALESCE, D=absolute to start, C=absolute right by one pixel, B=zero wheel, Control=original zero move. {POSTS} posts per row."
    );
    println!(
        "Effects sampled until {} ms after an echo, or 2 s from posting without one. Fixture counts posts with any window procedure call / tagged queued mouse message / other queued mouse message / WM_MOUSEMOVE / WM_MOUSEWHEEL / WM_MOUSEHOVER or WM_MOUSELEAVE. Hover tracking ({HOVER_MS} ms) starts only on a delivered move.",
        EFFECT_SETTLE.as_millis(),
    );
    println!(
        "arch | probe | hook | EPP (SPI_GETMOUSE thresholds/accel) | echo <=30 ms | echo <=2 s | latency ms min/median/p95/max | cursor moved | max delta px | at start at cutoff | exact absolute target at cutoff | fixture any/tagged/other/move/wheel/hover | fixture ids | other ids | restore ok/skipped-off-target/not-restored"
    );
    for (mode_index, mode) in MODES.into_iter().enumerate() {
        for (probe_index, probe) in PROBES.into_iter().enumerate() {
            let row = mode_index * PROBES.len() + probe_index;
            let mut summary = Summary::default();
            for post in 0..POSTS {
                let tag = TAG_BASE + row * POSTS + post;
                let (echo, effects) = measure_post(&window, &desktop, &events, probe, tag);
                summary.record(echo, effects);
            }
            assert!(
                !hook.overflow.load(Ordering::Acquire),
                "mouse hook diagnostic queue overflowed"
            );
            summary.print(&arch, probe, mode, &precision);
        }
    }
}
