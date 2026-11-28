use super::{cursor_position, Receiver, RestorePointer};
use crate::{post_input, InputHooks, RawInputEvent, RawInputPost};
use std::sync::{atomic::AtomicBool, atomic::Ordering, mpsc, Arc};
use std::time::{Duration, Instant};
use windows_sys::Win32::{
    Foundation::POINT,
    UI::{Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
};

const POSTS: usize = 50;
const TAG_BASE: usize = 0xC3B2_0000;
const PROBES: [Probe; 4] = [Probe::A, Probe::B, Probe::C, Probe::Control];
const MODES: [&str; 2] = ["swallow", "pass"];
const ROWS: usize = PROBES.len() * MODES.len();
const ECHO_LIMIT: Duration = Duration::from_secs(2);
const PROBE_LIMIT: Duration = Duration::from_millis(30);
const EFFECT_SETTLE: Duration = Duration::from_millis(100);
const POLL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug)]
enum Probe {
    A,
    B,
    C,
    Control,
}

impl Probe {
    fn post(self, tag: usize, dx: i32) -> usize {
        let flags = match self {
            Self::A => MOUSEEVENTF_MOVE | MOUSEEVENTF_MOVE_NOCOALESCE,
            Self::B => MOUSEEVENTF_WHEEL,
            Self::C => MOUSEEVENTF_MOVE,
            Self::Control => {
                return post_input(tag, &[RawInputPost::RelativeMouseMove { x: 0, y: 0 }]);
            }
        };
        let input = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy: 0,
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
struct Effects {
    tagged_message: bool,
    other_mouse_message: bool,
    cursor_delta: u32,
}

fn pump_fixture(window: &Receiver, tag: usize, effects: &mut Effects) {
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
                if GetMessageExtraInfo() as usize == tag {
                    effects.tagged_message = true;
                } else {
                    effects.other_mouse_message = true;
                }
            }
            DispatchMessageW(&message);
        }
    }
}

fn cursor_delta(from: POINT, to: POINT) -> u32 {
    from.x.abs_diff(to.x).max(from.y.abs_diff(to.y))
}

fn guard_post(window: &Receiver, probe: Probe, original: POINT) -> i32 {
    let dx = if matches!(probe, Probe::C) {
        // Windows can accelerate a relative move by up to four times.
        [1, -1]
            .into_iter()
            .find(|direction| {
                (0..=4).all(|distance| {
                    window.contains_client_point(POINT {
                        x: original.x.saturating_add(direction * distance),
                        y: original.y,
                    })
                })
            })
            .expect("a one-pixel move and its accelerated path must stay inside the owned client")
    } else {
        assert!(
            window.contains_client_point(original),
            "pointer must be inside the owned client"
        );
        0
    };
    assert_eq!(
        cursor_delta(original, cursor_position()),
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
    dx
}

fn measure_post(
    window: &Receiver,
    events: &mpsc::Receiver<(usize, Instant)>,
    probe: Probe,
    tag: usize,
) -> (Option<Duration>, Effects) {
    // Drain setup and restoration messages before recording the next post.
    pump_fixture(window, tag, &mut Effects::default());
    let original = cursor_position();
    let dx = guard_post(window, probe, original);
    let restore = RestorePointer(original);
    let started = Instant::now();
    assert_eq!(
        probe.post(tag, dx),
        1,
        "SendInput rejected {probe:?} (tag {tag:#x})"
    );
    let echo_deadline = started + ECHO_LIMIT;
    let mut echo = None;
    let mut effects = Effects::default();
    loop {
        pump_fixture(window, tag, &mut effects);
        effects.cursor_delta = effects
            .cursor_delta
            .max(cursor_delta(original, cursor_position()));
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
            break;
        }
        std::thread::sleep(remaining.min(POLL));
    }
    drop(restore);
    assert_eq!(
        cursor_delta(original, cursor_position()),
        0,
        "fixture pointer was not restored"
    );
    (echo.map(|at| at - started), effects)
}

#[derive(Default)]
struct Summary {
    echoes: Vec<Duration>,
    moved: usize,
    max_delta: u32,
    tagged_messages: usize,
    other_mouse_messages: usize,
}

impl Summary {
    fn record(&mut self, echo: Option<Duration>, effects: Effects) {
        self.echoes.extend(echo);
        self.moved += usize::from(effects.cursor_delta != 0);
        self.max_delta = self.max_delta.max(effects.cursor_delta);
        self.tagged_messages += usize::from(effects.tagged_message);
        self.other_mouse_messages += usize::from(effects.other_mouse_message);
    }

    fn print(mut self, arch: &str, probe: Probe, mode: &str) {
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
        println!(
            "{arch} | {probe:?} | {mode} | {on_time}/{POSTS} | {n}/{POSTS} | {latency} | {}/{POSTS} | {} | {}/{POSTS} | {}/{POSTS}",
            self.moved, self.max_delta, self.tagged_messages, self.other_mouse_messages
        );
    }
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
    let window = Receiver::new();
    // SAFETY: The fixture was created by this thread; focus has no other target.
    unsafe { SetFocus(window.0) };
    let (hook, events) = Hook::new();
    println!(
        "Mouse probe measurement: A=zero move + NOCOALESCE, B=zero wheel, C=one-pixel move, Control=original zero move."
    );
    println!(
        "Effects sampled until 100 ms after an echo, or 2 s from posting without one. Fixture columns count posts with at least one queued mouse message (matching tag / other)."
    );
    println!(
        "arch | probe | hook | echo <=30 ms | echo <=2 s | latency ms min/median/p95/max | cursor moved | max delta px | fixture tagged | fixture other"
    );
    for (mode_index, mode) in MODES.into_iter().enumerate() {
        for (probe_index, probe) in PROBES.into_iter().enumerate() {
            let row = mode_index * PROBES.len() + probe_index;
            let mut summary = Summary::default();
            for post in 0..POSTS {
                let tag = TAG_BASE + row * POSTS + post;
                let (echo, effects) = measure_post(&window, &events, probe, tag);
                summary.record(echo, effects);
            }
            assert!(
                !hook.overflow.load(Ordering::Acquire),
                "mouse hook diagnostic queue overflowed"
            );
            summary.print(&arch, probe, mode);
        }
    }
}
