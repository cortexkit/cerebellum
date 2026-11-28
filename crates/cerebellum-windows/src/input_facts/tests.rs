use super::*;
use crate::foreground_window_number;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;
use windows_sys::Win32::{
    Foundation::POINT, System::LibraryLoader::GetModuleHandleW, UI::WindowsAndMessaging::*,
};

mod mouse_probe_measurement;

static UNASSIGNED_UP: AtomicUsize = AtomicUsize::new(0);

unsafe extern "system" fn receiver(hwnd: HWND, message: u32, key: WPARAM, data: LPARAM) -> LRESULT {
    if (message, key) == (WM_KEYUP, 0xE8) {
        UNASSIGNED_UP.fetch_add(1, Ordering::Release);
    }
    // SAFETY: The default procedure receives the original system message.
    unsafe { DefWindowProcW(hwnd, message, key, data) }
}

struct Receiver(HWND);

impl Receiver {
    fn new() -> Self {
        let owned = Self::create(receiver);
        // SAFETY: The receiver is an owned window on this thread.
        assert_ne!(
            unsafe { SetForegroundWindow(owned.0) },
            0,
            "foreground rights for the owned receiver"
        );
        assert_eq!(foreground_window_number(), Some(owned.0 as usize as u32));
        owned
    }

    fn create(proc: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT) -> Self {
        let pointer = cursor_position();
        let class: Vec<_> = "STATIC\0".encode_utf16().collect();
        let title: Vec<_> = "Cerebellum input observer fixture\0"
            .encode_utf16()
            .collect();
        // SAFETY: The buffers are nul-terminated; the receiver runs on the
        // thread owning the window, which also destroys it.
        unsafe {
            let window = CreateWindowExW(
                0,
                class.as_ptr(),
                title.as_ptr(),
                WS_POPUP | WS_VISIBLE,
                pointer.x.saturating_sub(110),
                pointer.y.saturating_sub(60),
                220,
                120,
                null_mut(),
                null_mut(),
                GetModuleHandleW(null_mut()),
                null_mut(),
            );
            assert!(!window.is_null());
            let owned = Self(window);
            assert_ne!(
                SetWindowLongPtrW(window, GWLP_WNDPROC, proc as *const () as isize),
                0
            );
            owned
        }
    }

    fn contains_client_point(&self, point: POINT) -> bool {
        let (Ok(x), Ok(y)) = (i16::try_from(point.x), i16::try_from(point.y)) else {
            return false;
        };
        let lparam = (u32::from(x as u16) | (u32::from(y as u16) << 16)) as i32 as isize;
        // SAFETY: Both calls use screen coordinates. WM_NCHITTEST reads no
        // borrowed memory and is sent only to our own window on this thread.
        unsafe {
            WindowFromPoint(point) == self.0
                && SendMessageW(self.0, WM_NCHITTEST, 0, lparam) == HTCLIENT as isize
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        // SAFETY: We own this window on this thread.
        unsafe { DestroyWindow(self.0) };
    }
}

fn cursor_position() -> POINT {
    let mut position = POINT::default();
    // SAFETY: The system writes into this local POINT.
    assert_ne!(unsafe { GetCursorPos(&mut position) }, 0);
    position
}

struct RestorePointer(POINT);

impl Drop for RestorePointer {
    fn drop(&mut self) {
        let mut now = POINT::default();
        // SAFETY: These calls read or set the hosted fixture's desktop cursor.
        unsafe {
            if GetCursorPos(&mut now) != 0 && (now.x, now.y) != (self.0.x, self.0.y) {
                SetCursorPos(self.0.x, self.0.y);
            }
        }
    }
}

const TAG: usize = 0xC3B1_5A09;
const MOUSE_CONTROL_TAG: usize = TAG ^ 1;
const WAIT: Duration = Duration::from_secs(2);
const PROBE_BOUND: Duration = Duration::from_millis(30);

#[derive(Debug, PartialEq, Eq)]
enum Echo {
    ZeroMove,
    KeyboardMarker,
    NonzeroMove,
}

fn echo(event: RawInputEvent) -> Option<Echo> {
    match event {
        RawInputEvent::Mouse {
            tag: TAG,
            message: WM_MOUSEMOVE,
            injected: true,
            ..
        } => Some(Echo::ZeroMove),
        RawInputEvent::Mouse {
            tag: MOUSE_CONTROL_TAG,
            message: WM_MOUSEMOVE,
            injected: true,
            ..
        } => Some(Echo::NonzeroMove),
        RawInputEvent::Keyboard {
            tag: TAG,
            key: 0xE8,
            up: true,
            injected: true,
            ..
        } => Some(Echo::KeyboardMarker),
        _ => None,
    }
}

struct Observation {
    event: RawInputEvent,
    at: Instant,
}

fn report_observed(event: RawInputEvent) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match event {
        RawInputEvent::Keyboard { tag, key, flags, up, injected, event_tick } => writeln!(out,
            "S9 keyboard vk={key:#04x} flags={flags:#04x} up={up} injected={injected} time={event_tick} tag={tag:#x}"),
        RawInputEvent::Mouse { tag, message, flags, injected, event_tick } => writeln!(out,
            "S9 mouse message={message:#06x} flags={flags:#04x} injected={injected} time={event_tick} tag={tag:#x}"),
        RawInputEvent::Foreground { event_tick } => writeln!(out, "S9 WinEvent foreground time={event_tick}"),
        RawInputEvent::Focus { event_tick } => writeln!(out, "S9 WinEvent focus time={event_tick}"),
    }.unwrap();
}

fn wait_for_echoes(
    events: &mpsc::Receiver<Observation>,
    deadline: Instant,
    ready: impl Fn(&[(Echo, Instant)]) -> bool,
) -> Vec<(Echo, Instant)> {
    let mut echoes = Vec::new();
    let record = |echoes: &mut Vec<_>, observation: Observation| {
        report_observed(observation.event);
        echoes.extend(echo(observation.event).map(|echo| (echo, observation.at)));
    };
    loop {
        // Dispatch the receiver's own key messages while the hook thread
        // independently records low-level observations.
        let mut message = MSG::default();
        while Instant::now() < deadline
            // SAFETY: The message comes from this thread's own queue.
            && unsafe { PeekMessageW(&mut message, null_mut(), 0, 0, PM_REMOVE) } != 0
        {
            unsafe { DispatchMessageW(&message) };
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || ready(&echoes) {
            for observation in events.try_iter().take(128) {
                record(&mut echoes, observation);
            }
            return echoes;
        }
        match events.recv_timeout(remaining.min(Duration::from_millis(2))) {
            Ok(observation) => record(&mut echoes, observation),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return echoes,
        }
    }
}

fn nonzero_mouse_control(window: &Receiver, events: &mpsc::Receiver<Observation>) {
    let original = cursor_position();
    use std::io::Write;
    // Windows can apply up to four times the requested relative delta.
    // Require even the longest possible move to stay wholly in this client.
    let dx = [1, -1].into_iter().find(|direction| {
        (0..=4).all(|distance| {
            window.contains_client_point(POINT {
                x: original.x.saturating_add(direction * distance),
                y: original.y,
            })
        })
    });
    let dx = dx
        .filter(|_| {
            let now = cursor_position();
            (now.x, now.y) == (original.x, original.y)
                && foreground_window_number() == Some(window.0 as usize as u32)
        })
        .expect("the pointer and full mouse control move must be in the owned foreground client");
    let restore = RestorePointer(original);
    let started = Instant::now();
    let accepted = post_input(
        MOUSE_CONTROL_TAG,
        &[RawInputPost::RelativeMouseMove { x: dx, y: 0 }],
    );
    let observed = wait_for_echoes(events, started + WAIT, |echoes| {
        echoes.iter().any(|(echo, _)| *echo == Echo::NonzeroMove)
    });
    drop(restore);
    let now = cursor_position();
    assert_eq!(
        (now.x, now.y),
        (original.x, original.y),
        "hosted pointer was not restored"
    );
    writeln!(
        std::io::stdout().lock(),
        "S9 one-pixel mouse control dx={dx} accepted={accepted} echoes={observed:?}"
    )
    .unwrap();
    assert_eq!(accepted, 1, "SendInput accepted the nonzero fixture move");
    assert!(
        observed.iter().any(|(echo, _)| *echo == Echo::NonzeroMove),
        "the nonzero move did not reach the mouse hook"
    );
}

#[test]
fn github_hosted_zero_move_has_no_echo_but_nonzero_move_reaches_hook() {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
        || std::env::var("RUNNER_ARCH").as_deref() != Ok("X64")
    {
        return;
    }
    use std::io::Write;
    assert_eq!(crate::input_desktop_name().as_deref().unwrap(), "Default");
    let window = Receiver::new();
    let hwnd = window.0 as usize as u32;
    let (report, events) = mpsc::sync_channel(128);
    let overflow = Arc::new(AtomicBool::new(false));
    let overflow_on_pump = Arc::clone(&overflow);
    let _hooks = InputHooks::start(
        Some(std::process::id()),
        Duration::from_secs(1),
        move |event| {
            // Timestamp the callback, not the later read from the test thread.
            let observation = Observation {
                event,
                at: Instant::now(),
            };
            if report.try_send(observation).is_err() {
                overflow_on_pump.store(true, Ordering::Release);
            }
            echo(event).is_some()
        },
    )
    .expect("pump ready with keyboard, mouse and WinEvent hooks installed");
    writeln!(
        std::io::stdout().lock(),
        "S9 pump ready; starting dual probe"
    )
    .unwrap();
    assert_eq!(foreground_window_number(), Some(hwnd));
    let start = Instant::now();
    assert_eq!(
        post_input(
            TAG,
            &[
                RawInputPost::RelativeMouseMove { x: 0, y: 0 },
                RawInputPost::VirtualKey {
                    key: 0xE8,
                    up: true,
                    extended: false
                },
            ]
        ),
        2,
        "SendInput accepted the fixture probe batch"
    );
    let probe_cutoff = start + PROBE_BOUND;
    let keyboard_cutoff = start + WAIT;
    let probes = wait_for_echoes(&events, keyboard_cutoff, |echoes| {
        Instant::now() >= probe_cutoff
            && echoes.iter().any(|(echo, _)| *echo == Echo::KeyboardMarker)
    });
    assert!(
        !overflow.load(Ordering::Acquire),
        "hook diagnostic queue overflowed"
    );
    // GitHub Actions run 46120211536 saw both the keyboard marker and the
    // nonzero control, but no callback for the original zero-distance move.
    assert!(
        probes
            .iter()
            .any(|(echo, at)| *echo == Echo::KeyboardMarker && *at <= keyboard_cutoff),
        "the keyboard probe did not echo: {probes:?}"
    );
    assert!(!probes.iter().any(|(echo, at)| *echo == Echo::ZeroMove && *at <= probe_cutoff),
        "the Windows zero-distance move now echoes within {PROBE_BOUND:?}; review the production probe: {probes:?}");
    nonzero_mouse_control(&window, &events);
    assert!(
        !overflow.load(Ordering::Acquire),
        "hook diagnostic queue overflowed"
    );
    assert_eq!(
        UNASSIGNED_UP.load(Ordering::Acquire),
        0,
        "no keyboard marker should reach the owned receiver"
    );
}
