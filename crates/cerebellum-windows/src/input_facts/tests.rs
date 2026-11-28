use super::*;
use crate::foreground_window_number;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;
use windows_sys::Win32::{
    Foundation::POINT, System::LibraryLoader::GetModuleHandleW, UI::WindowsAndMessaging::*,
};

static DELIVERED: AtomicUsize = AtomicUsize::new(0);
static UNASSIGNED_UP: AtomicUsize = AtomicUsize::new(0);

unsafe extern "system" fn receiver(hwnd: HWND, message: u32, key: WPARAM, data: LPARAM) -> LRESULT {
    match (message, key) {
        (WM_KEYDOWN, 0x87) => {
            DELIVERED.fetch_add(1, Ordering::Release);
        }
        (WM_KEYUP, 0xE8) => {
            UNASSIGNED_UP.fetch_add(1, Ordering::Release);
        }
        _ => {}
    }
    // SAFETY: The default procedure receives the original system message.
    unsafe { DefWindowProcW(hwnd, message, key, data) }
}

struct Receiver(HWND);

impl Receiver {
    fn new() -> Self {
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
                SetWindowLongPtrW(window, GWLP_WNDPROC, receiver as *const () as isize),
                0
            );
            assert_ne!(
                SetForegroundWindow(window),
                0,
                "foreground rights for the owned receiver"
            );
            assert_eq!(foreground_window_number(), Some(window as usize as u32));
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

#[derive(Debug, PartialEq, Eq)]
enum Echo {
    ZeroMove,
    KeyboardMarker,
    KeyDown,
    KeyUp,
    ForeignDown,
    ForeignUp,
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
        RawInputEvent::Keyboard {
            tag: TAG,
            key: 0x87,
            up,
            injected: true,
            ..
        } => Some(if up { Echo::KeyUp } else { Echo::KeyDown }),
        RawInputEvent::Keyboard {
            tag: 0,
            key: 0x87,
            up,
            injected: true,
            ..
        } => Some(if up {
            Echo::ForeignUp
        } else {
            Echo::ForeignDown
        }),
        _ => None,
    }
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
    events: &mpsc::Receiver<RawInputEvent>,
    deadline: Instant,
    ready: impl Fn(&[Echo]) -> bool,
) -> Vec<Echo> {
    let mut echoes = Vec::new();
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
            return echoes;
        }
        match events.recv_timeout(remaining.min(Duration::from_millis(2))) {
            Ok(event) => {
                report_observed(event);
                echoes.extend(echo(event));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return echoes,
        }
    }
}

fn nonzero_mouse_control(window: &Receiver, events: &mpsc::Receiver<RawInputEvent>) {
    let original = cursor_position();
    let mut out = std::io::stdout().lock();
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
    let Some(dx) = dx.filter(|_| {
        let now = cursor_position();
        (now.x, now.y) == (original.x, original.y)
            && foreground_window_number() == Some(window.0 as usize as u32)
    }) else {
        writeln!(out, "S9 nonzero mouse control unavailable: pointer and full move not in the owned foreground client").unwrap();
        return;
    };
    drop(out);
    let restore = RestorePointer(original);
    let started = Instant::now();
    let accepted = post_input(
        MOUSE_CONTROL_TAG,
        &[RawInputPost::RelativeMouseMove { x: dx, y: 0 }],
    );
    let observed = wait_for_echoes(events, started + WAIT, |echoes| {
        echoes.contains(&Echo::NonzeroMove)
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
}

#[test]
fn github_hosted_input_hooks_observe_both_probes_and_route_only_the_owned_fixture_key() {
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
            // Never wait for a logger inside the system callback.
            if report.try_send(event).is_err() {
                overflow_on_pump.store(true, Ordering::Release);
            }
            match echo(event) {
                Some(Echo::KeyDown | Echo::KeyUp) => foreground_window_number() != Some(hwnd),
                Some(_) => true,
                None => false,
            }
        },
    )
    .expect("pump ready with keyboard, mouse and WinEvent hooks installed");
    writeln!(
        std::io::stdout().lock(),
        "S9 pump ready; starting dual probe"
    )
    .unwrap();
    let key = |key, up| RawInputPost::VirtualKey {
        key,
        up,
        extended: false,
    };
    let post = |tag, events: &[RawInputPost]| {
        assert_eq!(foreground_window_number(), Some(hwnd));
        assert_eq!(
            post_input(tag, events),
            events.len(),
            "SendInput accepted the fixture batch"
        );
    };
    let start = Instant::now();
    post(
        TAG,
        &[
            RawInputPost::RelativeMouseMove { x: 0, y: 0 },
            key(0xE8, true),
        ],
    );
    let probes = wait_for_echoes(&events, start + WAIT, |echoes| {
        echoes.contains(&Echo::ZeroMove) && echoes.contains(&Echo::KeyboardMarker)
    });
    let probe = start.elapsed();
    assert!(
        !overflow.load(Ordering::Acquire),
        "hook diagnostic queue overflowed"
    );
    if !probes.contains(&Echo::ZeroMove) {
        // Test whether any move reaches the mouse hook. A successful control
        // cannot permit keyboard payload when either original echo is missing.
        nonzero_mouse_control(&window, &events);
    }
    assert!(
        !overflow.load(Ordering::Acquire),
        "hook diagnostic queue overflowed"
    );
    assert!(
        probes.len() == 2
            && probes.contains(&Echo::ZeroMove)
            && probes.contains(&Echo::KeyboardMarker),
        "expected one zero move and one key-up, observed {probes:?}"
    );

    let start_key = Instant::now();
    post(TAG, &[key(0x87, false), key(0x87, true), key(0xE8, true)]);
    post(0, &[key(0x87, false), key(0x87, true)]);
    let payload = wait_for_echoes(&events, start_key + WAIT, |echoes| {
        echoes.len() >= 5 && DELIVERED.load(Ordering::Acquire) != 0
    });
    assert!(
        !overflow.load(Ordering::Acquire),
        "hook diagnostic queue overflowed"
    );
    assert_eq!(
        payload,
        [
            Echo::KeyDown,
            Echo::KeyUp,
            Echo::KeyboardMarker,
            Echo::ForeignDown,
            Echo::ForeignUp
        ]
    );
    assert_eq!(
        DELIVERED.load(Ordering::Acquire),
        1,
        "only our tagged key reached the receiver"
    );
    assert_eq!(
        UNASSIGNED_UP.load(Ordering::Acquire),
        0,
        "no marker should reach the receiver"
    );
    writeln!(std::io::stdout().lock(), "Hosted S9 smoke, not bracket timing: two probes {probe:?}; tagged key and foreign-event observation {:?}", start_key.elapsed()).unwrap();
}
