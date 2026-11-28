use super::*;
use crate::foreground_window_number;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;
use windows_sys::Win32::{System::LibraryLoader::GetModuleHandleW, UI::WindowsAndMessaging::*};

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
                WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                20,
                20,
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
}

impl Drop for Receiver {
    fn drop(&mut self) {
        // SAFETY: We own this window on this thread.
        unsafe { DestroyWindow(self.0) };
    }
}

#[test]
fn github_hosted_input_hooks_observe_both_probes_and_route_only_the_owned_fixture_key() {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
        || std::env::var("RUNNER_ARCH").as_deref() != Ok("X64")
    {
        return;
    }
    assert_eq!(crate::input_desktop_name().as_deref().unwrap(), "Default");
    let window = Receiver::new();
    let hwnd = window.0 as usize as u32;
    let bits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&bits);
    let markers = Arc::new(AtomicUsize::new(0));
    let seen_markers = Arc::clone(&markers);
    const TAG: usize = 0xC3B1_5A09;
    let _hooks = InputHooks::start(
        Some(std::process::id()),
        Duration::from_secs(1),
        move |event| {
            let (flag, swallow) = match event {
                RawInputEvent::Mouse {
                    tag: TAG,
                    message: WM_MOUSEMOVE,
                    injected: true,
                    ..
                } => (1, true),
                RawInputEvent::Keyboard {
                    tag: TAG,
                    key: 0xE8,
                    up: true,
                    injected: true,
                    ..
                } => {
                    seen_markers.fetch_add(1, Ordering::Release);
                    (2, true)
                }
                RawInputEvent::Keyboard {
                    tag: TAG,
                    key: 0x87,
                    injected: true,
                    ..
                } => (4, foreground_window_number() != Some(hwnd)),
                RawInputEvent::Keyboard {
                    tag: 0,
                    key: 0x87,
                    injected: true,
                    ..
                } => (8, true),
                _ => (0, false),
            };
            seen.fetch_or(flag, Ordering::Release);
            swallow
        },
    )
    .expect("keyboard, mouse and WinEvent hooks installed");
    let key = |key, up| RawInputPost::VirtualKey {
        key,
        up,
        extended: false,
    };
    assert_eq!(foreground_window_number(), Some(hwnd));
    let start = Instant::now();
    assert_eq!(
        post_input(
            TAG,
            &[
                RawInputPost::RelativeMouseMove { x: 0, y: 0 },
                key(0xE8, true),
            ]
        ),
        2
    );
    let give_up = start + Duration::from_secs(2);
    while bits.load(Ordering::Acquire) & 3 != 3 && Instant::now() < give_up {
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        bits.load(Ordering::Acquire) & 3,
        3,
        "both typed probe echoes"
    );
    let probe = start.elapsed();
    assert_eq!(foreground_window_number(), Some(hwnd));
    let start_key = Instant::now();
    assert_eq!(
        post_input(TAG, &[key(0x87, false), key(0x87, true), key(0xE8, true)]),
        3
    );
    assert_eq!(foreground_window_number(), Some(hwnd));
    assert_eq!(post_input(0, &[key(0x87, false), key(0x87, true)]), 2);
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        let mut message = MSG::default();
        // SAFETY: These messages are from this thread's queue and are dispatched normally.
        unsafe {
            while PeekMessageW(&mut message, null_mut(), 0, 0, PM_REMOVE) != 0 {
                DispatchMessageW(&message);
            }
        }
        if bits.load(Ordering::Acquire) == 15
            && markers.load(Ordering::Acquire) == 2
            && DELIVERED.load(Ordering::Acquire) != 0
        {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(bits.load(Ordering::Acquire), 15);
    assert_eq!(
        markers.load(Ordering::Acquire),
        2,
        "keyboard probe and routing sentinel each echoed"
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
    use std::io::Write;
    writeln!(std::io::stdout().lock(), "Hosted S9 smoke, not bracket timing: two probes {probe:?}; tagged key and foreign-event observation {:?}", start_key.elapsed()).unwrap();
}
