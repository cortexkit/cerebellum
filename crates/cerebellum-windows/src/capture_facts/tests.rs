use super::*;
use std::ptr::{null, null_mut};
use std::sync::mpsc;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, DispatchMessageW, GetForegroundWindow, GetMessageW,
    GetWindowLongPtrW, PostMessageW, SetWindowDisplayAffinity, SetWindowTextW, ShowWindow,
    GWL_EXSTYLE, MSG, SW_SHOWNOACTIVATE, WDA_EXCLUDEFROMCAPTURE, WM_CLOSE, WS_EX_LAYERED,
    WS_OVERLAPPEDWINDOW,
};

fn jpeg_dimensions(bytes: &[u8]) -> (u16, u16) {
    assert!(bytes.starts_with(&[0xff, 0xd8]) && bytes.ends_with(&[0xff, 0xd9]));
    let mut cursor = 2;
    while bytes[cursor..].starts_with(&[0xff]) {
        let marker = bytes[cursor + 1];
        let length = u16::from_be_bytes(bytes[cursor + 2..cursor + 4].try_into().unwrap());
        if matches!(marker, 0xc0..=0xc2) {
            let height = u16::from_be_bytes(bytes[cursor + 5..cursor + 7].try_into().unwrap());
            let width = u16::from_be_bytes(bytes[cursor + 7..cursor + 9].try_into().unwrap());
            return (width, height);
        }
        assert_ne!(marker, 0xda, "no frame header before scan");
        cursor += 2 + usize::from(length);
    }
    panic!("no JPEG frame header")
}

#[test]
fn wic_scales_bgra_to_a_jpeg_with_the_requested_dimensions() {
    let _apartment = Apartment::enter().unwrap();
    let source = DesktopFrame {
        info: WindowFrameMetadata {
            width: 37,
            height: 21,
            received_at: Instant::now(),
        },
        bgra: [10, 20, 30, 0].repeat(37 * 21),
    };
    let bytes = jpeg::encode(&source, 17, 11).unwrap();
    assert_eq!(jpeg_dimensions(&bytes), (17, 11));
}

struct Fixture {
    hwnd: usize,
    gui: Option<std::thread::JoinHandle<()>>,
}

impl Fixture {
    fn new() -> Self {
        let (tx, rx) = mpsc::sync_channel(1);
        let gui = std::thread::spawn(move || {
            // Use the system's STATIC class to own a window without a custom
            // callback. No foreign window is dismissed or activated.
            let class: Vec<u16> = "STATIC\0".encode_utf16().collect();
            let title: Vec<u16> = "WGC fixture / first marker\0".encode_utf16().collect();
            unsafe {
                let hwnd = CreateWindowExW(
                    0,
                    class.as_ptr(),
                    title.as_ptr(),
                    WS_OVERLAPPEDWINDOW,
                    80,
                    80,
                    480,
                    360,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null(),
                );
                assert!(!hwnd.is_null(), "create the fixture window");
                ShowWindow(hwnd, SW_SHOWNOACTIVATE);
                if tx.send(hwnd as usize).is_ok() {
                    let mut message = MSG::default();
                    while GetMessageW(&mut message, null_mut(), 0, 0) > 0 {
                        if message.hwnd == hwnd && message.message == WM_CLOSE {
                            break;
                        }
                        DispatchMessageW(&message);
                    }
                }
                DestroyWindow(hwnd);
            }
        });
        let hwnd = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("start fixture window");
        Self {
            hwnd,
            gui: Some(gui),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if unsafe { PostMessageW(self.hwnd as _, WM_CLOSE, 0, 0) } != 0 {
            self.gui.take().unwrap().join().expect("fixture teardown");
        }
    }
}

#[test]
#[ignore = "requires a split-token medium-integrity Windows console, Default input desktop and WGC"]
fn wgc_captures_and_encodes_fresh_frames_then_tears_down() {
    assert!(matches!(
        crate::current_session_provenance(),
        crate::SessionProvenance::Console { .. }
    ));
    let token = crate::current_process_token_facts().expect("read test token");
    assert!(!token.elevated && token.integrity_rid == 0x2000);
    assert_eq!(
        crate::current_process_token_elevation_type(),
        Some(crate::TokenElevationType::Limited)
    );
    assert_eq!(crate::input_desktop_name().unwrap(), "Default");
    set_process_per_monitor_v2();
    assert!(per_monitor_v2(), "Per-Monitor-V2 is not established");
    assert_eq!(
        capture_support(),
        Some(true),
        "graphics capture must be available"
    );
    let foreground = unsafe { GetForegroundWindow() };
    assert!(!foreground.is_null(), "runner has no foreground window");
    let fixture = Fixture::new();
    let read = || {
        first_window_jpeg(
            fixture.hwnd as u32,
            Instant::now() + Duration::from_secs(2),
            &|| true,
            |info| {
                assert!(info.width > 240 && info.height > 180);
                Some((240, 180))
            },
        )
        .expect("start and close an independent capture session")
        .expect("compositor delivers first frame")
    };
    let first = read();
    let marker: Vec<u16> = "WGC fixture / SECOND, different marker\0"
        .encode_utf16()
        .collect();
    assert_ne!(
        unsafe { SetWindowTextW(fixture.hwnd as _, marker.as_ptr()) },
        0
    );
    let second = read();
    for bytes in [&first, &second] {
        assert_eq!(jpeg_dimensions(bytes), (240, 180));
    }
    assert_ne!(
        first, second,
        "second independent session did not show the changed marker"
    );
    assert_eq!(unsafe { GetForegroundWindow() }, foreground);
}

#[test]
fn github_hosted_affinity_and_wgc_measurement() {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
        || std::env::var("RUNNER_ARCH").as_deref() != Ok("X64")
    {
        return;
    }
    let log = |message: std::fmt::Arguments<'_>| {
        use std::io::Write;
        // The workflow captures normal libtest output even on success.
        writeln!(
            std::io::stdout().lock(),
            "S6 affinity measurement: {message}"
        )
        .unwrap();
    };
    set_process_per_monitor_v2();
    let ordinary = Fixture::new();
    let style = unsafe { GetWindowLongPtrW(ordinary.hwnd as _, GWL_EXSTYLE) } as u32;
    assert_eq!(style & WS_EX_LAYERED, 0, "ordinary fixture is not layered");
    let affinity = window_capture_properties(ordinary.hwnd as u32).display_affinity;
    log(format_args!(
        "ordinary nonlayered HWND: {affinity:#x?} (None means GetWindowDisplayAffinity failed)"
    ));

    let own = Fixture::new();
    let setting = unsafe { SetWindowDisplayAffinity(own.hwnd as _, WDA_EXCLUDEFROMCAPTURE) };
    let set_error = (setting == 0).then(std::io::Error::last_os_error);
    let affinity = window_capture_properties(own.hwnd as u32).display_affinity;
    log(format_args!(
        "WDA_EXCLUDEFROMCAPTURE: Set error={set_error:?}, Get={affinity:#x?}, WGC IsSupported={:?}",
        capture_support()
    ));
    let _apartment = Apartment::enter().expect("initialize WinRT for the measurement");
    // Deliberately call WGC directly on the test-owned fixture to measure the
    // OS's result without the caller's display-affinity gate.
    let deadline = Instant::now() + Duration::from_secs(2);
    match first_window_frame(own.hwnd as u32, deadline, &|| true) {
        Err(error) => log(format_args!("WGC result: error {error:?}")),
        Ok(None) => log(format_args!("WGC result: no frame within 2 s")),
        Ok(Some(frame)) => {
            let black = frame
                .bgra
                .as_chunks::<4>()
                .0
                .iter()
                .all(|pixel| pixel[..3] == [0; 3]);
            let result = if black {
                "black frame"
            } else {
                "non-black pixels"
            };
            log(format_args!(
                "WGC result: {result}, {}x{}",
                frame.info.width, frame.info.height
            ));
        }
    }
    assert!(
        set_error.is_none(),
        "failed to set affinity on the test-owned window: {set_error:?}"
    );
}
