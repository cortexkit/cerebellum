use super::*;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use windows_sys::Win32::Foundation::{HINSTANCE, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

static PRESSED: AtomicU32 = AtomicU32::new(0);

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_COMMAND && wparam >> 16 == 0 {
        PRESSED.store((wparam & 0xffff) as u32, Ordering::Release);
    }
    // SAFETY: Forward the owning thread's unmodified message to Windows.
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

struct Controls {
    window: u32,
    buttons: [u32; 2],
    checkbox: u32,
    edit: u32,
    thread: Option<thread::JoinHandle<()>>,
}

impl Controls {
    fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let gui = thread::spawn(move || {
            let class = wide("STATIC");
            let window_title = wide("Cerebellum addressed controls test");
            // SAFETY: All windows are created and destroyed on this thread.
            // Class and title buffers remain live for their Win32 calls.
            unsafe {
                let module: HINSTANCE = GetModuleHandleW(ptr::null());
                let window = CreateWindowExW(
                    0,
                    class.as_ptr(),
                    window_title.as_ptr(),
                    WS_OVERLAPPEDWINDOW,
                    50,
                    50,
                    340,
                    260,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    module,
                    ptr::null(),
                );
                assert!(!window.is_null());
                assert_ne!(
                    SetWindowLongPtrW(window, GWLP_WNDPROC, window_proc as *const () as isize),
                    0
                );
                let child = |class: &str, title: &str, style: i32, id: usize, y: i32| {
                    let hwnd = CreateWindowExW(
                        0,
                        wide(class).as_ptr(),
                        wide(title).as_ptr(),
                        WS_CHILD | WS_VISIBLE | style as u32,
                        10,
                        y,
                        200,
                        30,
                        window,
                        id as HMENU,
                        module,
                        ptr::null(),
                    );
                    assert!(!hwnd.is_null());
                    hwnd as usize as u32
                };
                let buttons = [
                    child("Button", "Identical", BS_PUSHBUTTON, 1, 10),
                    child("Button", "Identical", BS_PUSHBUTTON, 2, 50),
                ];
                let checkbox = child("Button", "Check", BS_AUTOCHECKBOX, 3, 90);
                let edit = child("Edit", "before", ES_AUTOHSCROLL, 4, 130);
                ShowWindow(window, SW_SHOWNOACTIVATE);
                if tx
                    .send((window as usize as u32, buttons, checkbox, edit))
                    .is_ok()
                {
                    let mut message = MSG::default();
                    while GetMessageW(&mut message, ptr::null_mut(), 0, 0) > 0 {
                        if message.hwnd == window && message.message == WM_CLOSE {
                            break;
                        }
                        DispatchMessageW(&message);
                    }
                }
                DestroyWindow(window);
            }
        });
        let (window, buttons, checkbox, edit) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            window,
            buttons,
            checkbox,
            edit,
            thread: Some(gui),
        }
    }
}

impl Drop for Controls {
    fn drop(&mut self) {
        // SAFETY: The fixture thread created and owns this exact window.
        if unsafe { PostMessageW(self.window as usize as HWND, WM_CLOSE, 0, 0) } != 0 {
            self.thread.take().unwrap().join().unwrap();
        }
    }
}

fn exercise_owned_controls() {
    let controls = Controls::new();
    let foreground = crate::foreground_window_number();
    let pid = std::process::id();
    let ProcessStartTime::Started(generation) = process_start_time(pid) else {
        panic!("test process has no creation time");
    };
    let end = Instant::now() + Duration::from_secs(5);
    let [first, second] = controls.buttons;
    let (window, checkbox, edit) = (controls.window, controls.checkbox, controls.edit);
    with_scoped_uia(pid, generation, end, move |uia| -> Result<(), Failure> {
        let id = |window| {
            uia.runtime_id(&uia.at_window(window)?)
                .map(|id| id.unwrap())
        };
        let left = id(first)?;
        let right = id(second)?;
        assert_ne!(left, right);
        // This control exposes Invoke; requesting Toggle must not fall back to it.
        assert!(uia
            .toggle_at(window, &right, |_| Ok::<_, Failure>(()))
            .is_err());
        assert_eq!(PRESSED.load(Ordering::Acquire), 0);
        uia.invoke_at(window, &right, |_| Ok(()))?;
        while PRESSED.load(Ordering::Acquire) == 0 && Instant::now() < end {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(PRESSED.load(Ordering::Acquire), 2);
        uia.toggle_at(window, &id(checkbox)?, |_| Ok(()))?;
        let mut checked = 0;
        // SAFETY: BM_GETCHECK takes no input pointers; checked is writable and
        // the test retains the checkbox HWND until this callback returns.
        assert_ne!(
            unsafe {
                SendMessageTimeoutW(
                    checkbox as usize as HWND,
                    BM_GETCHECK,
                    0,
                    0,
                    SMTO_ABORTIFHUNG,
                    1000,
                    &mut checked,
                )
            },
            0
        );
        assert_eq!(checked, 1);
        uia.set_value_at(window, &id(edit)?, "after λ", |_, read_only| {
            assert!(!read_only);
            Ok(())
        })?;
        assert_eq!(
            uia.current_value(&uia.at_window(edit)?)?.as_deref(),
            Some("after λ")
        );
        Ok(())
    })
    .unwrap();
    assert_eq!(crate::foreground_window_number(), foreground);
}

#[test]
fn github_hosted_scoped_uia_actuates_only_owned_controls() {
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted")
        && std::env::var("RUNNER_ARCH").as_deref() == Ok("X64")
    {
        exercise_owned_controls();
    }
}
