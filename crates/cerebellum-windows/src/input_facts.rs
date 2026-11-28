//! Raw input observations and posts. The caller supplies the hook disposition.

use std::cell::RefCell;
use std::io;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    System::SystemInformation::GetTickCount,
    UI::{
        Accessibility::{SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK},
        Input::KeyboardAndMouse::{
            GetAsyncKeyState, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT,
            KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, MOUSEEVENTF_MOVE,
            MOUSEINPUT,
        },
        WindowsAndMessaging::{
            CallNextHookEx, DispatchMessageW, PeekMessageW, SetWindowsHookExW, UnhookWindowsHookEx,
            EVENT_OBJECT_FOCUS, EVENT_SYSTEM_FOREGROUND, HC_ACTION, KBDLLHOOKSTRUCT, MSG,
            MSLLHOOKSTRUCT, PM_NOREMOVE, PM_REMOVE, WH_KEYBOARD_LL, WH_MOUSE_LL,
            WINEVENT_OUTOFCONTEXT,
        },
    },
};

#[derive(Debug, Clone, Copy)]
pub enum RawInputEvent {
    Keyboard {
        tag: usize,
        key: u32,
        flags: u32,
        up: bool,
        injected: bool,
        event_tick: u32,
    },
    Mouse {
        tag: usize,
        message: u32,
        flags: u32,
        injected: bool,
        event_tick: u32,
    },
    Foreground {
        event_tick: u32,
    },
    Focus {
        event_tick: u32,
    },
}

type InputCallback = Box<dyn Fn(RawInputEvent) -> bool + Send>;
thread_local! {
    static INPUT_CALLBACK: RefCell<Option<InputCallback>> = const { RefCell::new(None) };
}

fn dispatch(event: RawInputEvent) -> bool {
    // No Rust unwind may cross the system callback ABI.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        INPUT_CALLBACK.with_borrow(|read| read.as_ref().is_some_and(|callback| callback(event)))
    }))
    .unwrap_or(false)
}

unsafe extern "system" fn keyboard(code: i32, message: WPARAM, data: LPARAM) -> LRESULT {
    if code == HC_ACTION as i32 && data != 0 {
        // SAFETY: HC_ACTION provides a KBDLLHOOKSTRUCT for this call.
        let event = unsafe { &*(data as *const KBDLLHOOKSTRUCT) };
        if dispatch(RawInputEvent::Keyboard {
            tag: event.dwExtraInfo,
            key: event.vkCode,
            flags: event.flags,
            up: event.flags & 0x80 != 0,
            injected: event.flags & 0x10 != 0,
            event_tick: event.time,
        }) {
            return 1;
        }
    }
    // SAFETY: Forward the unchanged hook arguments; the first parameter is ignored.
    unsafe { CallNextHookEx(null_mut(), code, message, data) }
}

unsafe extern "system" fn mouse(code: i32, message: WPARAM, data: LPARAM) -> LRESULT {
    if code == HC_ACTION as i32 && data != 0 {
        // SAFETY: HC_ACTION provides an MSLLHOOKSTRUCT for this call.
        let event = unsafe { &*(data as *const MSLLHOOKSTRUCT) };
        if dispatch(RawInputEvent::Mouse {
            tag: event.dwExtraInfo,
            message: message as u32,
            flags: event.flags,
            injected: event.flags & 1 != 0,
            event_tick: event.time,
        }) {
            return 1;
        }
    }
    // SAFETY: Forward the unchanged hook arguments; the first parameter is ignored.
    unsafe { CallNextHookEx(null_mut(), code, message, data) }
}

unsafe extern "system" fn window_event(
    _: HWINEVENTHOOK,
    event: u32,
    _: HWND,
    _: i32,
    _: i32,
    _: u32,
    event_tick: u32,
) {
    match event {
        EVENT_SYSTEM_FOREGROUND => dispatch(RawInputEvent::Foreground { event_tick }),
        EVENT_OBJECT_FOCUS => dispatch(RawInputEvent::Focus { event_tick }),
        _ => false,
    };
}

pub struct InputHooks {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl InputHooks {
    /// `focus_pid` installs the foreground hook and a process-filtered focus hook.
    /// The callback runs on the pump thread and must not block.
    /// Success means the pump thread created its message queue and installed
    /// every requested hook, not that any input has been observed yet.
    pub fn start(
        focus_pid: Option<u32>,
        wait: Duration,
        callback: impl Fn(RawInputEvent) -> bool + Send + 'static,
    ) -> io::Result<Self> {
        let (started, ready) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("windows-input-events".into())
            .spawn(move || {
                INPUT_CALLBACK.replace(Some(Box::new(callback)));
                // SAFETY: All callbacks have the system ABI. LL hooks execute
                // on this thread, with callbacks in the current executable.
                unsafe {
                    let mut message = MSG::default();
                    // PeekMessage creates this thread's queue even when it is
                    // empty. Create it before installing or reporting readiness.
                    PeekMessageW(&mut message, null_mut(), 0, 0, PM_NOREMOVE);
                    let keyboard = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard), null_mut(), 0);
                    let mouse = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse), null_mut(), 0);
                    let mut events = [null_mut(); 2];
                    if let Some(pid) = focus_pid.filter(|pid| *pid != 0) {
                        for (slot, event, process) in [
                            (0, EVENT_SYSTEM_FOREGROUND, 0),
                            (1, EVENT_OBJECT_FOCUS, pid),
                        ] {
                            events[slot] = SetWinEventHook(
                                event,
                                event,
                                null_mut(),
                                Some(window_event),
                                process,
                                0,
                                WINEVENT_OUTOFCONTEXT,
                            );
                        }
                    }
                    let installed = !keyboard.is_null()
                        && !mouse.is_null()
                        && (focus_pid.is_none() || events.iter().all(|hook| !hook.is_null()));
                    if started.send(installed).is_ok() && installed {
                        while !stopping.load(Ordering::Acquire) {
                            if PeekMessageW(&mut message, null_mut(), 0, 0, PM_REMOVE) != 0 {
                                DispatchMessageW(&message);
                            } else {
                                thread::sleep(Duration::from_millis(1));
                            }
                        }
                    }
                    for hook in events.into_iter().filter(|hook| !hook.is_null()) {
                        UnhookWinEvent(hook);
                    }
                    for hook in [keyboard, mouse].into_iter().filter(|hook| !hook.is_null()) {
                        UnhookWindowsHookEx(hook);
                    }
                }
            })?;
        let hooks = Self {
            stop,
            thread: Some(thread),
        };
        if ready.recv_timeout(wait) == Ok(true) {
            Ok(hooks)
        } else {
            Err(io::Error::other("Windows input hooks did not start"))
        }
    }
}

impl Drop for InputHooks {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Do not wait on a stalled pump. Once resumed it only unhooks; callers
        // must deactivate any swallowing callback before dropping this handle.
        drop(self.thread.take());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawInputPost {
    VirtualKey { key: u16, up: bool, extended: bool },
    Unicode { unit: u16, up: bool },
    RelativeMouseMove { x: i32, y: i32 },
}

pub fn post_input(tag: usize, events: &[RawInputPost]) -> usize {
    let raw: Vec<_> = events
        .iter()
        .map(|event| {
            let keyboard = |key, scan, flags| INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 {
                    ki: KEYBDINPUT {
                        wVk: key,
                        wScan: scan,
                        dwFlags: flags,
                        time: 0,
                        dwExtraInfo: tag,
                    },
                },
            };
            let released = |up| if up { KEYEVENTF_KEYUP } else { 0 };
            match *event {
                RawInputPost::VirtualKey { key, up, extended } => keyboard(
                    key,
                    0,
                    released(up) | if extended { KEYEVENTF_EXTENDEDKEY } else { 0 },
                ),
                RawInputPost::Unicode { unit, up } => {
                    keyboard(0, unit, released(up) | KEYEVENTF_UNICODE)
                }
                RawInputPost::RelativeMouseMove { x, y } => INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 {
                        mi: MOUSEINPUT {
                            dx: x,
                            dy: y,
                            mouseData: 0,
                            dwFlags: MOUSEEVENTF_MOVE,
                            time: 0,
                            dwExtraInfo: tag,
                        },
                    },
                },
            }
        })
        .collect();
    let Ok(len) = raw.len().try_into() else {
        return 0;
    };
    // SAFETY: `raw` holds `len` initialized INPUT values for the duration of the call.
    unsafe { SendInput(len, raw.as_ptr(), std::mem::size_of::<INPUT>() as i32) as usize }
}

pub fn async_key_down(key: u8) -> bool {
    // SAFETY: GetAsyncKeyState takes only a virtual-key value.
    unsafe { GetAsyncKeyState(i32::from(key)) < 0 }
}

pub fn input_tick() -> u32 {
    // SAFETY: GetTickCount takes no arguments and returns a value.
    unsafe { GetTickCount() }
}

#[cfg(test)]
mod tests;
