//! WinEvent foreground HWND and event-clock readings.

use std::cell::RefCell;
use std::io;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::{
    Foundation::HWND,
    UI::{
        Accessibility::{SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK},
        WindowsAndMessaging::{
            DispatchMessageW, PeekMessageW, EVENT_SYSTEM_FOREGROUND, MSG, PM_REMOVE,
            WINEVENT_OUTOFCONTEXT,
        },
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForegroundEvent {
    pub number: u32,
    pub event_tick: u32,
}

thread_local! {
    static EVENTS: RefCell<Option<mpsc::SyncSender<ForegroundEvent>>> = const { RefCell::new(None) };
}

unsafe extern "system" fn foreground_event(
    _: HWINEVENTHOOK,
    _: u32,
    window: HWND,
    _: i32,
    _: i32,
    _: u32,
    event_tick: u32,
) {
    if !window.is_null() {
        let _ = EVENTS.try_with(|events| {
            if let Some(events) = events.borrow().as_ref() {
                let _ = events.try_send(ForegroundEvent {
                    number: window as usize as u32,
                    event_tick,
                });
            }
        });
    }
}

/// Owns the thread pumping the foreground hook. No input events are requested
/// or posted. The receiver is bounded and a slow consumer can miss events.
pub struct ForegroundEvents {
    receive: mpsc::Receiver<ForegroundEvent>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ForegroundEvents {
    pub fn start() -> io::Result<Self> {
        let (send, receive) = mpsc::sync_channel(64);
        let (started, ready) = mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("windows-foreground-events".into())
            .spawn(move || {
                EVENTS.replace(Some(send));
                // SAFETY: The callback has the WinEvent ABI and uses only a thread-
                // local sender. Registration and removal are on the same thread.
                let hook = unsafe {
                    SetWinEventHook(
                        EVENT_SYSTEM_FOREGROUND,
                        EVENT_SYSTEM_FOREGROUND,
                        null_mut(),
                        Some(foreground_event),
                        0,
                        0,
                        WINEVENT_OUTOFCONTEXT,
                    )
                };
                if hook.is_null() {
                    let _ = started.send(Err(io::Error::last_os_error()));
                    return;
                }
                if started.send(Ok(())).is_ok() {
                    while !stopping.load(Ordering::Acquire) {
                        let mut message = MSG::default();
                        // SAFETY: The message buffer is writable and belongs to this thread.
                        if unsafe { PeekMessageW(&mut message, null_mut(), 0, 0, PM_REMOVE) } != 0 {
                            // SAFETY: The message was read from this thread's own queue.
                            unsafe { DispatchMessageW(&message) };
                        } else {
                            thread::sleep(Duration::from_millis(1));
                        }
                    }
                }
                // SAFETY: The hook is live and is owned by this thread.
                unsafe { UnhookWinEvent(hook) };
            })?;
        let events = Self {
            receive,
            stop,
            thread: Some(thread),
        };
        ready.recv().map_err(io::Error::other)??;
        Ok(events)
    }

    pub fn next(&self, wait: Duration) -> Option<ForegroundEvent> {
        self.receive.recv_timeout(wait).ok()
    }
}

impl Drop for ForegroundEvents {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
