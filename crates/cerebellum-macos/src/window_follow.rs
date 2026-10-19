//! Watching another application's window move, resize or close, so the agent
//! cursor's badge can stay on the element it points at.
//!
//! One thread, started the first time a window is watched, runs a Core
//! Foundation run loop that sleeps until something happens. Each watched
//! window has its own accessibility observer, whose notifications for that
//! window (moved, resized, destroyed) wake the thread; a kqueue registered for
//! each watched application's exit wakes it when the application quits, which
//! some applications do without reporting their windows destroyed. Nothing
//! runs between those events: there is no timer and no polling.
//!
//! Every observer is created, used and released on that one thread, so a
//! notification can never race the removal of its watch. Each notification
//! names its watch by number, not by pointer: one arriving for a watch already
//! removed finds nothing and is ignored.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use objc2_core_foundation::{
    kCFFileDescriptorReadCallBack, kCFRunLoopDefaultMode, CFFileDescriptor, CFOptionFlags,
    CFRetained, CFRunLoop, CFRunLoopSource, CFString, CFType,
};

use crate::ax_state::{owned, AxRetainedElement};

type CfTypeRef = *const c_void;

const AX_ERROR_SUCCESS: i32 = 0;
const MOVED: &str = "AXMoved";
const RESIZED: &str = "AXResized";
const DESTROYED: &str = "AXUIElementDestroyed";

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXObserverCreate(
        application: c_int,
        callback: unsafe extern "C" fn(CfTypeRef, CfTypeRef, CfTypeRef, *mut c_void),
        observer: *mut CfTypeRef,
    ) -> i32;
    fn AXObserverAddNotification(
        observer: CfTypeRef,
        element: CfTypeRef,
        notification: CfTypeRef,
        refcon: *mut c_void,
    ) -> i32;
    fn AXObserverRemoveNotification(
        observer: CfTypeRef,
        element: CfTypeRef,
        notification: CfTypeRef,
    ) -> i32;
    fn AXObserverGetRunLoopSource(observer: CfTypeRef) -> CfTypeRef;
    fn AXUIElementGetPid(element: CfTypeRef, pid: *mut c_int) -> i32;
}

/// `struct kevent` as the macOS kernel defines it.
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelEvent {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: *mut c_void,
}

#[repr(C)]
struct Timespec {
    seconds: isize,
    nanoseconds: isize,
}

const EVFILT_PROC: i16 = -5;
const EV_ADD: u16 = 0x0001;
const EV_DELETE: u16 = 0x0002;
const EV_ONESHOT: u16 = 0x0010;
const NOTE_EXIT: u32 = 0x8000_0000;

extern "C" {
    fn kqueue() -> c_int;
    fn kevent(
        queue: c_int,
        changes: *const KernelEvent,
        change_count: c_int,
        events: *mut KernelEvent,
        event_count: c_int,
        timeout: *const Timespec,
    ) -> c_int;
}

/// What happened to a watched window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AxWindowChange {
    Moved,
    Resized,
    /// The window was destroyed or its application quit. The watch reports
    /// nothing after this.
    Gone,
}

type Changed = Arc<dyn Fn(AxWindowChange) + Send + Sync>;

struct Watch {
    observer: CFRetained<CFType>,
    window: AxRetainedElement,
    pid: c_int,
    changed: Changed,
}

thread_local! {
    /// The live watches, by number. Only the follower thread touches it.
    static WATCHES: RefCell<HashMap<u64, Watch>> = RefCell::new(HashMap::new());
}

struct Follower {
    run_loop: CFRetained<CFRunLoop>,
    exits: c_int,
}

// SAFETY: the run loop is only used to schedule blocks on its own thread and
// to wake it, both of which Core Foundation documents as safe from any
// thread; the kqueue descriptor is a plain integer the kernel synchronises.
unsafe impl Send for Follower {}
// SAFETY: as above.
unsafe impl Sync for Follower {}

static FOLLOWER: OnceLock<Option<Follower>> = OnceLock::new();
static NEXT_WATCH: AtomicU64 = AtomicU64::new(1);

fn follower() -> Option<&'static Follower> {
    FOLLOWER
        .get_or_init(|| {
            let (ready, started) = std::sync::mpsc::channel();
            std::thread::Builder::new()
                .name("agent-cursor-window-follow".into())
                .spawn(move || run_follower(ready))
                .ok()?;
            started.recv().ok().flatten()
        })
        .as_ref()
}

fn run_follower(ready: std::sync::mpsc::Sender<Option<Follower>>) {
    // SAFETY: creates a kqueue descriptor, or -1.
    let exits = unsafe { kqueue() };
    if exits < 0 {
        let _ = ready.send(None);
        return;
    }
    // SAFETY: the descriptor is owned by the CFFileDescriptor from here on,
    // which closes it if it is ever invalidated; no context is passed.
    let descriptor =
        unsafe { CFFileDescriptor::new(None, exits, true, Some(on_exit), std::ptr::null()) };
    let (Some(descriptor), Some(run_loop)) = (descriptor, CFRunLoop::current()) else {
        let _ = ready.send(None);
        return;
    };
    let Some(source) = CFFileDescriptor::new_run_loop_source(None, Some(&descriptor), 0) else {
        let _ = ready.send(None);
        return;
    };
    // SAFETY: kCFRunLoopDefaultMode is a constant string Core Foundation
    // exports for the life of the process, so the reference never dangles.
    let mode = unsafe { kCFRunLoopDefaultMode };
    run_loop.add_source(Some(&source), mode);
    descriptor.enable_call_backs(kCFFileDescriptorReadCallBack);
    let _ = ready.send(Some(Follower {
        run_loop: run_loop.clone(),
        exits,
    }));
    // The exit source never goes away, so this sleeps until a notification,
    // an exit or a scheduled block, for the life of the process.
    CFRunLoop::run();
}

/// Run `work` on the follower thread, soon. Never waits for it.
fn on_follower(work: impl FnOnce() + Send + 'static) -> bool {
    let Some(follower) = follower() else {
        return false;
    };
    // The block may be called only once by Core Foundation, but its type
    // must be callable many times; the work is taken out on the first call.
    let work = Mutex::new(Some(work));
    let block = block2::RcBlock::new(move || {
        if let Some(work) = work.lock().ok().and_then(|mut work| work.take()) {
            work();
        }
    });
    // SAFETY: CFRunLoopPerformBlock may be called from any thread; it copies
    // the block, and the mode is a process-lifetime constant.
    unsafe {
        let mode = kCFRunLoopDefaultMode.map(|mode| -> &CFType { mode });
        follower.run_loop.perform_block(mode, Some(&block));
    }
    follower.run_loop.wake_up();
    true
}

/// A running watch. Dropping it removes the window's observer.
#[derive(Debug)]
pub struct AxWindowWatch(u64);

impl Drop for AxWindowWatch {
    fn drop(&mut self) {
        let id = self.0;
        on_follower(move || remove(id));
    }
}

/// Watch `window` for moves, resizes and its end, reporting each to
/// `changed` on the follower thread until the watch is dropped. `None` when
/// the follower thread cannot run or the window's process cannot be named.
/// Registering happens on the follower thread, shortly after this returns;
/// if the accessibility API refuses it there, the watch simply never reports.
pub fn watch_window(
    window: &AxRetainedElement,
    changed: Box<dyn Fn(AxWindowChange) + Send + Sync>,
) -> Option<AxWindowWatch> {
    let mut pid: c_int = 0;
    // SAFETY: the element is retained for the call; `pid` is writable.
    if unsafe { AXUIElementGetPid(window.as_ptr(), &mut pid) } != AX_ERROR_SUCCESS || pid <= 0 {
        return None;
    }
    let id = NEXT_WATCH.fetch_add(1, Ordering::Relaxed);
    let window = AxRetainedElement(window.0.clone());
    let changed: Changed = Arc::from(changed);
    if !on_follower(move || add(id, pid, window, changed)) {
        return None;
    }
    Some(AxWindowWatch(id))
}

fn add(id: u64, pid: c_int, window: AxRetainedElement, changed: Changed) {
    let mut observer: CfTypeRef = std::ptr::null();
    // SAFETY: `observer` is writable storage for one owned reference.
    if unsafe { AXObserverCreate(pid, on_notification, &mut observer) } != AX_ERROR_SUCCESS {
        return;
    }
    // SAFETY: a successful create returns one owned reference.
    let Some(observer) = (unsafe { owned(observer) }) else {
        return;
    };
    let observer_ptr: CfTypeRef = CFRetained::as_ptr(&observer).as_ptr().cast();
    let mut added = 0;
    for name in [MOVED, RESIZED, DESTROYED] {
        let name = CFString::from_static_str(name);
        // SAFETY: observer, window and name are retained for the call; the
        // refcon is the watch's number, never dereferenced.
        let code = unsafe {
            AXObserverAddNotification(
                observer_ptr,
                window.as_ptr(),
                CFRetained::as_ptr(&name).as_ptr().cast(),
                id as *mut c_void,
            )
        };
        added += usize::from(code == AX_ERROR_SUCCESS);
    }
    if added == 0 {
        return;
    }
    // SAFETY: the source is owned by the observer, which outlives its use
    // here; the cast only names its Core Foundation type.
    let source = unsafe { &*AXObserverGetRunLoopSource(observer_ptr).cast::<CFRunLoopSource>() };
    if let Some(run_loop) = CFRunLoop::current() {
        // SAFETY: kCFRunLoopDefaultMode is a constant string Core Foundation
        // exports for the life of the process, so the reference never dangles.
        run_loop.add_source(Some(source), unsafe { kCFRunLoopDefaultMode });
    }
    watch_exit(pid, EV_ADD | EV_ONESHOT);
    WATCHES.with(|watches| {
        watches.borrow_mut().insert(
            id,
            Watch {
                observer,
                window,
                pid,
                changed,
            },
        )
    });
}

fn remove(id: u64) {
    let Some(watch) = WATCHES.with(|watches| watches.borrow_mut().remove(&id)) else {
        return;
    };
    let observer: CfTypeRef = CFRetained::as_ptr(&watch.observer).as_ptr().cast();
    for name in [MOVED, RESIZED, DESTROYED] {
        let name = CFString::from_static_str(name);
        // SAFETY: all three are retained for the call.
        unsafe {
            AXObserverRemoveNotification(
                observer,
                watch.window.as_ptr(),
                CFRetained::as_ptr(&name).as_ptr().cast(),
            )
        };
    }
    // SAFETY: the observer owns its run-loop source and is still alive here
    // (it is released only when `watch` drops, after this); the cast only
    // names the source's Core Foundation type.
    let source = unsafe { &*AXObserverGetRunLoopSource(observer).cast::<CFRunLoopSource>() };
    if let Some(run_loop) = CFRunLoop::current() {
        // SAFETY: kCFRunLoopDefaultMode is a constant string Core Foundation
        // exports for the life of the process, so the reference never dangles.
        run_loop.remove_source(Some(source), unsafe { kCFRunLoopDefaultMode });
    }
    let still_watched = WATCHES.with(|watches| {
        watches
            .borrow()
            .values()
            .any(|other| other.pid == watch.pid)
    });
    if !still_watched {
        watch_exit(watch.pid, EV_DELETE);
    }
}

/// Add or remove the exit registration for `pid`. Failure is harmless: an
/// application already gone is reported by its windows' destruction or by the
/// next read of its window failing.
fn watch_exit(pid: c_int, flags: u16) {
    let Some(follower) = FOLLOWER.get().and_then(Option::as_ref) else {
        return;
    };
    let change = KernelEvent {
        ident: pid as usize,
        filter: EVFILT_PROC,
        flags,
        fflags: NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: `change` is one valid kevent registration read for the call;
    // passing no output buffer and a zero event count asks the kernel only to
    // apply it, so nothing is written back and the call never blocks.
    unsafe {
        kevent(
            follower.exits,
            &change,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
}

/// Report `change` to watch `id` without holding the registry while the
/// report runs, so the report itself may drop watches.
fn report(id: u64, change: AxWindowChange) {
    let changed = WATCHES.with(|watches| watches.borrow().get(&id).map(|w| w.changed.clone()));
    if let Some(changed) = changed {
        changed(change);
    }
}

unsafe extern "C" fn on_notification(
    _observer: CfTypeRef,
    _element: CfTypeRef,
    notification: CfTypeRef,
    refcon: *mut c_void,
) {
    if notification.is_null() {
        return;
    }
    // SAFETY: the accessibility API passes the notification's name, a live
    // CFString, for the duration of the callback.
    let name = unsafe { &*notification.cast::<CFString>() }.to_string();
    let id = refcon as u64;
    match name.as_str() {
        MOVED => report(id, AxWindowChange::Moved),
        RESIZED => report(id, AxWindowChange::Resized),
        DESTROYED => {
            report(id, AxWindowChange::Gone);
            remove(id);
        }
        _ => {}
    }
}

unsafe extern "C-unwind" fn on_exit(
    descriptor: *mut CFFileDescriptor,
    _types: CFOptionFlags,
    _info: *mut c_void,
) {
    let Some(follower) = FOLLOWER.get().and_then(Option::as_ref) else {
        return;
    };
    let mut events = [KernelEvent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }; 16];
    let zero = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: a buffer of 16 events and a zero timeout: it never waits.
    let count = unsafe {
        kevent(
            follower.exits,
            std::ptr::null(),
            0,
            events.as_mut_ptr(),
            events.len() as c_int,
            &zero,
        )
    };
    for event in events.iter().take(count.max(0) as usize) {
        if event.filter != EVFILT_PROC || event.fflags & NOTE_EXIT == 0 {
            continue;
        }
        let pid = event.ident as c_int;
        let ended: Vec<u64> = WATCHES.with(|watches| {
            watches
                .borrow()
                .iter()
                .filter(|(_, watch)| watch.pid == pid)
                .map(|(id, _)| *id)
                .collect()
        });
        for id in ended {
            report(id, AxWindowChange::Gone);
            remove(id);
        }
    }
    // Callbacks are one-shot; ask for the next exit.
    // SAFETY: Core Foundation passes the live descriptor this source wraps.
    if let Some(descriptor) = unsafe { descriptor.as_ref() } {
        descriptor.enable_call_backs(kCFFileDescriptorReadCallBack);
    }
}
