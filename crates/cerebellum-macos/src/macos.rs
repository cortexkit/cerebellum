//! The framework calls themselves.
//!
//! Only the C functions declared below need `unsafe`; the CoreGraphics entry
//! points are safe bindings. Every `unsafe` block here is therefore a real one,
//! which is the point of keeping them few.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_core_graphics::CGImage;
use objc2_foundation::NSError;
use objc2_screen_capture_kit::{
    SCContentFilter, SCScreenshotManager, SCShareableContent, SCStreamConfiguration, SCWindow,
};

/// The prefix of `struct proc_bsdinfo` from `<sys/proc_info.h>`, up to and
/// including the two fields this reads.
///
/// Declared in full rather than as an opaque buffer with offsets, because a
/// field added upstream would shift an offset silently while a named field
/// keeps its meaning. The size is asserted against what the kernel reports it
/// wrote, so a layout that disagrees with this system is refused rather than
/// interpreted.
#[repr(C)]
#[derive(Default)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    /// The kernel's process command-name buffer, `MAXCOMLEN` (16) bytes.
    pbi_comm: [c_char; 16],
    /// The kernel's process-name buffer, `2 * MAXCOMLEN` (32) bytes.
    pbi_name: [c_char; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    /// Process start time, seconds since the epoch.
    pbi_start_tvsec: u64,
    /// Process start time, microseconds within the second.
    pbi_start_tvusec: u64,
}

/// The `proc_pidinfo` flavor asking the kernel to fill a BSD process-information
/// structure, which is what [`ProcBsdInfo`] mirrors. `PROC_PIDTBSDINFO` from
/// `<sys/proc_info.h>`.
const PROC_PIDTBSDINFO: c_int = 3;

extern "C" {
    /// The current graphical session's properties, or null outside one.
    fn CGSessionCopyCurrentDictionary() -> *const std::ffi::c_void;
    fn CFDictionaryGetValue(
        dictionary: *const std::ffi::c_void,
        key: *const std::ffi::c_void,
    ) -> *const std::ffi::c_void;
    fn CFBooleanGetValue(value: *const std::ffi::c_void) -> bool;
    fn CFStringCreateWithCString(
        allocator: *const std::ffi::c_void,
        cstr: *const c_char,
        encoding: u32,
    ) -> *const std::ffi::c_void;
    fn CFRelease(value: *const std::ffi::c_void);

    /// Kernel process information. Returns the byte count written, or 0.
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut std::ffi::c_void,
        buffer_size: c_int,
    ) -> c_int;

    /// The process the system attributes our permission grants to.
    ///
    /// Taking a grant to belong to the calling binary is wrong for anything
    /// launched by something else: the attribution follows the launching
    /// process, so a module spawned by a daemon inherits the daemon's grants
    /// and holds none of its own.
    fn responsibility_get_pid_responsible_for_pid(pid: c_int) -> c_int;

    /// Executable path for a pid. Returns the byte count written, or 0.
    fn proc_pidpath(pid: c_int, buffer: *mut c_char, buffer_size: c_uint) -> c_int;

    /// Non-zero when the calling thread is the main thread.
    fn pthread_main_np() -> c_int;
}

/// `PROC_PIDPATHINFO_MAXSIZE` from `<sys/proc_info.h>`.
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

/// Establish this process's window-server connection, at most once.
///
/// Creating a capture filter in a process that has never reached the window
/// server fails an assertion inside CoreGraphics and ABORTS THE PROCESS rather
/// than returning an error. Window enumeration works beforehand, so the process
/// looks healthy right up to the abort.
///
/// Reading the main display id is enough to establish the connection. It looks
/// like a call whose result is discarded, which is exactly why removing it must
/// stay difficult: the failure it prevents is a crash, not a refusal.
pub fn establish_window_server_connection() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = objc2_core_graphics::CGMainDisplayID();
    });
}

/// The executable path of the process our grants are attributed to.
///
/// The full path rather than a name, because the question this answers is
/// whether the attribution is still the one seen at startup, and a replacement
/// binary at a different location is precisely the change worth noticing.
///
/// `None` when the system reports no attribution or no path for it. That is
/// reported as absence rather than substituted with this process, because
/// "we could not establish who holds the grant" and "we hold it" are opposite
/// answers.
pub fn responsible_process() -> Option<String> {
    let self_pid = std::process::id() as c_int;
    // SAFETY: takes a pid by value and returns a pid. No pointers involved.
    let responsible = unsafe { responsibility_get_pid_responsible_for_pid(self_pid) };
    if responsible <= 0 {
        return None;
    }

    let mut buffer = vec![0 as c_char; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: the buffer is owned here, and its true capacity is passed, so the
    // call cannot write past it. The value written is a NUL-terminated path.
    let written = unsafe {
        proc_pidpath(
            responsible,
            buffer.as_mut_ptr(),
            PROC_PIDPATHINFO_MAXSIZE as c_uint,
        )
    };
    if written <= 0 {
        return None;
    }

    // SAFETY: the call above reported success, so the buffer holds a
    // NUL-terminated string within its capacity, and it outlives this read.
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// Whether screen capture is usable by this process right now.
///
/// This is the non-prompting query. The prompting variant exists and is
/// deliberately not called: a module spawned by a daemon raising a system
/// permission dialog on its own initiative is its own defect, and a dialog
/// nobody is present to answer is worse than a refusal.
pub fn screen_capture_is_permitted() -> bool {
    objc2_core_graphics::CGPreflightScreenCaptureAccess()
}

/// Whether the calling thread is NOT the main thread.
///
/// Reported so a permission reading can record where it was taken. A reading
/// from the main thread of a process whose main thread is a run loop is not
/// evidence about a background probe.
pub fn is_off_main_thread() -> bool {
    // SAFETY: takes no arguments, returns a plain integer, and is callable from
    // any thread.
    unsafe { pthread_main_np() == 0 }
}

/// Whether the screen is locked.
///
/// A locked screen still answers questions ABOUT windows -- the list, their
/// owners, their sizes -- while refusing their CONTENTS, so a caller that only
/// checks its permission concludes it can capture and then fails at the picture.
/// `None` when there is no graphical session to ask, which is not the same as an
/// unlocked one: a process with no session cannot capture either.
pub fn screen_is_locked() -> Option<bool> {
    // SAFETY: takes no arguments, and returns either null or a dictionary this
    // frame owns. Released below on every path that reaches it.
    let session = unsafe { CGSessionCopyCurrentDictionary() };
    if session.is_null() {
        return None;
    }

    // SAFETY: the key is a NUL-terminated literal and the dictionary is
    // non-null. The value is borrowed from the dictionary, so it is read before
    // the release. Both objects created here are released on every path.
    unsafe {
        // 0x08000100 is kCFStringEncodingUTF8.
        let key = CFStringCreateWithCString(
            std::ptr::null(),
            c"CGSSessionScreenIsLocked".as_ptr(),
            0x0800_0100,
        );
        let value = CFDictionaryGetValue(session, key);
        let locked = if value.is_null() {
            None
        } else {
            Some(CFBooleanGetValue(value))
        };
        CFRelease(key);
        CFRelease(session);
        locked
    }
}

/// When a process was started, as kernel-sourced microseconds since the epoch.
///
/// This is the discriminator that survives pid reuse. A pid alone identifies
/// whoever holds it now, which is exactly the process an identity check exists
/// to distinguish from the one that held it earlier; the start time separates
/// them because the replacement cannot share it.
///
/// `None` when the process is gone or the kernel reports a structure this does
/// not recognise. Absence rather than a zero, because a zero start time would
/// compare equal to another zero and read as a match.
pub fn process_start_time_micros(pid: u32) -> Option<u64> {
    let mut info = ProcBsdInfo::default();
    let size = std::mem::size_of::<ProcBsdInfo>() as c_int;
    // SAFETY: the buffer is owned here and its true size is passed, so the call
    // cannot write past it. The pid is passed by value.
    let written = unsafe {
        proc_pidinfo(
            pid as c_int,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut ProcBsdInfo as *mut std::ffi::c_void,
            size,
        )
    };

    // A short write means the kernel's structure is not the one declared above,
    // so the fields read would be some other data. Refuse rather than interpret.
    if written != size {
        return None;
    }

    // A process that reports it started at the epoch is not reporting a start
    // time, and two such processes would compare as the same generation.
    if info.pbi_start_tvsec == 0 {
        return None;
    }

    info.pbi_start_tvsec
        .checked_mul(1_000_000)?
        .checked_add(info.pbi_start_tvusec)
}

/// One window as the system reports it.
///
/// Deliberately without the window title. A title is readable only with a
/// permission this module may not hold, and it is chosen by the application, so
/// it is not identity evidence: two windows can carry the same one, and any
/// application can present a title belonging to another.
#[derive(Debug, Clone, PartialEq)]
pub struct RawWindow {
    pub window_id: u32,
    pub owner_pid: u32,
    pub owner_bundle_identifier: String,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub on_screen: bool,
}

/// Delivers one callback result to a waiting thread.
struct Delivery<T> {
    slot: Mutex<Option<T>>,
    ready: Condvar,
}

impl<T> Delivery<T> {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            slot: Mutex::new(None),
            ready: Condvar::new(),
        })
    }

    fn deliver(&self, value: T) {
        *self.slot.lock().unwrap() = Some(value);
        self.ready.notify_all();
    }

    /// Waits for a value, or gives up at the deadline.
    ///
    /// The bound exists because the callback is invoked by the system: if the
    /// window server never answers, an unbounded wait holds this thread
    /// forever, and the caller cannot distinguish that from slow work.
    fn wait(&self, timeout: Duration) -> Option<T> {
        let deadline = Instant::now() + timeout;
        let mut slot = self.slot.lock().unwrap();
        while slot.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (next, _) = self.ready.wait_timeout(slot, remaining).unwrap();
            slot = next;
        }
        slot.take()
    }
}

/// Every window the system is willing to describe to this process.
///
/// Returns an error rather than an empty list when the system declines, because
/// "no windows" and "not permitted to look" are different answers and only one
/// of them is about the machine's contents.
///
/// Unfiltered by owner: the caller matches against its own grant, so the
/// filtering happens where the grant is known rather than here.
///
/// The timeout bounds the WAIT for the system's answer, not the call that asks
/// for it. That call is normally a few microseconds and was measured at 2.5ms
/// under six threads enumerating concurrently, but it is a system call and
/// nothing here can bound it, so a caller passing a short deadline can still
/// block for longer than it asked. Moving the ask onto its own thread would
/// close the gap -- the system retains the callback, so it fires even after the
/// dispatching thread has exited -- at the cost of a thread per call and a
/// leaked one if the ask never returns. Left as it is because the module's
/// health reporting reads its own counters and never enumerates, so a slow
/// answer here delays the caller that asked rather than the module's ability to
/// report that it is alive.
pub fn enumerate_windows(timeout: Duration) -> Result<Vec<RawWindow>, String> {
    let delivery: Arc<Delivery<Result<Vec<RawWindow>, String>>> = Delivery::new();
    let sink = delivery.clone();

    let handler = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            // SAFETY: the system passes either a content object or an error, both
            // valid for the duration of this callback. Neither is retained beyond
            // it: every value read below is copied into an owned RawWindow.
            let outcome = unsafe {
                if let Some(error) = error.as_ref() {
                    Err(error.localizedDescription().to_string())
                } else if let Some(content) = content.as_ref() {
                    Ok(content
                        .windows()
                        .iter()
                        .filter_map(|window| {
                            let owner = window.owningApplication()?;
                            let frame = window.frame();
                            Some(RawWindow {
                                window_id: window.windowID(),
                                owner_pid: u32::try_from(owner.processID()).ok()?,
                                owner_bundle_identifier: owner.bundleIdentifier().to_string(),
                                x: frame.origin.x,
                                y: frame.origin.y,
                                width: frame.size.width,
                                height: frame.size.height,
                                on_screen: window.isOnScreen(),
                            })
                        })
                        .collect())
                } else {
                    Err("the system reported neither content nor an error".to_string())
                }
            };
            sink.deliver(outcome);
        },
    );

    // SAFETY: the handler outlives the call through the block's own retain, and
    // the delivery it writes into is kept alive by this frame until the wait
    // below returns.
    unsafe { SCShareableContent::getShareableContentWithCompletionHandler(&handler) };

    delivery
        .wait(timeout)
        .unwrap_or_else(|| Err(format!("the window list did not arrive within {timeout:?}")))
}

/// One window's pixels, as the system produced them.
///
/// The owner is read again at capture time rather than carried over from
/// enumeration, so a caller can tell whether the window it asked for is still
/// owned by the process it meant. A window id is reused after its window
/// closes, so the id alone does not answer that.
pub struct RawCapture {
    pub width: usize,
    pub height: usize,
    pub bytes_per_row: usize,
    /// Pixels in BGRA order, as the system delivers them.
    pub bgra: Vec<u8>,
    pub owner_pid_at_capture: u32,
}

/// Look up one window by id, if the system still describes it.
fn find_window(window_id: u32, timeout: Duration) -> Result<Retained<SCWindow>, String> {
    let delivery: Arc<Delivery<Result<Option<Retained<SCWindow>>, String>>> = Delivery::new();
    let sink = delivery.clone();

    let handler = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            // SAFETY: the system passes either a content object or an error, both
            // valid for this callback. The window is retained before the callback
            // returns.
            let outcome = unsafe {
                if let Some(error) = error.as_ref() {
                    Err(error.localizedDescription().to_string())
                } else if let Some(content) = content.as_ref() {
                    Ok(content
                        .windows()
                        .iter()
                        .find(|window| window.windowID() == window_id))
                } else {
                    Err("the system reported neither content nor an error".to_string())
                }
            };
            sink.deliver(outcome);
        },
    );

    // SAFETY: the handler outlives the call through the block's own retain.
    unsafe { SCShareableContent::getShareableContentWithCompletionHandler(&handler) };

    match delivery.wait(timeout) {
        Some(Ok(Some(window))) => Ok(window),
        Some(Ok(None)) => Err(format!("window {window_id} is no longer present")),
        Some(Err(reason)) => Err(reason),
        None => Err(format!("the window list did not arrive within {timeout:?}")),
    }
}

/// Capture one window's pixels, without bringing it forward.
///
/// Scoped to a single window rather than to a display: a display filter
/// composites in whatever else overlaps that region, so capturing one
/// application through it would hand back another application's pixels.
///
/// The cursor is excluded. It belongs to the user rather than to the window,
/// and its position at the moment of capture says where the user was pointing,
/// which is not part of the window's contents.
///
/// THE FIRST CAPTURE IN A PROCESS IS NOT LIKE THE REST, and a caller that
/// treats them alike will misread a healthy system as a broken one. Measured on
/// macOS 26: once a process has captured once, captures take about 40ms and
/// several at a time are fine. The FIRST one sets up this process's session
/// with the window server, and that setup contends system-wide -- while another
/// process is capturing, it does not proceed. Two processes starting together
/// blocked each other past 60 seconds, on different windows, with no error from
/// either side.
///
/// THE CONTENTION OUTLIVES THE PROCESS THAT CAUSED IT. A first capture that
/// takes 0.5 second on an idle machine took 14 seconds immediately after
/// another process had captured and exited, with no process of that program
/// left running. So it is the window server's own state that is busy, not a
/// competing process, and waiting for the other side to exit does not clear it.
///
/// So the deadline has to cover a wait for the system rather than for the work,
/// and a caller that wants a bounded first capture should perform one at
/// startup, when nothing else is competing, rather than on the first request
/// that needs it.
pub fn capture_window(window_id: u32, timeout: Duration) -> Result<RawCapture, String> {
    // Before any filter is created. Without a window-server connection the
    // filter constructor does not fail -- it aborts the process, which for a
    // module means the whole module dies rather than refusing one capture.
    establish_window_server_connection();

    let window = find_window(window_id, timeout)?;
    // SAFETY: the window is retained by this frame, so reading its properties
    // is valid for as long as it is held here.
    let (owner_pid_at_capture, frame) = unsafe {
        let owner = window
            .owningApplication()
            .and_then(|owner| u32::try_from(owner.processID()).ok())
            .ok_or_else(|| format!("window {window_id} reports no owning process"))?;
        (owner, window.frame())
    };
    // SAFETY: the window is retained here and outlives the filter's creation.
    let filter = unsafe {
        SCContentFilter::initWithDesktopIndependentWindow(SCContentFilter::alloc(), &window)
    };

    // SAFETY: plain object construction and property sets on an object owned
    // by this frame.
    let configuration = unsafe {
        let configuration = SCStreamConfiguration::new();
        configuration.setWidth((frame.size.width.max(1.0)) as usize);
        configuration.setHeight((frame.size.height.max(1.0)) as usize);
        configuration.setShowsCursor(false);
        configuration
    };

    let delivery: Arc<Delivery<Result<RawCapture, String>>> = Delivery::new();
    let sink = delivery.clone();
    let handler = RcBlock::new(move |image: *mut CGImage, error: *mut NSError| {
        // SAFETY: the system passes either an image or an error, both valid for
        // this callback. Pixel bytes are copied out before it returns.
        let outcome = unsafe {
            if let Some(error) = error.as_ref() {
                Err(error.localizedDescription().to_string())
            } else if let Some(image) = image.as_ref() {
                read_pixels(image, owner_pid_at_capture)
            } else {
                Err("the system reported neither an image nor an error".to_string())
            }
        };
        sink.deliver(outcome);
    });

    // SAFETY: filter and configuration are owned by this frame and outlive the
    // call; the handler outlives it through the block's own retain.
    unsafe {
        SCScreenshotManager::captureImageWithFilter_configuration_completionHandler(
            &filter,
            &configuration,
            Some(&handler),
        )
    };

    let outcome = delivery
        .wait(timeout)
        .unwrap_or_else(|| Err(format!("the capture did not arrive within {timeout:?}")));

    // A locked screen refuses pixel contents while still answering questions
    // ABOUT windows, and it does so with a generic stream failure that reads
    // like a fault in the capture itself. The state is read AFTER the failure
    // rather than checked before it, so what is reported is the state that
    // actually applied rather than one that may have changed since.
    outcome.map_err(|reason| {
        if screen_is_locked() == Some(true) {
            format!("the screen is locked, so window contents are not readable ({reason})")
        } else {
            reason
        }
    })
}

/// Copy an image's pixels out of the system's storage.
///
/// # Safety
///
/// `image` must be a valid image for the duration of the call.
unsafe fn read_pixels(image: &CGImage, owner_pid_at_capture: u32) -> Result<RawCapture, String> {
    let width = CGImage::width(Some(image));
    let height = CGImage::height(Some(image));
    let bytes_per_row = CGImage::bytes_per_row(Some(image));

    let provider =
        CGImage::data_provider(Some(image)).ok_or_else(|| "the image has no pixels".to_string())?;
    let data = objc2_core_graphics::CGDataProvider::data(Some(&provider))
        .ok_or_else(|| "the image's pixels could not be read".to_string())?;

    let length = data.length() as usize;
    let pointer = data.byte_ptr();
    if pointer.is_null() {
        return Err("the image's pixels are not readable".to_string());
    }
    // SAFETY: the pointer and length come from the same object, which is held
    // by this frame. The bytes are copied immediately, so nothing outlives it.
    let bgra = unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec();

    // A row stride shorter than the row means the buffer does not hold what its
    // dimensions describe, so nothing downstream could index it correctly.
    if bytes_per_row < width * 4 || bgra.len() < bytes_per_row * height {
        return Err(format!(
            "the image's pixels do not match its dimensions: {width}x{height}, \
             {bytes_per_row} bytes per row, {} bytes total",
            bgra.len()
        ));
    }

    Ok(RawCapture {
        width,
        height,
        bytes_per_row,
        bgra,
        owner_pid_at_capture,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes every test that talks to the window server.
    ///
    /// Window-server work contends system-wide and the contention outlasts the
    /// process that caused it: an operation taking half a second on an idle
    /// machine took fourteen after another process had captured and exited.
    /// So the lock is held by tests that merely SUFFER the contention as well as
    /// by those that cause it, or the former wait out the latter and fail for a
    /// reason unrelated to what they assert. Tests run as threads in one
    /// process, so a lock here covers them.
    static WINDOW_SERVER: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Whether this machine can currently produce window pixels at all.
    ///
    /// Two states prevent it and they are different: capture may not be
    /// permitted, or the screen may be locked. A locked screen still answers
    /// questions about windows while refusing their contents, so a test that
    /// only checks enumeration would proceed and then fail on the picture.
    ///
    /// Tests asserting a property OF a capture stop when this is false, since a
    /// machine that cannot capture has nothing to say about it. Tests asserting
    /// a REFUSAL do not need it: they are about what is refused, and both
    /// states refuse.
    fn pixels_are_obtainable() -> bool {
        screen_capture_is_permitted() && screen_is_locked() != Some(true)
    }

    /// The attribution resolves to a real executable on this system.
    ///
    /// Asserted as an absolute path that exists, rather than merely as "some
    /// string", because the failure this guards against is the resolution
    /// silently degrading to something a comparison would still accept.
    #[test]
    fn the_responsible_process_is_a_real_executable_path() {
        let Some(path) = responsible_process() else {
            panic!("no responsible process resolved for a running process");
        };
        assert!(
            path.starts_with('/'),
            "expected an absolute path, got {path:?}"
        );
        assert!(
            std::path::Path::new(&path).exists(),
            "resolved path does not exist: {path:?}"
        );
    }

    /// Establishing the window-server connection is safe to repeat.
    ///
    /// It is called before every capture rather than once at a place someone
    /// has to remember, so repeating it must be harmless.
    #[test]
    fn establishing_the_window_server_connection_twice_is_harmless() {
        establish_window_server_connection();
        establish_window_server_connection();
    }

    /// The capture permission query answers without prompting or aborting.
    ///
    /// The value is deliberately not asserted: it depends on whether this
    /// machine has granted capture, and demanding one answer would fail
    /// honestly on the other kind of machine.
    #[test]
    fn the_capture_permission_query_returns() {
        let _ = screen_capture_is_permitted();
    }

    /// Start times order the way process creation did.
    ///
    /// A child cannot start before its parent, so the comparison holds on any
    /// machine. It is asserted because it is the available check that a WRONG
    /// field is being read: a misread offset still yields a plausible-looking
    /// number, and a bound like "after 2020" would accept one, while an
    /// ordering two independent readings must satisfy would not.
    ///
    /// A child is used rather than the system's first process, which is owned
    /// by root and whose information the kernel declines to report here.
    #[test]
    fn start_times_order_the_way_process_creation_did() {
        let this_process =
            process_start_time_micros(std::process::id()).expect("this process exists");

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("spawn a child to compare against");
        let child_start = process_start_time_micros(child.id());
        let _ = child.kill();
        let _ = child.wait();

        let child_start = child_start.expect("a running child has a start time");
        assert!(
            this_process < child_start,
            "a child cannot predate its parent: {this_process} vs {child_start}"
        );
    }

    /// The reading is a wall-clock time in the past, at microsecond scale.
    ///
    /// Ordering alone would be satisfied by any two values with the right
    /// relation, including counters that are not times at all. This pins the
    /// units and the epoch, so a field holding something else has to coincide
    /// with a plausible recent timestamp to pass.
    #[test]
    fn a_start_time_is_a_past_wall_clock_time_in_microseconds() {
        let start = process_start_time_micros(std::process::id()).expect("this process exists");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_micros() as u64;

        assert!(start < now, "a process cannot start in the future");
        // This process was started by the test run, so its age is bounded by
        // how long a test binary plausibly runs rather than by machine uptime.
        assert!(
            now - start < 3_600_000_000,
            "a just-started process reporting an age over an hour is not reporting its start"
        );
    }

    /// The same process reads the same start time every time.
    ///
    /// A value that varied between readings could not discriminate a process
    /// from its replacement, which is the only thing this is for.
    #[test]
    fn a_start_time_is_stable_across_readings() {
        let pid = std::process::id();
        let first = process_start_time_micros(pid);
        let second = process_start_time_micros(pid);
        assert_eq!(first, second);
        assert!(first.is_some());
    }

    /// Enumeration agrees with the permission query.
    ///
    /// Asserted as an equivalence rather than as an outcome, because the answer
    /// depends on whether this machine has granted capture and a test demanding
    /// one would fail honestly on the other kind of machine. The equivalence
    /// holds either way, and it is the property the advertisement gate rests
    /// on: a capability advertised because the query said yes must not then
    /// fail at use.
    #[test]
    fn enumeration_agrees_with_the_permission_query() {
        let _serialized = WINDOW_SERVER.lock();
        let permitted = screen_capture_is_permitted();
        let enumerated = enumerate_windows(Duration::from_secs(10));

        assert_eq!(
            permitted,
            enumerated.is_ok(),
            "permission query said {permitted} but enumeration returned {enumerated:?}"
        );
    }

    /// A granted machine reports windows that carry an owner.
    ///
    /// Skipped rather than failed where capture is not granted: the property is
    /// about the shape of what enumeration returns, and a machine that refuses
    /// to answer has nothing to say about it.
    #[test]
    fn enumerated_windows_carry_an_owning_process() {
        let _serialized = WINDOW_SERVER.lock();
        let Ok(windows) = enumerate_windows(Duration::from_secs(10)) else {
            return;
        };
        assert!(!windows.is_empty(), "a running desktop has windows");
        for window in &windows {
            assert_ne!(window.owner_pid, 0, "a window with no owner: {window:?}");
            assert_ne!(window.window_id, 0, "a window with no id: {window:?}");
        }
    }

    /// A deadline that has already passed produces an error, not a wait.
    ///
    /// The bound is the only thing standing between a system that never answers
    /// and a thread held forever, so it has to be load-bearing rather than
    /// advisory.
    ///
    /// The proof is the CONTRAST between the two deadlines, not elapsed time. A
    /// call that ignored its deadline would wait for the window server and
    /// return the same window list as the generous call below, so an error from
    /// one and a list from the other can only mean the deadline was honoured.
    /// Measuring elapsed time instead would assert a wall-clock bound on a
    /// machine shared with other work, which fails for reasons unrelated to the
    /// property.
    ///
    /// Both calls fail on a machine without capture permission, where the
    /// contrast cannot be drawn and the test would pass vacuously, so it stops
    /// there rather than claiming a result.
    #[test]
    fn an_expired_deadline_refuses_rather_than_waits() {
        let _serialized = WINDOW_SERVER.lock();
        if enumerate_windows(Duration::from_secs(10)).is_err() {
            return;
        }
        assert!(
            enumerate_windows(Duration::ZERO).is_err(),
            "an expired deadline produced a window list, so it was not applied"
        );
    }

    /// A captured window yields pixels matching the size it reported.
    ///
    /// Skipped where capture is not granted: the property is about what a
    /// capture returns, and a machine that refuses to capture has nothing to
    /// say about it.
    #[test]
    fn a_captured_window_yields_pixels_of_its_own_size() {
        if !pixels_are_obtainable() {
            return;
        }
        let _serialized = WINDOW_SERVER.lock();
        let Ok(windows) = enumerate_windows(Duration::from_secs(10)) else {
            return;
        };
        // A window with area, since a zero-sized one would satisfy any claim
        // about its pixels.
        let Some(window) = windows
            .iter()
            .find(|window| window.on_screen && window.width >= 64.0 && window.height >= 64.0)
        else {
            return;
        };

        let capture = capture_window(window.window_id, Duration::from_secs(10))
            .expect("a window the system just listed can be captured");

        assert_eq!(
            capture.owner_pid_at_capture, window.owner_pid,
            "captured a window owned by a different process than the one enumerated"
        );
        assert!(capture.width > 0 && capture.height > 0);
        // Four bytes per pixel, so a buffer holding fewer than that is not the
        // image it claims to be.
        assert!(
            capture.bgra.len() >= capture.bytes_per_row * capture.height,
            "{}x{} at {} bytes per row cannot fit in {} bytes",
            capture.width,
            capture.height,
            capture.bytes_per_row,
            capture.bgra.len()
        );
        assert!(capture.bytes_per_row >= capture.width * 4);
    }

    /// Capturing a window that no longer exists refuses.
    ///
    /// Window ids are reused, so a request naming a departed window must not be
    /// answered with whatever now holds that id.
    #[test]
    fn capturing_a_window_that_is_gone_refuses() {
        let _serialized = WINDOW_SERVER.lock();
        // Above any id the window server has assigned on a running system.
        assert!(capture_window(u32::MAX - 1, Duration::from_secs(10)).is_err());
    }

    /// Creating a capture filter without the window-server connection kills the
    /// process, which is why [`capture_window`] establishes it first.
    ///
    /// The connection is established by a call whose result is discarded, so it
    /// reads like a line with no effect and invites removal. This asserts what
    /// removing it costs: not a failed capture but a dead process, which for a
    /// module means every capability it serves goes down with it.
    ///
    /// Run in a child process because the failure is an abort, which an
    /// in-process test cannot survive to assert anything about. The parent
    /// chooses the window and passes its id, so the child performs exactly one
    /// enumeration -- the same number [`capture_window`] performs, and the most
    /// that reliably completes in a process that has never reached the window
    /// server.
    #[test]
    fn creating_a_filter_without_the_window_server_connection_kills_the_process() {
        if !pixels_are_obtainable() {
            return;
        }
        let _serialized = WINDOW_SERVER.lock();
        use std::os::unix::process::ExitStatusExt;

        const TARGET_WINDOW: &str = "CK_UNGUARDED_FILTER_PROBE_WINDOW";

        if let Ok(window_id) = std::env::var(TARGET_WINDOW) {
            let window_id: u32 = window_id.parse().expect("the parent passes a window id");
            // Deliberately WITHOUT establish_window_server_connection().
            let Ok(window) = find_window(window_id, Duration::from_secs(10)) else {
                // Could not reach the filter, so this run proves nothing. Exit
                // cleanly and let the parent report a skip rather than treating
                // an unrelated failure as a confirmation.
                std::process::exit(0);
            };
            // SAFETY: the window is retained by this frame. This is expected to
            // abort, which is the point of the test.
            let _filter = unsafe {
                SCContentFilter::initWithDesktopIndependentWindow(SCContentFilter::alloc(), &window)
            };
            std::process::exit(0);
        }

        // Skip where capture is not permitted: the child cannot look up a
        // window, so it cannot reach the filter.
        let Ok(windows) = enumerate_windows(Duration::from_secs(10)) else {
            return;
        };
        let Some(window) = windows.first() else {
            return;
        };

        let status = std::process::Command::new(
            std::env::current_exe().expect("the test binary's own path"),
        )
        .args([
            "--exact",
            "macos::tests::creating_a_filter_without_the_window_server_connection_kills_the_process",
        ])
        .env(TARGET_WINDOW, window.window_id.to_string())
        .output()
        .expect("run the probe in a child process");

        // SIGABRT specifically, rather than "did not succeed": a child that
        // panicked for an unrelated reason, or failed to look up the window,
        // must not read as a confirmation.
        assert_eq!(
            status.status.signal(),
            Some(6),
            "expected the child to abort; it exited with {:?} and said: {}",
            status.status,
            String::from_utf8_lossy(&status.stderr)
        );
    }

    /// [`capture_window`] survives in a process that has established nothing.
    ///
    /// The companion to the test above, and the one that fences the CALL SITE
    /// rather than the hazard. Removing the establishing call from
    /// [`capture_window`] cannot be detected in this process: tests run as
    /// threads in one process, so a sibling that establishes the connection
    /// leaves it established for everyone, and the removed call looks
    /// redundant precisely because something else already did its work.
    ///
    /// The child process establishes nothing, so the call inside
    /// [`capture_window`] is the only thing standing between it and an abort.
    #[test]
    fn capturing_establishes_the_window_server_connection_itself() {
        if !pixels_are_obtainable() {
            return;
        }
        let _serialized = WINDOW_SERVER.lock();
        use std::os::unix::process::ExitStatusExt;

        const TARGET_WINDOW: &str = "CK_CAPTURE_SURVIVAL_PROBE_WINDOW";
        const CAPTURE_REFUSED: i32 = 3;

        if let Ok(window_id) = std::env::var(TARGET_WINDOW) {
            let window_id: u32 = window_id.parse().expect("the parent passes a window id");
            match capture_window(window_id, Duration::from_secs(10)) {
                Ok(_) => std::process::exit(0),
                // A typed refusal is still a survival, and it is reported
                // separately so the parent does not read it as a capture.
                Err(_) => std::process::exit(CAPTURE_REFUSED),
            }
        }

        let Ok(windows) = enumerate_windows(Duration::from_secs(10)) else {
            return;
        };
        let Some(window) = windows.iter().find(|window| window.on_screen) else {
            return;
        };

        let status = std::process::Command::new(
            std::env::current_exe().expect("the test binary's own path"),
        )
        .args([
            "--exact",
            "macos::tests::capturing_establishes_the_window_server_connection_itself",
        ])
        .env(TARGET_WINDOW, window.window_id.to_string())
        .output()
        .expect("run the probe in a child process");

        assert_ne!(
            status.status.signal(),
            Some(6),
            "capturing aborted the child, so it did not establish the window-server connection"
        );
        assert!(
            matches!(status.status.code(), Some(0) | Some(CAPTURE_REFUSED)),
            "the child neither captured nor refused: {:?}, {}",
            status.status,
            String::from_utf8_lossy(&status.stderr)
        );
    }

    /// A process that does not exist has no start time.
    ///
    /// Absence rather than a zero: a zero would compare equal to another zero
    /// and read as two processes sharing a generation.
    #[test]
    fn a_process_that_does_not_exist_reports_no_start_time() {
        // Above the highest pid this system can assign, so it identifies no
        // process.
        assert_eq!(process_start_time_micros(u32::MAX - 1), None);
    }
}
