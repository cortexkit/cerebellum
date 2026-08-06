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
use objc2_foundation::NSError;
use objc2_screen_capture_kit::SCShareableContent;

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

#[cfg(test)]
mod tests {
    use super::*;

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
    #[test]
    fn an_expired_deadline_refuses_rather_than_waits() {
        let started = Instant::now();
        let result = enumerate_windows(Duration::ZERO);
        assert!(result.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a zero deadline waited {:?}",
            started.elapsed()
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
