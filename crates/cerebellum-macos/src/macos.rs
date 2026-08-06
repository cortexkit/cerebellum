//! The framework calls themselves.
//!
//! Only the three C functions declared below need `unsafe`; the CoreGraphics
//! entry points are safe bindings. Every `unsafe` block here is therefore a
//! real one, which is the point of keeping them few.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint};
use std::sync::Once;

extern "C" {
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
}
