//! Keep the agent's browser from inheriting cerebellum's macOS privacy grants.
//!
//! macOS checks privacy permissions (Screen Recording, Accessibility, Input
//! Monitoring) against a process's *responsible process*, which a child
//! inherits from whoever spawned it. Spawning with the private libSystem
//! attribute `responsibility_spawnattrs_setdisclaim` makes the child its own
//! responsible process, so it holds none of the spawner's grants. That call
//! is resolved at runtime because it isn't in the public SDK headers.

#[cfg(target_os = "macos")]
use std::ffi::{c_char, c_int, c_void};

/// The operation that stops the browser inheriting the module's Screen
/// Recording, Accessibility and Input Monitoring grants is missing or failed,
/// so the browser must not be launched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponsibilityDisclaimUnavailable;

/// Resolve the operation and apply it to the spawn attributes. A missing
/// symbol and a non-zero result both refuse, so the browser is never
/// launched holding the module's grants.
pub fn require_responsibility_disclaim<T>(
    resolve: impl FnOnce() -> Option<T>,
    call: impl FnOnce(T) -> i32,
) -> Result<(), ResponsibilityDisclaimUnavailable> {
    let operation = resolve().ok_or(ResponsibilityDisclaimUnavailable)?;
    if call(operation) != 0 {
        return Err(ResponsibilityDisclaimUnavailable);
    }
    Ok(())
}

/// Apply libSystem's private disclaim attribute to initialized spawn attributes.
///
/// # Safety
/// `attributes` must point to a live, initialized Darwin `posix_spawnattr_t`.
/// `resolve_symbol` must implement libSystem's `dlsym` ABI and semantics.
#[cfg(target_os = "macos")]
pub(crate) unsafe fn disclaim_spawn_attributes(
    attributes: &mut *mut c_void,
    resolve_symbol: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void,
) -> Result<(), ResponsibilityDisclaimUnavailable> {
    type SetDisclaim = unsafe extern "C" fn(*mut *mut c_void, c_int) -> c_int;
    require_responsibility_disclaim(
        || {
            let symbol = unsafe {
                resolve_symbol(
                    (-2isize) as *mut c_void,
                    c"responsibility_spawnattrs_setdisclaim".as_ptr(),
                )
            };
            if symbol.is_null() {
                None
            } else {
                // SAFETY: libSystem declares this symbol as
                // `int responsibility_spawnattrs_setdisclaim(posix_spawnattr_t *, int)`.
                // Darwin's posix_spawnattr_t is an opaque pointer. The launch
                // contrast test checks that this call changes responsibility.
                Some(unsafe { std::mem::transmute::<*mut c_void, SetDisclaim>(symbol) })
            }
        },
        |operation| unsafe { operation(attributes, 1) },
    )
}

/// Launch an executable as its own responsible process, with
/// inherited standard streams and environment, and wait for its exit status.
/// Refuse before spawning if the responsibility attribute cannot be applied.
#[cfg(all(target_os = "macos", feature = "desk-probe"))]
pub fn spawn_disclaimed_and_wait(
    executable: &std::path::Path,
    arguments: &[std::ffi::OsString],
) -> std::io::Result<std::process::ExitStatus> {
    use std::ffi::{CString, OsStr};
    use std::io;
    use std::os::unix::{ffi::OsStrExt, process::ExitStatusExt};

    extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn posix_spawnattr_init(attributes: *mut *mut c_void) -> c_int;
        fn posix_spawnattr_destroy(attributes: *mut *mut c_void) -> c_int;
        fn posix_spawn(
            pid: *mut c_int,
            path: *const c_char,
            actions: *const *mut c_void,
            attributes: *const *mut c_void,
            argv: *const *mut c_char,
            environment: *const *mut c_char,
        ) -> c_int;
        fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    }

    let c_string = |value: &OsStr| {
        CString::new(value.as_bytes())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    };
    let argv = std::iter::once(executable.as_os_str())
        .chain(arguments.iter().map(|argument| argument.as_os_str()))
        .map(c_string)
        .collect::<io::Result<Vec<_>>>()?;
    let environment = std::env::vars_os()
        .map(|(mut name, value)| {
            name.push("=");
            name.push(value);
            c_string(&name)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let pointers = |strings: &[CString]| {
        strings
            .iter()
            .map(|string| string.as_ptr().cast_mut())
            .chain(std::iter::once(std::ptr::null_mut()))
            .collect::<Vec<_>>()
    };
    let argv_pointers = pointers(&argv);
    let environment_pointers = pointers(&environment);

    struct Attributes(*mut c_void);
    impl Drop for Attributes {
        fn drop(&mut self) {
            let _ = unsafe { posix_spawnattr_destroy(&mut self.0) };
        }
    }
    let mut raw_attributes = std::ptr::null_mut();
    let status = unsafe { posix_spawnattr_init(&mut raw_attributes) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let mut attributes = Attributes(raw_attributes);
    // SAFETY: initialization succeeded and Attributes keeps the object alive
    // until after posix_spawn. The resolver is libSystem's dlsym itself.
    unsafe { disclaim_spawn_attributes(&mut attributes.0, dlsym) }.map_err(|_| {
        io::Error::other("responsibility disclaim unavailable; refusing to launch undisclaimed")
    })?;
    let mut pid = 0;
    // No file actions or spawn flags replace or close the standard streams.
    // The owned C strings and pointer arrays remain live through this call.
    let status = unsafe {
        posix_spawn(
            &mut pid,
            argv[0].as_ptr(),
            std::ptr::null(),
            &attributes.0,
            argv_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        )
    };
    drop(attributes);
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    loop {
        let mut status = 0;
        if unsafe { waitpid(pid, &mut status, 0) } == pid {
            return Ok(std::process::ExitStatus::from_raw(status));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_symbol_refuses_launch() {
        assert_eq!(
            require_responsibility_disclaim(|| None::<()>, |_| panic!("missing operation called")),
            Err(ResponsibilityDisclaimUnavailable)
        );
    }

    #[test]
    fn failed_disclaim_refuses_launch() {
        assert_eq!(
            require_responsibility_disclaim(|| Some(()), |_| 1),
            Err(ResponsibilityDisclaimUnavailable)
        );
    }

    #[test]
    fn successful_disclaim_allows_launch() {
        assert_eq!(require_responsibility_disclaim(|| Some(()), |_| 0), Ok(()));
    }
}
