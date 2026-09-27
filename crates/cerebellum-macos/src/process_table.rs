//! The process table and one process's arguments, executable and host name.
//!
//! Read as evidence about who may be using a directory, so every function here
//! separates "there is nothing" from "this could not be read". A caller that
//! folded the two would treat an unreadable process as one that does not exist,
//! which is the direction that lets a second program open files the first
//! still holds.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

extern "C" {
    /// Every pid in the system. Returns the number of pids written, or -1.
    fn proc_listallpids(buffer: *mut c_void, buffer_size: c_int) -> c_int;

    /// Executable path for a pid. Returns the byte count written, or 0.
    fn proc_pidpath(pid: c_int, buffer: *mut c_char, buffer_size: c_uint) -> c_int;

    fn sysctl(
        name: *mut c_int,
        name_length: c_uint,
        old: *mut c_void,
        old_length: *mut usize,
        new: *mut c_void,
        new_length: usize,
    ) -> c_int;

    fn gethostname(name: *mut c_char, length: usize) -> c_int;

    #[link_name = "__error"]
    fn errno_location() -> *mut c_int;
}

/// `CTL_KERN`, `KERN_ARGMAX` and `KERN_PROCARGS2` from `<sys/sysctl.h>`.
const CTL_KERN: c_int = 1;
const KERN_ARGMAX: c_int = 8;
const KERN_PROCARGS2: c_int = 49;
/// `ESRCH`: no process holds the pid.
const ESRCH: c_int = 3;
/// `PROC_PIDPATHINFO_MAXSIZE` from `<sys/proc_info.h>`.
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

/// Every pid the kernel reports, or the errno when it refuses.
///
/// The table is read into a buffer sized from the kernel's own estimate plus
/// room for processes started meanwhile. A read that fills the buffer exactly
/// may have been cut short, so it is retried larger rather than returned: a
/// silently truncated table would read as "no process uses this", which is
/// the answer a caller must never get by accident.
pub fn all_process_ids() -> Result<Vec<u32>, i32> {
    // SAFETY: a null buffer of size zero asks only for the count.
    let estimate = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if estimate < 0 {
        // SAFETY: reads a thread-local set by the call above.
        return Err(unsafe { errno_location().read() });
    }
    let mut capacity = (estimate as usize).saturating_add(256);
    for _ in 0..4 {
        let mut pids = vec![0 as c_int; capacity];
        let bytes = c_int::try_from(capacity * std::mem::size_of::<c_int>()).map_err(|_| 0)?;
        // SAFETY: the buffer is owned here and its true size in bytes is
        // passed, so the call cannot write past it.
        let count = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if count < 0 {
            // SAFETY: reads a thread-local set by the call above.
            return Err(unsafe { errno_location().read() });
        }
        let count = count as usize;
        if count < capacity {
            pids.truncate(count);
            return Ok(pids
                .into_iter()
                .filter(|pid| *pid > 0)
                .map(|pid| pid as u32)
                .collect());
        }
        capacity = capacity.saturating_mul(2);
    }
    // The table kept outgrowing the buffer; report it unread.
    Err(0)
}

/// A process's argument vector, as `ps` reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessArguments {
    Read(Vec<OsString>),
    NoSuchProcess,
    /// The kernel refused (for another user's process, or a zombie, it answers
    /// `EINVAL`), or answered in a shape this parser does not recognise.
    Unreadable(i32),
}

/// Read `pid`'s arguments through `KERN_PROCARGS2`.
///
/// The kernel answers with the argument count, the executable path, padding,
/// and then that many NUL-terminated arguments followed by the environment.
/// Only the arguments are returned.
pub fn process_arguments(pid: u32) -> ProcessArguments {
    let Some(argument_maximum) = argument_maximum() else {
        return ProcessArguments::Unreadable(0);
    };
    let mut buffer = vec![0_u8; argument_maximum];
    let mut length = buffer.len();
    let mut name = [CTL_KERN, KERN_PROCARGS2, pid as c_int];
    // SAFETY: the name array and buffer are owned here, and the buffer's true
    // length is passed in `length`, which the kernel updates in place.
    let result = unsafe {
        errno_location().write(0);
        sysctl(
            name.as_mut_ptr(),
            name.len() as c_uint,
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        // SAFETY: reads a thread-local set by the call above.
        let errno = unsafe { errno_location().read() };
        return if errno == ESRCH {
            ProcessArguments::NoSuchProcess
        } else {
            ProcessArguments::Unreadable(errno)
        };
    }
    buffer.truncate(length.min(buffer.len()));
    match parse_procargs2(&buffer) {
        Some(arguments) => ProcessArguments::Read(arguments),
        None => ProcessArguments::Unreadable(0),
    }
}

fn argument_maximum() -> Option<usize> {
    let mut value: c_int = 0;
    let mut length = std::mem::size_of::<c_int>();
    let mut name = [CTL_KERN, KERN_ARGMAX];
    // SAFETY: `value` is owned here and its size is passed in `length`.
    let result = unsafe {
        sysctl(
            name.as_mut_ptr(),
            name.len() as c_uint,
            (&mut value as *mut c_int).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    (result == 0 && value > 0).then_some(value as usize)
}

/// Split a `KERN_PROCARGS2` answer into its arguments. `None` when the answer
/// is shorter than the argument count it declares.
fn parse_procargs2(buffer: &[u8]) -> Option<Vec<OsString>> {
    let count_bytes: [u8; 4] = buffer.get(..4)?.try_into().ok()?;
    let count = i32::from_ne_bytes(count_bytes);
    let count = usize::try_from(count).ok()?;
    let mut rest = &buffer[4..];
    // The executable path, then the NUL padding that aligns what follows.
    let path_end = rest.iter().position(|byte| *byte == 0)?;
    rest = &rest[path_end..];
    let first_argument = rest.iter().position(|byte| *byte != 0)?;
    rest = &rest[first_argument..];
    let mut arguments = Vec::with_capacity(count);
    for _ in 0..count {
        let end = rest.iter().position(|byte| *byte == 0)?;
        arguments.push(OsString::from_vec(rest[..end].to_vec()));
        rest = &rest[end + 1..];
    }
    Some(arguments)
}

/// The executable a process runs, `Ok(None)` when no process holds the pid,
/// or the errno when the kernel refuses.
pub fn process_executable_path(pid: u32) -> Result<Option<PathBuf>, i32> {
    let mut buffer = vec![0 as c_char; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: the buffer is owned here and its true size is passed.
    let written = unsafe {
        errno_location().write(0);
        proc_pidpath(
            pid as c_int,
            buffer.as_mut_ptr(),
            PROC_PIDPATHINFO_MAXSIZE as c_uint,
        )
    };
    if written <= 0 {
        // SAFETY: reads a thread-local set by the call above.
        let errno = unsafe { errno_location().read() };
        return if errno == ESRCH { Ok(None) } else { Err(errno) };
    }
    // SAFETY: the kernel NUL-terminates the path it wrote into the buffer.
    let path = unsafe { CStr::from_ptr(buffer.as_ptr()) };
    Ok(Some(PathBuf::from(OsString::from_vec(
        path.to_bytes().to_vec(),
    ))))
}

/// This machine's host name, as `gethostname` reports it.
pub fn host_name() -> Option<String> {
    let mut buffer = vec![0 as c_char; 1024];
    // SAFETY: the buffer is owned here and its length is passed; the last byte
    // stays NUL, so the result is terminated even if the name was cut.
    let result = unsafe { gethostname(buffer.as_mut_ptr(), buffer.len() - 1) };
    if result != 0 {
        return None;
    }
    // SAFETY: the buffer is NUL-terminated, as above.
    let name = unsafe { CStr::from_ptr(buffer.as_ptr()) };
    name.to_str().ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_in_the_table_and_its_arguments_read_back() {
        let pids = all_process_ids().expect("the process table reads");
        assert!(pids.contains(&std::process::id()));
        let ProcessArguments::Read(arguments) = process_arguments(std::process::id()) else {
            panic!("this process's arguments are readable to itself");
        };
        let expected: Vec<OsString> = std::env::args_os().collect();
        assert_eq!(arguments, expected);
        let executable = process_executable_path(std::process::id())
            .expect("own executable readable")
            .expect("this process exists");
        assert_eq!(
            executable.canonicalize().ok(),
            std::env::current_exe()
                .ok()
                .and_then(|path| path.canonicalize().ok())
        );
        assert!(host_name().is_some_and(|name| !name.is_empty()));
    }

    /// The owner read must answer for another user's process, or the only
    /// evidence that lets such a process be skipped is missing. launchd runs
    /// as root; this test does not.
    #[test]
    fn the_owner_of_another_user_s_process_is_readable() {
        let crate::macos::ProcessOwner::Running { uid: this_user, .. } =
            crate::macos::process_owner(std::process::id())
        else {
            panic!("this process's owner is readable");
        };
        if this_user == 0 {
            return;
        }
        assert!(matches!(
            crate::macos::process_owner(1),
            crate::macos::ProcessOwner::Running { uid: 0, .. }
        ));
    }

    #[test]
    fn a_short_answer_is_unreadable_not_empty() {
        let mut buffer = 2_i32.to_ne_bytes().to_vec();
        buffer.extend_from_slice(b"/bin/x\0\0\0only-one\0");
        assert_eq!(parse_procargs2(&buffer), None);
        let mut complete = 2_i32.to_ne_bytes().to_vec();
        complete.extend_from_slice(b"/bin/x\0\0\0first\0second\0ENV=1\0");
        assert_eq!(
            parse_procargs2(&complete),
            Some(vec![OsString::from("first"), OsString::from("second")])
        );
    }
}
