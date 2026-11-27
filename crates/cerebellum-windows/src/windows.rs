use std::{ffi::c_void, mem};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER,
        ERROR_INVALID_PARAMETER, FILETIME, HANDLE, HWND, LPARAM,
    },
    Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED},
    System::RemoteDesktop::{ProcessIdToSessionId, WTSGetActiveConsoleSessionId},
    System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    },
    UI::WindowsAndMessaging::{
        EnumWindows, GetWindowPlacement, GetWindowThreadProcessId, IsWindowVisible,
        SW_SHOWMINIMIZED, WINDOWPLACEMENT,
    },
};

/// What Windows reports when asked when a process started.
///
/// [`Self::Started`] is a `FILETIME`: wall-clock 100-nanosecond intervals since
/// 1601-01-01 UTC. It is not monotonic, and Microsoft does not document it as a
/// unique process token. Equal creation times are a strong practical
/// discriminator when comparing process generations, not a platform guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStartTime {
    /// The process creation `FILETIME`, in 100-nanosecond wall-clock intervals.
    Started(u64),
    /// No process holds this ID.
    NoSuchProcess,
    /// The process exists but this caller may not open it for the requested read.
    AccessDenied,
    /// Windows returned an error this seam does not otherwise classify.
    Unclassified(u32),
}

/// Why retaining a process object did not produce a handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessHandleError {
    /// No process holds this ID.
    NoSuchProcess,
    /// The process exists but this caller may not open it for the requested read.
    AccessDenied,
    /// Windows returned an error this seam does not otherwise classify.
    Unclassified(u32),
}

/// An owned reference to one Windows process object.
///
/// Keeping this handle alive keeps referring to the process object that was
/// opened, even if Windows later assigns the numeric ID to another process.
/// The handle closes when this wrapper drops.
#[derive(Debug)]
pub struct RetainedProcessHandle {
    pub(crate) handle: HANDLE,
}

impl Drop for RetainedProcessHandle {
    fn drop(&mut self) {
        // SAFETY: `handle` came from a successful `OpenProcess` call and this
        // wrapper owns it exclusively, so Drop closes it exactly once.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

/// Open and retain a reference to the process object currently holding `pid`.
///
/// The returned wrapper is stronger than retaining a timestamp: PID reuse does
/// not retarget an already-open Windows process handle. This function only
/// retains the kernel object; callers decide whether and how to use that fact.
pub fn retain_process_handle(pid: u32) -> Result<RetainedProcessHandle, ProcessHandleError> {
    open_process_handle(pid).map_err(Into::into)
}

/// Read the `FILETIME` at which Windows created the process currently holding `pid`.
pub fn process_start_time(pid: u32) -> ProcessStartTime {
    let process = match open_process_handle(pid) {
        Ok(process) => process,
        Err(error) => return error.into(),
    };
    process.creation_time()
}

impl RetainedProcessHandle {
    pub fn creation_time(&self) -> ProcessStartTime {
        creation_time(self.handle)
    }
}

fn creation_time(handle: HANDLE) -> ProcessStartTime {
    let mut creation = empty_file_time();
    let mut exit = empty_file_time();
    let mut kernel = empty_file_time();
    let mut user = empty_file_time();

    // SAFETY: the caller holds the live process handle, and every
    // output pointer names a writable `FILETIME` for the duration of this call.
    let read = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    if read == 0 {
        return process_access_failure().into();
    }

    ProcessStartTime::Started(file_time_ticks(creation))
}

/// What top-level desktop-window enumeration says about a process's windows.
///
/// `Visible` means an enumerated window has `WS_VISIBLE`, is not minimized, and
/// is not DWM-cloaked. `IsWindowVisible` reports the `WS_VISIBLE` style; it does
/// not say a human can see the window, which may still be obscured.
///
/// `Unknown` is distinct from `NotVisible`: on Windows 8 and later,
/// `EnumWindows` enumerates desktop-app top-level windows only. A pure UWP
/// process can therefore have no enumerated window, which is not an observation
/// that it has no on-screen window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowVisibility {
    /// At least one enumerated window met the raw Windows presentation checks.
    Visible,
    /// Enumerated windows for the process existed, but none met those checks.
    NotVisible,
    /// Enumeration could not make an absence claim for this process.
    Unknown,
}

/// Read the presentation state of the process's enumerated top-level windows.
///
/// This is a report about the Windows APIs named in [`WindowVisibility`], not a
/// measurement of what a person can see on a display.
pub fn enumerated_window_visibility(pid: u32) -> WindowVisibility {
    let mut search = WindowSearch {
        pid,
        saw_process_window: false,
        saw_indeterminate_window: false,
        saw_visible_window: false,
    };

    // SAFETY: `search` remains alive until `EnumWindows` returns, Windows calls
    // the callback synchronously, and the callback casts this exact pointer back
    // to `WindowSearch` before accessing it.
    let completed = unsafe {
        EnumWindows(
            Some(collect_window_visibility),
            (&mut search as *mut WindowSearch).cast::<c_void>() as LPARAM,
        )
    };

    if search.saw_visible_window {
        WindowVisibility::Visible
    } else if completed == 0 || search.saw_indeterminate_window {
        WindowVisibility::Unknown
    } else if search.saw_process_window {
        WindowVisibility::NotVisible
    } else {
        WindowVisibility::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessAccessFailure {
    NoSuchProcess,
    AccessDenied,
    Unclassified(u32),
}

impl From<ProcessAccessFailure> for ProcessStartTime {
    fn from(value: ProcessAccessFailure) -> Self {
        match value {
            ProcessAccessFailure::NoSuchProcess => Self::NoSuchProcess,
            ProcessAccessFailure::AccessDenied => Self::AccessDenied,
            ProcessAccessFailure::Unclassified(code) => Self::Unclassified(code),
        }
    }
}

impl From<ProcessAccessFailure> for ProcessHandleError {
    fn from(value: ProcessAccessFailure) -> Self {
        match value {
            ProcessAccessFailure::NoSuchProcess => Self::NoSuchProcess,
            ProcessAccessFailure::AccessDenied => Self::AccessDenied,
            ProcessAccessFailure::Unclassified(code) => Self::Unclassified(code),
        }
    }
}

fn open_process_handle(pid: u32) -> Result<RetainedProcessHandle, ProcessAccessFailure> {
    open_process_handle_with_access(pid, PROCESS_QUERY_LIMITED_INFORMATION)
}

pub(crate) fn open_process_handle_with_access(
    pid: u32,
    access: u32,
) -> Result<RetainedProcessHandle, ProcessAccessFailure> {
    // SAFETY: inheritance is disabled, and all arguments are passed by value.
    let handle = unsafe { OpenProcess(access, 0, pid) };
    if handle.is_null() {
        return Err(process_access_failure());
    }

    Ok(RetainedProcessHandle { handle })
}

fn process_access_failure() -> ProcessAccessFailure {
    // SAFETY: this reads the calling thread's last-error value immediately after
    // a failing Windows call and before another Windows call can replace it.
    let code = unsafe { GetLastError() };
    match code {
        ERROR_INVALID_PARAMETER => ProcessAccessFailure::NoSuchProcess,
        ERROR_ACCESS_DENIED => ProcessAccessFailure::AccessDenied,
        other => ProcessAccessFailure::Unclassified(other),
    }
}

fn empty_file_time() -> FILETIME {
    FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    }
}

fn file_time_ticks(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

struct WindowSearch {
    pid: u32,
    saw_process_window: bool,
    saw_indeterminate_window: bool,
    saw_visible_window: bool,
}

unsafe extern "system" fn collect_window_visibility(hwnd: HWND, lparam: LPARAM) -> i32 {
    // SAFETY: `enumerated_window_visibility` supplies this pointer to
    // `EnumWindows`, which invokes the callback synchronously while `search` is
    // alive. This callback neither stores it nor lets a panic cross the FFI edge.
    let search = unsafe { &mut *(lparam as *mut WindowSearch) };
    let mut window_pid = 0;

    // SAFETY: `hwnd` is supplied by `EnumWindows`, and `window_pid` is writable
    // for the duration of this call.
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, &mut window_pid) };
    if thread_id == 0 || window_pid != search.pid {
        return 1;
    }
    search.saw_process_window = true;

    // SAFETY: `hwnd` is supplied by `EnumWindows` for this callback invocation.
    if unsafe { IsWindowVisible(hwnd) } == 0 {
        return 1;
    }

    // SAFETY: `WINDOWPLACEMENT` consists entirely of C integer fields, points,
    // and rectangles, for which an all-zero initial state is valid before its
    // documented `length` field is set.
    let mut placement: WINDOWPLACEMENT = unsafe { mem::zeroed() };
    placement.length = mem::size_of::<WINDOWPLACEMENT>() as u32;
    // SAFETY: `hwnd` came from `EnumWindows`, and `placement` is writable with
    // its documented structure size in `length`.
    if unsafe { GetWindowPlacement(hwnd, &mut placement) } == 0 {
        search.saw_indeterminate_window = true;
        return 1;
    }
    if placement.showCmd == SW_SHOWMINIMIZED as u32 {
        return 1;
    }

    let mut cloaked = 0u32;
    // SAFETY: `hwnd` came from `EnumWindows`; `cloaked` is writable and its exact
    // byte size is supplied for the `DWMWA_CLOAKED` attribute.
    let result = unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_CLOAKED as u32,
            (&mut cloaked as *mut u32).cast::<c_void>(),
            mem::size_of::<u32>() as u32,
        )
    };
    if result != 0 {
        search.saw_indeterminate_window = true;
        return 1;
    }
    if cloaked != 0 {
        return 1;
    }

    search.saw_visible_window = true;
    1
}

use crate::session::SessionProvenance;

/// Read this process's session and compare it with the console's.
pub fn current_session_provenance() -> SessionProvenance {
    let pid = std::process::id();
    let mut session_id: u32 = 0;
    // SAFETY: `session_id` is a live, aligned u32 for the duration of the call,
    // and the call only writes through that pointer on success.
    let read = unsafe { ProcessIdToSessionId(pid, &mut session_id) };
    if read == 0 {
        // SAFETY: no arguments, and the value is only meaningful immediately
        // after a failed call on this thread.
        let last_error = unsafe { GetLastError() };
        return SessionProvenance::Unreadable { last_error };
    }

    // SAFETY: no arguments and no pointers; returns a session id or a sentinel.
    let console_session_id = unsafe { WTSGetActiveConsoleSessionId() };
    crate::session::classify(session_id, console_session_id)
}

use crate::window_list::{
    EnumerateWindowsError, TopLevelWindowOwner, TopLevelWindowReading, WindowOwnerUnreadable,
};

/// Enumerate top-level windows and name each one's owning executable.
///
/// `EnumWindows` failing is a typed error, never an empty list. A window whose
/// owner cannot be opened is retained as unreadable so the caller can see that
/// the named list is partial.
///
/// Session provenance is read alongside the list: from a non-interactive
/// session `EnumWindows` succeeds against the SERVICE desktop, and that empty
/// reading is true of this process's visibility, not of the console.
pub fn enumerate_top_level_windows() -> Result<TopLevelWindowReading, EnumerateWindowsError> {
    let mut search = WindowOwnerSearch {
        windows: Vec::new(),
    };

    // SAFETY: `search` remains alive until `EnumWindows` returns, Windows calls
    // the callback synchronously, and the callback casts this exact pointer back
    // to `WindowOwnerSearch` before accessing it.
    let completed = unsafe {
        EnumWindows(
            Some(collect_window_owners),
            (&mut search as *mut WindowOwnerSearch).cast::<c_void>() as LPARAM,
        )
    };
    if completed == 0 {
        // SAFETY: no arguments, and the value is only meaningful immediately
        // after a failed call on this thread.
        let last_error = unsafe { GetLastError() };
        return Err(EnumerateWindowsError::EnumerationFailed { last_error });
    }

    Ok(TopLevelWindowReading::from_enumerated(
        current_session_provenance(),
        search.windows,
    ))
}

struct WindowOwnerSearch {
    windows: Vec<TopLevelWindowOwner>,
}

unsafe extern "system" fn collect_window_owners(hwnd: HWND, lparam: LPARAM) -> i32 {
    // SAFETY: `enumerate_top_level_windows` supplies this pointer to
    // `EnumWindows`, which invokes the callback synchronously while `search` is
    // alive. This callback neither stores it nor lets a panic cross the FFI edge.
    let search = unsafe { &mut *(lparam as *mut WindowOwnerSearch) };
    let mut window_pid = 0;

    // SAFETY: `hwnd` is supplied by `EnumWindows`, and `window_pid` is writable
    // for the duration of this call.
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, &mut window_pid) };
    if thread_id == 0 {
        // SAFETY: this reads the calling thread's last-error value immediately
        // after a failing Windows call and before another Windows call can replace it.
        let last_error = unsafe { GetLastError() };
        search.windows.push(TopLevelWindowOwner::Unreadable(
            WindowOwnerUnreadable::ProcessIdUnreadable { last_error },
        ));
        return 1;
    }
    search.windows.push(read_window_owner(window_pid));
    1
}

fn read_window_owner(pid: u32) -> TopLevelWindowOwner {
    let process = match open_process_handle(pid) {
        Ok(process) => process,
        Err(ProcessAccessFailure::NoSuchProcess) => {
            return TopLevelWindowOwner::Unreadable(WindowOwnerUnreadable::NoSuchProcess { pid });
        }
        Err(ProcessAccessFailure::AccessDenied) => {
            return TopLevelWindowOwner::Unreadable(WindowOwnerUnreadable::AccessDenied { pid });
        }
        Err(ProcessAccessFailure::Unclassified(last_error)) => {
            return TopLevelWindowOwner::Unreadable(WindowOwnerUnreadable::Unclassified {
                pid,
                last_error,
            });
        }
    };
    match query_executable_basename(&process) {
        Ok(executable_basename) => TopLevelWindowOwner::Named {
            pid,
            executable_basename,
        },
        Err(last_error) => {
            TopLevelWindowOwner::Unreadable(WindowOwnerUnreadable::Unclassified { pid, last_error })
        }
    }
}

fn query_executable_basename(process: &RetainedProcessHandle) -> Result<String, u32> {
    match query_executable_basename_with_capacity(process, 260) {
        Err(code) if code == ERROR_INSUFFICIENT_BUFFER => {
            query_executable_basename_with_capacity(process, 32_768)
        }
        other => other,
    }
}

fn query_executable_basename_with_capacity(
    process: &RetainedProcessHandle,
    capacity: u32,
) -> Result<String, u32> {
    let mut buf = vec![0u16; capacity as usize];
    let mut char_count = capacity;
    // SAFETY: `process.handle` is a live handle owned by `process`; `buf` is
    // writable for `capacity` UTF-16 units; `char_count` is the documented in/out
    // size in characters.
    let ok =
        unsafe { QueryFullProcessImageNameW(process.handle, 0, buf.as_mut_ptr(), &mut char_count) };
    if ok == 0 {
        // SAFETY: this reads the calling thread's last-error value immediately
        // after a failing Windows call and before another Windows call can replace it.
        return Err(unsafe { GetLastError() });
    }
    let len = (char_count as usize).min(buf.len());
    let path = String::from_utf16(&buf[..len]).map_err(|_| 0u32)?;
    Ok(crate::window_list::executable_basename(&path))
}
