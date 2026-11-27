use crate::windows::{empty_file_time, file_time_ticks, RetainedProcessHandle};
use std::{io, mem::size_of, ptr::null_mut};
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows_sys::Win32::Foundation::{RtlNtStatusToDosError, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
use windows_sys::Win32::System::Threading::{WaitForSingleObject, PROCESS_BASIC_INFORMATION};

/// Wall-clock time, in the same FILETIME units as process creation times.
pub fn system_time_100ns() -> u64 {
    let mut time = empty_file_time();
    // SAFETY: time points to a writable FILETIME.
    unsafe { GetSystemTimePreciseAsFileTime(&mut time) };
    file_time_ticks(time)
}

impl RetainedProcessHandle {
    /// Read the inherited parent PID from this retained process object.
    pub fn parent_pid(&self) -> io::Result<u32> {
        let mut info = PROCESS_BASIC_INFORMATION::default();
        // SAFETY: the retained handle is live and info is writable with the
        // layout and size required for the process basic information class.
        let status = unsafe {
            NtQueryInformationProcess(
                self.raw_handle(),
                ProcessBasicInformation,
                (&mut info as *mut PROCESS_BASIC_INFORMATION).cast(),
                size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                null_mut(),
            )
        };
        if status < 0 {
            // SAFETY: converting a status by value does not dereference memory.
            return Err(io::Error::from_raw_os_error(unsafe {
                RtlNtStatusToDosError(status) as i32
            }));
        }
        u32::try_from(info.InheritedFromUniqueProcessId).map_err(io::Error::other)
    }

    /// Poll the exit signal without waiting. Requires a handle opened with SYNCHRONIZE.
    pub fn exit_signaled(&self) -> io::Result<bool> {
        // SAFETY: the process handle is live.
        match unsafe { WaitForSingleObject(self.raw_handle(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }
}
