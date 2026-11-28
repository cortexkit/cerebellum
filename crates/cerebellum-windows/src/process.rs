//! Creation-time and exit observations for browser custody.

use windows_sys::Win32::{
    Storage::FileSystem::SYNCHRONIZE,
    System::Threading::{GetCurrentProcess, PROCESS_QUERY_LIMITED_INFORMATION},
};

use crate::windows::{
    creation_time, open_process_handle_with_access, ProcessAccessFailure, ProcessStartTime,
    RetainedProcessHandle,
};

/// The raw creation `FILETIME` of this process, without opening it by PID.
pub fn current_process_creation_time() -> ProcessStartTime {
    // SAFETY: the pseudo-handle always refers to this process; it is not owned.
    creation_time(unsafe { GetCurrentProcess() })
}

/// What the kernel proves about the recorded (PID, creation `FILETIME`) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessGenerationLiveness {
    Live,
    Gone,
    Unknown,
}

/// Prove absence, reuse or exit without signaling any process.
pub fn observe_process_generation(pid: u32, creation_ticks: u64) -> ProcessGenerationLiveness {
    observe_with(pid, creation_ticks, open_process_handle_with_access)
}

trait ProcessEvidence {
    fn creation(&self) -> ProcessStartTime;
    fn signaled(&self) -> std::io::Result<bool>;
}

impl ProcessEvidence for RetainedProcessHandle {
    fn creation(&self) -> ProcessStartTime {
        self.creation_time()
    }

    fn signaled(&self) -> std::io::Result<bool> {
        self.exit_signaled()
    }
}

fn observe_with<H: ProcessEvidence>(
    pid: u32,
    creation_ticks: u64,
    mut open: impl FnMut(u32, u32) -> Result<H, ProcessAccessFailure>,
) -> ProcessGenerationLiveness {
    use ProcessGenerationLiveness::{Gone, Live, Unknown};

    // Windows rejects PID 0 with ERROR_INVALID_PARAMETER. An invalid record
    // must not turn that error into evidence that its process has died.
    if pid == 0 || creation_ticks == 0 {
        return Unknown;
    }
    let (process, queryable) = match open(pid, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(handle) => (handle, true),
        Err(ProcessAccessFailure::NoSuchProcess) => return Gone,
        Err(ProcessAccessFailure::AccessDenied) => match open(pid, SYNCHRONIZE) {
            Ok(handle) => (handle, false),
            Err(ProcessAccessFailure::NoSuchProcess) => return Gone,
            Err(_) => return Unknown,
        },
        Err(_) => return Unknown,
    };

    // A signaled process handle proves exit even if it cannot be queried.
    // While the recorded process is live, its PID cannot be reused.
    let wait = process.signaled();
    if matches!(wait, Ok(true)) {
        return Gone;
    }
    if queryable {
        match process.creation() {
            ProcessStartTime::Started(observed) if observed != creation_ticks => return Gone,
            ProcessStartTime::Started(_) if matches!(wait, Ok(false)) => return Live,
            _ => {}
        }
    }
    Unknown
}

#[cfg(test)]
mod tests;
