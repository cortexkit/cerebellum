mod com;
mod packages;
mod shell;
#[cfg(test)]
mod tests;

pub use packages::{
    package_applications, registered_packages, PackageApplication, RegisteredPackage,
};
pub use shell::{activate_application, read_shortcut, start_menu_directories, ShortcutFields};

use crate::RetainedProcessHandle;
use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::{
    Foundation::{
        ERROR_NO_MORE_FILES, FILETIME, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        JobObjects::IsProcessInJob,
        Threading::{
            CreateProcessW, GetProcessTimes, ResumeThread, TerminateProcess, WaitForSingleObject,
            CREATE_BREAKAWAY_FROM_JOB, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTF_USESHOWWINDOW,
            STARTUPINFOW,
        },
    },
    UI::{
        Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO},
        WindowsAndMessaging::SW_SHOWNOACTIVATE,
    },
};

pub struct SuspendedProcess {
    process: Option<RetainedProcessHandle>,
    thread: OwnedHandle,
}

impl SuspendedProcess {
    pub fn process(&self) -> &RetainedProcessHandle {
        self.process.as_ref().expect("owned suspended process")
    }

    pub fn resume(mut self) -> io::Result<RetainedProcessHandle> {
        use std::os::windows::io::AsRawHandle;
        // Only a previous count of one confirms the initial thread is runnable.
        if unsafe { ResumeThread(self.thread.as_raw_handle()) } != 1 {
            return Err(io::Error::last_os_error());
        }
        Ok(self.process.take().expect("owned suspended process"))
    }
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        if let Some(process) = &self.process {
            // The only handle this cleanup can use came from our own CreateProcessW.
            unsafe { TerminateProcess(process.raw_handle(), 1) };
        }
    }
}

pub fn suspended_process(image: &Path) -> io::Result<SuspendedProcess> {
    if !image.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let path = com::wide(image.as_os_str())?;
    let parent = image.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let directory = com::wide(parent.as_os_str())?;
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESHOWWINDOW,
        wShowWindow: SW_SHOWNOACTIVATE as u16,
        ..Default::default()
    };
    let mut result = PROCESS_INFORMATION::default();
    // A null command line passes only argv[0]. The current user's environment
    // is inherited, but neither handles nor job membership are requested.
    if unsafe {
        CreateProcessW(
            path.as_ptr(),
            null_mut(),
            null(),
            null(),
            0,
            CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB,
            null(),
            directory.as_ptr(),
            &startup,
            &mut result,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // Successful CreateProcessW transfers both handles to this caller.
    Ok(SuspendedProcess {
        process: Some(RetainedProcessHandle::from_owned(unsafe {
            OwnedHandle::from_raw_handle(result.hProcess)
        })),
        thread: unsafe { OwnedHandle::from_raw_handle(result.hThread) },
    })
}

impl RetainedProcessHandle {
    pub fn in_job(&self) -> io::Result<bool> {
        let mut member = 0;
        if unsafe { IsProcessInJob(self.raw_handle(), null_mut(), &mut member) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(member != 0)
    }

    pub fn lifetime_ticks(&self) -> io::Result<(u64, Option<u64>)> {
        let exited = match unsafe { WaitForSingleObject(self.raw_handle(), 0) } {
            WAIT_OBJECT_0 => true,
            WAIT_TIMEOUT => false,
            _ => return Err(io::Error::last_os_error()),
        };
        let mut times = [FILETIME::default(); 4];
        let [start, exit, kernel, user] = &mut times;
        if unsafe { GetProcessTimes(self.raw_handle(), start, exit, kernel, user) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let ticks =
            |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        // Windows leaves the exit field unspecified until the process exits.
        let exit = exited.then(|| ticks(*exit));
        if exit.is_some_and(|exit| exit < ticks(*start)) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok((ticks(*start), exit))
    }
}

pub fn process_parents() -> io::Result<Vec<(u32, u32)>> {
    use std::os::windows::io::AsRawHandle;
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut result = Vec::new();
    let mut read = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) };
    while read != 0 {
        result.push((entry.th32ProcessID, entry.th32ParentProcessID));
        read = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) };
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
        Ok(result)
    } else {
        Err(error)
    }
}

pub fn last_input_tick() -> Option<u32> {
    let mut input = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    (unsafe { GetLastInputInfo(&mut input) } != 0).then_some(input.dwTime)
}
