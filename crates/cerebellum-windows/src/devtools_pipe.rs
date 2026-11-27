use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    SetHandleInformation, ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED, HANDLE, HANDLE_FLAG_INHERIT,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTUPINFOEXW,
};

/// The read end of an anonymous pipe. There is only one protocol reader.
pub struct DevToolsPipeReader(File);

impl DevToolsPipeReader {
    /// Read buffered bytes, report `WouldBlock` when idle, or return zero on EOF.
    pub fn try_read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        if destination.is_empty() {
            return Ok(0);
        }

        let mut available = 0;
        // SAFETY: The file owns a live pipe handle; only `available` is an
        // output. No other local reader can consume the bytes we count here.
        let ok = unsafe {
            PeekNamedPipe(
                self.0.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error().map(|code| code as u32) {
                Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => Ok(0),
                _ => Err(error),
            };
        }
        if available == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let count = destination.len().min(available as usize);
        self.0.read(&mut destination[..count])
    }
}

/// An owned handle to the exact process started by `spawn_with_devtools_pipe`.
/// Dropping the handle releases the reference, not the running process.
pub struct DevToolsProcess(OwnedHandle);

impl DevToolsProcess {
    /// Return the exit code if the process exits within `timeout_ms`.
    pub fn wait(&self, timeout_ms: u32) -> io::Result<Option<u32>> {
        // SAFETY: The process handle is live for both calls; the exit-code
        // pointer is writable. Query it only once the process is signaled.
        unsafe {
            match WaitForSingleObject(self.0.as_raw_handle(), timeout_ms) {
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    bool_result(GetExitCodeProcess(self.0.as_raw_handle(), &mut code))?;
                    Ok(Some(code))
                }
                WAIT_TIMEOUT => Ok(None),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }

    pub fn terminate(&self, exit_code: u32) -> io::Result<()> {
        // SAFETY: The handle is live and was returned by CreateProcessW.
        unsafe { bool_result(TerminateProcess(self.0.as_raw_handle(), exit_code)) }
    }
}

/// Start an executable with the Windows Chromium CDP pipe switches. Returns
/// the process, parent command writer, and parent response reader. The caller
/// supplies an absolute executable path and arguments without debugging switches.
/// This primitive does not verify the executable identity or manage its profile.
///
/// The child inherits exactly its input reader and output writer. Both pipes
/// start non-inheritable, only those two ends are made inheritable, and only
/// those ends appear in the `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` passed to
/// `CreateProcessW`. `STARTF_USESTDHANDLES` is unset, so stdio is not passed.
/// See <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute>.
/// Do not run this alongside a spawn that inherits handles without an allowlist:
/// such a spawn could pick up the temporarily inheritable child ends.
pub fn spawn_with_devtools_pipe(
    executable: &Path,
    arguments: &[OsString],
) -> io::Result<(DevToolsProcess, File, DevToolsPipeReader)> {
    if !executable.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected an absolute executable path",
        ));
    }
    let mut image: Vec<_> = executable.as_os_str().encode_wide().collect();
    if image.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    image.push(0);

    let (child_command, command) = anonymous_pipe()?;
    let (response, child_response) = anonymous_pipe()?;
    let child_handles = [
        child_command.as_raw_handle(),
        child_response.as_raw_handle(),
    ];

    // Chromium adopts the two decimal uint32 handle values (input first), not
    // CRT slots 3 and 4. The inherited handles keep their values in the child.
    // https://github.com/chromium/chromium/blob/main/content/browser/devtools/devtools_agent_host_impl.cc#L90-L136
    // https://github.com/chromedp/chromedp/blob/v0.20.1/pipe_windows.go#L14-L40
    let pipe_switch = format!(
        "--remote-debugging-io-pipes={},{}",
        child_handles[0] as u32, child_handles[1] as u32
    );
    let mut command_line = Vec::new();
    for argument in [
        executable.as_os_str(),
        OsStr::new("--remote-debugging-pipe"),
        OsStr::new(&pipe_switch),
    ]
    .into_iter()
    .chain(arguments.iter().map(OsString::as_os_str))
    {
        append_argument(&mut command_line, argument)?;
    }
    command_line.push(0);

    for handle in child_handles {
        // SAFETY: Both entries are live handles owned by this function.
        unsafe {
            bool_result(SetHandleInformation(
                handle,
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            ))?;
        }
    }
    let mut attributes = HandleList::new(&child_handles)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes.as_ptr();
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: `image` and the writable command line are NUL-terminated UTF-16;
    // the initialized attribute list, inheritable handles, and Win32 structs
    // are live for the call. Null optional inputs use the parent's environment
    // and directory and create non-inheritable process/thread handles.
    unsafe {
        bool_result(CreateProcessW(
            image.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT,
            null(),
            null(),
            &startup.StartupInfo,
            &mut process,
        ))?;
    }
    drop(attributes);
    drop(child_command);
    drop(child_response);
    // SAFETY: A successful CreateProcessW transfers unique ownership of both
    // non-null handles in PROCESS_INFORMATION to the caller.
    let (process, _thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(process.hProcess),
            OwnedHandle::from_raw_handle(process.hThread),
        )
    };
    Ok((
        DevToolsProcess(process),
        command,
        DevToolsPipeReader(response),
    ))
}

fn anonymous_pipe() -> io::Result<(File, File)> {
    let (mut reader, mut writer) = (null_mut(), null_mut());
    // SAFETY: Both outputs are writable; null security attributes make both
    // pipe handles non-inheritable. Success transfers ownership of both ends.
    unsafe {
        bool_result(CreatePipe(&mut reader, &mut writer, null(), 0))?;
        Ok((
            File::from(OwnedHandle::from_raw_handle(reader)),
            File::from(OwnedHandle::from_raw_handle(writer)),
        ))
    }
}

struct HandleList<'a> {
    storage: Vec<usize>,
    _handles: &'a [HANDLE; 2],
}

impl<'a> HandleList<'a> {
    fn new(handles: &'a [HANDLE; 2]) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: The null list queries the storage required for one attribute.
        unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes) };
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut storage = vec![0_usize; bytes.div_ceil(size_of::<usize>())];
        // SAFETY: The list storage is aligned and at least `bytes` bytes long.
        unsafe {
            bool_result(InitializeProcThreadAttributeList(
                storage.as_mut_ptr().cast(),
                1,
                0,
                &mut bytes,
            ))?;
        }
        let mut list = Self {
            storage,
            _handles: handles,
        };
        // SAFETY: The list is initialized. The borrowed value has exactly two
        // entries and lives until after the attribute list is deleted.
        unsafe {
            bool_result(UpdateProcThreadAttribute(
                list.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                size_of_val(handles),
                null_mut(),
                null_mut(),
            ))?;
        }
        Ok(list)
    }

    fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for HandleList<'_> {
    fn drop(&mut self) {
        // SAFETY: Only successfully initialized lists acquire this owner.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

fn bool_result(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn append_argument(line: &mut Vec<u16>, argument: &OsStr) -> io::Result<()> {
    const QUOTE: u16 = b'"' as u16;
    const SLASH: u16 = b'\\' as u16;
    if !line.is_empty() {
        line.push(b' ' as u16);
    }
    line.push(QUOTE);
    // In Windows argv parsing, backslashes are literal unless followed by a
    // quote, where each pair encodes one backslash and an odd one escapes it.
    let mut slashes = 0;
    for unit in argument.encode_wide() {
        match unit {
            0 => return Err(io::ErrorKind::InvalidInput.into()),
            SLASH => slashes += 1,
            _ => {
                let count = if unit == QUOTE {
                    2 * slashes + 1
                } else {
                    slashes
                };
                line.extend(std::iter::repeat_n(SLASH, count));
                line.push(unit);
                slashes = 0;
            }
        }
    }
    line.extend(std::iter::repeat_n(SLASH, 2 * slashes));
    line.push(QUOTE);
    Ok(())
}
