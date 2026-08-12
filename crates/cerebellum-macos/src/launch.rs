//! Raw macOS process creation and executed-image readings.
//!
//! Policy does not live here. The functions accept an exact executable, argument
//! vector, environment, and descriptor set, then return process and code-signing
//! facts. Callers decide whether those facts authorize release.

use std::ffi::{c_char, c_int, c_short, c_void, CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::{process_start_time, ProcessStartTime};

const POSIX_SPAWN_START_SUSPENDED: c_short = 0x0080;
const POSIX_SPAWN_CLOEXEC_DEFAULT: c_short = 0x4000;
const F_DUPFD_CLOEXEC: c_int = 67;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
const SIGCONT: c_int = 19;
const SIGKILL: c_int = 9;
const WNOHANG: c_int = 1;
const PROC_PIDLISTFDS: c_int = 1;
const CF_NUMBER_SINT32_TYPE: c_int = 3;
const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;

#[repr(C)]
struct CfDictionaryKeyCallbacks {
    version: isize,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
    equal: *const c_void,
    hash: *const c_void,
}

#[repr(C)]
struct CfDictionaryValueCallbacks {
    version: isize,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
    equal: *const c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

type PosixSpawnAttr = *mut c_void;
type PosixSpawnFileActions = *mut c_void;
type CfTypeRef = *const c_void;
type CfDictionaryRef = *const c_void;
type CfStringRef = *const c_void;
type SecCodeRef = *const c_void;

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecGuestAttributePid: CfStringRef;
    static kSecCodeInfoIdentifier: CfStringRef;
    static kSecCodeInfoUnique: CfStringRef;

    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CfDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> i32;
    fn SecCodeCheckValidity(code: SecCodeRef, flags: u32, requirement: *const c_void) -> i32;
    fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        information: *mut CfDictionaryRef,
    ) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFTypeDictionaryKeyCallBacks: CfDictionaryKeyCallbacks;
    static kCFTypeDictionaryValueCallBacks: CfDictionaryValueCallbacks;

    fn CFNumberCreate(allocator: *const c_void, ty: c_int, value: *const c_void) -> CfTypeRef;
    fn CFDictionaryCreate(
        allocator: *const c_void,
        keys: *const *const c_void,
        values: *const *const c_void,
        count: isize,
        key_callbacks: *const CfDictionaryKeyCallbacks,
        value_callbacks: *const CfDictionaryValueCallbacks,
    ) -> CfDictionaryRef;
    fn CFDictionaryGetValue(dictionary: CfDictionaryRef, key: *const c_void) -> CfTypeRef;
    fn CFStringGetCString(
        string: CfStringRef,
        buffer: *mut c_char,
        buffer_size: isize,
        encoding: u32,
    ) -> bool;
    fn CFDataGetLength(data: CfTypeRef) -> isize;
    fn CFDataGetBytePtr(data: CfTypeRef) -> *const u8;
    fn CFRelease(value: CfTypeRef);
}

extern "C" {
    fn pipe(descriptors: *mut c_int) -> c_int;
    fn fork() -> c_int;
    fn read(fd: c_int, buffer: *mut c_void, count: usize) -> isize;
    fn write(fd: c_int, buffer: *const c_void, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    #[cfg(test)]
    fn flock(fd: c_int, operation: c_int) -> c_int;
    fn getdtablesize() -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn _exit(status: c_int) -> !;

    fn posix_spawn_file_actions_init(actions: *mut PosixSpawnFileActions) -> c_int;
    fn posix_spawn_file_actions_destroy(actions: *mut PosixSpawnFileActions) -> c_int;
    fn posix_spawn_file_actions_adddup2(
        actions: *mut PosixSpawnFileActions,
        source: c_int,
        target: c_int,
    ) -> c_int;
    fn posix_spawn_file_actions_addinherit_np(
        actions: *mut PosixSpawnFileActions,
        fd: c_int,
    ) -> c_int;
    fn posix_spawnattr_init(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_destroy(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_setflags(attributes: *mut PosixSpawnAttr, flags: c_short) -> c_int;
    fn posix_spawn(
        pid: *mut c_int,
        path: *const c_char,
        actions: *const PosixSpawnFileActions,
        attributes: *const PosixSpawnAttr,
        argv: *const *mut c_char,
        environment: *const *mut c_char,
    ) -> c_int;

    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffer_size: c_int,
    ) -> c_int;
}

/// The kernel generation that distinguishes a process from a later PID reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessGeneration {
    pub pid: u32,
    pub start_time_micros: u64,
}

/// Code-signing identity of the executable image currently mapped into a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedImageIdentity {
    pub signing_identifier: String,
    pub unique_code_hash: String,
}

impl ExecutedImageIdentity {
    pub fn display_identity(&self) -> String {
        format!(
            "identifier={};cdhash={}",
            self.signing_identifier, self.unique_code_hash
        )
    }
}

/// Raw launch failures, without a browser policy interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnError {
    InvalidExecutable,
    InvalidArgument,
    InvalidEnvironment,
    InvalidDescriptor,
    Pipe(io::ErrorKind),
    DuplicateDescriptor(io::ErrorKind),
    Fork(io::ErrorKind),
    Spawn(c_int),
    GuardianProtocol,
    ProcessMissing,
    ProcessInspectionDenied,
    ProcessLayoutMismatch,
    ProcessStartTimeMissing,
}

/// Failures while reading the mapped image's validated code-signing identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageIdentityError {
    NoSuchCode(i32),
    InvalidCode(i32),
    SigningInformation(i32),
    MissingSigningIdentifier,
    MissingUniqueCodeHash,
    InvalidSigningIdentifier,
}

/// Failures while controlling or reaping an exact process generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessControlError {
    AlreadyReleased,
    GenerationChanged,
    Signal(io::ErrorKind),
    GuardianProtocol,
    Reap(io::ErrorKind),
}

/// A target created in the suspended state with a death-pipe guardian.
///
/// `POSIX_SPAWN_START_SUSPENDED` stops the target after the kernel has installed
/// its executable image but before its first user-space instruction. That makes
/// the actual mapped image available to Security.framework without allowing the
/// browser to touch its profile. A separate guardian owns the target and blocks
/// on a pipe whose write end exists only in the launcher. EOF makes the guardian
/// kill and reap the still-suspended target, so launcher death cannot accidentally
/// turn the gate into release.
pub struct BarredChild {
    generation: ProcessGeneration,
    guardian_pid: c_int,
    command: Option<OwnedFd>,
    terminal_report: Option<OwnedFd>,
}

impl BarredChild {
    pub fn generation(&self) -> ProcessGeneration {
        self.generation
    }

    /// Release this exact generation once. The guardian resumes the target only
    /// after receiving the explicit byte; closing the descriptor means death,
    /// not success.
    pub fn release(mut self) -> Result<ReleasedChild, ProcessControlError> {
        verify_generation(self.generation)?;
        let command = self
            .command
            .take()
            .ok_or(ProcessControlError::AlreadyReleased)?;
        write_byte(command.as_raw_fd(), b'R').map_err(ProcessControlError::Signal)?;
        let released = ReleasedChild {
            generation: self.generation,
            guardian_pid: self.guardian_pid,
            guardian_release: Some(command),
            terminal_report: self.terminal_report.take(),
            reaped: false,
        };
        std::mem::forget(self);
        Ok(released)
    }

    /// Kill the barred target and wait for its guardian to reap it.
    pub fn terminate_and_reap(mut self) -> Result<(), ProcessControlError> {
        self.terminate_inner()?;
        std::mem::forget(self);
        Ok(())
    }

    fn terminate_inner(&mut self) -> Result<(), ProcessControlError> {
        let command = self
            .command
            .take()
            .ok_or(ProcessControlError::AlreadyReleased)?;
        let _ = write_byte(command.as_raw_fd(), b'T');
        wait_for_guardian(
            self.guardian_pid,
            self.generation,
            self.terminal_report
                .take()
                .ok_or(ProcessControlError::GuardianProtocol)?,
            command,
        )
    }
}

impl Drop for BarredChild {
    fn drop(&mut self) {
        let _ = self.terminate_inner();
    }
}

/// Ownership of a released target remains represented by this handle.
pub struct ReleasedChild {
    generation: ProcessGeneration,
    guardian_pid: c_int,
    guardian_release: Option<OwnedFd>,
    terminal_report: Option<OwnedFd>,
    reaped: bool,
}

impl ReleasedChild {
    pub fn generation(&self) -> ProcessGeneration {
        self.generation
    }

    /// Wait until the target exits and its guardian has reaped it.
    pub fn wait(mut self) -> Result<(), ProcessControlError> {
        wait_for_guardian(
            self.guardian_pid,
            self.generation,
            self.terminal_report
                .take()
                .ok_or(ProcessControlError::GuardianProtocol)?,
            self.guardian_release
                .take()
                .ok_or(ProcessControlError::GuardianProtocol)?,
        )?;
        self.reaped = true;
        Ok(())
    }

    /// Terminate only if the PID still names the released generation, then wait
    /// for the guardian that owns `waitpid` authority to reap it.
    pub fn terminate_and_reap(mut self) -> Result<(), ProcessControlError> {
        verify_generation(self.generation)?;
        // SAFETY: a plain pid and signal are passed by value. The generation was
        // checked immediately above; a mismatch is refused rather than signaled.
        if unsafe { kill(self.generation.pid as c_int, SIGKILL) } != 0 {
            return Err(ProcessControlError::Signal(
                io::Error::last_os_error().kind(),
            ));
        }
        wait_for_guardian(
            self.guardian_pid,
            self.generation,
            self.terminal_report
                .take()
                .ok_or(ProcessControlError::GuardianProtocol)?,
            self.guardian_release
                .take()
                .ok_or(ProcessControlError::GuardianProtocol)?,
        )?;
        self.reaped = true;
        Ok(())
    }
}

impl Drop for ReleasedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        if verify_generation(self.generation).is_ok() {
            // SAFETY: the exact generation was checked immediately before this
            // best-effort ownership cleanup.
            let _ = unsafe { kill(self.generation.pid as c_int, SIGKILL) };
        }
        if let (Some(report), Some(release)) =
            (self.terminal_report.take(), self.guardian_release.take())
        {
            let _ = wait_for_guardian(self.guardian_pid, self.generation, report, release);
        } else {
            let _ = wait_for_pid(self.guardian_pid);
        }
        self.reaped = true;
    }
}

/// Spawn an executable suspended before its first user-space instruction.
///
/// The target inherits descriptors 0, 1, 2 and the two CDP descriptors, mapped
/// to Chromium's fixed descriptors 3 and 4. `POSIX_SPAWN_CLOEXEC_DEFAULT` closes
/// every other descriptor rather than relying on unrelated code to have marked
/// its descriptors close-on-exec.
pub fn spawn_barred(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    cdp_command_read_fd: RawFd,
    cdp_response_write_fd: RawFd,
) -> Result<BarredChild, SpawnError> {
    if !executable.is_absolute() {
        return Err(SpawnError::InvalidExecutable);
    }
    if cdp_command_read_fd < 0
        || cdp_response_write_fd < 0
        || cdp_command_read_fd == cdp_response_write_fd
    {
        return Err(SpawnError::InvalidDescriptor);
    }

    let executable = c_string(executable.as_os_str()).ok_or(SpawnError::InvalidExecutable)?;
    let mut argument_strings = Vec::with_capacity(arguments.len() + 1);
    argument_strings.push(executable.clone());
    for argument in arguments {
        argument_strings.push(c_string(argument).ok_or(SpawnError::InvalidArgument)?);
    }
    let mut argv: Vec<*mut c_char> = argument_strings
        .iter()
        .map(|argument| argument.as_ptr().cast_mut())
        .collect();
    argv.push(std::ptr::null_mut());

    let mut environment_strings = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        let mut bytes = name.as_os_str().as_bytes().to_vec();
        if bytes.is_empty() || bytes.contains(&b'=') || bytes.contains(&0) {
            return Err(SpawnError::InvalidEnvironment);
        }
        bytes.push(b'=');
        bytes.extend_from_slice(value.as_os_str().as_bytes());
        environment_strings.push(CString::new(bytes).map_err(|_| SpawnError::InvalidEnvironment)?);
    }
    let mut envp: Vec<*mut c_char> = environment_strings
        .iter()
        .map(|entry| entry.as_ptr().cast_mut())
        .collect();
    envp.push(std::ptr::null_mut());

    let command_source = duplicate_descriptor(cdp_command_read_fd)?;
    let response_source = duplicate_descriptor(cdp_response_write_fd)?;
    let (death_read, death_write) = create_pipe()?;
    let (report_read, report_write) = create_pipe()?;
    // Build the allocation-backed spawn descriptions before fork. The guardian
    // then uses only process syscalls and prebuilt memory; it never enters the
    // allocator state copied from another thread at fork time.
    let (mut actions, mut attributes) =
        prepare_spawn(command_source.as_raw_fd(), response_source.as_raw_fd())?;

    // SAFETY: fork has no pointer arguments. The guardian branch below limits
    // itself to C process APIs and prebuilt C strings before calling `_exit`.
    let guardian_pid = unsafe { fork() };
    if guardian_pid < 0 {
        let _ = unsafe { posix_spawn_file_actions_destroy(&mut actions) };
        let _ = unsafe { posix_spawnattr_destroy(&mut attributes) };
        return Err(SpawnError::Fork(io::Error::last_os_error().kind()));
    }
    if guardian_pid == 0 {
        drop(death_write);
        drop(report_read);
        guardian_main(GuardianSpawn {
            death_read: death_read.as_raw_fd(),
            report_write: report_write.as_raw_fd(),
            command_source: command_source.as_raw_fd(),
            response_source: response_source.as_raw_fd(),
            executable: executable.as_ptr(),
            argv: argv.as_ptr(),
            envp: envp.as_ptr(),
            actions,
            attributes,
        });
    }

    let _ = unsafe { posix_spawn_file_actions_destroy(&mut actions) };
    let _ = unsafe { posix_spawnattr_destroy(&mut attributes) };
    drop(death_read);
    drop(report_write);
    drop(command_source);
    drop(response_source);

    let mut report = [0u8; 8];
    if read_exact_raw(report_read.as_raw_fd(), &mut report).is_err() {
        drop(death_write);
        let _ = wait_for_pid(guardian_pid);
        return Err(SpawnError::GuardianProtocol);
    }
    let spawn_status = c_int::from_ne_bytes(report[..4].try_into().expect("four status bytes"));
    let target_pid = c_int::from_ne_bytes(report[4..].try_into().expect("four pid bytes"));
    if spawn_status != 0 || target_pid <= 0 {
        drop(death_write);
        let _ = wait_for_pid(guardian_pid);
        return Err(SpawnError::Spawn(spawn_status));
    }

    let start_time_micros = match process_start_time(target_pid as u32) {
        ProcessStartTime::Started(value) => value,
        ProcessStartTime::NoSuchProcess => {
            drop(death_write);
            let _ = wait_for_pid(guardian_pid);
            return Err(SpawnError::ProcessMissing);
        }
        ProcessStartTime::NotPermitted => {
            drop(death_write);
            let _ = wait_for_pid(guardian_pid);
            return Err(SpawnError::ProcessInspectionDenied);
        }
        ProcessStartTime::LayoutMismatch => {
            drop(death_write);
            let _ = wait_for_pid(guardian_pid);
            return Err(SpawnError::ProcessLayoutMismatch);
        }
        ProcessStartTime::NoStartTime => {
            drop(death_write);
            let _ = wait_for_pid(guardian_pid);
            return Err(SpawnError::ProcessStartTimeMissing);
        }
    };

    Ok(BarredChild {
        generation: ProcessGeneration {
            pid: target_pid as u32,
            start_time_micros,
        },
        guardian_pid,
        command: Some(death_write),
        terminal_report: Some(report_read),
    })
}

/// Validate and read the code-signing identity of the image mapped into `pid`.
///
/// `SecCodeCopyGuestWithAttributes` asks the kernel code host for the running
/// guest. `SecCodeCheckValidity` then performs dynamic validation, including the
/// host chain, and Apple documents it as secure against filesystem-source
/// modification. Signing information is read only after that validation.
pub fn executed_image_identity(pid: u32) -> Result<ExecutedImageIdentity, ImageIdentityError> {
    let signed_pid = pid as c_int;
    // SAFETY: CoreFoundation copies the integer into an owned object.
    let number = unsafe {
        CFNumberCreate(
            std::ptr::null(),
            CF_NUMBER_SINT32_TYPE,
            (&signed_pid as *const c_int).cast(),
        )
    };
    if number.is_null() {
        return Err(ImageIdentityError::NoSuchCode(-1));
    }
    let key = unsafe { kSecGuestAttributePid };
    let keys = [key.cast::<c_void>()];
    let values = [number];
    // SAFETY: key and value arrays contain one valid CF object each; the standard
    // callbacks retain both into the returned dictionary.
    let attributes = unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    };
    unsafe { CFRelease(number) };
    if attributes.is_null() {
        return Err(ImageIdentityError::NoSuchCode(-1));
    }

    let mut code = std::ptr::null();
    // SAFETY: output points to one SecCodeRef slot, and attributes is retained.
    let lookup =
        unsafe { SecCodeCopyGuestWithAttributes(std::ptr::null(), attributes, 0, &mut code) };
    unsafe { CFRelease(attributes) };
    if lookup != 0 || code.is_null() {
        return Err(ImageIdentityError::NoSuchCode(lookup));
    }

    // SAFETY: code is a live SecCodeRef returned above. A null requirement asks
    // for signature, host-chain and dynamic-validity checks without local policy.
    let validity = unsafe { SecCodeCheckValidity(code, 0, std::ptr::null()) };
    if validity != 0 {
        unsafe { CFRelease(code) };
        return Err(ImageIdentityError::InvalidCode(validity));
    }

    let mut information = std::ptr::null();
    // SAFETY: code was validated and the output slot receives a retained
    // dictionary. Generic identifier and unique hash are available at this flag.
    let status = unsafe {
        SecCodeCopySigningInformation(code, SEC_CS_SIGNING_INFORMATION, &mut information)
    };
    unsafe { CFRelease(code) };
    if status != 0 || information.is_null() {
        return Err(ImageIdentityError::SigningInformation(status));
    }

    let identifier_value =
        unsafe { CFDictionaryGetValue(information, kSecCodeInfoIdentifier.cast::<c_void>()) };
    if identifier_value.is_null() {
        unsafe { CFRelease(information) };
        return Err(ImageIdentityError::MissingSigningIdentifier);
    }
    let mut identifier_buffer = vec![0 as c_char; 4096];
    let identifier_ok = unsafe {
        CFStringGetCString(
            identifier_value,
            identifier_buffer.as_mut_ptr(),
            identifier_buffer.len() as isize,
            CF_STRING_ENCODING_UTF8,
        )
    };
    if !identifier_ok {
        unsafe { CFRelease(information) };
        return Err(ImageIdentityError::InvalidSigningIdentifier);
    }
    // SAFETY: CFStringGetCString succeeded and therefore wrote a NUL terminator.
    let signing_identifier =
        match unsafe { std::ffi::CStr::from_ptr(identifier_buffer.as_ptr()) }.to_str() {
            Ok(identifier) => identifier.to_owned(),
            Err(_) => {
                unsafe { CFRelease(information) };
                return Err(ImageIdentityError::InvalidSigningIdentifier);
            }
        };

    let hash_value = unsafe { CFDictionaryGetValue(information, kSecCodeInfoUnique.cast()) };
    if hash_value.is_null() {
        unsafe { CFRelease(information) };
        return Err(ImageIdentityError::MissingUniqueCodeHash);
    }
    let hash_length = unsafe { CFDataGetLength(hash_value) };
    let hash_pointer = unsafe { CFDataGetBytePtr(hash_value) };
    if hash_length <= 0 || hash_pointer.is_null() {
        unsafe { CFRelease(information) };
        return Err(ImageIdentityError::MissingUniqueCodeHash);
    }
    // SAFETY: the pointer and length belong to the retained information
    // dictionary and are copied before it is released.
    let hash = unsafe { std::slice::from_raw_parts(hash_pointer, hash_length as usize) };
    let unique_code_hash = hex(hash);
    unsafe { CFRelease(information) };

    Ok(ExecutedImageIdentity {
        signing_identifier,
        unique_code_hash,
    })
}

/// Enumerate the descriptor numbers the kernel reports for a process.
pub fn process_descriptors(pid: u32) -> Result<Vec<RawFd>, io::ErrorKind> {
    // Ask for the required byte count first. A process may open another
    // descriptor between calls, so the second buffer includes spare entries.
    let required =
        unsafe { proc_pidinfo(pid as c_int, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if required < 0 {
        return Err(io::Error::last_os_error().kind());
    }
    let entry_size = std::mem::size_of::<ProcFdInfo>();
    let count = (required as usize / entry_size).saturating_add(16).max(16);
    let mut entries = vec![
        ProcFdInfo {
            proc_fd: -1,
            proc_fdtype: 0
        };
        count
    ];
    let capacity = (entries.len() * entry_size) as c_int;
    let written = unsafe {
        proc_pidinfo(
            pid as c_int,
            PROC_PIDLISTFDS,
            0,
            entries.as_mut_ptr().cast(),
            capacity,
        )
    };
    if written < 0 {
        return Err(io::Error::last_os_error().kind());
    }
    entries.truncate(written as usize / entry_size);
    Ok(entries.into_iter().map(|entry| entry.proc_fd).collect())
}

fn prepare_spawn(
    command_source: RawFd,
    response_source: RawFd,
) -> Result<(PosixSpawnFileActions, PosixSpawnAttr), SpawnError> {
    let mut actions: PosixSpawnFileActions = std::ptr::null_mut();
    let mut attributes: PosixSpawnAttr = std::ptr::null_mut();
    let mut status = unsafe { posix_spawn_file_actions_init(&mut actions) };
    if status == 0 {
        status = unsafe { posix_spawn_file_actions_adddup2(&mut actions, command_source, 3) };
    }
    if status == 0 {
        status = unsafe { posix_spawn_file_actions_adddup2(&mut actions, response_source, 4) };
    }
    for fd in 0..=4 {
        if status == 0 {
            status = unsafe { posix_spawn_file_actions_addinherit_np(&mut actions, fd) };
        }
    }
    if status == 0 {
        status = unsafe { posix_spawnattr_init(&mut attributes) };
    }
    if status == 0 {
        status = unsafe {
            posix_spawnattr_setflags(
                &mut attributes,
                POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT,
            )
        };
    }
    if status != 0 {
        if !actions.is_null() {
            let _ = unsafe { posix_spawn_file_actions_destroy(&mut actions) };
        }
        if !attributes.is_null() {
            let _ = unsafe { posix_spawnattr_destroy(&mut attributes) };
        }
        return Err(SpawnError::Spawn(status));
    }
    Ok((actions, attributes))
}

struct GuardianSpawn {
    death_read: RawFd,
    report_write: RawFd,
    command_source: RawFd,
    response_source: RawFd,
    executable: *const c_char,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
    actions: PosixSpawnFileActions,
    attributes: PosixSpawnAttr,
}

fn guardian_main(spawn: GuardianSpawn) -> ! {
    let GuardianSpawn {
        death_read,
        report_write,
        command_source,
        response_source,
        executable,
        argv,
        envp,
        actions,
        attributes,
    } = spawn;
    // The guardian exists only to convert death-pipe EOF into kill-and-reap. It
    // must not keep unrelated module descriptors alive while doing so, because
    // merely retaining a pipe or socket end changes who has authority over its
    // lifetime even when the guardian never reads it.
    let descriptor_limit = unsafe { getdtablesize() };
    for descriptor in 3..descriptor_limit {
        if ![death_read, report_write, command_source, response_source].contains(&descriptor) {
            let _ = unsafe { close(descriptor) };
        }
    }

    let mut target_pid = 0;
    let status = unsafe {
        posix_spawn(
            &mut target_pid,
            executable,
            &actions,
            &attributes,
            argv,
            envp,
        )
    };
    let _ = unsafe { close(command_source) };
    let _ = unsafe { close(response_source) };

    let mut report = [0u8; 8];
    report[..4].copy_from_slice(&status.to_ne_bytes());
    report[4..].copy_from_slice(&target_pid.to_ne_bytes());
    let _ = write_all_raw(report_write, &report);
    if status != 0 || target_pid <= 0 {
        let _ = unsafe { close(report_write) };
        unsafe { _exit(111) };
    }

    let mut command = [0u8; 1];
    let received = read_exact_raw(death_read, &mut command).is_ok();
    let reaped = if received && command[0] == b'R' {
        let mut child_status = 0;
        // A suspended direct child cannot legitimately disappear before release.
        // Checking waitpid first avoids signaling a PID already known to have
        // exited if an external actor terminated it.
        let observed = unsafe { waitpid(target_pid, &mut child_status, WNOHANG) };
        if observed == target_pid {
            true
        } else if observed == 0 {
            let _ = unsafe { kill(target_pid, SIGCONT) };
            waitpid_retry(target_pid).is_ok()
        } else {
            false
        }
    } else {
        let _ = unsafe { kill(target_pid, SIGKILL) };
        waitpid_retry(target_pid).is_ok()
    };
    let _ = write_byte(report_write, if reaped { b'R' } else { b'F' });
    let _ = unsafe { close(report_write) };
    // Keep the guardian alive after reporting so the launcher can verify that
    // the target disappeared while still parented here. Closing the launcher's
    // write end is the acknowledgement that this observation is complete.
    let mut acknowledgement = [0u8; 1];
    let _ = read_exact_raw(death_read, &mut acknowledgement);
    let _ = unsafe { close(death_read) };
    unsafe { _exit(if reaped { 0 } else { 112 }) }
}

fn verify_generation(generation: ProcessGeneration) -> Result<(), ProcessControlError> {
    match process_start_time(generation.pid) {
        ProcessStartTime::Started(start) if start == generation.start_time_micros => Ok(()),
        _ => Err(ProcessControlError::GenerationChanged),
    }
}

fn wait_for_guardian(
    guardian_pid: c_int,
    generation: ProcessGeneration,
    terminal_report: OwnedFd,
    guardian_release: OwnedFd,
) -> Result<(), ProcessControlError> {
    let mut report = [0u8; 1];
    let report_result = read_exact_raw(terminal_report.as_raw_fd(), &mut report);
    // Read this while the guardian is still our direct child. If the guardian
    // exited without waiting, the target could be reparented and disappear for a
    // different reason; checking before guardian reap proves its own waitpid won.
    let target_is_gone = process_start_time(generation.pid) == ProcessStartTime::NoSuchProcess;
    drop(terminal_report);
    drop(guardian_release);
    wait_for_pid(guardian_pid)?;
    if report_result.is_err() || report[0] != b'R' || !target_is_gone {
        return Err(ProcessControlError::GuardianProtocol);
    }
    Ok(())
}

fn wait_for_pid(pid: c_int) -> Result<(), ProcessControlError> {
    waitpid_retry(pid).map_err(ProcessControlError::Reap)
}

fn waitpid_retry(pid: c_int) -> Result<(), io::ErrorKind> {
    loop {
        let mut status = 0;
        let result = unsafe { waitpid(pid, &mut status, 0) };
        if result == pid {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.kind());
        }
    }
}

fn c_string(value: &OsStr) -> Option<CString> {
    CString::new(value.as_bytes()).ok()
}

fn create_pipe() -> Result<(OwnedFd, OwnedFd), SpawnError> {
    let mut descriptors = [-1; 2];
    if unsafe { pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(SpawnError::Pipe(io::Error::last_os_error().kind()));
    }
    for descriptor in descriptors {
        if unsafe { fcntl(descriptor, F_SETFD, FD_CLOEXEC) } < 0 {
            let _ = unsafe { close(descriptors[0]) };
            let _ = unsafe { close(descriptors[1]) };
            return Err(SpawnError::Pipe(io::Error::last_os_error().kind()));
        }
    }
    // SAFETY: both descriptors were freshly returned by pipe and ownership is
    // transferred exactly once into these values.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

fn duplicate_descriptor(source: RawFd) -> Result<OwnedFd, SpawnError> {
    let duplicated = unsafe { fcntl(source, F_DUPFD_CLOEXEC, 10) };
    if duplicated < 0 {
        return Err(SpawnError::DuplicateDescriptor(
            io::Error::last_os_error().kind(),
        ));
    }
    // SAFETY: fcntl returned a fresh descriptor owned by this call.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn write_byte(fd: RawFd, byte: u8) -> Result<(), io::ErrorKind> {
    write_all_raw(fd, &[byte])
}

fn write_all_raw(fd: RawFd, mut bytes: &[u8]) -> Result<(), io::ErrorKind> {
    while !bytes.is_empty() {
        let written = unsafe { write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written > 0 {
            bytes = &bytes[written as usize..];
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.kind());
        }
    }
    Ok(())
}

fn read_exact_raw(fd: RawFd, mut bytes: &mut [u8]) -> Result<(), io::ErrorKind> {
    while !bytes.is_empty() {
        let read_count = unsafe { read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if read_count > 0 {
            let (_, rest) = bytes.split_at_mut(read_count as usize);
            bytes = rest;
            continue;
        }
        if read_count == 0 {
            return Err(io::ErrorKind::UnexpectedEof);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.kind());
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, OpenOptions};
    use std::os::fd::AsRawFd;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    // Forking process fixtures concurrently makes each fixture inherit transient
    // descriptors from the others, obscuring the whitelist property under test.
    static LAUNCH_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cerebellum-macos-launch-{name}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn cdp_descriptors() -> (OwnedFd, OwnedFd, OwnedFd, OwnedFd) {
        let (command_read, command_write) = create_pipe().expect("command pipe");
        let (response_read, response_write) = create_pipe().expect("response pipe");
        (command_read, command_write, response_read, response_write)
    }

    fn spawn_shell(script: &str) -> BarredChild {
        let (command_read, _command_write, _response_read, response_write) = cdp_descriptors();
        spawn_barred(
            Path::new("/bin/sh"),
            &[OsString::from("-c"), OsString::from(script)],
            &[],
            command_read.as_raw_fd(),
            response_write.as_raw_fd(),
        )
        .expect("spawn barred shell")
    }

    #[test]
    fn barrier_holds_before_release_and_release_executes_once() {
        let _serial = LAUNCH_TESTS.lock().expect("serialize launch fixtures");
        let directory = TestDirectory::new("release");
        let effect = directory.join("effect");
        let script = format!("printf executed >> '{}'; exit 0", effect.display());
        let child = spawn_shell(&script);
        let generation = child.generation();

        // Give an incorrectly unsuspended target a real opportunity to create
        // its effect. The deadline only bounds the test; the assertion is the
        // absence of the target's filesystem effect, not elapsed time.
        let observation_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < observation_deadline && !effect.exists() {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            fs::read(&effect)
                .expect_err("the effect must not exist")
                .kind(),
            io::ErrorKind::NotFound,
            "the suspended target produced its effect before release"
        );

        child
            .release()
            .expect("release exact generation")
            .wait()
            .expect("guardian reaps target");
        assert_eq!(
            fs::read_to_string(&effect).expect("released target wrote effect"),
            "executed"
        );
        assert_eq!(
            process_start_time(generation.pid),
            ProcessStartTime::NoSuchProcess,
            "the target was not reaped after its effect"
        );
    }

    #[test]
    fn release_refuses_a_process_generation_that_no_longer_matches() {
        let _serial = LAUNCH_TESTS.lock().expect("serialize launch fixtures");
        let (command_read, _command_write, _response_read, response_write) = cdp_descriptors();
        let mut child = spawn_barred(
            Path::new("/bin/sleep"),
            &[OsString::from("30")],
            &[],
            command_read.as_raw_fd(),
            response_write.as_raw_fd(),
        )
        .expect("spawn suspended sleep");
        let pid = child.generation().pid;
        child.generation.start_time_micros += 1;

        assert_eq!(
            child.release().map(|_| ()),
            Err(ProcessControlError::GenerationChanged)
        );
        assert_eq!(process_start_time(pid), ProcessStartTime::NoSuchProcess);
    }

    #[test]
    fn termination_reaps_a_barred_target_without_running_it() {
        let _serial = LAUNCH_TESTS.lock().expect("serialize launch fixtures");
        let directory = TestDirectory::new("terminate");
        let effect = directory.join("effect");
        let child = spawn_shell(&format!("printf ran > '{}'; sleep 30", effect.display()));
        let generation = child.generation();

        child.terminate_and_reap().expect("terminate and reap");

        assert_eq!(
            fs::read(&effect)
                .expect_err("terminated target must not run")
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            process_start_time(generation.pid),
            ProcessStartTime::NoSuchProcess
        );
    }

    #[test]
    fn the_target_does_not_inherit_an_unintended_parent_descriptor() {
        let _serial = LAUNCH_TESTS.lock().expect("serialize launch fixtures");
        let directory = TestDirectory::new("descriptor-authority");
        let authority_path = directory.join("unintended.lock");
        let unintended = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&authority_path)
            .expect("open unintended descriptor");
        // SAFETY: flock takes a live descriptor and an operation by value.
        assert_eq!(unsafe { flock(unintended.as_raw_fd(), 2) }, 0);
        let (command_read, _command_write, _response_read, response_write) = cdp_descriptors();
        let child = spawn_barred(
            Path::new("/bin/sleep"),
            &[OsString::from("30")],
            &[],
            command_read.as_raw_fd(),
            response_write.as_raw_fd(),
        )
        .expect("spawn suspended sleep");

        let descriptors =
            process_descriptors(child.generation().pid).expect("enumerate descriptors");
        assert!(descriptors.contains(&0));
        assert!(descriptors.contains(&1));
        assert!(descriptors.contains(&2));
        assert!(descriptors.contains(&3));
        assert!(descriptors.contains(&4));
        // Descriptor numbers can be reused for intended pipes, so comparing the
        // parent's number would confuse a remapping with inheritance. Drop the
        // parent's lock-bearing descriptor and ask the kernel whether any other
        // process still carries that exact open-file authority.
        drop(unintended);
        let contender = File::open(&authority_path).expect("reopen authority file");
        // LOCK_EX | LOCK_NB succeeds only when neither target nor guardian kept
        // the parent's open file description alive.
        assert_eq!(unsafe { flock(contender.as_raw_fd(), 2 | 4) }, 0);
        child.terminate_and_reap().expect("reap descriptor fixture");
    }

    #[test]
    fn security_framework_validates_the_running_guest_before_reading_identity() {
        let source = include_str!("launch.rs");
        let lookup_pattern = [
            "SecCodeCopyGuestWith",
            "Attributes(std::ptr::null(), attributes, 0, &mut code)",
        ]
        .concat();
        let validation_pattern = ["SecCodeCheck", "Validity(code, 0, std::ptr::null())"].concat();
        let identity_pattern = [
            "SecCodeCopySigning",
            "Information(code, SEC_CS_SIGNING_INFORMATION",
        ]
        .concat();
        let lookup = source
            .find(&lookup_pattern)
            .expect("running-guest lookup call");
        let validation = source
            .find(&validation_pattern)
            .expect("dynamic code validation call");
        let identity = source
            .find(&identity_pattern)
            .expect("validated signing-information call");
        assert!(
            lookup < validation && validation < identity,
            "running code must be looked up and dynamically validated before identity is read"
        );
    }

    #[test]
    fn security_framework_reads_the_actual_suspended_image() {
        let _serial = LAUNCH_TESTS.lock().expect("serialize launch fixtures");
        let (command_read, _command_write, _response_read, response_write) = cdp_descriptors();
        let child = spawn_barred(
            Path::new("/bin/sleep"),
            &[OsString::from("30")],
            &[],
            command_read.as_raw_fd(),
            response_write.as_raw_fd(),
        )
        .expect("spawn suspended sleep");

        let identity = executed_image_identity(child.generation().pid).expect("attest sleep image");
        assert_eq!(identity.signing_identifier, "com.apple.sleep");
        assert!(!identity.unique_code_hash.is_empty());
        child
            .terminate_and_reap()
            .expect("reap attestation fixture");
    }

    #[test]
    fn parent_death_before_release_kills_the_suspended_target() {
        let _serial = LAUNCH_TESTS.lock().expect("serialize launch fixtures");
        let directory = TestDirectory::new("parent-death");
        let report = directory.join("pid");
        let helper = std::env::current_exe().expect("test executable");
        let status = Command::new(helper)
            .arg("--ignored")
            .arg("--exact")
            .arg("launch::tests::owner_process_exits_before_release")
            .env("CEREBELLUM_BARRIER_HELPER_REPORT", &report)
            .status()
            .expect("run owner helper");
        assert!(status.success(), "owner helper failed: {status}");
        let pid: u32 = fs::read_to_string(&report)
            .expect("helper wrote target pid")
            .parse()
            .expect("numeric target pid");

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if process_start_time(pid) == ProcessStartTime::NoSuchProcess {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "target {pid} survived owner death"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[ignore = "launched by parent_death_before_release_kills_the_suspended_target"]
    fn owner_process_exits_before_release() {
        let Some(report) = std::env::var_os("CEREBELLUM_BARRIER_HELPER_REPORT") else {
            return;
        };
        let child = spawn_shell("sleep 30");
        fs::write(report, child.generation().pid.to_string()).expect("write target pid");
        std::mem::forget(child);
        std::process::exit(0);
    }
}
