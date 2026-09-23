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

const POSIX_SPAWN_SETSIGDEF: c_short = 0x0004;
const POSIX_SPAWN_SETSIGMASK: c_short = 0x0008;
const POSIX_SPAWN_START_SUSPENDED: c_short = 0x0080;
const POSIX_SPAWN_CLOEXEC_DEFAULT: c_short = 0x4000;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
/// Where the target's standard descriptors point. The file-actions object
/// copies the path, so it need not outlive the spawn.
const NULL_DEVICE: &std::ffi::CStr = c"/dev/null";
const F_DUPFD_CLOEXEC: c_int = 67;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
// The value on Darwin. Declared here beside the other signal and fcntl
// constants rather than pulled from a crate, matching this module's existing
// practice of naming exactly the libc surface it uses.
const EINTR: c_int = 4;
/// Why a guardian exited, carried in its exit status.
///
/// The launcher cannot ask a dead guardian what happened, and a release that
/// fails with a broken pipe has already lost the answer. These make the exit
/// status the record instead. Offset by the signal-failure code when the
/// guardian could not signal the target at all.
///
/// Zero means the guardian carried out a command it was given -- release or
/// terminate. Both are normal, so neither is distinguished here: the code
/// answers "why did this guardian exit WITHOUT being commanded", which is the
/// question a launcher asks when it finds the pipe already closed.
const GUARDIAN_COMMANDED: c_int = 0;
const GUARDIAN_LAUNCHER_GONE: c_int = 101;
const GUARDIAN_UNKNOWN_COMMAND: c_int = 102;
const GUARDIAN_READ_FAILED: c_int = 103;
const GUARDIAN_SIGNAL_FAILED: c_int = 10;
const SIGCONT: c_int = 19;
const SIGKILL: c_int = 9;
#[cfg(test)]
const SIGTERM: c_int = 15;
#[cfg(test)]
const SIGUSR1: c_int = 30;
#[cfg(test)]
const SIG_BLOCK: c_int = 1;
#[cfg(test)]
const SIG_IGN: usize = 1;
#[cfg(test)]
const SIG_ERR: usize = usize::MAX;
#[cfg(test)]
const WNOHANG: c_int = 1;
#[cfg(test)]
const F_GETFL: c_int = 3;
#[cfg(test)]
const O_ACCMODE: c_int = 3;
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
type SignalSet = u32;
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
    #[cfg(test)]
    fn pthread_sigmask(how: c_int, set: *const SignalSet, old_set: *mut SignalSet) -> c_int;
    #[cfg(test)]
    fn sigaddset(set: *mut SignalSet, signal: c_int) -> c_int;
    fn sigemptyset(set: *mut SignalSet) -> c_int;
    fn sigfillset(set: *mut SignalSet) -> c_int;
    #[cfg(test)]
    fn sigprocmask(how: c_int, set: *const SignalSet, old_set: *mut SignalSet) -> c_int;
    #[cfg(test)]
    fn signal(signal: c_int, handler: *const c_void) -> *const c_void;
    fn getdtablesize() -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn notify_is_valid_token(token: c_int) -> bool;
    /// The thread's `errno` location. Read directly because the safe wrapper
    /// allocates, and the one caller runs in a fork child where only
    /// async-signal-safe calls are permitted.
    fn __error() -> *mut c_int;
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
    fn posix_spawn_file_actions_addopen(
        actions: *mut PosixSpawnFileActions,
        fd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: u16,
    ) -> c_int;
    fn posix_spawnattr_init(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_destroy(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_setflags(attributes: *mut PosixSpawnAttr, flags: c_short) -> c_int;
    fn posix_spawnattr_setsigdefault(
        attributes: *mut PosixSpawnAttr,
        signals: *const SignalSet,
    ) -> c_int;
    fn posix_spawnattr_setsigmask(
        attributes: *mut PosixSpawnAttr,
        signals: *const SignalSet,
    ) -> c_int;
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
    ProcessMissing,
    ProcessInspectionDenied,
    ProcessLayoutMismatch,
    /// The kernel refused to describe the process for a reason this code does
    /// not classify. Carries the errno, which is the only thing that can name
    /// it: without it a reader is left comparing struct definitions against a
    /// kernel header for a failure that never read a structure.
    ProcessInspectionFailed(i32),
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
    /// The guardian exited without releasing, carrying its reason in the code.
    ///
    /// See the `GUARDIAN_*` constants: the value distinguishes a launcher that
    /// died, a command byte that was not the release byte, and a read that
    /// failed outright, so an intermittent failure names its own branch rather
    /// than requiring a theory.
    GuardianExited(c_int),
    Reap(io::ErrorKind),
}

/// Terminate a process only if it is still the exact generation named.
///
/// The caller supplies the generation it recorded when the process was trusted,
/// and this re-reads the kernel's start time immediately before signalling. A
/// pid alone is not identity: pids are reused, so signalling on a pid match
/// after a crash can kill an unrelated program that happens to hold that number
/// now — on a machine this module does not own.
///
/// Reports whether a signal was sent, so a caller can tell "the process was
/// gone" from "the process was replaced" from "it was terminated". An
/// unreadable start time is refused rather than treated as a mismatch, since
/// not knowing is not the same as knowing it differs.
///
/// Lives here because this crate is the only one permitted raw system calls,
/// and a caller that instead spawned `/bin/kill` would achieve the same effect
/// while stepping outside the boundary that makes such calls auditable.
pub fn terminate_exact_generation(
    generation: ProcessGeneration,
) -> Result<TerminationOutcome, ProcessControlError> {
    // Read the start time directly rather than through `verify_generation`,
    // which folds an unreadable reading into "changed". Here the difference
    // decides whether a signal is sent, and NOT KNOWING WHETHER THIS IS THE
    // SAME PROCESS MUST NOT READ AS KNOWING IT IS NOT: the first is a refusal,
    // the second would let a caller conclude the orphan is already gone.
    match process_start_time(generation.pid) {
        ProcessStartTime::Started(start) if start == generation.start_time_micros => {}
        ProcessStartTime::Started(_) | ProcessStartTime::NoSuchProcess => {
            return Ok(TerminationOutcome::AlreadyGoneOrReplaced)
        }
        // Every reading that is not an answer refuses to signal. Unclassified
        // joins them for the reason the others are here: not knowing why the
        // kernel refused is not evidence about which process holds this pid,
        // and a signal sent on that basis could land on a replacement.
        ProcessStartTime::NotPermitted
        | ProcessStartTime::LayoutMismatch
        | ProcessStartTime::Unclassified(_)
        | ProcessStartTime::NoStartTime => return Err(ProcessControlError::GenerationChanged),
    }

    if unsafe { kill(generation.pid as c_int, SIGKILL) } != 0 {
        // A signal that fails because the process left in the meantime is the
        // outcome we wanted, not a failure.
        return match process_start_time(generation.pid) {
            ProcessStartTime::Started(start) if start == generation.start_time_micros => {
                Err(ProcessControlError::Signal(io::ErrorKind::Other))
            }
            ProcessStartTime::Started(_) | ProcessStartTime::NoSuchProcess => {
                Ok(TerminationOutcome::AlreadyGoneOrReplaced)
            }
            _ => Err(ProcessControlError::Signal(io::ErrorKind::Other)),
        };
    }
    Ok(TerminationOutcome::Signalled)
}

/// What a generation-checked termination did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationOutcome {
    /// The exact generation was signalled.
    Signalled,
    /// Nothing was signalled: that generation had already exited, or the pid
    /// now belongs to a different process.
    AlreadyGoneOrReplaced,
}

/// A target created in the suspended state with a death-pipe guardian.
///
/// `POSIX_SPAWN_START_SUSPENDED` stops the target after the kernel has installed
/// its executable image but before its first user-space instruction. That makes
/// the actual mapped image available to Security.framework without allowing the
/// browser to touch its profile. The launcher remains the target's parent so it
/// can reap every normal terminal path. A separate guardian blocks on a pipe
/// whose write end exists only in the launcher; EOF makes the guardian kill the
/// still-suspended target if the launcher dies before release.
pub struct BarredChild {
    generation: ProcessGeneration,
    guardian_pid: c_int,
    command: Option<OwnedFd>,
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
        let generation = self.generation;
        let result = release_guarded_target(self.guardian_pid, generation.pid as c_int, command);
        std::mem::forget(self);
        result.map(|_| ReleasedChild {
            generation,
            reaped: false,
        })
    }

    /// Kill the barred target, then reap both processes owned by the launcher.
    pub fn terminate_and_reap(mut self) -> Result<(), ProcessControlError> {
        let result = self.terminate_inner();
        std::mem::forget(self);
        result
    }

    fn terminate_inner(&mut self) -> Result<(), ProcessControlError> {
        let command = self
            .command
            .take()
            .ok_or(ProcessControlError::AlreadyReleased)?;
        terminate_guarded_target(self.guardian_pid, self.generation.pid as c_int, command)
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
    reaped: bool,
}

impl ReleasedChild {
    pub fn generation(&self) -> ProcessGeneration {
        self.generation
    }

    /// Wait until the target exits and reap it in the launcher.
    pub fn wait(mut self) -> Result<(), ProcessControlError> {
        let result = wait_for_pid(self.generation.pid as c_int);
        if result.is_ok() {
            self.reaped = true;
        }
        result
    }

    /// Terminate only if the PID still names the released generation, then reap
    /// the launcher's direct child.
    pub fn terminate_and_reap(mut self) -> Result<(), ProcessControlError> {
        verify_generation(self.generation)?;
        // SAFETY: a plain pid and signal are passed by value. The generation was
        // checked immediately above; a mismatch is refused rather than signaled.
        let signal_result = if unsafe { kill(self.generation.pid as c_int, SIGKILL) } == 0 {
            Ok(())
        } else {
            Err(ProcessControlError::Signal(
                io::Error::last_os_error().kind(),
            ))
        };
        let reap_result = wait_for_pid(self.generation.pid as c_int);
        if reap_result.is_ok() {
            self.reaped = true;
        }
        signal_result?;
        reap_result
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
        if wait_for_pid(self.generation.pid as c_int).is_ok() {
            self.reaped = true;
        }
    }
}

/// Spawn an executable suspended before its first user-space instruction.
///
/// The target receives `/dev/null` on descriptors 0 (read-only), 1 and 2
/// (write-only), and the two CDP descriptors mapped to Chromium's fixed
/// descriptors 3 and 4. It does not inherit this process's standard streams:
/// the daemon captures this module's stderr into a file that must stay empty
/// unless this module itself printed, and a browser's own logging (which can
/// carry page-derived text) would otherwise land there.
/// `POSIX_SPAWN_CLOEXEC_DEFAULT` closes every other descriptor rather than
/// relying on unrelated code to have marked its descriptors close-on-exec. Its
/// signal mask starts empty and all inherited ignored dispositions start at
/// their defaults.
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

    prepare_fork_handlers();

    let command_source = duplicate_descriptor(cdp_command_read_fd)?;
    let response_source = duplicate_descriptor(cdp_response_write_fd)?;
    let (death_read, death_write) = create_pipe()?;
    let (mut actions, mut attributes) =
        prepare_spawn(command_source.as_raw_fd(), response_source.as_raw_fd())?;

    // `posix_spawn` may enter framework and libc initialization, so it must run
    // in the ordinary multithreaded process rather than in a child of `fork`.
    let mut target_pid = 0;
    let spawn_status = unsafe {
        posix_spawn(
            &mut target_pid,
            executable.as_ptr(),
            &actions,
            &attributes,
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    let _ = unsafe { posix_spawn_file_actions_destroy(&mut actions) };
    let _ = unsafe { posix_spawnattr_destroy(&mut attributes) };
    drop(command_source);
    drop(response_source);
    if spawn_status != 0 || target_pid <= 0 {
        return Err(SpawnError::Spawn(spawn_status));
    }

    // Read the table limit before fork so the guardian can close inherited
    // descriptors using only the async-signal-safe `close` syscall.
    let descriptor_limit = unsafe { getdtablesize() };
    // SAFETY: fork has no pointer arguments. The child branch calls only
    // async-signal-safe process functions before `_exit`.
    let guardian_pid = unsafe { fork() };
    if guardian_pid < 0 {
        let error = io::Error::last_os_error().kind();
        let _ = unsafe { kill(target_pid, SIGKILL) };
        let _ = waitpid_retry(target_pid);
        return Err(SpawnError::Fork(error));
    }
    if guardian_pid == 0 {
        guardian_main(death_read.as_raw_fd(), target_pid, descriptor_limit);
    }
    drop(death_read);

    let start_time_micros = match process_start_time(target_pid as u32) {
        ProcessStartTime::Started(value) => value,
        ProcessStartTime::NoSuchProcess => {
            let _ = terminate_guarded_target(guardian_pid, target_pid, death_write);
            return Err(SpawnError::ProcessMissing);
        }
        ProcessStartTime::NotPermitted => {
            let _ = terminate_guarded_target(guardian_pid, target_pid, death_write);
            return Err(SpawnError::ProcessInspectionDenied);
        }
        ProcessStartTime::LayoutMismatch => {
            let _ = terminate_guarded_target(guardian_pid, target_pid, death_write);
            return Err(SpawnError::ProcessLayoutMismatch);
        }
        // Carries the errno rather than borrowing the layout-mismatch error,
        // so a launch that fails this way can be diagnosed from the failure
        // instead of from a guess about which kernel structure moved.
        ProcessStartTime::Unclassified(errno) => {
            let _ = terminate_guarded_target(guardian_pid, target_pid, death_write);
            return Err(SpawnError::ProcessInspectionFailed(errno));
        }
        ProcessStartTime::NoStartTime => {
            let _ = terminate_guarded_target(guardian_pid, target_pid, death_write);
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
    // Standard descriptors are opened fresh on /dev/null in the child rather
    // than inherited, so nothing the browser prints reaches this process's own
    // streams. Descriptors a file action opens survive CLOEXEC_DEFAULT.
    for (fd, flags) in [(0, O_RDONLY), (1, O_WRONLY), (2, O_WRONLY)] {
        if status == 0 {
            status = unsafe {
                posix_spawn_file_actions_addopen(&mut actions, fd, NULL_DEVICE.as_ptr(), flags, 0)
            };
        }
    }
    for fd in 3..=4 {
        if status == 0 {
            status = unsafe { posix_spawn_file_actions_addinherit_np(&mut actions, fd) };
        }
    }
    if status == 0 {
        status = unsafe { posix_spawnattr_init(&mut attributes) };
    }
    let mut signal_mask = 0;
    if status == 0 {
        status = unsafe { sigemptyset(&mut signal_mask) };
    }
    if status == 0 {
        status = unsafe { posix_spawnattr_setsigmask(&mut attributes, &signal_mask) };
    }
    let mut default_signals = 0;
    if status == 0 {
        status = unsafe { sigfillset(&mut default_signals) };
    }
    if status == 0 {
        status = unsafe { posix_spawnattr_setsigdefault(&mut attributes, &default_signals) };
    }
    if status == 0 {
        status = unsafe {
            posix_spawnattr_setflags(
                &mut attributes,
                POSIX_SPAWN_START_SUSPENDED
                    | POSIX_SPAWN_CLOEXEC_DEFAULT
                    | POSIX_SPAWN_SETSIGMASK
                    | POSIX_SPAWN_SETSIGDEF,
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

fn prepare_fork_handlers() {
    // libnotify installs a child-side `fork` handler backed by lazily initialized
    // once-state. If another thread starts that initialization while `fork`
    // snapshots the process, the child inherits an in-progress gate whose owner
    // thread no longer exists. libSystem detects that gate in `_notify_fork_child`
    // and kills the child before `fork` returns. This side-effect-free public
    // query initializes libnotify's process-global state before the guardian can
    // enter the child side of `fork`.
    let _ = unsafe { notify_is_valid_token(0) };
}

fn guardian_main(death_read: RawFd, target_pid: c_int, descriptor_limit: c_int) -> ! {
    // Only async-signal-safe calls are allowed here: another thread may have held
    // any userspace lock when `fork` copied the process. Closing every inherited
    // descriptor except the death pipe also prevents this helper from extending
    // unrelated pipe, socket, or file authority.
    for descriptor in 0..descriptor_limit {
        if descriptor != death_read {
            let _ = unsafe { close(descriptor) };
        }
    }

    let mut command = 0u8;
    // A signal may interrupt this read without consuming the command. Retry
    // rather than treating that interruption as a command failure and killing a
    // target the launcher was about to release. `errno` is read through the raw
    // location because the safe wrapper is not async-signal-safe in a fork child.
    let received = loop {
        // SAFETY: a one-byte buffer this frame owns, and a descriptor kept open
        // above.
        let result = unsafe { read(death_read, (&mut command as *mut u8).cast(), 1) };
        if result >= 0 {
            break result;
        }
        // SAFETY: reading the thread's errno location, which is valid whenever
        // a libc call has just reported failure.
        if unsafe { *__error() } != EINTR {
            break result;
        }
    };
    // The exit code records WHICH branch was taken, because the launcher can
    // otherwise only observe that the guardian is gone. A release that finds a
    // closed pipe has already lost the reason unless the guardian carried it.
    let (signal, reason) = match (received, command) {
        // Both commanded outcomes exit zero: the guardian did what it was told.
        (1, b'R') => (SIGCONT, GUARDIAN_COMMANDED),
        (1, b'T') => (SIGKILL, GUARDIAN_COMMANDED),
        // Every write end closed. The launcher holds one until it commands, so
        // this means the launcher died -- which is what the guardian exists for.
        (0, _) => (SIGKILL, GUARDIAN_LAUNCHER_GONE),
        (1, _) => (SIGKILL, GUARDIAN_UNKNOWN_COMMAND),
        _ => (SIGKILL, GUARDIAN_READ_FAILED),
    };
    // Before release the launcher is still the target's parent, so an exited
    // target retains its PID until that parent reaps it. After launcher death,
    // the guardian cannot read a start time without violating fork safety; PID
    // reuse would require an independent target death, launchd reaping it, and a
    // reuse in the interval between death-pipe wakeup and this signal.
    let signalled = unsafe { kill(target_pid, signal) } == 0;
    let _ = unsafe { close(death_read) };
    unsafe {
        _exit(if signalled {
            reason
        } else {
            reason + GUARDIAN_SIGNAL_FAILED
        })
    }
}

fn verify_generation(generation: ProcessGeneration) -> Result<(), ProcessControlError> {
    match process_start_time(generation.pid) {
        ProcessStartTime::Started(start) if start == generation.start_time_micros => Ok(()),
        _ => Err(ProcessControlError::GenerationChanged),
    }
}

fn release_guarded_target(
    guardian_pid: c_int,
    target_pid: c_int,
    command: OwnedFd,
) -> Result<(), ProcessControlError> {
    let write_result = write_byte(command.as_raw_fd(), b'R').map_err(ProcessControlError::Signal);
    drop(command);
    let guardian_result = wait_for_guardian(guardian_pid);
    if write_result.is_err() || guardian_result.is_err() {
        // The target is our unreaped direct child, so its PID cannot have been
        // reused. A failed guardian command is therefore safe to contain here.
        let _ = unsafe { kill(target_pid, SIGKILL) };
        let _ = wait_for_pid(target_pid);
    }
    // PREFER THE GUARDIAN'S REASON OVER THE WRITE'S SYMPTOM. A failed write
    // means the pipe had no reader, which means the guardian had already
    // exited -- and its exit code says why. Reporting the write error first
    // discards the answer in favour of the observation that prompted the
    // question, so a broken pipe reads as an unexplained transport failure
    // while the cause sits unread in a value this function already holds.
    if write_result.is_err() && guardian_result.is_err() {
        return guardian_result;
    }
    write_result?;
    guardian_result
}

fn terminate_guarded_target(
    guardian_pid: c_int,
    target_pid: c_int,
    command: OwnedFd,
) -> Result<(), ProcessControlError> {
    let write_result = write_byte(command.as_raw_fd(), b'T').map_err(ProcessControlError::Signal);
    drop(command);
    // Wait for the guardian before reaping the target. Until the launcher reaps
    // its direct child, the target PID cannot be reused under the guardian.
    let guardian_result = wait_for_guardian(guardian_pid);
    if write_result.is_err() || guardian_result.is_err() {
        let _ = unsafe { kill(target_pid, SIGKILL) };
    }
    let target_result = wait_for_pid(target_pid);
    write_result?;
    guardian_result?;
    target_result
}

fn wait_for_guardian(guardian_pid: c_int) -> Result<(), ProcessControlError> {
    let status = waitpid_status_retry(guardian_pid).map_err(ProcessControlError::Reap)?;
    if status != 0 {
        // Report the EXIT CODE, not the raw wait status. The raw value packs the
        // code into its high byte, so a guardian that exited 102 surfaces as
        // 26112 -- a number that looks like corruption and hides the reason the
        // guardian went to the trouble of recording.
        return Err(ProcessControlError::GuardianExited(exit_code(status)));
    }
    Ok(())
}

fn wait_for_pid(pid: c_int) -> Result<(), ProcessControlError> {
    waitpid_status_retry(pid)
        .map(|_| ())
        .map_err(ProcessControlError::Reap)
}

fn waitpid_retry(pid: c_int) -> Result<(), io::ErrorKind> {
    waitpid_status_retry(pid).map(|_| ())
}

/// The exit code inside a `waitpid` status.
///
/// A normal exit packs the code into the high byte of the low 16 bits. A status
/// that does not describe a normal exit -- a signalled or stopped child -- has
/// no exit code, and is reported as the raw value negated so it cannot be
/// mistaken for one.
fn exit_code(status: c_int) -> c_int {
    const WAIT_STATUS_MASK: c_int = 0x7f;
    if status & WAIT_STATUS_MASK == 0 {
        (status >> 8) & 0xff
    } else {
        -status
    }
}

fn waitpid_status_retry(pid: c_int) -> Result<c_int, io::ErrorKind> {
    loop {
        let mut status = 0;
        let result = unsafe { waitpid(pid, &mut status, 0) };
        if result == pid {
            return Ok(status);
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

    /// Take the serialization lock without letting one failure rename the rest.
    ///
    /// A panicking test poisons this mutex, so every later test that unwraps the
    /// lock fails with `PoisonError` instead of running. One real failure then
    /// arrives as six or seven, all naming tests that were never executed, and
    /// the one that actually broke is indistinguishable from the ones that did
    /// not. That happened here: a single spawn failure was read as a broad
    /// failure of the launch layer, and diagnosing it meant separating the
    /// original from its victims before anything could be investigated.
    ///
    /// Recovering the guard is safe because the data is `()` — there is no
    /// invariant a panicking holder could have left half-established. What the
    /// lock protects is the ordering between fixtures, and the next test wants
    /// that ordering whether or not its predecessor panicked.
    fn serialize_launch_fixtures() -> std::sync::MutexGuard<'static, ()> {
        LAUNCH_TESTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

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

    fn assert_reaped_by_launcher(pid: u32) {
        let mut status = 0;
        // A successful wait here would consume a zombie and prove the production
        // path returned before fulfilling its own reaping responsibility.
        let observed = unsafe { waitpid(pid as c_int, &mut status, WNOHANG) };
        assert_eq!(
            observed, -1,
            "target {pid} remained waitable by its launcher"
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(10),
            "waitpid refused for a reason other than ECHILD"
        );
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

    fn observed_signal_state(name: &str) -> (u32, usize) {
        let directory = TestDirectory::new(name);
        let report = directory.join("signal-state");
        let helper = std::env::current_exe().expect("test executable");
        let status = Command::new(helper)
            .arg("--ignored")
            .arg("--exact")
            .arg("launch::tests::signal_state_parent_launches_observer")
            .env("CEREBELLUM_SIGNAL_STATE_REPORT", &report)
            .status()
            .expect("run signal-state parent helper");
        assert_eq!(
            status.code(),
            Some(0),
            "signal-state helper failed: {status}"
        );

        let raw = fs::read_to_string(report).expect("spawned observer wrote signal state");
        let mut values = raw.lines();
        let mask = values
            .next()
            .expect("observer reported a mask")
            .parse()
            .expect("numeric signal mask");
        let disposition = values
            .next()
            .expect("observer reported a disposition")
            .parse()
            .expect("numeric signal disposition");
        assert!(values.next().is_none(), "unexpected signal report: {raw:?}");
        (mask, disposition)
    }

    #[test]
    fn spawned_child_starts_with_empty_signal_mask() {
        let _serial = serialize_launch_fixtures();
        let (mask, _) = observed_signal_state("signal-mask");
        assert_eq!(mask, 0, "spawned child reported signal mask {mask}");
    }

    #[test]
    fn spawned_child_starts_with_default_signal_disposition() {
        let _serial = serialize_launch_fixtures();
        let (_, disposition) = observed_signal_state("signal-disposition");
        assert_eq!(
            disposition, 0,
            "spawned child reported signal disposition {disposition}"
        );
    }

    #[test]
    #[ignore = "launched by the signal-state regression tests"]
    fn signal_state_parent_launches_observer() {
        let Some(report) = std::env::var_os("CEREBELLUM_SIGNAL_STATE_REPORT") else {
            return;
        };

        let mut blocked = 0;
        assert_eq!(unsafe { sigemptyset(&mut blocked) }, 0);
        assert_eq!(unsafe { sigaddset(&mut blocked, SIGTERM) }, 0);
        assert_eq!(
            unsafe { pthread_sigmask(SIG_BLOCK, &blocked, std::ptr::null_mut()) },
            0
        );
        let previous = unsafe { signal(SIGUSR1, SIG_IGN as *const c_void) };
        assert_ne!(previous as usize, SIG_ERR, "ignore SIGUSR1");

        let (command_read, _command_write, _response_read, response_write) = cdp_descriptors();
        let executable = std::env::current_exe().expect("test executable");
        let child = spawn_barred(
            &executable,
            &[
                OsString::from("--ignored"),
                OsString::from("--exact"),
                OsString::from("launch::tests::signal_state_observer_reports_own_state"),
            ],
            &[(OsString::from("CEREBELLUM_SIGNAL_STATE_REPORT"), report)],
            command_read.as_raw_fd(),
            response_write.as_raw_fd(),
        )
        .expect("spawn barred signal observer");
        child
            .release()
            .expect("release signal observer")
            .wait()
            .expect("reap signal observer");
    }

    #[test]
    #[ignore = "launched by the signal-state parent helper"]
    fn signal_state_observer_reports_own_state() {
        let Some(report) = std::env::var_os("CEREBELLUM_SIGNAL_STATE_REPORT") else {
            return;
        };

        let mut mask = 0;
        assert_eq!(
            unsafe { sigprocmask(SIG_BLOCK, std::ptr::null(), &mut mask) },
            0
        );
        let disposition = unsafe { signal(SIGUSR1, std::ptr::null()) } as usize;
        fs::write(report, format!("{mask}\n{disposition}\n")).expect("write observed signal state");
    }

    /// Written by the observer to its own stdout and stderr. Its presence in a
    /// stream the launching process can read is the leak under test.
    const STDIO_MARKER: &str = "cerebellum-stdio-leak-marker";

    /// Run the stdio helper with piped standard streams and return what the
    /// observer reported about its descriptors plus everything that reached the
    /// helper's stdout and stderr.
    ///
    /// The helper is a separate process so that its fd 1 and 2 are pipes this
    /// test reads, standing in for the daemon's capture of the module's stderr.
    /// `mode` chooses how the helper launches the observer: `barred` goes
    /// through `spawn_barred`, `inherited` uses a plain `Command` that inherits
    /// the helper's streams and so must visibly leak.
    fn observe_standard_streams(name: &str, mode: &str) -> (String, String, String) {
        let directory = TestDirectory::new(name);
        let report = directory.join("stdio");
        let helper = std::env::current_exe().expect("test executable");
        let output = Command::new(helper)
            .arg("--ignored")
            .arg("--exact")
            .arg("launch::tests::stdio_parent_launches_observer")
            .env("CEREBELLUM_STDIO_REPORT", &report)
            .env("CEREBELLUM_STDIO_SPAWN", mode)
            // A pipe rather than /dev/null, so the inherited control cannot
            // read as /dev/null on fd 0 by accident.
            .stdin(std::process::Stdio::piped())
            .output()
            .expect("run stdio parent helper");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert_eq!(
            output.status.code(),
            Some(0),
            "stdio helper failed: {}\nstdout: {stdout}\nstderr: {stderr}",
            output.status
        );
        let report = fs::read_to_string(report).expect("observer wrote its descriptor report");
        (report, stdout, stderr)
    }

    #[test]
    fn the_target_writes_its_standard_streams_to_dev_null() {
        let _serial = serialize_launch_fixtures();
        let (report, stdout, stderr) = observe_standard_streams("stdio-barred", "barred");
        assert!(
            !stderr.contains(STDIO_MARKER),
            "the target's stderr reached the launcher's stderr: {stderr:?}"
        );
        assert!(
            !stdout.contains(STDIO_MARKER),
            "the target's stdout reached the launcher's stdout: {stdout:?}"
        );
        // Access mode 0 is O_RDONLY, 1 is O_WRONLY.
        assert_eq!(report, "0 null 0\n1 null 1\n2 null 1\n");
    }

    /// The positive control for the test above: an observer that does inherit
    /// the helper's streams is seen to deliver the marker, so the absence
    /// asserted above is not a capture that could never see anything.
    #[test]
    fn an_inheriting_child_is_seen_to_leak_the_marker() {
        let _serial = serialize_launch_fixtures();
        let (report, stdout, stderr) = observe_standard_streams("stdio-inherited", "inherited");
        assert!(stderr.contains(STDIO_MARKER), "stderr capture: {stderr:?}");
        assert!(stdout.contains(STDIO_MARKER), "stdout capture: {stdout:?}");
        assert!(
            report.contains("1 other") && report.contains("2 other"),
            "inherited pipes read as /dev/null: {report:?}"
        );
    }

    #[test]
    #[ignore = "launched by the standard-stream tests"]
    fn stdio_parent_launches_observer() {
        let Some(report) = std::env::var_os("CEREBELLUM_STDIO_REPORT") else {
            return;
        };
        let mode = std::env::var("CEREBELLUM_STDIO_SPAWN").expect("spawn mode");
        let executable = std::env::current_exe().expect("test executable");
        let observer = [
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from("launch::tests::stdio_observer_reports_own_descriptors"),
        ];
        match mode.as_str() {
            "barred" => {
                let (command_read, _command_write, _response_read, response_write) =
                    cdp_descriptors();
                spawn_barred(
                    &executable,
                    &observer,
                    &[(OsString::from("CEREBELLUM_STDIO_REPORT"), report)],
                    command_read.as_raw_fd(),
                    response_write.as_raw_fd(),
                )
                .expect("spawn barred stdio observer")
                .release()
                .expect("release stdio observer")
                .wait()
                .expect("reap stdio observer");
            }
            "inherited" => {
                let status = Command::new(&executable)
                    .args(&observer)
                    .env("CEREBELLUM_STDIO_REPORT", report)
                    .status()
                    .expect("run inheriting stdio observer");
                assert!(status.success(), "inheriting observer failed: {status}");
            }
            other => panic!("unknown spawn mode {other:?}"),
        }
    }

    #[test]
    #[ignore = "launched by the stdio parent helper"]
    fn stdio_observer_reports_own_descriptors() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let Some(report) = std::env::var_os("CEREBELLUM_STDIO_REPORT") else {
            return;
        };
        let null = fs::metadata("/dev/null").expect("stat /dev/null");
        let mut lines = String::new();
        for fd in 0..=2 {
            // SAFETY: fd is open for the life of this process; ManuallyDrop
            // keeps the borrowed File from closing it.
            let file = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
            let metadata = file.metadata().expect("fstat standard descriptor");
            let is_null = metadata.file_type().is_char_device() && metadata.rdev() == null.rdev();
            let access = unsafe { fcntl(fd, F_GETFL) } & O_ACCMODE;
            let kind = if is_null { "null" } else { "other" };
            lines.push_str(&format!("{fd} {kind} {access}\n"));
        }
        fs::write(report, lines).expect("write descriptor report");
        // Raw writes, because the test harness captures print! output.
        let marker = format!("{STDIO_MARKER}\n");
        write_all_raw(1, marker.as_bytes()).expect("write marker to stdout");
        write_all_raw(2, marker.as_bytes()).expect("write marker to stderr");
    }

    #[test]
    fn barrier_holds_before_release_and_release_executes_once() {
        let _serial = serialize_launch_fixtures();
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
        assert_reaped_by_launcher(generation.pid);
    }

    #[test]
    fn release_refuses_a_process_generation_that_no_longer_matches() {
        let _serial = serialize_launch_fixtures();
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
        let _serial = serialize_launch_fixtures();
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
        assert_reaped_by_launcher(generation.pid);
    }

    #[test]
    fn released_termination_reaps_the_target_in_the_launcher() {
        let _serial = serialize_launch_fixtures();
        let released = spawn_shell("sleep 30")
            .release()
            .expect("release exact generation");
        let generation = released.generation();

        released
            .terminate_and_reap()
            .expect("terminate and reap released target");

        assert_eq!(
            process_start_time(generation.pid),
            ProcessStartTime::NoSuchProcess
        );
        assert_reaped_by_launcher(generation.pid);
    }

    #[test]
    fn the_target_does_not_inherit_an_unintended_parent_descriptor() {
        let _serial = serialize_launch_fixtures();
        let directory = TestDirectory::new("descriptor-authority");
        let authority_path = directory.join("unintended.lock");
        let unintended = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&authority_path)
            .expect("open unintended descriptor");
        // Rust opens files close-on-exec by default. Clear that flag so this test
        // proves the spawn policy closes unspecified descriptors rather than
        // accidentally relying on the caller's descriptor hygiene.
        assert_eq!(unsafe { fcntl(unintended.as_raw_fd(), F_SETFD, 0) }, 0);
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

        let mut descriptors =
            process_descriptors(child.generation().pid).expect("enumerate descriptors");
        descriptors.sort_unstable();
        assert_eq!(descriptors, vec![0, 1, 2, 3, 4]);
        // Descriptor numbers can be reused for intended pipes, so comparing the
        // parent's number would confuse a remapping with inheritance. Drop the
        // parent's lock-bearing descriptor and ask the kernel whether any other
        // process still carries that exact open-file authority.
        drop(unintended);
        let contender = File::open(&authority_path).expect("reopen authority file");
        // The parent can resume before the newly forked guardian is scheduled to
        // close its inherited descriptors. Wait only for that finite setup step;
        // LOCK_EX | LOCK_NB then proves neither process retains the authority.
        let deadline = Instant::now() + Duration::from_secs(2);
        let lock_result = loop {
            let result = unsafe { flock(contender.as_raw_fd(), 2 | 4) };
            if result == 0 || Instant::now() >= deadline {
                break result;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(lock_result, 0);
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
        let _serial = serialize_launch_fixtures();
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
        let _serial = serialize_launch_fixtures();
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
        assert_eq!(status.code(), Some(0), "owner helper failed: {status}");
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

#[cfg(test)]
mod termination_tests {
    use super::*;
    use std::process::Command;

    /// A pid alone never authorizes a signal.
    ///
    /// Pids are reused. After a crash the recorded pid may belong to an
    /// unrelated program — a shell, an editor, anything the user started since
    /// — so signalling on a pid match would let this module kill a stranger's
    /// process on a machine it does not own. Only the recorded start time
    /// distinguishes the two, and it is the single reason the generation is
    /// captured at launch.
    #[test]
    fn a_pid_whose_start_time_differs_is_never_signalled() {
        // A live process this test owns, standing in for whatever now holds a
        // recycled pid. Killing it would be the defect.
        let mut victim = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn a process to protect");
        let pid = victim.id();
        let real_start = match process_start_time(pid) {
            ProcessStartTime::Started(start) => start,
            other => panic!("could not read a start time: {other:?}"),
        };

        // The same pid, recorded with a generation that is not this process.
        let stale = ProcessGeneration {
            pid,
            start_time_micros: real_start - 1,
        };

        let outcome = terminate_exact_generation(stale).expect("a mismatch is not a failure");

        assert_eq!(
            outcome,
            TerminationOutcome::AlreadyGoneOrReplaced,
            "a mismatched generation must report nothing was signalled"
        );
        assert!(
            matches!(process_start_time(pid), ProcessStartTime::Started(start) if start == real_start),
            "an unrelated process holding the recorded pid was killed"
        );

        let _ = victim.kill();
        let _ = victim.wait();
    }

    /// The matching generation is signalled, so the refusal above is not simply
    /// a function that never signals anything.
    #[test]
    fn the_exact_generation_is_signalled() {
        let mut target = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn a target");
        let pid = target.id();
        let start = match process_start_time(pid) {
            ProcessStartTime::Started(start) => start,
            other => panic!("could not read a start time: {other:?}"),
        };

        let outcome = terminate_exact_generation(ProcessGeneration {
            pid,
            start_time_micros: start,
        })
        .expect("terminating the exact generation");

        assert_eq!(outcome, TerminationOutcome::Signalled);
        let _ = target.wait();
    }
}
