//! Raw Linux process creation and executed-image readings.
//!
//! Policy does not live here. The functions return process and image facts; a
//! caller decides which image warrants release and what an unavailable reading means.

use std::ffi::{c_char, c_int, c_void, CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::{process_start_time, ProcessStartTime};

const CDP_COMMAND_FD: RawFd = 3;
const CDP_RESPONSE_FD: RawFd = 4;

/// The kernel generation that distinguishes a process from later PID reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessGeneration {
    pub pid: u32,
    pub start_time_micros: u64,
}

/// Raw identity facts for the executable image currently mapped into a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedImageIdentity {
    pub resolved_path: PathBuf,
    pub image_sha256: String,
    pub build_id: Option<String>,
}

/// Raw failures while constructing the ptrace launch barrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnError {
    InvalidExecutable,
    InvalidArgument,
    InvalidEnvironment,
    InvalidDescriptor,
    DuplicateDescriptor(io::ErrorKind),
    Fork(io::ErrorKind),
    Ptrace(io::ErrorKind),
    Signal(io::ErrorKind),
    Wait(io::ErrorKind),
    UnexpectedStop,
    ProcessMissing,
    ProcessInspectionDenied,
    ProcessLayoutMismatch,
    ProcessStartTimeMissing,
}

/// Raw failures while reading the mapped executable image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageIdentityError {
    ProcessMissing,
    ProcessInspectionDenied,
    ProcessLayoutMismatch,
    ProcessStartTimeMissing,
    GenerationChanged,
    Executable(io::ErrorKind),
    Read(io::ErrorKind),
}

/// Failures while controlling or reaping an exact process generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessControlError {
    AlreadyReleased,
    GenerationChanged,
    GenerationUnreadable,
    Ptrace(io::ErrorKind),
    Signal(io::ErrorKind),
    Reap(io::ErrorKind),
    UnexpectedStop,
    ProcessExited,
    ExecChainExhausted,
}

/// What a generation-checked termination did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationOutcome {
    /// The exact generation was signalled.
    Signalled,
    /// Nothing was signalled because that generation exited or the PID changed.
    AlreadyGoneOrReplaced,
}

/// A target stopped after exec, before its first user-space instruction.
pub struct BarredChild {
    /// Kept private so an owned capability cannot be retargeted after launch.
    generation: ProcessGeneration,
    active: bool,
    exec_hops: usize,
}

impl BarredChild {
    pub fn generation(&self) -> ProcessGeneration {
        self.generation
    }

    /// Continue to one later exec stop, bounded across this handle's walk.
    pub fn continue_to_next_exec_stop(
        &mut self,
        maximum_hops: usize,
    ) -> Result<ExecutedImageIdentity, ProcessControlError> {
        if self.exec_hops >= maximum_hops {
            return Err(ProcessControlError::ExecChainExhausted);
        }
        ptrace_continue(self.generation.pid as c_int)?;
        let status = wait_for_status(self.generation.pid as c_int)?;
        if !is_stopped(status) {
            return Err(ProcessControlError::ProcessExited);
        }
        if !is_exec_stop(status) {
            return Err(ProcessControlError::UnexpectedStop);
        }
        self.exec_hops += 1;
        executed_image_identity(self.generation.pid).map_err(image_error_to_control)
    }

    /// Detach from the exact stopped generation and let it execute.
    pub fn release(mut self) -> Result<ReleasedChild, ProcessControlError> {
        ensure_generation(self.generation)?;
        ptrace_detach(self.generation.pid as c_int)?;
        self.active = false;
        Ok(ReleasedChild {
            generation: self.generation,
            reaped: false,
        })
    }

    /// Kill and reap the stopped target without allowing it to execute.
    pub fn terminate_and_reap(mut self) -> Result<(), ProcessControlError> {
        let result = self.terminate_inner();
        self.active = false;
        result
    }

    fn terminate_inner(&mut self) -> Result<(), ProcessControlError> {
        if !self.active {
            return Err(ProcessControlError::AlreadyReleased);
        }
        signal_kill(self.generation.pid as c_int)?;
        wait_for_pid(self.generation.pid as c_int)
    }
}

impl Drop for BarredChild {
    fn drop(&mut self) {
        if self.active {
            let _ = self.terminate_inner();
        }
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

    /// Kill this exact generation and reap it if this process owns the child.
    pub fn terminate_and_reap(mut self) -> Result<(), ProcessControlError> {
        let result = terminate_exact_generation(
            self.generation.pid,
            self.generation.start_time_micros,
            Instant::now() + Duration::from_secs(2),
        );
        if result.is_ok() {
            self.reaped = true;
        }
        result.map(|_| ())
    }
}

impl Drop for ReleasedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let _ = terminate_exact_generation(
            self.generation.pid,
            self.generation.start_time_micros,
            Instant::now() + Duration::from_millis(100),
        );
    }
}

/// Spawn an executable stopped after exec, with CDP descriptors at 3 and 4.
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
    let mut argv: Vec<*const c_char> = argument_strings
        .iter()
        .map(|value| value.as_ptr())
        .collect();
    argv.push(std::ptr::null());

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
    let mut envp: Vec<*const c_char> = environment_strings
        .iter()
        .map(|value| value.as_ptr())
        .collect();
    envp.push(std::ptr::null());

    // Sources above fd 4 avoid a dup2 ordering collision when callers happen
    // to provide descriptors 3 and 4 in the opposite order.
    let command_source = duplicate_descriptor(cdp_command_read_fd)?;
    let response_source = duplicate_descriptor(cdp_response_write_fd)?;
    // Read this before fork: post-fork code must do only async-signal-safe work.
    let descriptor_limit = descriptor_limit();

    // SAFETY: fork has no pointer arguments. The child calls only raw syscalls
    // before execve or _exit, avoiding allocator and runtime state after fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(SpawnError::Fork(io::Error::last_os_error().kind()));
    }
    if pid == 0 {
        child_exec(
            command_source,
            response_source,
            descriptor_limit,
            executable.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
        );
    }

    // SAFETY: these are parent-owned duplicates; the child has its own copies.
    unsafe {
        libc::close(command_source);
        libc::close(response_source);
    }

    let status = wait_for_status_spawn(pid, libc::WUNTRACED)?;
    if !is_stopped(status) || stop_signal(status) != libc::SIGSTOP {
        let _ = signal_kill(pid);
        let _ = wait_for_pid(pid);
        return Err(SpawnError::UnexpectedStop);
    }

    // A launcher death before SEIZE leaves this child stopped before execve, so it
    // never maps or runs the browser rather than escaping as an unattended process.
    let options = (libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACEEXEC) as usize;
    // SAFETY: pid is this process's group-stopped child and options is the ptrace ABI value.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SEIZE,
            pid,
            std::ptr::null_mut::<c_void>(),
            options as *mut c_void,
        )
    } != 0
    {
        let error = io::Error::last_os_error().kind();
        let _ = signal_kill(pid);
        let _ = wait_for_pid(pid);
        return Err(SpawnError::Ptrace(error));
    }
    #[cfg(test)]
    test_parent_death_checkpoint(ParentDeathCheckpoint::AfterSeizeBeforeExec, pid);

    if unsafe { libc::kill(pid, libc::SIGCONT) } != 0 {
        let error = io::Error::last_os_error().kind();
        let _ = signal_kill(pid);
        let _ = wait_for_pid(pid);
        return Err(SpawnError::Signal(error));
    }
    let status = wait_for_status_spawn(pid, 0)?;
    if !is_stopped(status) {
        let _ = signal_kill(pid);
        let _ = wait_for_pid(pid);
        return Err(SpawnError::UnexpectedStop);
    }
    // SAFETY: pid is this process's stopped tracee; LISTEN preserves its group stop.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_LISTEN,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<c_void>(),
        )
    } != 0
    {
        let error = io::Error::last_os_error().kind();
        let _ = signal_kill(pid);
        let _ = wait_for_pid(pid);
        return Err(SpawnError::Ptrace(error));
    }
    if unsafe { libc::kill(pid, libc::SIGCONT) } != 0 {
        let error = io::Error::last_os_error().kind();
        let _ = signal_kill(pid);
        let _ = wait_for_pid(pid);
        return Err(SpawnError::Signal(error));
    }

    let mut status = wait_for_status_spawn(pid, 0)?;
    for _ in 0..5 {
        if is_exec_stop(status) {
            break;
        }
        if !is_stopped(status) {
            let _ = signal_kill(pid);
            let _ = wait_for_pid(pid);
            return Err(SpawnError::UnexpectedStop);
        }
        // SAFETY: pid is this process's stopped tracee; no pointer is dereferenced.
        if unsafe {
            libc::ptrace(
                libc::PTRACE_CONT,
                pid,
                std::ptr::null_mut::<c_void>(),
                std::ptr::null_mut::<c_void>(),
            )
        } != 0
        {
            let error = io::Error::last_os_error().kind();
            let _ = signal_kill(pid);
            let _ = wait_for_pid(pid);
            return Err(SpawnError::Ptrace(error));
        }
        status = wait_for_status_spawn(pid, 0)?;
    }
    if !is_exec_stop(status) {
        let _ = signal_kill(pid);
        let _ = wait_for_pid(pid);
        return Err(SpawnError::UnexpectedStop);
    }
    #[cfg(test)]
    test_parent_death_checkpoint(ParentDeathCheckpoint::AfterExecStop, pid);
    let start_time_micros = start_time_for_spawn(pid as u32)?;
    Ok(BarredChild {
        generation: ProcessGeneration {
            pid: pid as u32,
            start_time_micros,
        },
        active: true,
        exec_hops: 0,
    })
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum ParentDeathCheckpoint {
    AfterSeizeBeforeExec,
    AfterExecStop,
}

#[cfg(test)]
fn test_parent_death_checkpoint(checkpoint: ParentDeathCheckpoint, pid: c_int) {
    let expected = match checkpoint {
        ParentDeathCheckpoint::AfterSeizeBeforeExec => "after-seize-before-exec",
        ParentDeathCheckpoint::AfterExecStop => "after-exec-stop",
    };
    if std::env::var_os("CEREBELLUM_LINUX_BARRIER_CHECKPOINT").as_deref()
        != Some(OsStr::new(expected))
    {
        return;
    }
    let Some(report) = std::env::var_os("CEREBELLUM_LINUX_BARRIER_HELPER_REPORT") else {
        return;
    };
    fs::write(report, pid.to_string()).expect("write checkpoint target pid");
    // SAFETY: the test helper intentionally models an owner that dies at this point.
    unsafe { libc::_exit(0) }
}

/// Read raw identity facts from the executable currently mapped into `pid`.
pub fn executed_image_identity(pid: u32) -> Result<ExecutedImageIdentity, ImageIdentityError> {
    let before = start_time_for_identity(pid)?;
    let resolved_path = fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|error| ImageIdentityError::Executable(error.kind()))?;
    let image_sha256 = sha256_file(&resolved_path)?;
    let build_id = elf_build_id(&resolved_path)?;
    let after = start_time_for_identity(pid)?;
    if before != after {
        return Err(ImageIdentityError::GenerationChanged);
    }
    Ok(ExecutedImageIdentity {
        resolved_path,
        image_sha256,
        build_id,
    })
}

/// Enumerate descriptor numbers the kernel reports for a process.
pub fn process_descriptors(pid: u32) -> Result<Vec<RawFd>, io::ErrorKind> {
    let mut descriptors = fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|error| error.kind())?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<RawFd>().ok())
        .collect::<Vec<_>>();
    descriptors.sort_unstable();
    Ok(descriptors)
}

/// Kill a PID only when procfs still identifies the recorded generation.
pub fn terminate_exact_generation(
    pid: u32,
    start_time_micros: u64,
    reap_deadline: Instant,
) -> Result<TerminationOutcome, ProcessControlError> {
    match process_start_time(pid) {
        ProcessStartTime::Started(start) if start == start_time_micros => {}
        ProcessStartTime::Started(_) | ProcessStartTime::NoSuchProcess => {
            return Ok(TerminationOutcome::AlreadyGoneOrReplaced)
        }
        ProcessStartTime::NotPermitted
        | ProcessStartTime::LayoutMismatch
        | ProcessStartTime::NoStartTime => return Err(ProcessControlError::GenerationUnreadable),
    }
    if unsafe { libc::kill(pid as c_int, libc::SIGKILL) } != 0 {
        return match process_start_time(pid) {
            ProcessStartTime::Started(start) if start == start_time_micros => Err(
                ProcessControlError::Signal(io::Error::last_os_error().kind()),
            ),
            ProcessStartTime::Started(_) | ProcessStartTime::NoSuchProcess => {
                Ok(TerminationOutcome::AlreadyGoneOrReplaced)
            }
            _ => Err(ProcessControlError::GenerationUnreadable),
        };
    }
    reap_if_owned(pid as c_int, reap_deadline)?;
    Ok(TerminationOutcome::Signalled)
}

fn child_exec(
    command_source: RawFd,
    response_source: RawFd,
    descriptor_limit: RawFd,
    executable: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> ! {
    // SAFETY: the descriptors and C-string pointers were checked before fork.
    unsafe {
        if libc::dup2(command_source, CDP_COMMAND_FD) < 0
            || libc::dup2(response_source, CDP_RESPONSE_FD) < 0
        {
            libc::_exit(110);
        }
        for fd in 5..descriptor_limit {
            libc::close(fd);
        }
        if libc::raise(libc::SIGSTOP) != 0 {
            libc::_exit(111);
        }
        libc::execve(executable, argv, envp);
        libc::_exit(112);
    }
}

fn duplicate_descriptor(fd: RawFd) -> Result<RawFd, SpawnError> {
    // SAFETY: fcntl duplicates one live descriptor without retaining Rust references.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 5) };
    if duplicate < 0 {
        return Err(SpawnError::DuplicateDescriptor(
            io::Error::last_os_error().kind(),
        ));
    }
    Ok(duplicate)
}

fn descriptor_limit() -> RawFd {
    // SAFETY: sysconf reads process-global kernel configuration.
    let limit = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    limit.clamp(5, 1_048_576) as RawFd
}

fn start_time_for_spawn(pid: u32) -> Result<u64, SpawnError> {
    match process_start_time(pid) {
        ProcessStartTime::Started(value) => Ok(value),
        ProcessStartTime::NoSuchProcess => Err(SpawnError::ProcessMissing),
        ProcessStartTime::NotPermitted => Err(SpawnError::ProcessInspectionDenied),
        ProcessStartTime::LayoutMismatch => Err(SpawnError::ProcessLayoutMismatch),
        ProcessStartTime::NoStartTime => Err(SpawnError::ProcessStartTimeMissing),
    }
}

fn start_time_for_identity(pid: u32) -> Result<u64, ImageIdentityError> {
    match process_start_time(pid) {
        ProcessStartTime::Started(value) => Ok(value),
        ProcessStartTime::NoSuchProcess => Err(ImageIdentityError::ProcessMissing),
        ProcessStartTime::NotPermitted => Err(ImageIdentityError::ProcessInspectionDenied),
        ProcessStartTime::LayoutMismatch => Err(ImageIdentityError::ProcessLayoutMismatch),
        ProcessStartTime::NoStartTime => Err(ImageIdentityError::ProcessStartTimeMissing),
    }
}

fn ensure_generation(generation: ProcessGeneration) -> Result<(), ProcessControlError> {
    match process_start_time(generation.pid) {
        ProcessStartTime::Started(start) if start == generation.start_time_micros => Ok(()),
        ProcessStartTime::Started(_) | ProcessStartTime::NoSuchProcess => {
            Err(ProcessControlError::GenerationChanged)
        }
        ProcessStartTime::NotPermitted
        | ProcessStartTime::LayoutMismatch
        | ProcessStartTime::NoStartTime => Err(ProcessControlError::GenerationUnreadable),
    }
}

fn image_error_to_control(error: ImageIdentityError) -> ProcessControlError {
    match error {
        ImageIdentityError::GenerationChanged | ImageIdentityError::ProcessMissing => {
            ProcessControlError::GenerationChanged
        }
        ImageIdentityError::ProcessInspectionDenied
        | ImageIdentityError::ProcessLayoutMismatch
        | ImageIdentityError::ProcessStartTimeMissing => ProcessControlError::GenerationUnreadable,
        ImageIdentityError::Executable(kind) | ImageIdentityError::Read(kind) => {
            ProcessControlError::Reap(kind)
        }
    }
}

fn ptrace_continue(pid: c_int) -> Result<(), ProcessControlError> {
    // SAFETY: pid is the tracee owned by this handle; no pointer is dereferenced.
    if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, std::ptr::null_mut::<c_void>(), 0) } != 0 {
        return Err(ProcessControlError::Ptrace(
            io::Error::last_os_error().kind(),
        ));
    }
    Ok(())
}

fn ptrace_detach(pid: c_int) -> Result<(), ProcessControlError> {
    // SAFETY: pid is the stopped tracee owned by this handle; no pointer is dereferenced.
    if unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, std::ptr::null_mut::<c_void>(), 0) } != 0 {
        return Err(ProcessControlError::Ptrace(
            io::Error::last_os_error().kind(),
        ));
    }
    Ok(())
}

fn signal_kill(pid: c_int) -> Result<(), ProcessControlError> {
    // SAFETY: pid and SIGKILL are scalar syscall arguments.
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
        return Err(ProcessControlError::Signal(
            io::Error::last_os_error().kind(),
        ));
    }
    Ok(())
}

fn wait_for_status_spawn(pid: c_int, options: c_int) -> Result<c_int, SpawnError> {
    let mut status = 0;
    loop {
        // SAFETY: status points to owned storage and pid is passed by value.
        let observed = unsafe { libc::waitpid(pid, &mut status, options) };
        if observed == pid {
            return Ok(status);
        }
        if observed < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(SpawnError::Wait(io::Error::last_os_error().kind()));
    }
}

fn wait_for_status(pid: c_int) -> Result<c_int, ProcessControlError> {
    let mut status = 0;
    loop {
        // SAFETY: status points to owned storage and pid is passed by value.
        let observed = unsafe { libc::waitpid(pid, &mut status, 0) };
        if observed == pid {
            return Ok(status);
        }
        if observed < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(ProcessControlError::Reap(io::Error::last_os_error().kind()));
    }
}

fn wait_for_pid(pid: c_int) -> Result<(), ProcessControlError> {
    wait_for_status(pid).map(|_| ())
}

fn reap_if_owned(pid: c_int, deadline: Instant) -> Result<(), ProcessControlError> {
    let mut status = 0;
    loop {
        // SAFETY: status points to owned storage and pid is passed by value.
        let observed = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if observed == pid {
            return Ok(());
        }
        if observed < 0 {
            let error = io::Error::last_os_error();
            return match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::InvalidInput | io::ErrorKind::NotFound => Ok(()),
                _ if error.raw_os_error() == Some(libc::ECHILD) => Ok(()),
                _ => Err(ProcessControlError::Reap(error.kind())),
            };
        }
        if Instant::now() >= deadline {
            return Err(ProcessControlError::Reap(io::ErrorKind::TimedOut));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn is_stopped(status: c_int) -> bool {
    status & 0x7f == 0x7f
}

fn stop_signal(status: c_int) -> c_int {
    (status >> 8) & 0xff
}

fn is_exec_stop(status: c_int) -> bool {
    is_stopped(status) && (status >> 8) == (libc::SIGTRAP | (libc::PTRACE_EVENT_EXEC << 8))
}

fn c_string(value: &OsStr) -> Option<CString> {
    CString::new(value.as_bytes()).ok()
}

fn sha256_file(path: &Path) -> Result<String, ImageIdentityError> {
    let mut file = File::open(path).map_err(|error| ImageIdentityError::Read(error.kind()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| ImageIdentityError::Read(error.kind()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex(&digest.finalize()))
}

fn elf_build_id(path: &Path) -> Result<Option<String>, ImageIdentityError> {
    let mut file = File::open(path).map_err(|error| ImageIdentityError::Read(error.kind()))?;
    let mut header = [0_u8; 64];
    if file.read_exact(&mut header).is_err() || &header[..4] != b"\x7fELF" || header[5] != 1 {
        return Ok(None);
    }
    let class = header[4];
    let (program_offset, entry_size, entry_count) = match class {
        1 => (
            u32_at(&header, 28)? as u64,
            u16_at(&header, 42)? as usize,
            u16_at(&header, 44)?,
        ),
        2 => (
            u64_at(&header, 32)?,
            u16_at(&header, 54)? as usize,
            u16_at(&header, 56)?,
        ),
        _ => return Ok(None),
    };
    for index in 0..entry_count {
        let offset = program_offset + u64::from(index) * entry_size as u64;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| ImageIdentityError::Read(error.kind()))?;
        let mut entry = vec![0_u8; entry_size];
        file.read_exact(&mut entry)
            .map_err(|error| ImageIdentityError::Read(error.kind()))?;
        if u32_at(&entry, 0)? != libc::PT_NOTE {
            continue;
        }
        let (note_offset, note_size) = match class {
            1 => (u32_at(&entry, 4)? as u64, u32_at(&entry, 16)? as usize),
            _ => (u64_at(&entry, 8)?, u64_at(&entry, 32)? as usize),
        };
        if note_size > 16 * 1024 * 1024 {
            continue;
        }
        file.seek(SeekFrom::Start(note_offset))
            .map_err(|error| ImageIdentityError::Read(error.kind()))?;
        let mut notes = vec![0_u8; note_size];
        file.read_exact(&mut notes)
            .map_err(|error| ImageIdentityError::Read(error.kind()))?;
        if let Some(build_id) = gnu_build_id(&notes) {
            return Ok(Some(build_id));
        }
    }
    Ok(None)
}

fn gnu_build_id(notes: &[u8]) -> Option<String> {
    let mut offset: usize = 0;
    while offset.checked_add(12)? <= notes.len() {
        let name_size = u32_at(notes, offset).ok()? as usize;
        let descriptor_size = u32_at(notes, offset + 4).ok()? as usize;
        let note_type = u32_at(notes, offset + 8).ok()?;
        offset += 12;
        let name_end = offset.checked_add(name_size)?;
        let descriptor_start = align4(name_end)?;
        let descriptor_end = descriptor_start.checked_add(descriptor_size)?;
        let next = align4(descriptor_end)?;
        if next > notes.len() {
            return None;
        }
        if note_type == 3 && notes.get(offset..name_end) == Some(b"GNU\0") {
            return Some(hex(notes.get(descriptor_start..descriptor_end)?));
        }
        offset = next;
    }
    None
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, ImageIdentityError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(ImageIdentityError::Read(io::ErrorKind::InvalidData))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ImageIdentityError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(ImageIdentityError::Read(io::ErrorKind::InvalidData))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, ImageIdentityError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(ImageIdentityError::Read(io::ErrorKind::InvalidData))?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Command;

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        }
    }

    fn spawn_sleep() -> BarredChild {
        let (command_read, _command_write) = pipe();
        let (_response_read, response_write) = pipe();
        spawn_barred(
            Path::new("/bin/sleep"),
            &[OsString::from("30")],
            &[],
            command_read.as_raw_fd(),
            response_write.as_raw_fd(),
        )
        .expect("spawn barred sleep")
    }

    fn wait_for_target_death(report: &Path) {
        let pid: u32 = fs::read_to_string(report)
            .expect("helper wrote target pid")
            .parse()
            .expect("numeric target pid");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match process_start_time(pid) {
                ProcessStartTime::NoSuchProcess => return,
                ProcessStartTime::Started(start) if Instant::now() >= deadline => {
                    let _ = terminate_exact_generation(
                        pid,
                        start,
                        Instant::now() + Duration::from_secs(1),
                    );
                    panic!("target {pid} survived launcher death");
                }
                ProcessStartTime::Started(_) => std::thread::sleep(Duration::from_millis(10)),
                observed => panic!("cannot observe target {pid}: {observed:?}"),
            }
        }
    }

    fn launcher_death_at_checkpoint_kills_target(checkpoint: &str, name: &str) {
        let report =
            std::env::temp_dir().join(format!("cerebellum-linux-{name}-{}", std::process::id()));
        let _ = fs::remove_file(&report);
        let status = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--ignored")
            .arg("--exact")
            .arg("launch::tests::owner_process_exits_at_requested_checkpoint")
            .env("CEREBELLUM_LINUX_BARRIER_CHECKPOINT", checkpoint)
            .env("CEREBELLUM_LINUX_BARRIER_HELPER_REPORT", &report)
            .status()
            .expect("run owner helper");
        assert_eq!(status.code(), Some(0), "owner helper failed: {status}");
        wait_for_target_death(&report);
        let _ = fs::remove_file(report);
    }

    #[test]
    fn release_refuses_a_process_generation_that_no_longer_matches() {
        let mut child = spawn_sleep();
        child.generation.start_time_micros += 1;
        assert_eq!(
            child.release().map(|_| ()),
            Err(ProcessControlError::GenerationChanged)
        );
    }

    #[test]
    fn parent_death_after_exec_stop_kills_the_target_before_the_next_ptrace_call() {
        launcher_death_at_checkpoint_kills_target("after-exec-stop", "exec-stop-owner-death");
    }

    #[test]
    fn parent_death_after_seize_kills_the_target_before_execve() {
        launcher_death_at_checkpoint_kills_target("after-seize-before-exec", "seize-owner-death");
    }

    #[test]
    #[ignore = "launched by the launcher-death regression tests"]
    fn owner_process_exits_at_requested_checkpoint() {
        if std::env::var_os("CEREBELLUM_LINUX_BARRIER_HELPER_REPORT").is_none() {
            return;
        }
        let _ = spawn_sleep();
        panic!("spawn barrier missed the requested test checkpoint");
    }
}
