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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::exec_stop::{
    continue_to_exec_stop, ExecStopLoopError, ExecStopObservation, ExecStopOutcome,
};
use crate::{process_generation, ProcessGenerationReading};

const CDP_COMMAND_FD: RawFd = 3;
const CDP_RESPONSE_FD: RawFd = 4;
// Normal helper reaping produces only a handful of stops. This allows a broad
// transient burst while still refusing a sustained signal storm between execs.
const MAX_INTERVENING_SIGNAL_STOPS: usize = 64;

/// The kernel generation that distinguishes a process from later PID reuse.
///
/// The boot ID and the start in ticks since boot are both fixed at creation,
/// so a wall-clock step cannot make a live process read as a different one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessGeneration {
    pub pid: u32,
    pub boot_id: [u8; 16],
    pub start_ticks: u64,
}

/// A caller's verdict on whether a pid still holds the generation it recorded.
///
/// Termination of a recorded generation takes this verdict from the caller
/// rather than comparing readings itself, because what a mismatch means
/// depends on how the record was written, and that is policy this crate does
/// not own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationMatch {
    /// The pid holds exactly the recorded generation: the only case that may signal.
    Exact,
    /// The recorded generation no longer exists; the pid is absent or belongs to
    /// another process.
    GoneOrReplaced,
    /// The readings could not establish either answer.
    Unreadable,
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
    /// `/dev/null` could not be opened for the target's standard descriptors.
    NullDevice(io::ErrorKind),
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
    UnexpectedStop { signal: c_int },
    ProcessExited,
    ExecChainExhausted,
    SignalStopLimitExceeded { last_signal: c_int, limit: usize },
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
        let pid = self.generation.pid as c_int;
        match continue_to_next_exec_stop_with(pid, || wait_for_status(pid).map(Some))? {
            ExecStopOutcome::Exec => {}
            ExecStopOutcome::Deadline => {
                return Err(ProcessControlError::Reap(io::ErrorKind::TimedOut));
            }
        }
        self.exec_hops += 1;
        executed_image_identity(self.generation.pid).map_err(image_error_to_control)
    }

    /// Continue until the next exec stop or a deadline, reporting timeout as
    /// an observation because a running final image has no kernel event that
    /// proves it will never exec later.
    pub fn continue_to_next_exec_stop_with_deadline(
        &mut self,
        maximum_hops: usize,
        deadline: Instant,
    ) -> Result<Option<ExecutedImageIdentity>, ProcessControlError> {
        if self.exec_hops >= maximum_hops {
            return Err(ProcessControlError::ExecChainExhausted);
        }
        let pid = self.generation.pid as c_int;
        match continue_to_next_exec_stop_with(pid, || wait_for_status_until(pid, deadline))? {
            ExecStopOutcome::Deadline => Ok(None),
            ExecStopOutcome::Exec => {
                self.exec_hops += 1;
                executed_image_identity(self.generation.pid)
                    .map(Some)
                    .map_err(image_error_to_control)
            }
        }
    }

    /// Detach from the exact stopped generation and let it execute.
    pub fn release(mut self) -> Result<ReleasedChild, ProcessControlError> {
        self.detach()?;
        Ok(ReleasedChild {
            generation: self.generation,
            reaped: false,
        })
    }

    fn detach(&mut self) -> Result<(), ProcessControlError> {
        ensure_generation(self.generation)?;
        ptrace_detach(self.generation.pid as c_int)?;
        self.active = false;
        Ok(())
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
        let generation = self.generation;
        let result = terminate_exact_generation(
            generation.pid,
            Instant::now() + Duration::from_secs(2),
            || own_generation_match(generation),
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
        let generation = self.generation;
        let _ = terminate_exact_generation(
            generation.pid,
            Instant::now() + Duration::from_millis(100),
            || own_generation_match(generation),
        );
    }
}

/// Desktop launch has no browser command or response descriptors, and its
/// released owner never signals the child. Ptrace stays on the spawning thread.
pub struct DesktopBarredChild(BarredChild, std::marker::PhantomData<std::rc::Rc<()>>);

impl DesktopBarredChild {
    pub fn generation(&self) -> ProcessGeneration {
        self.0.generation()
    }

    pub fn prepare_reaper(&self) -> io::Result<DesktopReaper> {
        DesktopReaper::start(self.generation(), wait_for_exit)
    }

    pub fn release(mut self, reaper: DesktopReaper) -> Result<DesktopChild, ProcessControlError> {
        if reaper.generation != self.generation() {
            return Err(ProcessControlError::GenerationChanged);
        }
        self.0.detach()?;
        let _ = reaper.released.send(());
        Ok(DesktopChild {
            status: reaper.status,
        })
    }
}

/// A prestarted waiter sits idle until detach succeeds. If the launch is
/// refused, the barred owner alone kills and reaps the child.
pub struct DesktopReaper {
    generation: ProcessGeneration,
    released: oneshot::Sender<()>,
    status: oneshot::Receiver<io::Result<DesktopExit>>,
}

static DESKTOP_REAPER_WAIT_FAILURES: AtomicU64 = AtomicU64::new(0);

pub fn desktop_reaper_wait_failures() -> u64 {
    DESKTOP_REAPER_WAIT_FAILURES.load(Ordering::Relaxed)
}

impl DesktopReaper {
    fn start(
        generation: ProcessGeneration,
        wait: fn(u32) -> io::Result<DesktopExit>,
    ) -> io::Result<Self> {
        let (released, ready) = oneshot::channel();
        let (report, status) = oneshot::channel();
        std::thread::Builder::new()
            .name("desktop-child-reaper".into())
            .spawn(move || {
                if ready.blocking_recv().is_ok() {
                    let result = wait(generation.pid);
                    if result.is_err() {
                        DESKTOP_REAPER_WAIT_FAILURES.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ = report.send(result);
                }
            })?;
        Ok(Self {
            generation,
            released,
            status,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum DesktopExit {
    Code(i32),
    Signal(i32),
}

/// Dropping the receiver neither signals the detached process nor joins its
/// reaper. There is no second path that can wait for the child.
pub struct DesktopChild {
    status: oneshot::Receiver<io::Result<DesktopExit>>,
}

impl DesktopChild {
    pub async fn exit(self) -> io::Result<DesktopExit> {
        self.status
            .await
            .map_err(|_| io::Error::other("desktop child reaper ended without status"))?
    }

    pub async fn exit_within(self, settle: Duration) -> io::Result<Option<DesktopExit>> {
        match tokio::time::timeout(settle, self.exit()).await {
            Ok(result) => result.map(Some),
            Err(_) => Ok(None),
        }
    }
}

fn wait_for_exit(pid: u32) -> io::Result<DesktopExit> {
    loop {
        // SAFETY: waitid initializes info on success, and never reads the buffer.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        return match info.si_code {
            // SAFETY: these SIGCHLD codes carry a status in siginfo_t.
            libc::CLD_EXITED => Ok(DesktopExit::Code(unsafe { info.si_status() })),
            libc::CLD_KILLED | libc::CLD_DUMPED => {
                Ok(DesktopExit::Signal(unsafe { info.si_status() }))
            }
            _ => Err(io::Error::other("unexpected desktop child wait status")),
        };
    }
}

pub fn spawn_desktop_barred(
    executable: &Path,
    arguments: &[OsString],
    session: &crate::session::Environment,
) -> Result<DesktopBarredChild, SpawnError> {
    let mut environment = vec![("PATH".into(), "/usr/bin:/bin".into())];
    environment.extend(
        session
            .iter()
            .filter(|(name, _)| desktop_variable(name))
            .map(|(name, value)| (name.into(), value.into())),
    );
    spawn(executable, arguments, &environment, None)
        .map(|child| DesktopBarredChild(child, std::marker::PhantomData))
}

fn desktop_variable(name: &str) -> bool {
    name.starts_with("LC_")
        || matches!(
            name,
            "DISPLAY"
                | "XAUTHORITY"
                | "WAYLAND_DISPLAY"
                | "XDG_RUNTIME_DIR"
                | "XDG_SESSION_TYPE"
                | "XDG_CURRENT_DESKTOP"
                | "XDG_DATA_DIRS"
                | "XDG_CONFIG_DIRS"
                | "HOME"
                | "DBUS_SESSION_BUS_ADDRESS"
                | "AT_SPI_BUS_ADDRESS"
                | "LANG"
                | "GTK_IM_MODULE"
                | "QT_IM_MODULE"
                | "XMODIFIERS"
        )
}

#[derive(Debug)]
pub struct ScopeUnavailable;

/// Wait for the systemd user manager to finish the scope's start job, not
/// merely to accept it. Until then the caller retains the stopped child.
pub async fn place_desktop_scope(generation: ProcessGeneration) -> Result<(), ScopeUnavailable> {
    // SAFETY: geteuid has no arguments and returns the effective uid.
    let uid = unsafe { libc::geteuid() };
    let address = format!("unix:path=/run/user/{uid}/bus");
    let connection = zbus::connection::Builder::address(address.as_str())
        .build()
        .await
        .map_err(|_| ScopeUnavailable)?;
    let name = scope_name(generation);
    place_scope_on(&connection, &name, generation.pid)
        .await
        .map_err(|_| ScopeUnavailable)?;
    // A completed job is not enough if the child did not actually move. Read
    // the kernel's systemd cgroup rather than trusting a user-bus reply alone.
    let cgroups = fs::read_to_string(format!("/proc/{}/cgroup", generation.pid))
        .map_err(|_| ScopeUnavailable)?;
    if has_scope_membership(&cgroups, &name) {
        Ok(())
    } else {
        Err(ScopeUnavailable)
    }
}

fn scope_name(generation: ProcessGeneration) -> String {
    format!(
        "app-cerebellum-{}-{}.scope",
        generation.pid, generation.start_ticks
    )
}

fn has_scope_membership(cgroups: &str, name: &str) -> bool {
    cgroups.lines().any(|line| {
        let Some((hierarchy, path)) = line.rsplit_once(':') else {
            return false;
        };
        (hierarchy == "0:" || hierarchy.ends_with(":name=systemd"))
            && Path::new(path).file_name() == Some(OsStr::new(name))
    })
}

async fn place_scope_on(connection: &zbus::Connection, name: &str, pid: u32) -> zbus::Result<()> {
    use std::future::poll_fn;
    use std::pin::Pin;
    use zbus::export::futures_core::Stream;
    use zbus::proxy::{CacheProperties, MethodFlags};
    use zbus::{OwnedObjectPath, Proxy, Variant};

    type Properties<'a> = Vec<(&'a str, Variant<'a>)>;

    let manager = zbus::proxy::Builder::<Proxy<'_>>::new(connection)
        .destination("org.freedesktop.systemd1")
        .path("/org/freedesktop/systemd1")
        .interface("org.freedesktop.systemd1.Manager")
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let mut jobs = manager.receive_signal("JobRemoved").await?;
    let _: Option<()> = manager
        .call_with_flags("Subscribe", MethodFlags::NO_AUTO_START, &())
        .await?;
    let properties = vec![("PIDs", Variant::new(vec![pid]))];
    let auxiliary: Vec<(&str, Properties<'_>)> = Vec::new();
    let job: OwnedObjectPath = manager
        .call_with_flags(
            "StartTransientUnit",
            MethodFlags::NO_AUTO_START,
            &(name, "fail", properties, auxiliary),
        )
        .await?
        .ok_or_else(|| zbus::Error::Failure("scope start returned no job".into()))?;
    while let Some(signal) = poll_fn(|cx| Pin::new(&mut jobs).poll_next(cx)).await {
        let (_, path, unit, result): (u32, OwnedObjectPath, String, String) =
            signal.body().deserialize()?;
        if path == job && unit == name {
            return if result == "done" {
                Ok(())
            } else {
                Err(zbus::Error::Failure(
                    "scope start job did not succeed".into(),
                ))
            };
        }
    }
    Err(zbus::Error::Failure("scope job signal stream ended".into()))
}

/// Spawn an executable stopped after exec, with CDP descriptors at 3 and 4.
///
/// Descriptors 0 (read-only), 1 and 2 (write-only) point at `/dev/null`
/// instead of this process's standard streams: the daemon captures this
/// module's stderr into a file that must stay empty unless this module itself
/// printed, and a browser's own logging (which can carry page-derived text)
/// would otherwise land there.
///
/// Before the initial stop, ignored application signal dispositions are reset
/// and the application signal mask is cleared. Signals in libc's reserved
/// real-time range below its runtime `SIGRTMIN()` are outside this contract:
/// libc does not let applications inspect or reset them. Any other disposition
/// query/reset failure aborts the child before the barrier and fails the spawn.
pub fn spawn_barred(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    cdp_command_read_fd: RawFd,
    cdp_response_write_fd: RawFd,
) -> Result<BarredChild, SpawnError> {
    spawn(
        executable,
        arguments,
        environment,
        Some((cdp_command_read_fd, cdp_response_write_fd)),
    )
}

fn spawn(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    cdp: Option<(RawFd, RawFd)>,
) -> Result<BarredChild, SpawnError> {
    if !executable.is_absolute() {
        return Err(SpawnError::InvalidExecutable);
    }
    if cdp.is_some_and(|(command, response)| command < 0 || response < 0 || command == response) {
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
    let (command_source, response_source) = if let Some((command, response)) = cdp {
        let command = duplicate_descriptor(command)?;
        let response = match duplicate_descriptor(response) {
            Ok(fd) => fd,
            Err(error) => {
                close_descriptors(&[command]);
                return Err(error);
            }
        };
        (command, response)
    } else {
        (-1, -1)
    };
    // Opened here rather than in the child, which may make only
    // async-signal-safe calls between fork and exec. Like the CDP sources they
    // sit above fd 4, so the child's dup2 onto 0..=4 never overwrites a source
    // it has yet to copy.
    let null_read = match open_null_device(libc::O_RDONLY) {
        Ok(fd) => fd,
        Err(error) => {
            close_descriptors(&[command_source, response_source]);
            return Err(error);
        }
    };
    let null_write = match open_null_device(libc::O_WRONLY) {
        Ok(fd) => fd,
        Err(error) => {
            close_descriptors(&[command_source, response_source, null_read]);
            return Err(error);
        }
    };
    // Read this before fork: post-fork code must do only async-signal-safe work.
    let descriptor_limit = descriptor_limit();
    let real_time_min = libc::SIGRTMIN();
    let real_time_max = libc::SIGRTMAX();

    // SAFETY: fork has no pointer arguments. The child calls only raw syscalls
    // before execve or _exit, avoiding allocator and runtime state after fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = io::Error::last_os_error().kind();
        close_descriptors(&[command_source, response_source, null_read, null_write]);
        return Err(SpawnError::Fork(error));
    }
    if pid == 0 {
        child_exec(
            command_source,
            response_source,
            null_read,
            null_write,
            descriptor_limit,
            executable.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            real_time_min,
            real_time_max,
        );
    }

    // These are parent-owned duplicates; the child has its own copies.
    close_descriptors(&[command_source, response_source, null_read, null_write]);

    let status = wait_for_status_spawn(pid, libc::WUNTRACED)?;
    if !is_stopped(status) || stop_signal(status) != libc::SIGSTOP {
        let _ = signal_kill(pid);
        let _ = wait_for_pid(pid);
        return Err(SpawnError::UnexpectedStop);
    }
    #[cfg(test)]
    test_parent_death_checkpoint(ParentDeathCheckpoint::AfterInitialStop, pid);

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
    let (boot_id, start_ticks) = match start_time_for_spawn(pid as u32) {
        Ok(generation) => generation,
        Err(error) => {
            let _ = signal_kill(pid);
            let _ = wait_for_pid(pid);
            return Err(error);
        }
    };
    Ok(BarredChild {
        generation: ProcessGeneration {
            pid: pid as u32,
            boot_id,
            start_ticks,
        },
        active: true,
        exec_hops: 0,
    })
}

#[cfg(test)]
// The checkpoint names mirror the lifecycle stages and all intentionally use the same prefix.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy)]
enum ParentDeathCheckpoint {
    AfterInitialStop,
    AfterSeizeBeforeExec,
    AfterExecStop,
}

#[cfg(test)]
fn test_parent_death_checkpoint(checkpoint: ParentDeathCheckpoint, pid: c_int) {
    let expected = match checkpoint {
        ParentDeathCheckpoint::AfterInitialStop => "after-initial-stop",
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

/// Kill a PID only while `current_match` answers that it holds the recorded generation.
///
/// The verdict is taken once to authorize the signal and again if the signal
/// fails, so a process that exited between the two reads is reported as gone
/// rather than as a signalling failure.
pub fn terminate_exact_generation(
    pid: u32,
    reap_deadline: Instant,
    current_match: impl FnMut() -> GenerationMatch,
) -> Result<TerminationOutcome, ProcessControlError> {
    terminate_exact_generation_with(pid, reap_deadline, current_match, |pid| {
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            Err(io::Error::last_os_error().kind())
        } else {
            Ok(())
        }
    })
}

fn terminate_exact_generation_with(
    pid: u32,
    reap_deadline: Instant,
    mut current_match: impl FnMut() -> GenerationMatch,
    signal_kill: impl FnOnce(c_int) -> Result<(), io::ErrorKind>,
) -> Result<TerminationOutcome, ProcessControlError> {
    match current_match() {
        GenerationMatch::Exact => {}
        GenerationMatch::GoneOrReplaced => return Ok(TerminationOutcome::AlreadyGoneOrReplaced),
        GenerationMatch::Unreadable => return Err(ProcessControlError::GenerationUnreadable),
    }
    if let Err(error) = signal_kill(pid as c_int) {
        return match current_match() {
            GenerationMatch::Exact => Err(ProcessControlError::Signal(error)),
            GenerationMatch::GoneOrReplaced => Ok(TerminationOutcome::AlreadyGoneOrReplaced),
            GenerationMatch::Unreadable => Err(ProcessControlError::GenerationUnreadable),
        };
    }
    reap_if_owned(pid as c_int, reap_deadline)?;
    Ok(TerminationOutcome::Signalled)
}

// Each argument is a distinct fork-safe syscall input or execution parameter.
#[allow(clippy::too_many_arguments)]
fn child_exec(
    command_source: RawFd,
    response_source: RawFd,
    null_read: RawFd,
    null_write: RawFd,
    descriptor_limit: RawFd,
    executable: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    real_time_min: c_int,
    real_time_max: c_int,
) -> ! {
    // SAFETY: the descriptors and C-string pointers were checked before fork.
    unsafe {
        let desktop = command_source < 0;
        if desktop {
            if libc::setsid() < 0 {
                libc::_exit(117);
            }
        } else if libc::dup2(command_source, CDP_COMMAND_FD) < 0
            || libc::dup2(response_source, CDP_RESPONSE_FD) < 0
        {
            libc::_exit(110);
        }
        // The target's standard streams go to /dev/null, never to the
        // launcher's own stdout and stderr.
        if libc::dup2(null_read, libc::STDIN_FILENO) < 0
            || libc::dup2(null_write, libc::STDOUT_FILENO) < 0
            || libc::dup2(null_write, libc::STDERR_FILENO) < 0
        {
            libc::_exit(116);
        }
        if desktop {
            // A descriptor can be above a lowered RLIMIT_NOFILE. Close the
            // whole range or fail before exec rather than inherit one.
            if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) != 0 {
                libc::_exit(118);
            }
        } else {
            for fd in 5..descriptor_limit {
                libc::close(fd);
            }
        }
        // Orphaned stopped groups receive SIGHUP then SIGCONT. execve resets caught
        // dispositions but preserves ignored ones, so clear application ignores
        // before the initial stop. libc's private real-time signals are excluded:
        // its sigaction rejects them, and posix_spawn can leave one ignored.
        if let Err(exit_code) = reset_ignored_signals(real_time_min, real_time_max) {
            libc::_exit(exit_code);
        }
        let mut empty_mask: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut empty_mask) != 0
            || libc::sigprocmask(libc::SIG_SETMASK, &empty_mask, std::ptr::null_mut()) != 0
        {
            libc::_exit(115);
        }
        if libc::raise(libc::SIGSTOP) != 0 {
            libc::_exit(111);
        }
        libc::execve(executable, argv, envp);
        libc::_exit(112);
    }
}

fn libc_reserved_signals(real_time_min: c_int) -> std::ops::Range<c_int> {
    // Linux's highest traditional signal is SIGSYS on most architectures,
    // SIGUSR2 on Alpha/SPARC, and SIGXFSZ on MIPS/PA-RISC. The gap before
    // libc's runtime SIGRTMIN belongs to libc, not to application handlers.
    let last_standard_signal = libc::SIGSYS.max(libc::SIGUSR2).max(libc::SIGXFSZ);
    (last_standard_signal + 1)..real_time_min
}

fn reset_ignored_signals(real_time_min: c_int, real_time_max: c_int) -> Result<(), c_int> {
    // SAFETY: sigaction and sigemptyset use stack-owned ABI values and are
    // async-signal-safe, so this helper is also safe between fork and exec.
    unsafe {
        let mut default_disposition: libc::sigaction = std::mem::zeroed();
        default_disposition.sa_sigaction = libc::SIG_DFL;
        if libc::sigemptyset(&mut default_disposition.sa_mask) != 0 {
            return Err(114);
        }
        let reserved = libc_reserved_signals(real_time_min);
        for signal in 1..=real_time_max {
            if signal == libc::SIGKILL || signal == libc::SIGSTOP || reserved.contains(&signal) {
                continue;
            }
            let mut current: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(signal, std::ptr::null(), &mut current) != 0 {
                return Err(113);
            }
            if current.sa_sigaction == libc::SIG_IGN
                && libc::sigaction(signal, &default_disposition, std::ptr::null_mut()) != 0
            {
                return Err(113);
            }
        }
        Ok(())
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

/// Open `/dev/null` close-on-exec at a descriptor above 4.
fn open_null_device(access: c_int) -> Result<RawFd, SpawnError> {
    // SAFETY: the path is a C string literal and open retains no pointer.
    let opened = unsafe { libc::open(c"/dev/null".as_ptr(), access | libc::O_CLOEXEC) };
    if opened < 0 {
        return Err(SpawnError::NullDevice(io::Error::last_os_error().kind()));
    }
    // A process started with a closed standard descriptor gets that low
    // number back from open; move it above 4 like the CDP sources.
    let moved = duplicate_descriptor(opened);
    close_descriptors(&[opened]);
    moved
}

fn close_descriptors(descriptors: &[RawFd]) {
    for &fd in descriptors {
        // SAFETY: each descriptor is owned by the caller and not used again.
        unsafe {
            libc::close(fd);
        }
    }
}

fn descriptor_limit() -> RawFd {
    // SAFETY: sysconf reads process-global kernel configuration.
    let limit = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    limit.clamp(5, 1_048_576) as RawFd
}

fn start_time_for_spawn(pid: u32) -> Result<([u8; 16], u64), SpawnError> {
    match process_generation(pid) {
        ProcessGenerationReading::Started {
            boot_id,
            start_ticks,
        } => Ok((boot_id, start_ticks)),
        ProcessGenerationReading::NoSuchProcess => Err(SpawnError::ProcessMissing),
        ProcessGenerationReading::NotPermitted
        | ProcessGenerationReading::StatReadFailed
        | ProcessGenerationReading::BootIdUnavailable => Err(SpawnError::ProcessInspectionDenied),
        ProcessGenerationReading::LayoutMismatch => Err(SpawnError::ProcessLayoutMismatch),
        ProcessGenerationReading::NoStartTime => Err(SpawnError::ProcessStartTimeMissing),
    }
}

fn start_time_for_identity(pid: u32) -> Result<([u8; 16], u64), ImageIdentityError> {
    match process_generation(pid) {
        ProcessGenerationReading::Started {
            boot_id,
            start_ticks,
        } => Ok((boot_id, start_ticks)),
        ProcessGenerationReading::NoSuchProcess => Err(ImageIdentityError::ProcessMissing),
        ProcessGenerationReading::NotPermitted
        | ProcessGenerationReading::StatReadFailed
        | ProcessGenerationReading::BootIdUnavailable => {
            Err(ImageIdentityError::ProcessInspectionDenied)
        }
        ProcessGenerationReading::LayoutMismatch => Err(ImageIdentityError::ProcessLayoutMismatch),
        ProcessGenerationReading::NoStartTime => Err(ImageIdentityError::ProcessStartTimeMissing),
    }
}

/// Compare a generation this process spawned, and still holds a handle to,
/// against procfs.
///
/// Such a child cannot outlive this boot while its handle exists, so exact
/// equality of the reading is the whole question. Durable records that may
/// predate this boot or this record format are classified by the caller and
/// reach termination through [`terminate_exact_generation`]'s verdict instead.
fn own_generation_match(generation: ProcessGeneration) -> GenerationMatch {
    match process_generation(generation.pid) {
        ProcessGenerationReading::Started {
            boot_id,
            start_ticks,
        } if boot_id == generation.boot_id && start_ticks == generation.start_ticks => {
            GenerationMatch::Exact
        }
        ProcessGenerationReading::Started { .. } | ProcessGenerationReading::NoSuchProcess => {
            GenerationMatch::GoneOrReplaced
        }
        ProcessGenerationReading::NotPermitted
        | ProcessGenerationReading::StatReadFailed
        | ProcessGenerationReading::BootIdUnavailable
        | ProcessGenerationReading::LayoutMismatch
        | ProcessGenerationReading::NoStartTime => GenerationMatch::Unreadable,
    }
}

fn ensure_generation(generation: ProcessGeneration) -> Result<(), ProcessControlError> {
    match own_generation_match(generation) {
        GenerationMatch::Exact => Ok(()),
        GenerationMatch::GoneOrReplaced => Err(ProcessControlError::GenerationChanged),
        GenerationMatch::Unreadable => Err(ProcessControlError::GenerationUnreadable),
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

fn continue_to_next_exec_stop_with(
    pid: c_int,
    wait_for_stop: impl FnMut() -> Result<Option<c_int>, ProcessControlError>,
) -> Result<ExecStopOutcome, ProcessControlError> {
    let mut wait_for_stop = wait_for_stop;
    continue_to_exec_stop(
        MAX_INTERVENING_SIGNAL_STOPS,
        |signal| ptrace_continue(pid, signal),
        || wait_for_stop().map(|status| status.map(exec_stop_observation)),
    )
    .map_err(|error| match error {
        ExecStopLoopError::Control(error) => error,
        ExecStopLoopError::UnexpectedStop { signal } => {
            ProcessControlError::UnexpectedStop { signal }
        }
        ExecStopLoopError::ProcessExited => ProcessControlError::ProcessExited,
        ExecStopLoopError::SignalStopLimitExceeded { last_signal, limit } => {
            ProcessControlError::SignalStopLimitExceeded { last_signal, limit }
        }
    })
}

fn ptrace_continue(pid: c_int, signal: Option<c_int>) -> Result<(), ProcessControlError> {
    // SAFETY: pid is the owned tracee, and ptrace interprets its data argument as
    // a signal number for PTRACE_CONT rather than dereferencing it as a pointer.
    let signal = signal.unwrap_or(0) as usize as *mut c_void;
    if unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<c_void>(),
            signal,
        )
    } != 0
    {
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

fn wait_for_status_until(
    pid: c_int,
    deadline: Instant,
) -> Result<Option<c_int>, ProcessControlError> {
    let mut status = 0;
    loop {
        // SAFETY: status points to owned storage and pid is passed by value.
        let observed = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if observed == pid {
            return Ok(Some(status));
        }
        if observed < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ProcessControlError::Reap(error.kind()));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(1));
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

fn exec_stop_observation(status: c_int) -> ExecStopObservation {
    if !is_stopped(status) {
        return ExecStopObservation::ProcessExited;
    }
    if is_exec_stop(status) {
        return ExecStopObservation::Exec;
    }

    let signal = stop_signal(status);
    if signal == 0 || status >> 16 != 0 {
        ExecStopObservation::UnexpectedStop(signal)
    } else {
        ExecStopObservation::SignalDelivery(signal)
    }
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
    use crate::{process_start_time, ProcessStartTime};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};

    #[tokio::test]
    async fn desktop_launch_scope_waits_for_the_matching_systemd_job() {
        use std::io::{BufRead, BufReader};
        use std::process::{Child, Stdio};
        use std::sync::atomic::{AtomicBool, Ordering};
        use zbus::connection::Builder;
        use zbus::object_server::SignalEmitter;
        use zbus::{OwnedObjectPath, OwnedVariant};

        struct Bus(Child);
        impl Drop for Bus {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        type Properties = Vec<(String, OwnedVariant)>;
        struct Manager(AtomicBool);
        #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
        impl Manager {
            fn subscribe(&self) {
                self.0.store(true, Ordering::Release);
            }

            async fn start_transient_unit(
                &self,
                unit: &str,
                mode: &str,
                properties: Properties,
                auxiliary: Vec<(String, Properties)>,
                #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
            ) -> OwnedObjectPath {
                assert!(self.0.swap(false, Ordering::AcqRel));
                assert_eq!(mode, "fail");
                assert!(auxiliary.is_empty());
                let [(key, pids)] = properties.try_into().unwrap();
                assert_eq!(key, "PIDs");
                assert_eq!(Vec::<u32>::try_from(pids).unwrap(), [42]);
                let job = OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/9").unwrap();
                let other = OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/7").unwrap();
                Self::job_removed(&emitter, 7, &other, unit, "failed")
                    .await
                    .unwrap();
                Self::job_removed(&emitter, 9, &job, "other.scope", "failed")
                    .await
                    .unwrap();
                let result = if unit == "test-good.scope" {
                    "done"
                } else {
                    "failed"
                };
                Self::job_removed(&emitter, 9, &job, unit, result)
                    .await
                    .unwrap();
                job
            }

            #[zbus(signal)]
            async fn job_removed(
                emitter: &SignalEmitter<'_>,
                id: u32,
                path: &OwnedObjectPath,
                unit: &str,
                result: &str,
            ) -> zbus::Result<()>;
        }

        let address = format!("unix:abstract=ck-desktop-scope-{}", std::process::id());
        let mut bus = Bus(Command::new("dbus-daemon")
            .args([
                "--session",
                "--nofork",
                "--print-address=1",
                &format!("--address={address}"),
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap());
        let mut active = String::new();
        BufReader::new(bus.0.stdout.take().unwrap())
            .read_line(&mut active)
            .unwrap();
        assert!(!active.is_empty());
        let address = address.as_str();
        let _service = Builder::address(address)
            .name("org.freedesktop.systemd1")
            .serve_at("/org/freedesktop/systemd1", Manager(AtomicBool::new(false)))
            .build()
            .await
            .unwrap();
        let client = Builder::address(address).build().await.unwrap();
        for (unit, ok) in [("test-good.scope", true), ("test-bad.scope", false)] {
            let result =
                tokio::time::timeout(Duration::from_secs(2), place_scope_on(&client, unit, 42))
                    .await
                    .unwrap();
            assert_eq!(result.is_ok(), ok, "{result:?}");
        }
        assert!(has_scope_membership(
            "0::/user.slice/test-good.scope\n",
            "test-good.scope"
        ));
        assert!(has_scope_membership(
            "1:name=systemd:/user.slice/test-good.scope\n",
            "test-good.scope"
        ));
        assert!(!has_scope_membership(
            "2:cpu:/test-good.scope\n0::/user.slice/daemon.service\n",
            "test-good.scope"
        ));
    }

    #[tokio::test]
    async fn desktop_launch_uses_a_new_session_and_only_the_desktop_environment_and_stdio() {
        let (read, _) = pipe();
        // SAFETY: duplicate a valid fd without CLOEXEC, so exec alone cannot
        // account for the extra descriptor being absent.
        let inherited = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_DUPFD, 100) };
        assert!(inherited >= 100);
        let _inherited = unsafe { OwnedFd::from_raw_fd(inherited) };
        let environment = [
            ("PATH", "/home/fixture/.local/bin:/usr/bin"),
            ("XDG_CURRENT_DESKTOP", "Fixture"),
            ("XMODIFIERS", "@im=fixture"),
            ("LC_MESSAGES", "C.UTF-8"),
            ("LD_PRELOAD", "/not-passed.so"),
            ("GTK_MODULES", "not-passed"),
            ("QT_PLUGIN_PATH", "/not-passed"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
        let child = spawn_desktop_barred(Path::new("/usr/bin/true"), &[], &environment).unwrap();
        let pid = child.generation().pid;
        assert_eq!(unsafe { libc::getsid(pid as c_int) }, pid as c_int);
        assert_eq!(process_descriptors(pid).unwrap(), vec![0, 1, 2]);
        for fd in 0..3 {
            assert_eq!(
                fs::read_link(format!("/proc/{pid}/fd/{fd}")).unwrap(),
                Path::new("/dev/null")
            );
        }
        let actual = fs::read(format!("/proc/{pid}/environ")).unwrap();
        let mut vars: Vec<_> = actual
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .collect();
        vars.sort_unstable();
        assert_eq!(
            vars,
            [
                b"LC_MESSAGES=C.UTF-8".as_slice(),
                b"PATH=/usr/bin:/bin",
                b"XDG_CURRENT_DESKTOP=Fixture",
                b"XMODIFIERS=@im=fixture"
            ]
        );
        let reaper = child.prepare_reaper().unwrap();
        let running = child.release(reaper).unwrap();
        assert_eq!(
            running.exit_within(Duration::from_secs(2)).await.unwrap(),
            Some(DesktopExit::Code(0))
        );
    }

    #[tokio::test]
    async fn desktop_launch_reports_signals_instead_of_a_successful_launch() {
        // Use a shell only to test raw child-wait behavior; the desktop entry
        // resolver separately refuses shell-based entries before spawning.
        let args = ["-c".into(), "ulimit -c 0; kill -SEGV $$".into()];
        let child = spawn_desktop_barred(Path::new("/bin/sh"), &args, &Default::default()).unwrap();
        let reaper = child.prepare_reaper().unwrap();
        assert_eq!(
            child
                .release(reaper)
                .unwrap()
                .exit_within(Duration::from_secs(2))
                .await
                .unwrap(),
            Some(DesktopExit::Signal(libc::SIGSEGV))
        );
    }

    #[tokio::test]
    async fn desktop_launch_failed_wait_and_receiver_drop_never_kill_a_detached_child() {
        fn failed_wait(_: u32) -> io::Result<DesktopExit> {
            Err(io::Error::from_raw_os_error(libc::ECHILD))
        }
        let failures_before = desktop_reaper_wait_failures();
        for fail in [false, true] {
            let child = spawn_desktop_barred(
                Path::new("/usr/bin/sleep"),
                &["30".into()],
                &Default::default(),
            )
            .unwrap();
            let generation = child.generation();
            let reaper = if fail {
                DesktopReaper::start(generation, failed_wait).unwrap()
            } else {
                child.prepare_reaper().unwrap()
            };
            let detached = child.release(reaper).unwrap();
            if fail {
                assert_eq!(
                    detached
                        .exit_within(Duration::from_secs(2))
                        .await
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::ECHILD)
                );
            } else {
                drop(detached);
            }
            assert_eq!(own_generation_match(generation), GenerationMatch::Exact);
            // A test-owned cleanup signal, not part of the detached owner.
            signal_kill(generation.pid as c_int).unwrap();
            if fail {
                wait_for_pid(generation.pid as c_int).unwrap();
            }
        }
        assert_eq!(desktop_reaper_wait_failures(), failures_before + 1);
    }

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

    fn signal_state_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct SignalState {
        dispositions: Vec<(c_int, libc::sigaction)>,
        mask: libc::sigset_t,
    }

    impl Drop for SignalState {
        fn drop(&mut self) {
            // SAFETY: these values came from this process immediately before the test mutation.
            unsafe {
                libc::sigprocmask(libc::SIG_SETMASK, &self.mask, std::ptr::null_mut());
                for (signal, disposition) in &self.dispositions {
                    libc::sigaction(*signal, disposition, std::ptr::null_mut());
                }
            }
        }
    }

    fn ignore_signals_and_block_sighup_and_sigterm() -> SignalState {
        // SAFETY: the test serializes its process-wide signal state and restores it in Drop.
        unsafe {
            let signals = [libc::SIGHUP, libc::SIGUSR1, libc::SIGRTMIN()];
            let mut dispositions = Vec::with_capacity(signals.len());
            for signal in signals {
                let mut disposition = std::mem::zeroed();
                assert_eq!(
                    libc::sigaction(signal, std::ptr::null(), &mut disposition),
                    0,
                    "read signal disposition for {signal}"
                );
                dispositions.push((signal, disposition));

                let mut ignored: libc::sigaction = std::mem::zeroed();
                ignored.sa_sigaction = libc::SIG_IGN;
                assert_eq!(
                    libc::sigemptyset(&mut ignored.sa_mask),
                    0,
                    "empty signal mask"
                );
                assert_eq!(
                    libc::sigaction(signal, &ignored, std::ptr::null_mut()),
                    0,
                    "ignore signal {signal}"
                );
            }

            let mut mask = std::mem::zeroed();
            assert_eq!(
                libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
                0,
                "read signal mask"
            );
            let mut blocked = mask;
            assert_eq!(libc::sigaddset(&mut blocked, libc::SIGHUP), 0, "add SIGHUP");
            assert_eq!(
                libc::sigaddset(&mut blocked, libc::SIGTERM),
                0,
                "add SIGTERM"
            );
            assert_eq!(
                libc::sigprocmask(libc::SIG_SETMASK, &blocked, std::ptr::null_mut()),
                0,
                "block SIGHUP and SIGTERM"
            );
            SignalState { dispositions, mask }
        }
    }

    struct StoppedChild {
        pid: u32,
    }

    impl Drop for StoppedChild {
        fn drop(&mut self) {
            // SAFETY: this is the exact PID reported by the checkpoint helper.
            unsafe {
                libc::kill(self.pid as c_int, libc::SIGKILL);
            }
        }
    }

    fn proc_signal_mask(pid: u32, field: &str) -> u64 {
        let status = fs::read_to_string(format!("/proc/{pid}/status")).expect("read child status");
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .expect("signal mask field");
        u64::from_str_radix(value.trim(), 16).expect("hex signal mask")
    }

    fn print_signal_state(stage: &str, pid: u32) {
        let ignored = proc_signal_mask(pid, "SigIgn:");
        let blocked = proc_signal_mask(pid, "SigBlk:");
        eprintln!("{stage}: pid={pid} SigIgn={ignored:#x} SigBlk={blocked:#x}");
    }

    fn application_signal_mask() -> u64 {
        let reserved = libc_reserved_signals(libc::SIGRTMIN());
        // The test inherits ignored SIGHUP, SIGUSR1, and SIGRTMIN. All three
        // must remain checked: SIGRTMIN is the first application real-time
        // signal, not one of libc's private signals below that boundary.
        for signal in [libc::SIGHUP, libc::SIGUSR1, libc::SIGRTMIN()] {
            assert!(!reserved.contains(&signal), "application signal {signal}");
        }
        let reserved_mask = reserved.fold(0_u64, |mask, signal| mask | (1_u64 << (signal - 1)));
        !reserved_mask
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
                ProcessStartTime::Started(_) if Instant::now() >= deadline => {
                    if let ProcessGenerationReading::Started {
                        boot_id,
                        start_ticks,
                    } = process_generation(pid)
                    {
                        let generation = ProcessGeneration {
                            pid,
                            boot_id,
                            start_ticks,
                        };
                        let _ = terminate_exact_generation(
                            pid,
                            Instant::now() + Duration::from_secs(1),
                            || own_generation_match(generation),
                        );
                    }
                    panic!("target {pid} survived launcher death");
                }
                ProcessStartTime::Started(_) => std::thread::sleep(Duration::from_millis(10)),
                ProcessStartTime::NotPermitted
                | ProcessStartTime::StatReadFailed
                | ProcessStartTime::SystemTimeBaseUnavailable
                | ProcessStartTime::LayoutMismatch
                | ProcessStartTime::NoStartTime
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
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
    fn initial_barrier_clears_the_inherited_signal_environment() {
        let _lock = signal_state_lock();
        print_signal_state("initial-barrier test start", std::process::id());
        let _signal_state = ignore_signals_and_block_sighup_and_sigterm();
        let report = std::env::temp_dir().join(format!(
            "cerebellum-linux-sighup-state-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&report);
        let status = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--ignored")
            .arg("--exact")
            .arg("launch::tests::owner_process_exits_at_requested_checkpoint")
            .env("CEREBELLUM_LINUX_BARRIER_CHECKPOINT", "after-initial-stop")
            .env("CEREBELLUM_LINUX_BARRIER_HELPER_REPORT", &report)
            .status()
            .expect("run owner helper");
        assert_eq!(status.code(), Some(0), "owner helper failed: {status}");

        let child = StoppedChild {
            pid: fs::read_to_string(&report)
                .expect("helper wrote child pid")
                .parse()
                .expect("numeric child pid"),
        };
        let ignored = proc_signal_mask(child.pid, "SigIgn:");
        let blocked = proc_signal_mask(child.pid, "SigBlk:");
        print_signal_state("initial-barrier child", child.pid);
        let application_mask = application_signal_mask();
        assert_eq!(
            ignored & application_mask,
            0,
            "child retained ignored application dispositions at the barrier (SigIgn={ignored:#x}, SigBlk={blocked:#x})"
        );
        assert_eq!(
            blocked & application_mask,
            0,
            "child retained an inherited application signal mask at the barrier (SigIgn={ignored:#x}, SigBlk={blocked:#x})"
        );

        drop(child);
        let _ = fs::remove_file(report);
    }

    #[test]
    fn execd_image_does_not_inherit_the_launchers_signal_environment() {
        let _lock = signal_state_lock();
        print_signal_state("exec-image test start", std::process::id());
        let _signal_state = ignore_signals_and_block_sighup_and_sigterm();
        let child = spawn_sleep();
        let ignored = proc_signal_mask(child.generation().pid, "SigIgn:");
        let blocked = proc_signal_mask(child.generation().pid, "SigBlk:");
        print_signal_state("exec-stop child", child.generation().pid);
        let application_mask = application_signal_mask();
        assert_eq!(
            ignored & application_mask,
            0,
            "exec'd image retained ignored application dispositions (SigIgn={ignored:#x}, SigBlk={blocked:#x})"
        );
        assert_eq!(
            blocked & application_mask,
            0,
            "exec'd image retained the launcher's application signal mask (SigIgn={ignored:#x}, SigBlk={blocked:#x})"
        );
    }

    #[test]
    fn a_non_reserved_disposition_query_failure_aborts_signal_reset() {
        let _lock = signal_state_lock();
        let real_time_min = libc::SIGRTMIN();
        let invalid_signal = libc::SIGRTMAX() + 1;
        // An out-of-range signal forces a real sigaction failure without
        // changing a live process's dispositions or libc's private handlers.
        // SAFETY: the child only runs the fork-safe reset helper and _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork signal-reset helper");
        if pid == 0 {
            let exit_code = reset_ignored_signals(real_time_min, invalid_signal)
                .err()
                .unwrap_or(0);
            // SAFETY: _exit terminates the forked helper without running destructors.
            unsafe { libc::_exit(exit_code) };
        }
        let status = wait_for_status_spawn(pid, 0).expect("wait for signal-reset helper");
        assert!(libc::WIFEXITED(status), "helper did not exit: {status}");
        assert_eq!(libc::WEXITSTATUS(status), 113, "query failure was skipped");
    }

    #[test]
    fn bounded_exec_wait_reports_no_later_exec_without_releasing_the_target() {
        let _lock = signal_state_lock();
        let mut child = spawn_sleep();
        let generation = child.generation();
        let observed = child
            .continue_to_next_exec_stop_with_deadline(1, Instant::now() + Duration::from_millis(20))
            .expect("bounded wait must be an observation");
        assert_eq!(observed, None);
        child.terminate_and_reap().expect("terminate bounded probe");
        assert_eq!(
            process_start_time(generation.pid),
            ProcessStartTime::NoSuchProcess
        );
    }

    #[test]
    fn release_refuses_a_process_generation_that_no_longer_matches() {
        let mut child = spawn_sleep();
        child.generation.start_ticks += 1;
        assert_eq!(
            child.release().map(|_| ()),
            Err(ProcessControlError::GenerationChanged)
        );
    }

    #[test]
    fn termination_refuses_unreadable_generations_without_signalling() {
        let mut signalled = false;
        assert_eq!(
            terminate_exact_generation_with(
                42,
                Instant::now() + Duration::from_secs(1),
                || GenerationMatch::Unreadable,
                |_| {
                    signalled = true;
                    Ok(())
                },
            ),
            Err(ProcessControlError::GenerationUnreadable)
        );
        assert!(
            !signalled,
            "an unreadable generation must refuse before signalling"
        );
    }

    #[test]
    fn termination_of_a_gone_or_replaced_generation_does_not_signal() {
        let mut signalled = false;
        assert_eq!(
            terminate_exact_generation_with(
                42,
                Instant::now() + Duration::from_secs(1),
                || GenerationMatch::GoneOrReplaced,
                |_| {
                    signalled = true;
                    Ok(())
                },
            ),
            Ok(TerminationOutcome::AlreadyGoneOrReplaced)
        );
        assert!(!signalled, "a replaced pid belongs to another process");
    }

    /// The subc daemon hands this module its launch nonce on a pipe that is
    /// inheritable by design (it has to survive the daemon's exec). The module
    /// reads and closes it at startup, but the browser launch must not depend
    /// on that: a pipe left open without close-on-exec, on whatever number,
    /// must not reach the browser. Checked from the kernel's side, by the
    /// pipe's identity in the target's descriptor table, so a number reused
    /// for an intended pipe is not mistaken for inheritance.
    #[test]
    fn the_target_does_not_inherit_an_inheritable_pipe() {
        let (stand_in, _stand_in_write) = pipe();
        // `pipe()` above opens close-on-exec; clear it, as the daemon does for
        // the nonce pipe it hands over.
        assert_eq!(
            unsafe { libc::fcntl(stand_in.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        let identity = std::fs::read_link(format!("/proc/self/fd/{}", stand_in.as_raw_fd()))
            .expect("read the stand-in pipe's identity");
        let child = spawn_sleep();
        let pid = child.generation().pid;
        let held: Vec<_> = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .expect("list the target's descriptors")
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_link(entry.path()).ok())
            .collect();
        // The standard streams and both CDP pipes are there, so an empty
        // listing cannot pass for an absent pipe.
        assert_eq!(held.len(), 5, "{held:?}");
        assert!(
            !held.contains(&identity),
            "the target inherited the stand-in pipe {identity:?}: {held:?}"
        );
        child.terminate_and_reap().expect("reap the target");
    }

    #[test]
    fn a_spawned_generation_reads_back_as_its_own_exact_match() {
        let child = spawn_sleep();
        assert_eq!(
            own_generation_match(child.generation()),
            GenerationMatch::Exact
        );
        let mut other_boot = child.generation();
        other_boot.boot_id[0] ^= 0xff;
        assert_eq!(
            own_generation_match(other_boot),
            GenerationMatch::GoneOrReplaced
        );
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
        let report =
            std::env::temp_dir().join(format!("cerebellum-linux-{name}-{}", std::process::id()));
        let _ = fs::remove_file(&report);
        let output = Command::new(std::env::current_exe().expect("test executable"))
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
        let contents = fs::read_to_string(&report).expect("observer wrote its descriptor report");
        let _ = fs::remove_file(report);
        (contents, stdout, stderr)
    }

    #[test]
    fn the_target_writes_its_standard_streams_to_dev_null() {
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
                let (command_read, _command_write) = pipe();
                let (_response_read, response_write) = pipe();
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
            // SAFETY: F_GETFL reads the flags of a live descriptor.
            let access = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE;
            let kind = if is_null { "null" } else { "other" };
            lines.push_str(&format!("{fd} {kind} {access}\n"));
        }
        fs::write(report, lines).expect("write descriptor report");
        // Raw writes, because the test harness captures print! output.
        let marker = format!("{STDIO_MARKER}\n");
        for fd in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
            // SAFETY: the buffer is live for the duration of the call. The
            // length is checked so a partial marker cannot silently weaken
            // the positive control.
            let written = unsafe { libc::write(fd, marker.as_ptr().cast(), marker.len()) };
            assert_eq!(written, marker.len() as isize, "write marker to fd {fd}");
        }
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
