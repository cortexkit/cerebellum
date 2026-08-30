#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use cerebellum_linux::{
    executed_image_identity, process_descriptors, process_start_time, spawn_barred,
    terminate_exact_generation, BarredChild, ProcessControlError, ProcessStartTime,
    TerminationOutcome,
};

fn launch_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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

fn cdp_descriptors() -> (OwnedFd, OwnedFd, OwnedFd, OwnedFd) {
    let (command_read, command_write) = pipe();
    let (response_read, response_write) = pipe();
    (command_read, command_write, response_read, response_write)
}

/// Spawn a script under a shell that supports `exec -a`.
///
/// `exec -a` is a bashism. Ubuntu and Debian make /bin/sh dash, which has no
/// `-a`, so the shell dies before reaching the exec the test is waiting for and
/// the failure surfaces as ProcessExited -- a real capability gap wearing the
/// costume of a launcher defect. Naming bash explicitly keeps the test about
/// argv[0] rewriting rather than about which shell the distribution installs.
fn spawn_bash(script: &str) -> BarredChild {
    assert!(
        Path::new("/bin/bash").exists(),
        "this test rewrites argv[0] with `exec -a`, which requires bash; /bin/sh is dash on \
         Debian and Ubuntu and cannot express it"
    );
    let (command_read, _command_write, _response_read, response_write) = cdp_descriptors();
    spawn_barred(
        Path::new("/bin/bash"),
        &[OsString::from("-c"), OsString::from(script)],
        &[],
        command_read.as_raw_fd(),
        response_write.as_raw_fd(),
    )
    .expect("spawn barred bash")
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

fn temporary_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("cerebellum-linux-{name}-{}", std::process::id()))
}

#[test]
fn barrier_holds_before_release_and_release_executes_once() {
    let _lock = launch_lock();
    let effect = temporary_path("release-effect");
    let _ = fs::remove_file(&effect);
    let child = spawn_shell(&format!("printf executed > '{}'", effect.display()));

    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        fs::read(&effect).expect_err("barred target ran").kind(),
        io::ErrorKind::NotFound
    );

    child
        .release()
        .expect("release target")
        .wait()
        .expect("reap target");
    assert_eq!(
        fs::read_to_string(&effect).expect("released effect"),
        "executed"
    );
    let _ = fs::remove_file(effect);
}

#[test]
fn termination_reaps_a_barred_target_without_running_it() {
    let _lock = launch_lock();
    let effect = temporary_path("barred-termination");
    let _ = fs::remove_file(&effect);
    let child = spawn_shell(&format!("printf ran > '{}'; sleep 30", effect.display()));
    child.terminate_and_reap().expect("terminate barred target");
    assert_eq!(
        fs::read(&effect).expect_err("barred target ran").kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn released_termination_reaps_the_target_in_the_launcher() {
    let _lock = launch_lock();
    let released = spawn_shell("sleep 30").release().expect("release target");
    let generation = released.generation();
    released
        .terminate_and_reap()
        .expect("terminate released target");
    assert_eq!(
        process_start_time(generation.pid),
        ProcessStartTime::NoSuchProcess
    );
}

#[test]
fn the_target_does_not_inherit_an_unintended_parent_descriptor() {
    let _lock = launch_lock();
    let authority = temporary_path("descriptor-authority");
    let _ = fs::remove_file(&authority);
    let unintended = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&authority)
        .unwrap();
    assert_eq!(
        unsafe { libc::fcntl(unintended.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    let child = spawn_shell("sleep 30");
    let mut descriptors = process_descriptors(child.generation().pid).expect("process descriptors");
    descriptors.sort_unstable();
    assert_eq!(descriptors, vec![0, 1, 2, 3, 4]);
    drop(unintended);
    child.terminate_and_reap().expect("reap descriptor fixture");
    let _ = fs::remove_file(authority);
}

#[test]
fn parent_death_before_release_kills_the_suspended_target() {
    let _lock = launch_lock();
    let report = temporary_path("owner-death-pid");
    let _ = fs::remove_file(&report);
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--ignored")
        .arg("--exact")
        .arg("owner_process_exits_before_release")
        .env("CEREBELLUM_LINUX_BARRIER_HELPER_REPORT", &report)
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
    let _ = fs::remove_file(report);
}

#[test]
#[ignore = "launched by parent_death_before_release_kills_the_suspended_target"]
fn owner_process_exits_before_release() {
    let Some(report) = std::env::var_os("CEREBELLUM_LINUX_BARRIER_HELPER_REPORT") else {
        return;
    };
    let child = spawn_shell("sleep 30");
    fs::write(report, child.generation().pid.to_string()).expect("write target pid");
    std::mem::forget(child);
    std::process::exit(0);
}

#[test]
fn executed_identity_reads_the_barred_mapped_image() {
    let _lock = launch_lock();
    let script = temporary_path("mapped-image-script");
    fs::write(&script, "#!/bin/sh\nsleep 30\n").expect("write wrapper script");
    let mut permissions = fs::metadata(&script)
        .expect("script metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).expect("make script executable");
    let (command_read, _command_write, _response_read, response_write) = cdp_descriptors();
    let child = spawn_barred(
        &script,
        &[],
        &[],
        command_read.as_raw_fd(),
        response_write.as_raw_fd(),
    )
    .expect("spawn barred wrapper");
    let identity = executed_image_identity(child.generation().pid).expect("read suspended image");
    assert_eq!(
        identity.resolved_path,
        fs::canonicalize("/bin/sh").expect("shell path")
    );
    assert_eq!(identity.image_sha256.len(), 64);
    child.terminate_and_reap().expect("reap identity fixture");
    let _ = fs::remove_file(script);
}

#[test]
fn an_exec_chain_reports_the_next_mapped_image_and_honors_its_bound() {
    let _lock = launch_lock();
    let mut child = spawn_shell("exec /bin/sleep 30");
    assert_eq!(
        child.continue_to_next_exec_stop(0),
        Err(ProcessControlError::ExecChainExhausted)
    );
    let identity = child.continue_to_next_exec_stop(1).expect("next exec stop");
    assert!(identity.resolved_path.ends_with("sleep"));
    child.terminate_and_reap().expect("reap wrapper fixture");
}

#[test]
fn exec_chain_attestation_ignores_rewritten_argv_zero() {
    let _lock = launch_lock();
    let mut child = spawn_bash("exec -a somethingelse /bin/sleep 30");
    let identity = child.continue_to_next_exec_stop(1).expect("next exec stop");

    assert_eq!(
        identity.resolved_path,
        fs::canonicalize("/bin/sleep").expect("sleep path")
    );
    child.terminate_and_reap().expect("reap argv zero fixture");
}

#[test]
fn a_pid_whose_start_time_differs_is_never_signalled() {
    let _lock = launch_lock();
    let mut victim = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("spawn victim");
    let pid = victim.id();
    let ProcessStartTime::Started(start) = process_start_time(pid) else {
        panic!("start time unavailable")
    };
    let outcome =
        terminate_exact_generation(pid, start - 1, Instant::now() + Duration::from_secs(1))
            .expect("mismatch is an observation");
    assert_eq!(outcome, TerminationOutcome::AlreadyGoneOrReplaced);
    assert!(matches!(process_start_time(pid), ProcessStartTime::Started(value) if value == start));
    let _ = victim.kill();
    let _ = victim.wait();
}

#[test]
fn the_exact_generation_is_signalled() {
    let _lock = launch_lock();
    let mut target = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("spawn target");
    let pid = target.id();
    let ProcessStartTime::Started(start) = process_start_time(pid) else {
        panic!("start time unavailable")
    };
    let outcome = terminate_exact_generation(pid, start, Instant::now() + Duration::from_secs(1))
        .expect("terminate exact generation");
    assert_eq!(outcome, TerminationOutcome::Signalled);
    let _ = target.wait();
}
