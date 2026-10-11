//! Kernel-sourced socket peers and generation-bound running-code checks.
//!
//! Callers supply the host or server signing requirement from trusted
//! configuration, never from a frame or from the peer's own reported identity.

use crate::{
    code_satisfies_requirement, process_start_time, CodeSigningError, ProcessGeneration,
    ProcessStartTime, RequirementCheck,
};
use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::time::Duration;

// <sys/un.h>: the local-domain socket options are not SOL_SOCKET options.
const SOL_LOCAL: c_int = 0;
const LOCAL_PEERPID: c_int = 2;

extern "C" {
    fn getsockopt(
        socket: c_int,
        level: c_int,
        name: c_int,
        value: *mut c_void,
        size: *mut u32,
    ) -> c_int;
    fn getppid() -> c_int;
}

/// The main Google Chrome executable signed by Google's Developer ID.
/// Stock ad-hoc Chrome for Testing is not a production signing identity.
pub const CHROME_PARENT_REQUIREMENT: &str = "identifier \"com.google.Chrome\" \
     and anchor apple generic \
     and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
     and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
     and certificate leaf[subject.OU] = \"EQHXZ8M8AV\"";

/// The official Chrome for Testing version and platform whose loader hash is
/// pinned by the `chrome-for-testing-parent-probe` feature.
#[cfg(feature = "chrome-for-testing-parent-probe")]
pub const CHROME_FOR_TESTING_PARENT_PROBE_VERSION: &str = "155.0.8059.39 (mac-arm64)";

// The official Chrome for Testing loader is only linker/ad-hoc signed. Its
// cdhash pins that loader, but does NOT seal its dynamically loaded framework
// dependencies.
// The chrome-for-testing-parent-probe feature permits this weaker boundary only
// for an operator-approved test, and release-build.sh's signing-topology revision
// makes compilation reject the feature in shipped builds.
#[cfg(feature = "chrome-for-testing-parent-probe")]
const CHROME_FOR_TESTING_PARENT_PROBE_REQUIREMENT: &str =
    "cdhash H\"8f2a5ce4af6d1cd71fe66113dd809e4d106c3106\"";

/// Read the pid associated with a connected local socket by the kernel.
/// Works on both an accepted stream and a stream connected to a listener.
/// No pid supplied in the socket's payload is used.
pub fn local_socket_peer_pid(socket: &impl AsFd) -> io::Result<u32> {
    let mut pid: c_int = 0;
    let mut size = std::mem::size_of_val(&pid) as u32;
    // SAFETY: the borrowed descriptor stays live during the call; the output
    // buffer and its length have the pid_t and socklen_t layouts on macOS.
    let status = unsafe {
        getsockopt(
            socket.as_fd().as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERPID,
            (&mut pid as *mut c_int).cast(),
            &mut size,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    if size != std::mem::size_of_val(&pid) as u32 || pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the kernel did not report a positive peer pid",
        ));
    }
    Ok(pid as u32)
}

/// The process failed a code-signing requirement, or its pid and start time
/// could not be confirmed unchanged across the check.
#[derive(Debug)]
pub enum ProcessRequirementError {
    PeerPid(io::Error),
    StartTime(ProcessStartTime),
    CodeSigning(CodeSigningError),
    NotSatisfied(i32),
    ProcessChanged,
    ParentChanged,
    #[cfg(feature = "chrome-for-testing-parent-probe")]
    ProbeParentNotSatisfied {
        status: i32,
        required_version: &'static str,
    },
}

impl std::fmt::Display for ProcessRequirementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerPid(error) => write!(formatter, "socket peer pid unavailable: {error}"),
            Self::StartTime(value) => write!(formatter, "process start time unavailable: {value:?}"),
            Self::CodeSigning(error) => write!(formatter, "running-code check failed: {error:?}"),
            Self::NotSatisfied(status) => write!(formatter, "running code does not satisfy the signing requirement ({status})"),
            Self::ProcessChanged => formatter.write_str("process generation changed during the signing check"),
            Self::ParentChanged => formatter.write_str("parent relationship changed during the signing check"),
            #[cfg(feature = "chrome-for-testing-parent-probe")]
            Self::ProbeParentNotSatisfied { status, required_version } => write!(formatter,
                "probe parent must be Chrome for Testing {required_version}; pinned running-code requirement failed ({status})"),
        }
    }
}

impl std::error::Error for ProcessRequirementError {}

/// Check a socket peer's running code against a trusted signing requirement.
/// The start time must remain readable and unchanged across the signature
/// check, so a later holder of the pid cannot satisfy it for the original peer.
/// This reports code identity only; callers still enforce socket uid and frame
/// admission, including the host's separate parent-check attestation.
pub fn peer_satisfies_requirement(
    socket: &impl AsFd,
    requirement: &str,
    timeout: Duration,
) -> Result<ProcessGeneration, ProcessRequirementError> {
    let pid = local_socket_peer_pid(socket).map_err(ProcessRequirementError::PeerPid)?;
    process_requirement_with(
        pid,
        requirement,
        timeout,
        process_start_time,
        code_satisfies_requirement,
    )
}

/// Check the calling host's current parent before opening the bridge socket.
/// Both the parent's generation and the parent relationship must survive the
/// signature check; a host reparented after Chrome exits does not pass.
pub fn parent_satisfies_chrome_requirement(
    timeout: Duration,
) -> Result<ProcessGeneration, ProcessRequirementError> {
    current_parent_requirement(CHROME_PARENT_REQUIREMENT, timeout)
}

/// Check a pinned Chrome for Testing parent for a real-browser acceptance test.
/// Its ad-hoc loader hash is a weaker identity than the production Chrome
/// signature, so this function exists only with `chrome-for-testing-parent-probe`.
/// Compilation rejects that feature when release-build.sh supplies its signing
/// attestation. Different builds fail with the required version/platform named.
#[cfg(feature = "chrome-for-testing-parent-probe")]
pub fn parent_satisfies_chrome_for_testing_probe_requirement(
    timeout: Duration,
) -> Result<ProcessGeneration, ProcessRequirementError> {
    current_parent_requirement(CHROME_FOR_TESTING_PARENT_PROBE_REQUIREMENT, timeout)
        .map_err(probe_parent_error)
}

#[cfg(feature = "chrome-for-testing-parent-probe")]
fn probe_parent_error(error: ProcessRequirementError) -> ProcessRequirementError {
    match error {
        ProcessRequirementError::NotSatisfied(status) => {
            ProcessRequirementError::ProbeParentNotSatisfied {
                status,
                required_version: CHROME_FOR_TESTING_PARENT_PROBE_VERSION,
            }
        }
        other => other,
    }
}

fn current_parent_requirement(
    requirement: &str,
    timeout: Duration,
) -> Result<ProcessGeneration, ProcessRequirementError> {
    parent_requirement_with(
        || {
            // SAFETY: getppid has no arguments or borrowed memory.
            unsafe { getppid() as u32 }
        },
        |pid| {
            process_requirement_with(
                pid,
                requirement,
                timeout,
                process_start_time,
                code_satisfies_requirement,
            )
        },
    )
}

fn parent_requirement_with(
    mut parent: impl FnMut() -> u32,
    check: impl FnOnce(u32) -> Result<ProcessGeneration, ProcessRequirementError>,
) -> Result<ProcessGeneration, ProcessRequirementError> {
    let pid = parent();
    let generation = check(pid)?;
    if parent() != pid {
        return Err(ProcessRequirementError::ParentChanged);
    }
    Ok(generation)
}

fn process_requirement_with(
    pid: u32,
    requirement: &str,
    timeout: Duration,
    mut start_time: impl FnMut(u32) -> ProcessStartTime,
    check: impl FnOnce(u32, &str, Duration) -> Result<RequirementCheck, CodeSigningError>,
) -> Result<ProcessGeneration, ProcessRequirementError> {
    let before = match start_time(pid) {
        ProcessStartTime::Started(micros) => micros,
        other => return Err(ProcessRequirementError::StartTime(other)),
    };
    let result = check(pid, requirement, timeout).map_err(ProcessRequirementError::CodeSigning)?;
    let after = match start_time(pid) {
        ProcessStartTime::Started(micros) => micros,
        other => return Err(ProcessRequirementError::StartTime(other)),
    };
    if after != before {
        return Err(ProcessRequirementError::ProcessChanged);
    }
    let generation = ProcessGeneration {
        pid,
        start_time_micros: before,
    };
    match result {
        RequirementCheck::Satisfied => Ok(generation),
        RequirementCheck::NotSatisfied(status) => {
            Err(ProcessRequirementError::NotSatisfied(status))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    const BOUND: Duration = Duration::from_secs(10);

    #[test]
    fn signature_check_is_bound_to_the_same_process_generation() {
        let mut times = [
            ProcessStartTime::Started(123),
            ProcessStartTime::Started(123),
        ]
        .into_iter();
        let result = process_requirement_with(
            42,
            "trusted requirement",
            BOUND,
            |pid| {
                assert_eq!(pid, 42);
                times.next().unwrap()
            },
            |pid, requirement, timeout| {
                assert_eq!(
                    (pid, requirement, timeout),
                    (42, "trusted requirement", BOUND)
                );
                Ok(RequirementCheck::Satisfied)
            },
        )
        .unwrap();
        assert_eq!(
            result,
            ProcessGeneration {
                pid: 42,
                start_time_micros: 123
            }
        );
        assert!(
            times.next().is_none(),
            "both start-time readings must happen"
        );
    }

    #[test]
    fn a_satisfied_signature_does_not_mask_pid_reuse() {
        let mut times = [
            ProcessStartTime::Started(123),
            ProcessStartTime::Started(456),
        ]
        .into_iter();
        assert!(matches!(
            process_requirement_with(
                42,
                "trusted",
                BOUND,
                |_| times.next().unwrap(),
                |_, _, _| Ok(RequirementCheck::Satisfied)
            ),
            Err(ProcessRequirementError::ProcessChanged)
        ));
    }

    #[test]
    fn unreadable_start_times_never_compare_as_the_same_generation() {
        for absent in [
            ProcessStartTime::NoSuchProcess,
            ProcessStartTime::NotPermitted,
            ProcessStartTime::LayoutMismatch,
            ProcessStartTime::Unclassified(5),
            ProcessStartTime::NoStartTime,
        ] {
            assert!(matches!(
                process_requirement_with(42, "trusted", BOUND, |_| absent,
                    |_, _, _| panic!("no signature check without an initial generation")),
                Err(ProcessRequirementError::StartTime(value)) if value == absent
            ));
            let mut times = [ProcessStartTime::Started(123), absent].into_iter();
            assert!(matches!(
                process_requirement_with(42, "trusted", BOUND, |_| times.next().unwrap(),
                    |_, _, _| Ok(RequirementCheck::Satisfied)),
                Err(ProcessRequirementError::StartTime(value)) if value == absent
            ));
        }
    }

    #[test]
    fn signature_check_errors_are_not_success() {
        assert!(matches!(
            process_requirement_with(
                42,
                "trusted",
                BOUND,
                |_| ProcessStartTime::Started(123),
                |_, _, _| Err(CodeSigningError::TimedOut)
            ),
            Err(ProcessRequirementError::CodeSigning(
                CodeSigningError::TimedOut
            ))
        ));
    }

    #[test]
    fn a_changed_parent_relationship_does_not_pass() {
        let mut parents = [42, 1].into_iter();
        assert!(matches!(
            parent_requirement_with(
                || parents.next().unwrap(),
                |pid| Ok(ProcessGeneration {
                    pid,
                    start_time_micros: 123
                })
            ),
            Err(ProcessRequirementError::ParentChanged)
        ));
    }

    #[test]
    fn a_stable_parent_relationship_returns_the_checked_generation() {
        let generation = parent_requirement_with(
            || 42,
            |pid| {
                Ok(ProcessGeneration {
                    pid,
                    start_time_micros: 123,
                })
            },
        )
        .unwrap();
        assert_eq!(
            generation,
            ProcessGeneration {
                pid: 42,
                start_time_micros: 123
            }
        );
    }

    #[test]
    fn a_non_chrome_parent_does_not_satisfy_the_browser_requirement() {
        assert!(matches!(
            parent_satisfies_chrome_requirement(BOUND),
            Err(ProcessRequirementError::NotSatisfied(_))
        ));
    }

    #[test]
    #[cfg(feature = "chrome-for-testing-parent-probe")]
    fn a_different_probe_parent_names_the_exact_required_cft_build() {
        let error = parent_satisfies_chrome_for_testing_probe_requirement(BOUND).unwrap_err();
        assert!(matches!(
            error,
            ProcessRequirementError::ProbeParentNotSatisfied {
                required_version: "155.0.8059.39 (mac-arm64)",
                ..
            }
        ));
        assert!(error.to_string().contains("155.0.8059.39 (mac-arm64)"));
        assert!(matches!(
            code_satisfies_requirement(
                std::process::id(),
                CHROME_FOR_TESTING_PARENT_PROBE_REQUIREMENT,
                BOUND
            ),
            Ok(RequirementCheck::NotSatisfied(_))
        ));
    }

    #[test]
    fn a_non_socket_cannot_report_a_peer_pid() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(local_socket_peer_pid(&file).is_err());
    }

    /// An executable built by Cargo has no trusted signing credential. On
    /// Apple Silicon it has only the ad-hoc signature required to execute.
    /// The separate client process also distinguishes LOCAL_PEERPID from a
    /// mistaken getpid call; the client checks the listener's pid in turn.
    #[test]
    fn unsigned_socket_peer_is_refused() {
        let peer = SocketPeer::start();
        assert_eq!(
            local_socket_peer_pid(&peer.stream).unwrap(),
            peer.child.id()
        );
        let identity = crate::code_signing_identity(peer.child.id(), BOUND).unwrap();
        assert!(
            identity.team_id.is_none(),
            "the fixture must not have a trusted signer"
        );
        let host_requirement = "identifier \"ck-browser-native-host\" and anchor apple generic";
        assert!(
            matches!(
                peer_satisfies_requirement(&peer.stream, host_requirement, BOUND),
                Err(ProcessRequirementError::NotSatisfied(_))
            ),
            "an unsigned peer must not pass"
        );
        // The Chrome requirement is parsed by Security.framework too, not
        // merely compared as a string in a test double.
        assert!(matches!(
            peer_satisfies_requirement(&peer.stream, CHROME_PARENT_REQUIREMENT, BOUND),
            Err(ProcessRequirementError::NotSatisfied(_))
        ));
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn a_matching_peer_requirement_reports_its_kernel_generation() {
        let peer = SocketPeer::start();
        let requirement = crate::code_signing_identity(peer.child.id(), BOUND)
            .unwrap()
            .designated_requirement
            .expect("the ad-hoc fixture has a cdhash requirement");
        let generation = peer_satisfies_requirement(&peer.stream, &requirement, BOUND).unwrap();
        assert_eq!(generation.pid, peer.child.id());
        assert_eq!(
            ProcessStartTime::Started(generation.start_time_micros),
            process_start_time(peer.child.id())
        );
    }

    struct SocketPeer {
        stream: UnixStream,
        child: Child,
        directory: PathBuf,
    }

    impl SocketPeer {
        fn start() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            // A short path avoids sockaddr_un's small path limit on macOS.
            let directory = PathBuf::from(format!(
                "/tmp/ck-peer-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            let socket_path = directory.join("socket");
            let listener = UnixListener::bind(&socket_path).unwrap();
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "peer_attestation::tests::socket_client_fixture",
                    "--ignored",
                ])
                .env("CK_PEER_TEST_SOCKET", &socket_path)
                .env("CK_PEER_TEST_SERVER_PID", std::process::id().to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + BOUND;
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = std::fs::remove_dir_all(&directory);
                        panic!("fixture did not connect: {error}");
                    }
                }
            };
            stream.set_read_timeout(Some(BOUND)).unwrap();
            let mut peer = Self {
                stream,
                child,
                directory,
            };
            let mut ready = [0];
            peer.stream
                .read_exact(&mut ready)
                .expect("client checked the server's kernel peer pid");
            assert_eq!(ready, [1]);
            peer
        }
    }

    impl Drop for SocketPeer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    #[ignore = "invoked only as a scratch socket client subprocess"]
    fn socket_client_fixture() {
        let mut stream =
            UnixStream::connect(std::env::var_os("CK_PEER_TEST_SOCKET").unwrap()).unwrap();
        let server_pid: u32 = std::env::var("CK_PEER_TEST_SERVER_PID")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(local_socket_peer_pid(&stream).unwrap(), server_pid);
        stream.write_all(&[1]).unwrap();
        stream.set_read_timeout(Some(BOUND * 4)).unwrap();
        let _ = stream.read(&mut [0]);
    }
}
