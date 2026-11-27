//! Linux process and package evidence for the native-messaging handshake.
//!
//! These checks do blocking work. The caller owns the handshake deadlines and
//! maps an error to the refusal for its current step.

use cerebellum_bridge_protocol::peer_trailer::{self, PeerRole};
use cerebellum_bridge_protocol::{AttestationV1, HostParentAttestation, PlatformParentAttestation};
pub use ed25519_dalek::VerifyingKey;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

mod dpkg;
mod process;
#[cfg(test)]
mod tests;

use process::{current_parent, peer_credentials, PidFd, Stat};

const TARGET: &str = env!("CEREBELLUM_LINUX_TARGET");

/// Check for both pidfd primitives before binding a bridge listener.
/// The kernel-floor message is used only for an unsupported primitive here,
/// never when observing a particular peer or parent.
pub fn probe_kernel() -> io::Result<()> {
    bind_probe(PidFd::open(std::process::id()))?;
    let (socket, _peer) = UnixStream::pair()?;
    bind_probe(PidFd::for_peer(socket.as_fd()))?;
    Ok(())
}

fn bind_probe<T>(result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| match error.raw_os_error() {
        Some(libc::ENOSYS | libc::ENOPROTOOPT | libc::EINVAL) => {
            io::Error::new(io::ErrorKind::Unsupported, "needs Linux 6.5+")
        }
        _ => error,
    })
}

/// Failure to acquire Linux socket peer evidence before image verification.
#[derive(Debug)]
pub enum PeerObservationError {
    /// The kernel-reported peer UID differs from this process's effective UID.
    WrongUser,
    /// The same-user peer (or credentials) could not be observed.
    Observation(io::Error),
}

impl std::fmt::Display for PeerObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongUser => f.write_str("socket peer has a different UID"),
            Self::Observation(error) => write!(f, "could not observe socket peer: {error}"),
        }
    }
}

impl std::error::Error for PeerObservationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WrongUser => None,
            Self::Observation(error) => Some(error),
        }
    }
}

/// The process ID and kernel-issued pidfd of a connected Unix socket peer.
#[derive(Debug)]
pub struct PeerIdentity {
    pid: u32,
    pidfd: PidFd,
}

/// Check the peer UID before acquiring its `SO_PEERPIDFD` descriptor.
/// This does not touch procfs or inspect the peer image.
pub fn observe_peer(socket: &impl AsFd) -> Result<PeerIdentity, PeerObservationError> {
    let socket = socket.as_fd();
    let creds = peer_credentials(socket).map_err(PeerObservationError::Observation)?;
    // SAFETY: geteuid has no memory or ownership requirements.
    let euid = unsafe { libc::geteuid() };
    if creds.uid != euid {
        return Err(PeerObservationError::WrongUser);
    }
    let pid = u32::try_from(creds.pid)
        .ok()
        .filter(|&pid| pid > 0)
        .ok_or_else(|| PeerObservationError::Observation(invalid("invalid socket peer PID")))?;
    let pidfd = PidFd::for_peer(socket).map_err(PeerObservationError::Observation)?;
    Ok(PeerIdentity { pid, pidfd })
}

impl PeerIdentity {
    /// Step 2: verify a daemon peer before the host writes its hello.
    pub fn verify_cerebellum(self, key: &VerifyingKey) -> io::Result<()> {
        self.verify_image(key, PeerRole::Cerebellum)?;
        Ok(())
    }

    /// Pre-hello step 3: verify and retain the host identity for the parent re-check.
    pub fn verify_host(self, key: &VerifyingKey) -> io::Result<VerifiedHost> {
        let stat = self.verify_image(key, PeerRole::Host)?;
        Ok(VerifiedHost { peer: self, stat })
    }

    fn verify_image(&self, key: &VerifyingKey, role: PeerRole) -> io::Result<Stat> {
        let mut image = File::open(exe_path(self.pid))?;
        let stat = Stat::read(self.pid)?;
        self.pidfd.require_pid(self.pid)?;
        self.pidfd.require_live()?;
        peer_trailer::verify(&mut image, key, role, TARGET)?;
        self.pidfd.require_live()?;
        Ok(stat)
    }
}

/// Step-1 evidence retaining the launching process's pidfd and image.
#[derive(Debug)]
pub struct ParentEvidence {
    process: ParentProcess,
    attestation: HostParentAttestation,
}

/// Step 1: derive the current parent's Linux attestation without connecting.
/// Call [`ParentEvidence::check_before_connect`] again at the connection decision.
pub fn attest_parent(key: &VerifyingKey) -> io::Result<ParentEvidence> {
    let pid = current_parent();
    let pidfd = PidFd::open(pid)?;
    if current_parent() != pid {
        return Err(invalid("launching parent changed"));
    }
    let mut process = ParentProcess::observe(pid, pidfd)?;
    let attestation = process.attest(key)?.into();
    let evidence = ParentEvidence {
        process,
        attestation,
    };
    evidence.check_before_connect()?;
    Ok(evidence)
}

impl ParentEvidence {
    /// The attestation for the hello, after the host has verified its daemon peer.
    pub fn attestation(&self) -> &HostParentAttestation {
        &self.attestation
    }

    /// Call immediately before connecting, leaving the evidence alive across connect.
    pub fn check_before_connect(&self) -> io::Result<()> {
        let process = &self.process;
        process.require_unchanged()?;
        if current_parent() != process.pid {
            return Err(invalid("launching parent changed"));
        }
        process.pidfd.require_live()
    }
}

/// The verified host image's process generation, backed by a retained pidfd.
#[derive(Debug)]
pub struct VerifiedHost {
    peer: PeerIdentity,
    stat: Stat,
}

impl VerifiedHost {
    /// Post-hello step 3: re-derive the host's parent evidence and match it
    /// exactly. Call only after the listener checks the hello protocol and origin.
    pub fn recheck_parent(
        self,
        attestation: &HostParentAttestation,
        key: &VerifyingKey,
    ) -> io::Result<()> {
        let pid = self.stat.parent_pid;
        let pidfd = PidFd::open(pid)?;
        self.require_unchanged()?;
        let mut parent = ParentProcess::observe(pid, pidfd)?;
        require_matching_parent(attestation, parent.attest(key)?)?;
        parent.require_unchanged()?;
        self.require_unchanged()?;
        // The host and parent must still be live after the final procfs lookup.
        parent.pidfd.require_live()?;
        self.peer.pidfd.require_live()
    }

    fn require_unchanged(&self) -> io::Result<()> {
        if Stat::read(self.peer.pid)? != self.stat {
            return Err(invalid("host generation or its parent changed"));
        }
        Ok(())
    }
}

fn require_matching_parent(
    claimed: &HostParentAttestation,
    observed: PlatformParentAttestation,
) -> io::Result<()> {
    if *claimed != HostParentAttestation::from(observed) {
        return Err(invalid(
            "Linux parent attestation does not match observed evidence",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct ParentProcess {
    pid: u32,
    pidfd: PidFd,
    start_ticks: u64,
    image: File,
    path: PathBuf,
}

impl ParentProcess {
    fn observe(pid: u32, pidfd: PidFd) -> io::Result<Self> {
        let stat = Stat::read(pid)?;
        let proc_exe = exe_path(pid);
        let image = File::open(&proc_exe)?;
        let path = fs::read_link(proc_exe)?;
        require_named_image(&path)?;
        pidfd.require_pid(pid)?;
        pidfd.require_live()?;
        Ok(Self {
            pid,
            pidfd,
            start_ticks: stat.start_ticks,
            image,
            path,
        })
    }

    fn attest(&mut self, _key: &VerifyingKey) -> io::Result<PlatformParentAttestation> {
        let error = match dpkg::verify_image(&self.path, &self.image) {
            Ok((browser, package)) => {
                return Ok(PlatformParentAttestation::Linux {
                    v: AttestationV1,
                    browser,
                    pid: self.pid,
                    start_ticks: self.start_ticks,
                    package,
                })
            }
            Err(error) => error,
        };
        #[cfg(feature = "bridge-test-identities")]
        if peer_trailer::is_test_peer_key(_key) {
            peer_trailer::verify(&mut self.image, _key, PeerRole::TestParent, TARGET)?;
            return Ok(PlatformParentAttestation::LinuxTest {
                v: AttestationV1,
                pid: self.pid,
                start_ticks: self.start_ticks,
            });
        }
        Err(error)
    }

    fn require_unchanged(&self) -> io::Result<()> {
        let current = Stat::read(self.pid)?;
        let proc_exe = exe_path(self.pid);
        let image = self.image.metadata()?;
        let running = fs::metadata(&proc_exe)?;
        if current.start_ticks != self.start_ticks
            || (image.dev(), image.ino()) != (running.dev(), running.ino())
            || fs::read_link(proc_exe)? != self.path
        {
            return Err(invalid("launching process generation or image changed"));
        }
        Ok(())
    }
}

fn exe_path(pid: u32) -> PathBuf {
    format!("/proc/{pid}/exe").into()
}

fn require_named_image(path: &Path) -> io::Result<()> {
    if path.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Err(invalid("launching executable was deleted"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
