//! Linux process and package evidence for the native-messaging handshake.
//!
//! These checks do blocking work. The caller owns the handshake deadlines and
//! maps an error to the refusal for its current step.

use crate::peer_trailer::{self, PeerRole};
use crate::{AttestationV1, HostParentAttestation, PlatformParentAttestation};
use cerebellum_linux::bridge::{
    observe_kernel_pidfds, open_executable, read_effective_uid, read_executable_metadata,
    read_executable_path, read_parent_pid, read_peer_credentials, PidFd, ProcessStat,
};
pub use ed25519_dalek::VerifyingKey;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

mod dpkg;
#[cfg(test)]
mod tests;

const TARGET: &str = env!("CEREBELLUM_LINUX_TARGET");

/// Check for both pidfd primitives before binding a bridge listener.
/// Only this probe reports an unsupported primitive as `needs Linux 6.5+`;
/// observations of a particular peer or parent report the underlying read failure.
pub fn probe_kernel() -> io::Result<()> {
    observe_kernel_pidfds()
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
    let creds = read_peer_credentials(socket).map_err(PeerObservationError::Observation)?;
    if creds.uid != read_effective_uid() {
        return Err(PeerObservationError::WrongUser);
    }
    let pid = u32::try_from(creds.pid)
        .ok()
        .filter(|&pid| pid > 0)
        .ok_or_else(|| PeerObservationError::Observation(invalid("invalid socket peer PID")))?;
    let pidfd = PidFd::open_peer(socket).map_err(PeerObservationError::Observation)?;
    Ok(PeerIdentity { pid, pidfd })
}

impl PeerIdentity {
    /// Verify a daemon peer before the host writes its hello.
    pub fn verify_cerebellum(self, key: &VerifyingKey) -> io::Result<()> {
        self.verify_image(key, PeerRole::Cerebellum)?;
        Ok(())
    }

    /// Before reading the hello, verify the host and retain its identity for the parent re-check.
    pub fn verify_host(self, key: &VerifyingKey) -> io::Result<VerifiedHost> {
        let stat = self.verify_image(key, PeerRole::Host)?;
        Ok(VerifiedHost { peer: self, stat })
    }

    fn verify_image(&self, key: &VerifyingKey, role: PeerRole) -> io::Result<ProcessStat> {
        let mut image = open_executable(self.pid)?;
        let stat = ProcessStat::read(self.pid)?;
        require_pid(&self.pidfd, self.pid)?;
        require_live(&self.pidfd)?;
        peer_trailer::verify(&mut image, key, role, TARGET)?;
        require_live(&self.pidfd)?;
        Ok(stat)
    }
}

/// Evidence retaining the launching process's pidfd and image across connect.
#[derive(Debug)]
pub struct ParentEvidence {
    process: ParentProcess,
    attestation: HostParentAttestation,
}

/// Derive the current parent's Linux attestation without connecting.
/// Call [`ParentEvidence::check_before_connect`] again at the connection decision.
pub fn attest_parent(key: &VerifyingKey) -> io::Result<ParentEvidence> {
    let pid = read_parent_pid();
    let pidfd = PidFd::open_process(pid)?;
    if read_parent_pid() != pid {
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
        if read_parent_pid() != process.pid {
            return Err(invalid("launching parent changed"));
        }
        require_live(&process.pidfd)
    }
}

/// The verified host image's process generation, backed by a retained pidfd.
#[derive(Debug)]
pub struct VerifiedHost {
    peer: PeerIdentity,
    stat: ProcessStat,
}

impl VerifiedHost {
    /// After the hello, re-derive the host's parent evidence and match it
    /// exactly. Call only after the listener checks the hello protocol and origin.
    pub fn recheck_parent(
        self,
        attestation: &HostParentAttestation,
        key: &VerifyingKey,
    ) -> io::Result<()> {
        let pid = self.stat.parent_pid;
        let pidfd = PidFd::open_process(pid)?;
        self.require_unchanged()?;
        let mut parent = ParentProcess::observe(pid, pidfd)?;
        require_matching_parent(attestation, parent.attest(key)?)?;
        parent.require_unchanged()?;
        self.require_unchanged()?;
        // The host and parent must still be live after the final procfs lookup.
        require_live(&parent.pidfd)?;
        require_live(&self.peer.pidfd)
    }

    fn require_unchanged(&self) -> io::Result<()> {
        if ProcessStat::read(self.peer.pid)? != self.stat {
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
        let stat = ProcessStat::read(pid)?;
        let image = open_executable(pid)?;
        let path = read_executable_path(pid)?;
        require_named_image(&path)?;
        require_pid(&pidfd, pid)?;
        require_live(&pidfd)?;
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
        let current = ProcessStat::read(self.pid)?;
        let image = self.image.metadata()?;
        let running = read_executable_metadata(self.pid)?;
        if current.start_ticks != self.start_ticks
            || (image.dev(), image.ino()) != (running.dev(), running.ino())
            || read_executable_path(self.pid)? != self.path
        {
            return Err(invalid("launching process generation or image changed"));
        }
        Ok(())
    }
}

fn require_pid(pidfd: &PidFd, pid: u32) -> io::Result<()> {
    if pidfd.read_pid()?.and_then(|pid| u32::try_from(pid).ok()) != Some(pid) {
        return Err(invalid("pidfd does not name the observed process"));
    }
    Ok(())
}

fn require_live(pidfd: &PidFd) -> io::Result<()> {
    if pidfd.read_ready()? {
        return Err(invalid(
            "pidfd is ready; process liveness was not established",
        ));
    }
    Ok(())
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
