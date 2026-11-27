use super::{
    retain_process_handle_for_image, verify_installed_chrome, verify_system_cmd, ImageRefusal,
    OpenedProcessImage, ProcessHandleError, RetainedProcessHandle, VerifyingKey,
};
use crate::peer_trailer::{self, PeerRole};
use crate::{AttestationV1, HostParentAttestation, PlatformParentAttestation, WindowsProcess};
use cerebellum_windows::{
    current_process_token_user_sid, named_pipe_client_pid, named_pipe_server_pid, ProcessStartTime,
};
use std::{fmt, io, os::windows::io::AsHandle};

#[cfg(test)]
mod tests;

const TARGET: &str = env!("CEREBELLUM_WINDOWS_TARGET");

pub fn current_user_sid() -> io::Result<String> {
    current_process_token_user_sid()
}

#[derive(Debug)]
pub enum PeerObservationError {
    WrongUser,
    Observation(io::Error),
}

impl fmt::Display for PeerObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongUser => f.write_str("could not establish a matching pipe peer user SID"),
            Self::Observation(error) => write!(f, "could not observe pipe peer: {error}"),
        }
    }
}

impl std::error::Error for PeerObservationError {}

#[derive(Debug)]
pub struct PeerIdentity(Process);

/// Observe the pipe client before reading the hello or verifying its image.
/// Record `connected_at` as the first action after observing connect completion.
pub fn observe_client_peer(
    pipe: &impl AsHandle,
    connected_at: u64,
) -> Result<PeerIdentity, PeerObservationError> {
    observe_peer(named_pipe_client_pid(pipe.as_handle()), connected_at)
}

/// Observe the pipe server before verifying its image or sending the hello.
/// Record `connected_at` immediately before the CreateFileW call that succeeds.
pub fn observe_server_peer(
    pipe: &impl AsHandle,
    connected_at: u64,
) -> Result<PeerIdentity, PeerObservationError> {
    observe_peer(named_pipe_server_pid(pipe.as_handle()), connected_at)
}

fn observe_peer(
    pid: io::Result<u32>,
    connected_at: u64,
) -> Result<PeerIdentity, PeerObservationError> {
    use PeerObservationError::{Observation, WrongUser};
    let pid = pid.map_err(Observation)?;
    let handle = retain_process_handle_for_image(pid).map_err(|error| match error {
        ProcessHandleError::AccessDenied => WrongUser,
        other => Observation(handle_error(other)),
    })?;
    let process = Process::observe(pid, handle).map_err(Observation)?;
    require_earlier(process.generation.creation_100ns, connected_at).map_err(Observation)?;
    let peer_sid = process.handle.token_user_sid().map_err(|error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            WrongUser
        } else {
            Observation(error)
        }
    })?;
    if peer_sid != current_user_sid().map_err(Observation)? {
        return Err(WrongUser);
    }
    Ok(PeerIdentity(process))
}

impl PeerIdentity {
    pub fn verify_cerebellum(self, key: &VerifyingKey) -> io::Result<()> {
        self.verify_image(key, PeerRole::Cerebellum)
    }

    pub fn verify_host(self, key: &VerifyingKey) -> io::Result<VerifiedHost> {
        self.verify_image(key, PeerRole::Host)?;
        Ok(VerifiedHost(self.0))
    }

    fn verify_image(&self, key: &VerifyingKey, role: PeerRole) -> io::Result<()> {
        let mut image = self.0.open_image()?.into_file();
        peer_trailer::verify(&mut image, key, role, TARGET)?;
        self.0.require_live()
    }
}

#[derive(Debug)]
pub struct VerifiedHost(Process);

impl VerifiedHost {
    /// Re-derive the launch chain after the listener has checked protocol and origin.
    pub fn recheck_parent(
        self,
        attestation: &HostParentAttestation,
        key: &VerifyingKey,
    ) -> io::Result<()> {
        let evidence = attest_chain(&self.0, key)?;
        require_matching_parent(attestation, evidence.attestation())?;
        evidence.check_before_connect()?;
        self.0.require_live()
    }
}

fn require_matching_parent(
    claimed: &HostParentAttestation,
    observed: &HostParentAttestation,
) -> io::Result<()> {
    if claimed != observed {
        return Err(invalid(
            "Windows parent attestation does not match observed evidence",
        ));
    }
    Ok(())
}

/// Retains the exact ancestor process objects used for the parent attestation.
#[derive(Debug)]
pub struct ParentEvidence {
    launcher: Process,
    chrome: Option<Process>,
    attestation: HostParentAttestation,
}

impl ParentEvidence {
    pub fn attestation(&self) -> &HostParentAttestation {
        &self.attestation
    }

    /// Poll the retained handles immediately before connecting and before every retry.
    pub fn check_before_connect(&self) -> io::Result<()> {
        self.launcher.require_live()?;
        if let Some(chrome) = &self.chrome {
            chrome.require_live()?;
        }
        Ok(())
    }
}

pub fn attest_parent(key: &VerifyingKey) -> io::Result<ParentEvidence> {
    attest_chain(&Process::open(std::process::id())?, key)
}

fn attest_chain(host: &Process, _key: &VerifyingKey) -> io::Result<ParentEvidence> {
    let launcher = host.parent()?;
    let launcher_image = launcher.open_image()?;
    #[cfg(feature = "bridge-test-identities")]
    let launcher_image = if peer_trailer::is_test_peer_key(_key) {
        use std::io::{Seek, SeekFrom};
        let mut image = launcher_image;
        if peer_trailer::verify(image.file_mut(), _key, PeerRole::TestParent, TARGET).is_ok() {
            let attestation = PlatformParentAttestation::WindowsTest {
                v: AttestationV1,
                parent: launcher.generation,
            };
            return finish_chain(host, launcher, None, attestation);
        }
        image.file_mut().seek(SeekFrom::Start(0))?;
        image
    } else {
        launcher_image
    };
    verify_system_cmd(&launcher_image).map_err(io::Error::other)?;
    let chrome = launcher.parent()?;
    let chrome_image = chrome.open_image()?;
    verify_installed_chrome(&chrome_image).map_err(io::Error::other)?;
    let attestation = PlatformParentAttestation::Windows {
        v: AttestationV1,
        chrome: chrome.generation,
        launcher: launcher.generation,
    };
    finish_chain(host, launcher, Some(chrome), attestation)
}

fn finish_chain(
    host: &Process,
    launcher: Process,
    chrome: Option<Process>,
    attestation: PlatformParentAttestation,
) -> io::Result<ParentEvidence> {
    let evidence = ParentEvidence {
        launcher,
        chrome,
        attestation: attestation.into(),
    };
    evidence.check_before_connect()?;
    host.require_live()?;
    Ok(evidence)
}

#[derive(Debug)]
struct Process {
    handle: RetainedProcessHandle,
    generation: WindowsProcess,
}

impl Process {
    fn open(pid: u32) -> io::Result<Self> {
        Self::observe(
            pid,
            retain_process_handle_for_image(pid).map_err(handle_error)?,
        )
    }

    fn observe(pid: u32, handle: RetainedProcessHandle) -> io::Result<Self> {
        let creation_100ns = match handle.creation_time() {
            ProcessStartTime::Started(time) => time,
            other => {
                return Err(io::Error::other(format!(
                    "could not read process creation time: {other:?}"
                )))
            }
        };
        Ok(Self {
            handle,
            generation: WindowsProcess {
                pid,
                creation_100ns,
            },
        })
    }

    fn parent(&self) -> io::Result<Self> {
        let parent = Self::open(self.handle.parent_pid()?)?;
        require_earlier(
            parent.generation.creation_100ns,
            self.generation.creation_100ns,
        )?;
        Ok(parent)
    }

    fn open_image(&self) -> io::Result<OpenedProcessImage> {
        OpenedProcessImage::open(&self.handle)
            .map_err(ImageRefusal::from)
            .map_err(io::Error::other)
    }

    fn require_live(&self) -> io::Result<()> {
        if self.handle.exit_signaled()? {
            return Err(invalid("pipe peer or ancestor process exited"));
        }
        Ok(())
    }
}

fn require_earlier(created: u64, boundary: u64) -> io::Result<()> {
    if created >= boundary {
        return Err(invalid(
            "process creation time does not precede the observation",
        ));
    }
    Ok(())
}

fn handle_error(error: ProcessHandleError) -> io::Error {
    match error {
        ProcessHandleError::NoSuchProcess => invalid("process no longer exists"),
        ProcessHandleError::AccessDenied => io::ErrorKind::PermissionDenied.into(),
        ProcessHandleError::Unclassified(code) => io::Error::from_raw_os_error(code as i32),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
