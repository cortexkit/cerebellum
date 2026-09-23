//! Pipe-backed CDP readiness for an attested browser launch.

use std::cmp;
use std::io;
// Only the unix pipe implementation below drives these traits. The readiness
// loop's `pipe.read` is this module's own trait method, not io::Read, so on a
// platform without that implementation these are genuinely unused rather than
// suppressed.
#[cfg(unix)]
use std::io::{Read, Write};
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::browser_launch::{
    AttestedLaunchError, AttestedLaunchRequest, BarredLaunchProcess, BarredProcessLauncher,
    LaunchAttestationRecord, LaunchJournalPort, PlatformLaunchError, ReleasedAttestedBrowser,
};
use crate::cdp::{parse_json_message, CdpError, CdpFrameDecoder, CdpTransport};

const HANDSHAKE_METHOD: &str = "Browser.getVersion";
const POLL_INTERVAL: Duration = Duration::from_millis(1);
const READ_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileStartupCause {
    ChildExit,
    PipeClosed,
    DeadlineExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupAmbiguity {
    IndeterminateStartupFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupPossibleReason {
    ExternalProfileHolder,
    ProfileUnopenableOrCorrupt,
    BrowserStartupFailure,
    InvalidBrowserInvocation,
    PlatformOrSandboxDenial,
}

const POSSIBLE_REASONS: [StartupPossibleReason; 5] = [
    StartupPossibleReason::ExternalProfileHolder,
    StartupPossibleReason::ProfileUnopenableOrCorrupt,
    StartupPossibleReason::BrowserStartupFailure,
    StartupPossibleReason::InvalidBrowserInvocation,
    StartupPossibleReason::PlatformOrSandboxDenial,
];

/// The complete public failure payload. Possible reasons are deliberately fixed
/// rather than selected from observations because this layer cannot distinguish
/// profile contention from other startup failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileStartupIndeterminate {
    outcome: String,
    pub cause: ProfileStartupCause,
    ambiguity: StartupAmbiguity,
    possible_reasons: [StartupPossibleReason; 5],
}

impl ProfileStartupIndeterminate {
    pub(crate) fn new(cause: ProfileStartupCause) -> Self {
        Self {
            outcome: "profile_startup_indeterminate".to_string(),
            cause,
            ambiguity: StartupAmbiguity::IndeterminateStartupFailure,
            possible_reasons: POSSIBLE_REASONS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserVersion {
    pub product: String,
    pub protocol_version: String,
}

/// Exit status is diagnostic input only. Every status, including zero, has the
/// same pre-readiness meaning because a contending headed Chromium exits zero
/// without becoming the process on the inherited pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExitStatus {
    Code(i32),
    Signaled,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeHandshakeState {
    Pending,
    Ready(BrowserVersion),
    Failed(ProfileStartupIndeterminate),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeBuildError {
    DeadlineOverflow,
    Transport(CdpError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HandshakeTerminal {
    Ready(BrowserVersion),
    Failed(ProfileStartupIndeterminate),
}

/// Stateful handshake policy around the transport-agnostic CDP correlator.
/// Bytes enter only through the NUL decoder; `CdpTransport` remains the sole
/// owner of request identifiers, pending state, and response correlation.
#[derive(Debug)]
pub struct PipeHandshake {
    transport: CdpTransport,
    request_id: u64,
    request_bytes: Vec<u8>,
    deadline: Instant,
    decoder: CdpFrameDecoder,
    terminal: Option<HandshakeTerminal>,
}

impl PipeHandshake {
    pub fn new(released_at: Instant, deadline_ms: NonZeroU64) -> Result<Self, HandshakeBuildError> {
        let deadline = released_at
            .checked_add(Duration::from_millis(deadline_ms.get()))
            .ok_or(HandshakeBuildError::DeadlineOverflow)?;
        let mut transport = CdpTransport::new();
        let command = transport
            .issue_command(HANDSHAKE_METHOD, None, None, released_at)
            .map_err(HandshakeBuildError::Transport)?;
        let mut request_bytes = command
            .json_bytes()
            .map_err(HandshakeBuildError::Transport)?;
        request_bytes.push(0);
        Ok(Self {
            transport,
            request_id: command.id,
            request_bytes,
            deadline,
            decoder: CdpFrameDecoder::default(),
            terminal: None,
        })
    }

    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    pub fn request_bytes(&self) -> &[u8] {
        &self.request_bytes
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Apply observations from one monotonic sampling turn. Failure precedence
    /// is decided before parsing bytes so an exit or close observed in the same
    /// turn cannot be reclassified by a response buffered behind it.
    pub fn observe(
        &mut self,
        observed_at: Instant,
        child_exit: Option<ChildExitStatus>,
        pipe_closed: bool,
        bytes: &[u8],
    ) -> PipeHandshakeState {
        if let Some(terminal) = &self.terminal {
            return terminal.clone().into();
        }
        if child_exit.is_some() {
            return self.fail(ProfileStartupCause::ChildExit);
        }
        if pipe_closed {
            return self.fail(ProfileStartupCause::PipeClosed);
        }
        if observed_at >= self.deadline {
            return self.fail(ProfileStartupCause::DeadlineExpired);
        }

        for frame in self.decoder.push(bytes) {
            if let Some(version) = self.observe_frame(&frame) {
                self.terminal = Some(HandshakeTerminal::Ready(version.clone()));
                return PipeHandshakeState::Ready(version);
            }
        }
        PipeHandshakeState::Pending
    }

    pub fn into_transport_parts(self) -> (CdpTransport, CdpFrameDecoder) {
        (self.transport, self.decoder)
    }

    fn fail(&mut self, cause: ProfileStartupCause) -> PipeHandshakeState {
        let failure = ProfileStartupIndeterminate::new(cause);
        self.terminal = Some(HandshakeTerminal::Failed(failure.clone()));
        PipeHandshakeState::Failed(failure)
    }

    fn observe_frame(&mut self, frame: &[u8]) -> Option<BrowserVersion> {
        // A newline before NUL is a different framing protocol, even though a
        // JSON parser would otherwise accept trailing whitespace after a value.
        if frame.is_empty() || frame.contains(&b'\n') || frame.contains(&b'\r') {
            return None;
        }
        let value = parse_json_message(frame).ok()?;
        let object = value.as_object()?;
        if !object.contains_key("id") {
            let _ = self.transport.observe_event(frame);
            return None;
        }
        let response = self.transport.observe_response(frame).ok()?;
        if response.id != self.request_id || response.error.is_some() {
            return None;
        }
        let result = response.result?;
        let product = result.get("product").and_then(Value::as_str)?;
        let protocol_version = result.get("protocolVersion").and_then(Value::as_str)?;
        Some(BrowserVersion {
            product: product.to_string(),
            protocol_version: protocol_version.to_string(),
        })
    }
}

impl From<HandshakeTerminal> for PipeHandshakeState {
    fn from(value: HandshakeTerminal) -> Self {
        match value {
            HandshakeTerminal::Ready(version) => Self::Ready(version),
            HandshakeTerminal::Failed(failure) => Self::Failed(failure),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeRead {
    Bytes(usize),
    WouldBlock,
    Closed,
}

pub trait CdpPipeIo {
    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()>;
    fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead>;
}

pub trait HandshakeClock {
    fn now(&mut self) -> Instant;
    fn sleep(&mut self, duration: Duration);
}

#[derive(Debug, Default)]
pub struct SystemHandshakeClock;

impl HandshakeClock for SystemHandshakeClock {
    fn now(&mut self) -> Instant {
        Instant::now()
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

pub trait HandshakeProcess: Sized {
    fn observe_exit(&mut self) -> Option<ChildExitStatus>;
    fn wait_and_reap(self) -> Result<(), PlatformLaunchError>;
    fn terminate_and_reap(self) -> Result<(), PlatformLaunchError>;
}

pub trait FailedLaunchRollback {
    fn rollback(
        &mut self,
        failure: &ProfileStartupIndeterminate,
    ) -> Result<(), PlatformLaunchError>;

    /// A failure before readiness can still leave the prepared profile owned by
    /// the launch operation, even when no child was created. The default does
    /// nothing for existing adapters; adapters that own a profile must finish its
    /// rollback.
    fn rollback_attested(
        &mut self,
        failure: &AttestedLaunchError,
    ) -> Result<(), PlatformLaunchError> {
        let _ = failure;
        Ok(())
    }
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct NoopFailedLaunchRollback;

#[cfg(test)]
impl FailedLaunchRollback for NoopFailedLaunchRollback {
    fn rollback(
        &mut self,
        _failure: &ProfileStartupIndeterminate,
    ) -> Result<(), PlatformLaunchError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessCleanupStage {
    Reap,
    Rollback,
    JournalFinalization,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchReadinessError {
    HandshakeSetupFailed,
    ProfileStartupIndeterminate(ProfileStartupIndeterminate),
    CleanupFailed {
        primary: Option<ProfileStartupIndeterminate>,
        stage: ReadinessCleanupStage,
    },
}

pub struct ReadyAttestedBrowser<P, IO> {
    pub attestation: LaunchAttestationRecord,
    pub process: P,
    pub pipe: IO,
    pub transport: CdpTransport,
    pub decoder: CdpFrameDecoder,
    pub browser_version: BrowserVersion,
}

pub fn complete_pipe_handshake<P, IO, C, R>(
    released: ReleasedAttestedBrowser<P>,
    mut pipe: IO,
    deadline_ms: NonZeroU64,
    clock: &mut C,
    rollback: &mut R,
) -> Result<ReadyAttestedBrowser<P, IO>, LaunchReadinessError>
where
    P: HandshakeProcess,
    IO: CdpPipeIo,
    C: HandshakeClock,
    R: FailedLaunchRollback,
{
    let ReleasedAttestedBrowser {
        attestation,
        observed_executable_identity_chain: _,
        mut process,
        released_at,
    } = released;
    let mut handshake = match PipeHandshake::new(released_at, deadline_ms) {
        Ok(handshake) => handshake,
        Err(_) => {
            return match process.terminate_and_reap() {
                Ok(()) => Err(LaunchReadinessError::HandshakeSetupFailed),
                Err(_) => Err(LaunchReadinessError::CleanupFailed {
                    primary: None,
                    stage: ReadinessCleanupStage::Reap,
                }),
            }
        }
    };

    let initial_state = if pipe.write_frame(handshake.request_bytes()).is_err() {
        handshake.observe(clock.now(), None, true, &[])
    } else {
        PipeHandshakeState::Pending
    };
    if let PipeHandshakeState::Failed(failure) = initial_state {
        return Err(finish_failed_handshake(process, failure, rollback));
    }

    let mut read_buffer = vec![0; READ_CHUNK_BYTES];
    loop {
        let child_exit = process.observe_exit();
        let (pipe_closed, bytes) = if child_exit.is_some() {
            (false, &[][..])
        } else {
            match pipe.read(&mut read_buffer) {
                Ok(PipeRead::Bytes(bytes)) if bytes <= read_buffer.len() => {
                    (false, &read_buffer[..bytes])
                }
                Ok(PipeRead::Bytes(_)) => (true, &[][..]),
                Ok(PipeRead::WouldBlock) => (false, &[][..]),
                Ok(PipeRead::Closed) | Err(_) => (true, &[][..]),
            }
        };
        let state = handshake.observe(clock.now(), child_exit, pipe_closed, bytes);
        match state {
            PipeHandshakeState::Pending => {
                let remaining = handshake.deadline().saturating_duration_since(clock.now());
                clock.sleep(cmp::min(POLL_INTERVAL, remaining));
            }
            PipeHandshakeState::Ready(browser_version) => {
                let (transport, decoder) = handshake.into_transport_parts();
                return Ok(ReadyAttestedBrowser {
                    attestation,
                    process,
                    pipe,
                    transport,
                    decoder,
                    browser_version,
                });
            }
            PipeHandshakeState::Failed(failure) => {
                return Err(finish_failed_handshake(process, failure, rollback));
            }
        }
    }
}

fn finish_failed_handshake<P, R>(
    process: P,
    failure: ProfileStartupIndeterminate,
    rollback: &mut R,
) -> LaunchReadinessError
where
    P: HandshakeProcess,
    R: FailedLaunchRollback,
{
    let reap = match failure.cause {
        ProfileStartupCause::ChildExit => process.wait_and_reap(),
        ProfileStartupCause::PipeClosed | ProfileStartupCause::DeadlineExpired => {
            process.terminate_and_reap()
        }
    };
    if reap.is_err() {
        return LaunchReadinessError::CleanupFailed {
            primary: Some(failure),
            stage: ReadinessCleanupStage::Reap,
        };
    }
    if rollback.rollback(&failure).is_err() {
        return LaunchReadinessError::CleanupFailed {
            primary: Some(failure),
            stage: ReadinessCleanupStage::Rollback,
        };
    }
    LaunchReadinessError::ProfileStartupIndeterminate(failure)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestedReadinessError {
    AttestedLaunch(AttestedLaunchError),
    Readiness(LaunchReadinessError),
    CleanupFailed {
        primary: AttestedLaunchError,
        stage: ReadinessCleanupStage,
    },
}

pub fn launch_attested_to_readiness_with<J, L, IO, C, R>(
    journal: &mut J,
    launcher: &mut L,
    request: &AttestedLaunchRequest,
    pipe: IO,
    deadline_ms: NonZeroU64,
    clock: &mut C,
    rollback: &mut R,
) -> Result<
    ReadyAttestedBrowser<<L::Process as BarredLaunchProcess>::Released, IO>,
    AttestedReadinessError,
>
where
    J: LaunchJournalPort,
    L: BarredProcessLauncher,
    <L::Process as BarredLaunchProcess>::Released: HandshakeProcess,
    IO: CdpPipeIo,
    C: HandshakeClock,
    R: FailedLaunchRollback,
{
    let released = match crate::browser_launch::launch_attested_with_release_clock(
        journal,
        launcher,
        request,
        || clock.now(),
    ) {
        Ok(released) => released,
        Err(primary) => {
            // For these errors, either no child was created, or the child was
            // already terminated and reaped. If termination or reaping failed,
            // process ownership remains unresolved, so the profile must not be
            // mutated.
            if !matches!(primary, AttestedLaunchError::TerminationOrReapFailed)
                && rollback.rollback_attested(&primary).is_err()
            {
                return Err(AttestedReadinessError::CleanupFailed {
                    primary,
                    stage: ReadinessCleanupStage::Rollback,
                });
            }
            return Err(AttestedReadinessError::AttestedLaunch(primary));
        }
    };
    let result = complete_pipe_handshake(released, pipe, deadline_ms, clock, rollback);
    // Keep the journal attempt open unless the child was reaped and profile rollback
    // succeeded: recovery still owns unresolved process or profile cleanup.
    if let Err(LaunchReadinessError::ProfileStartupIndeterminate(failure)) = &result {
        if journal
            .finalize_startup_failure(&request.launch_attempt_id, failure)
            .is_err()
        {
            return Err(AttestedReadinessError::Readiness(
                LaunchReadinessError::CleanupFailed {
                    primary: Some(failure.clone()),
                    stage: ReadinessCleanupStage::JournalFinalization,
                },
            ));
        }
    }
    result.map_err(AttestedReadinessError::Readiness)
}

#[cfg(unix)]
pub struct UnixCdpPipe {
    command: std::os::unix::net::UnixStream,
    response: std::os::unix::net::UnixStream,
}

#[cfg(unix)]
impl UnixCdpPipe {
    pub fn new(
        command: std::os::unix::net::UnixStream,
        response: std::os::unix::net::UnixStream,
    ) -> io::Result<Self> {
        response.set_nonblocking(true)?;
        Ok(Self { command, response })
    }
}

#[cfg(unix)]
impl CdpPipeIo for UnixCdpPipe {
    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.command.write_all(bytes)
    }

    fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
        match self.response.read(destination) {
            Ok(0) => Ok(PipeRead::Closed),
            Ok(bytes) => Ok(PipeRead::Bytes(bytes)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(PipeRead::WouldBlock),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use cerebellum_core::journal::JournalError as CoreJournalError;
    use serde_json::json;

    use super::*;
    use crate::browser_launch::{
        AuthorizedLaunchIntent, BrowserProcessGeneration, ExecutableIdentityChain,
        ExecutableIdentityCheckpoints, ExecutableIdentityClaim, ExecutableIdentityRecord,
        LaunchGenerationRecord, LaunchIdentityMismatchRecord, LaunchProfileIdentity,
        LaunchRouteIdentity, PreSpawnIdentityVerification, VerifiedExecutableIdentity,
    };

    fn instant() -> Instant {
        Instant::now()
    }

    fn deadline_ms(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("non-zero deadline")
    }

    fn valid_response(id: u64) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({
            "id": id,
            "result": {
                "product": "Chrome/151.0.0.0",
                "protocolVersion": "1.3"
            }
        }))
        .expect("serialize response");
        bytes.push(0);
        bytes
    }

    fn new_handshake() -> (PipeHandshake, Instant) {
        let released_at = instant();
        (
            PipeHandshake::new(released_at, deadline_ms(100)).expect("handshake"),
            released_at,
        )
    }

    fn assert_pending_then_ready(bytes: &[u8]) {
        let (mut handshake, released_at) = new_handshake();
        assert_eq!(
            handshake.observe(released_at + Duration::from_millis(1), None, false, bytes),
            PipeHandshakeState::Pending
        );
        let request_id = handshake.request_id();
        assert_eq!(
            handshake.observe(
                released_at + Duration::from_millis(2),
                None,
                false,
                &valid_response(request_id),
            ),
            PipeHandshakeState::Ready(BrowserVersion {
                product: "Chrome/151.0.0.0".to_string(),
                protocol_version: "1.3".to_string(),
            })
        );
    }

    #[test]
    fn request_is_one_json_object_followed_by_one_nul() {
        let (handshake, _) = new_handshake();
        let request = handshake.request_bytes();
        assert_eq!(request.last(), Some(&0));
        assert_eq!(request.iter().filter(|byte| **byte == 0).count(), 1);
        assert!(!request.contains(&b'\n'));
        assert_eq!(
            serde_json::from_slice::<Value>(&request[..request.len() - 1]).expect("request JSON"),
            json!({"id": handshake.request_id(), "method": "Browser.getVersion"})
        );
    }

    #[test]
    fn correlated_well_formed_version_response_establishes_readiness() {
        let (mut handshake, released_at) = new_handshake();
        let request_id = handshake.request_id();
        assert_eq!(
            handshake.observe(
                released_at + Duration::from_millis(1),
                None,
                false,
                &valid_response(request_id),
            ),
            PipeHandshakeState::Ready(BrowserVersion {
                product: "Chrome/151.0.0.0".to_string(),
                protocol_version: "1.3".to_string(),
            })
        );
    }

    #[test]
    fn newline_delimited_json_is_not_readiness() {
        let (handshake, _) = new_handshake();
        let mut frame = valid_response(handshake.request_id());
        frame.insert(frame.len() - 1, b'\n');
        assert_pending_then_ready(&frame);
    }

    #[test]
    fn unterminated_json_is_not_readiness() {
        let (mut handshake, released_at) = new_handshake();
        let request_id = handshake.request_id();
        let mut frame = valid_response(request_id);
        frame.pop();
        assert_eq!(
            handshake.observe(released_at + Duration::from_millis(1), None, false, &frame),
            PipeHandshakeState::Pending
        );
        assert_eq!(
            handshake.observe(released_at + Duration::from_millis(100), None, false, &[]),
            PipeHandshakeState::Failed(ProfileStartupIndeterminate::new(
                ProfileStartupCause::DeadlineExpired
            ))
        );
    }

    #[test]
    fn empty_frame_is_not_readiness() {
        assert_pending_then_ready(&[0]);
    }

    #[test]
    fn invalid_utf8_frame_is_not_readiness() {
        assert_pending_then_ready(&[0xff, 0]);
    }

    #[test]
    fn non_object_frame_is_not_readiness() {
        assert_pending_then_ready(b"[]\0");
    }

    #[test]
    fn event_is_not_readiness() {
        assert_pending_then_ready(b"{\"method\":\"Browser.downloadWillBegin\"}\0");
    }

    #[test]
    fn uncorrelated_id_does_not_establish_or_poison_readiness() {
        let (handshake, _) = new_handshake();
        let other = valid_response(handshake.request_id() + 1);
        assert_pending_then_ready(&other);
    }

    #[test]
    fn cdp_error_response_does_not_establish_readiness() {
        let (mut handshake, released_at) = new_handshake();
        let error = serde_json::to_vec(&json!({
            "id": handshake.request_id(),
            "error": {"code": -32601, "message": "not found"}
        }))
        .expect("serialize error");
        let mut frame = error;
        frame.push(0);
        assert_eq!(
            handshake.observe(released_at + Duration::from_millis(1), None, false, &frame),
            PipeHandshakeState::Pending
        );
        assert_eq!(
            handshake.observe(released_at + Duration::from_millis(100), None, false, &[]),
            PipeHandshakeState::Failed(ProfileStartupIndeterminate::new(
                ProfileStartupCause::DeadlineExpired
            ))
        );
    }

    #[test]
    fn version_fields_must_both_be_strings() {
        for result in [
            json!({"product": "Chrome/151.0.0.0"}),
            json!({"protocolVersion": "1.3"}),
            json!({"product": 151, "protocolVersion": "1.3"}),
            json!({"product": "Chrome/151.0.0.0", "protocolVersion": 1.3}),
        ] {
            let (mut handshake, released_at) = new_handshake();
            let mut frame = serde_json::to_vec(&json!({
                "id": handshake.request_id(),
                "result": result
            }))
            .expect("serialize malformed version");
            frame.push(0);
            assert_eq!(
                handshake.observe(released_at + Duration::from_millis(1), None, false, &frame,),
                PipeHandshakeState::Pending
            );
        }
    }

    #[test]
    fn racing_failures_use_fixed_precedence_and_never_replace_the_cause() {
        let (mut handshake, released_at) = new_handshake();
        assert_eq!(
            handshake.observe(
                released_at + Duration::from_millis(100),
                Some(ChildExitStatus::Code(21)),
                true,
                &[],
            ),
            PipeHandshakeState::Failed(ProfileStartupIndeterminate::new(
                ProfileStartupCause::ChildExit
            ))
        );
        assert_eq!(
            handshake.observe(released_at + Duration::from_millis(101), None, true, &[],),
            PipeHandshakeState::Failed(ProfileStartupIndeterminate::new(
                ProfileStartupCause::ChildExit
            ))
        );

        let (mut handshake, released_at) = new_handshake();
        assert_eq!(
            handshake.observe(released_at + Duration::from_millis(100), None, true, &[],),
            PipeHandshakeState::Failed(ProfileStartupIndeterminate::new(
                ProfileStartupCause::PipeClosed
            ))
        );
    }

    #[derive(Clone)]
    struct EventLog(Arc<Mutex<Vec<&'static str>>>);

    impl EventLog {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }

        fn push(&self, event: &'static str) {
            self.0.lock().expect("event log").push(event);
        }

        fn snapshot(&self) -> Vec<&'static str> {
            self.0.lock().expect("event log").clone()
        }
    }

    struct FakeProcess {
        exit: Option<ChildExitStatus>,
        events: EventLog,
    }

    impl HandshakeProcess for FakeProcess {
        fn observe_exit(&mut self) -> Option<ChildExitStatus> {
            self.events.push("exit_observed");
            self.exit
        }

        fn wait_and_reap(self) -> Result<(), PlatformLaunchError> {
            self.events.push("waited_and_reaped");
            Ok(())
        }

        fn terminate_and_reap(self) -> Result<(), PlatformLaunchError> {
            self.events.push("terminated_and_reaped");
            Ok(())
        }
    }

    enum ReadAction {
        Bytes(Vec<u8>),
        WouldBlock,
        Closed,
    }

    struct FakePipe {
        actions: VecDeque<ReadAction>,
        repeat: Option<Vec<u8>>,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        events: EventLog,
    }

    impl FakePipe {
        fn new(actions: impl IntoIterator<Item = ReadAction>, events: EventLog) -> Self {
            Self {
                actions: actions.into_iter().collect(),
                repeat: None,
                writes: Arc::new(Mutex::new(Vec::new())),
                events,
            }
        }

        fn malformed_forever(events: EventLog) -> Self {
            Self {
                actions: VecDeque::new(),
                repeat: Some(vec![0xff, 0]),
                writes: Arc::new(Mutex::new(Vec::new())),
                events,
            }
        }
    }

    impl CdpPipeIo for FakePipe {
        fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.events.push("request_written");
            self.writes.lock().expect("writes").push(bytes.to_vec());
            Ok(())
        }

        fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
            let action = self
                .actions
                .pop_front()
                .or_else(|| self.repeat.clone().map(ReadAction::Bytes))
                .unwrap_or(ReadAction::WouldBlock);
            match action {
                ReadAction::Bytes(bytes) => {
                    destination[..bytes.len()].copy_from_slice(&bytes);
                    Ok(PipeRead::Bytes(bytes.len()))
                }
                ReadAction::WouldBlock => Ok(PipeRead::WouldBlock),
                ReadAction::Closed => Ok(PipeRead::Closed),
            }
        }
    }

    struct FakeClock {
        now: Instant,
    }

    impl HandshakeClock for FakeClock {
        fn now(&mut self) -> Instant {
            self.now
        }

        fn sleep(&mut self, duration: Duration) {
            self.now += duration;
        }
    }

    struct RecordingRollback {
        events: EventLog,
    }

    impl FailedLaunchRollback for RecordingRollback {
        fn rollback(
            &mut self,
            _failure: &ProfileStartupIndeterminate,
        ) -> Result<(), PlatformLaunchError> {
            self.events.push("rollback_completed");
            Ok(())
        }

        fn rollback_attested(
            &mut self,
            _failure: &AttestedLaunchError,
        ) -> Result<(), PlatformLaunchError> {
            self.events.push("rollback_completed");
            Ok(())
        }
    }

    fn executable_identity() -> ExecutableIdentityClaim {
        ExecutableIdentityClaim::CodeSigned {
            signing_identifier: "com.example.browser".to_string(),
            unique_code_hash: "abc123".to_string(),
        }
    }

    /// The file read before spawn, whose one slice is the image that ran.
    fn verified_executable_identity() -> VerifiedExecutableIdentity {
        VerifiedExecutableIdentity::CodeSignedFile {
            signing_identifier: "com.example.browser".to_string(),
            slice_code_hashes: std::collections::BTreeSet::from(["abc123".to_string()]),
        }
    }

    fn launch_request() -> AttestedLaunchRequest {
        AttestedLaunchRequest {
            launch_attempt_id: "attempt-1".to_string(),
            holder_id: "holder-1".to_string(),
            route: LaunchRouteIdentity {
                principal: "direct:agent".to_string(),
                conversation_key: "conversation-1".to_string(),
                agent_project_id: "project-1".to_string(),
                session_kind: cerebellum_core::identity::SessionKind::Primary,
            },
            profile: LaunchProfileIdentity {
                profile_uuid: "profile-1".to_string(),
                canonical_profile_path: b"/tmp/profile-1".to_vec(),
                disposition: crate::browser_launch::LaunchProfile::Registry(
                    cerebellum_core::identity::ProfileDisposition::Durable,
                ),
            },
            executable: PathBuf::from("/Applications/Browser.app/Contents/MacOS/Browser"),
            arguments: vec![OsString::from("--remote-debugging-pipe")],
            environment: vec![],
            verified_executable_identity: verified_executable_identity(),
            pre_spawn_identity_verification: PreSpawnIdentityVerification::Established,
        }
    }

    fn attestation() -> LaunchAttestationRecord {
        let request = launch_request();
        LaunchAttestationRecord {
            generation: LaunchGenerationRecord {
                intent: AuthorizedLaunchIntent {
                    format_version: "ck-browser-launch-attestation/v2".to_string(),
                    launch_attempt_id: request.launch_attempt_id,
                    holder_id: request.holder_id,
                    route: request.route,
                    profile: request.profile,
                    verified_executable_identity: request.verified_executable_identity.clone(),
                    launch_vector: crate::browser_launch::VerifiedLaunchVector::new(
                        &request.executable,
                        &request.arguments,
                        &request.environment,
                    ),
                },
                process_generation: BrowserProcessGeneration {
                    pid: 42,
                    start_time_micros: 77,
                    boot_id: None,
                },
            },
            observed_executable_identity: executable_identity(),
            executable_identity_chain:
                crate::browser_launch::ExecutableIdentityChain::NoWalkPerformed {
                    attestation: crate::browser_launch::ExecutableIdentityRecord {
                        claim: executable_identity(),
                        path: Some(request.executable),
                    },
                },
            executable_identity_checkpoints: ExecutableIdentityCheckpoints::BeforeSpawnAndAfterExec,
        }
    }

    fn released(
        clock: &FakeClock,
        exit: Option<ChildExitStatus>,
        events: EventLog,
    ) -> ReleasedAttestedBrowser<FakeProcess> {
        let attestation = attestation();
        let observed_executable_identity_chain = attestation.executable_identity_chain.clone();
        ReleasedAttestedBrowser {
            attestation,
            observed_executable_identity_chain,
            process: FakeProcess { exit, events },
            released_at: clock.now,
        }
    }

    fn exact_failure(error: LaunchReadinessError) -> ProfileStartupIndeterminate {
        match error {
            LaunchReadinessError::ProfileStartupIndeterminate(failure) => failure,
            other => panic!("expected exact startup failure, got {other:?}"),
        }
    }

    #[test]
    fn zero_exit_status_is_child_exit_never_readiness() {
        let events = EventLog::new();
        let mut clock = FakeClock { now: instant() };
        let response = valid_response(1);
        let pipe = FakePipe::new([ReadAction::Bytes(response)], events.clone());
        let mut rollback = RecordingRollback {
            events: events.clone(),
        };

        let error = complete_pipe_handshake(
            released(&clock, Some(ChildExitStatus::Code(0)), events.clone()),
            pipe,
            deadline_ms(10),
            &mut clock,
            &mut rollback,
        )
        .err()
        .expect("zero exit must fail");

        assert_eq!(
            exact_failure(error),
            ProfileStartupIndeterminate::new(ProfileStartupCause::ChildExit)
        );
        assert_eq!(
            events.snapshot(),
            vec![
                "request_written",
                "exit_observed",
                "waited_and_reaped",
                "rollback_completed"
            ]
        );
    }

    #[test]
    fn pipe_close_returns_exact_typed_cause_after_reap_and_rollback() {
        let events = EventLog::new();
        let mut clock = FakeClock { now: instant() };
        let pipe = FakePipe::new([ReadAction::Closed], events.clone());
        let mut rollback = RecordingRollback {
            events: events.clone(),
        };

        let error = complete_pipe_handshake(
            released(&clock, None, events.clone()),
            pipe,
            deadline_ms(10),
            &mut clock,
            &mut rollback,
        )
        .err()
        .expect("pipe close must fail");

        let failure = exact_failure(error);
        assert_eq!(failure.cause, ProfileStartupCause::PipeClosed);
        assert_eq!(
            serde_json::to_value(&failure).expect("serialize failure"),
            json!({
                "outcome": "profile_startup_indeterminate",
                "cause": "pipe_closed",
                "ambiguity": "indeterminate_startup_failure",
                "possible_reasons": [
                    "external_profile_holder",
                    "profile_unopenable_or_corrupt",
                    "browser_startup_failure",
                    "invalid_browser_invocation",
                    "platform_or_sandbox_denial"
                ]
            })
        );
        assert_eq!(
            events.snapshot(),
            vec![
                "request_written",
                "exit_observed",
                "terminated_and_reaped",
                "rollback_completed"
            ]
        );
    }

    #[test]
    fn deadline_expiry_returns_exact_typed_cause() {
        let events = EventLog::new();
        let mut clock = FakeClock { now: instant() };
        let pipe = FakePipe::new([ReadAction::WouldBlock], events.clone());
        let mut rollback = RecordingRollback {
            events: events.clone(),
        };

        let error = complete_pipe_handshake(
            released(&clock, None, events.clone()),
            pipe,
            deadline_ms(3),
            &mut clock,
            &mut rollback,
        )
        .err()
        .expect("deadline must fail");

        assert_eq!(
            exact_failure(error).cause,
            ProfileStartupCause::DeadlineExpired
        );
    }

    #[test]
    fn malformed_frames_forever_still_end_at_the_deadline() {
        let events = EventLog::new();
        let mut clock = FakeClock { now: instant() };
        let pipe = FakePipe::malformed_forever(events.clone());
        let mut rollback = RecordingRollback {
            events: events.clone(),
        };

        let error = complete_pipe_handshake(
            released(&clock, None, events),
            pipe,
            deadline_ms(3),
            &mut clock,
            &mut rollback,
        )
        .err()
        .expect("malformed peer must time out");

        assert_eq!(
            exact_failure(error).cause,
            ProfileStartupCause::DeadlineExpired
        );
    }

    struct SuccessfulLauncher;

    impl BarredProcessLauncher for SuccessfulLauncher {
        type Process = FakeBarredProcess;
        fn spawn_barred(
            &mut self,
            _: &AttestedLaunchRequest,
        ) -> Result<Self::Process, PlatformLaunchError> {
            Ok(FakeBarredProcess)
        }
    }

    pub(crate) fn fail_after_attestation<J: LaunchJournalPort>(
        journal: &mut J,
    ) -> AttestedReadinessError {
        let events = EventLog::new();
        run_failed_launch(journal, events)
    }

    fn run_failed_launch<J: LaunchJournalPort>(
        journal: &mut J,
        events: EventLog,
    ) -> AttestedReadinessError {
        launch_attested_to_readiness_with(
            journal,
            &mut SuccessfulLauncher,
            &launch_request(),
            FakePipe::new([ReadAction::WouldBlock], events.clone()),
            deadline_ms(3),
            &mut FakeClock { now: instant() },
            &mut RecordingRollback { events },
        )
        .err()
        .expect("handshake must fail")
    }

    struct FinalizationJournal {
        events: EventLog,
        refuse: bool,
    }

    impl LaunchJournalPort for FinalizationJournal {
        type Handle = ();
        fn record_intent(&mut self, _: &AuthorizedLaunchIntent) -> Result<(), CoreJournalError> {
            Ok(())
        }
        fn record_generation(
            &mut self,
            _: &mut (),
            _: &LaunchGenerationRecord,
        ) -> Result<(), CoreJournalError> {
            Ok(())
        }
        fn commit_attestation(
            &mut self,
            _: &mut (),
            _: &LaunchAttestationRecord,
        ) -> Result<(), CoreJournalError> {
            Ok(())
        }
        fn record_identity_mismatch(
            &mut self,
            _: &mut (),
            _: &LaunchIdentityMismatchRecord,
        ) -> Result<(), CoreJournalError> {
            panic!("identity matches")
        }
        fn finalize_startup_failure(
            &mut self,
            id: &str,
            failure: &ProfileStartupIndeterminate,
        ) -> Result<(), CoreJournalError> {
            assert_eq!(id, launch_request().launch_attempt_id);
            assert_eq!(failure.cause, ProfileStartupCause::DeadlineExpired);
            self.events.push("journal_closed");
            if self.refuse {
                Err(CoreJournalError::StorageUnavailable)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn rollback_runs_before_the_journal_is_closed() {
        let events = EventLog::new();
        let mut journal = FinalizationJournal {
            events: events.clone(),
            refuse: false,
        };
        run_failed_launch(&mut journal, events.clone());
        let log = events.snapshot();
        let rollback = log
            .iter()
            .position(|event| *event == "rollback_completed")
            .expect("rollback");
        let closed = log
            .iter()
            .position(|event| *event == "journal_closed")
            .expect("finalization");
        assert!(rollback < closed, "{log:?}");
    }

    #[test]
    fn a_journal_finalization_failure_is_a_cleanup_failure_not_silence() {
        let mut journal = FinalizationJournal {
            events: EventLog::new(),
            refuse: true,
        };
        assert_eq!(
            fail_after_attestation(&mut journal),
            AttestedReadinessError::Readiness(LaunchReadinessError::CleanupFailed {
                primary: Some(ProfileStartupIndeterminate::new(
                    ProfileStartupCause::DeadlineExpired
                )),
                stage: ReadinessCleanupStage::JournalFinalization,
            })
        );
    }

    struct FailingIntentJournal;

    impl LaunchJournalPort for FailingIntentJournal {
        fn finalize_startup_failure(
            &mut self,
            _: &str,
            _: &ProfileStartupIndeterminate,
        ) -> Result<(), CoreJournalError> {
            panic!("finalization cannot follow failed intent")
        }

        type Handle = ();

        fn record_intent(
            &mut self,
            _intent: &AuthorizedLaunchIntent,
        ) -> Result<Self::Handle, CoreJournalError> {
            Err(CoreJournalError::StorageUnavailable)
        }

        fn record_generation(
            &mut self,
            _handle: &mut Self::Handle,
            _record: &LaunchGenerationRecord,
        ) -> Result<(), CoreJournalError> {
            panic!("generation cannot be recorded after failed intent")
        }

        fn commit_attestation(
            &mut self,
            _handle: &mut Self::Handle,
            _record: &LaunchAttestationRecord,
        ) -> Result<(), CoreJournalError> {
            panic!("attestation cannot follow failed intent")
        }

        fn record_identity_mismatch(
            &mut self,
            _handle: &mut Self::Handle,
            _record: &LaunchIdentityMismatchRecord,
        ) -> Result<(), CoreJournalError> {
            panic!("mismatch cannot follow failed intent")
        }
    }

    struct NeverLauncher;

    impl BarredProcessLauncher for NeverLauncher {
        type Process = FakeBarredProcess;

        fn spawn_barred(
            &mut self,
            _request: &AttestedLaunchRequest,
        ) -> Result<Self::Process, PlatformLaunchError> {
            panic!("spawn cannot follow failed durable intent")
        }
    }

    struct FakeBarredProcess;

    impl crate::browser_launch::BarredLaunchProcess for FakeBarredProcess {
        type Released = FakeProcess;

        fn generation(&self) -> BrowserProcessGeneration {
            BrowserProcessGeneration {
                pid: 42,
                start_time_micros: 77,
                boot_id: None,
            }
        }

        fn executed_image_identity(&self) -> Result<ExecutableIdentityChain, PlatformLaunchError> {
            Ok(ExecutableIdentityChain::WalkedToMatch {
                hops: vec![ExecutableIdentityRecord {
                    claim: executable_identity(),
                    path: None,
                }],
            })
        }

        fn terminate_and_reap(self) -> Result<(), PlatformLaunchError> {
            Ok(())
        }

        fn release(self) -> Result<Self::Released, PlatformLaunchError> {
            Ok(FakeProcess {
                exit: None,
                events: EventLog::new(),
            })
        }
    }

    #[test]
    fn failed_durable_intent_prevents_spawn_release_and_pipe_write() {
        let events = EventLog::new();
        let pipe = FakePipe::new([], events.clone());
        let writes = pipe.writes.clone();
        let mut clock = FakeClock { now: instant() };
        let mut rollback = RecordingRollback {
            events: events.clone(),
        };

        let outcome = launch_attested_to_readiness_with(
            &mut FailingIntentJournal,
            &mut NeverLauncher,
            &launch_request(),
            pipe,
            deadline_ms(10),
            &mut clock,
            &mut rollback,
        );

        assert!(matches!(
            outcome,
            Err(AttestedReadinessError::AttestedLaunch(
                AttestedLaunchError::JournalRecordFailed {
                    stage: crate::browser_launch::LaunchRecordStage::Intent
                }
            ))
        ));
        assert!(writes.lock().expect("writes").is_empty());
        assert_eq!(events.snapshot(), vec!["rollback_completed"]);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod live_chrome_test {
    use std::ffi::OsString;
    use std::fs;
    use std::num::NonZeroU64;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use cerebellum_core::journal::JournalError as CoreJournalError;

    use super::*;
    use crate::browser_launch::{
        AttestedLaunchRequest, AuthorizedLaunchIntent, LaunchGenerationRecord,
        LaunchIdentityMismatchRecord, LaunchProfileIdentity, LaunchRouteIdentity,
        MacOsProcessLauncher, PreSpawnIdentityVerification, VerifiedExecutableIdentity,
    };

    struct PassingJournal;

    impl LaunchJournalPort for PassingJournal {
        fn finalize_startup_failure(
            &mut self,
            _: &str,
            _: &ProfileStartupIndeterminate,
        ) -> Result<(), CoreJournalError> {
            panic!("successful live handshake must not finalize startup failure")
        }

        type Handle = ();

        fn record_intent(
            &mut self,
            _intent: &AuthorizedLaunchIntent,
        ) -> Result<Self::Handle, CoreJournalError> {
            Ok(())
        }

        fn record_generation(
            &mut self,
            _handle: &mut Self::Handle,
            _record: &LaunchGenerationRecord,
        ) -> Result<(), CoreJournalError> {
            Ok(())
        }

        fn commit_attestation(
            &mut self,
            _handle: &mut Self::Handle,
            _record: &LaunchAttestationRecord,
        ) -> Result<(), CoreJournalError> {
            Ok(())
        }

        fn record_identity_mismatch(
            &mut self,
            _handle: &mut Self::Handle,
            _record: &LaunchIdentityMismatchRecord,
        ) -> Result<(), CoreJournalError> {
            Ok(())
        }
    }

    fn request(
        executable: PathBuf,
        arguments: Vec<OsString>,
        identity: VerifiedExecutableIdentity,
        profile: &Path,
    ) -> AttestedLaunchRequest {
        AttestedLaunchRequest {
            launch_attempt_id: "real-chrome-handshake".to_string(),
            holder_id: "real-chrome-test-holder".to_string(),
            route: LaunchRouteIdentity {
                principal: "direct:test".to_string(),
                conversation_key: "real-chrome-test".to_string(),
                agent_project_id: "real-chrome-test".to_string(),
                session_kind: cerebellum_core::identity::SessionKind::Primary,
            },
            profile: LaunchProfileIdentity {
                profile_uuid: "real-chrome-test".to_string(),
                canonical_profile_path: profile.as_os_str().as_bytes().to_vec(),
                disposition: crate::browser_launch::LaunchProfile::Registry(
                    cerebellum_core::identity::ProfileDisposition::Durable,
                ),
            },
            executable,
            arguments,
            environment: Vec::new(),
            verified_executable_identity: identity,
            pre_spawn_identity_verification: PreSpawnIdentityVerification::Established,
        }
    }

    #[test]
    #[ignore = "opens the installed Chrome binary and is run explicitly"]
    fn real_chrome_pipe_returns_a_correlated_version() {
        static SEQUENCE: AtomicU64 = AtomicU64::new(1);
        let chrome = PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        if !chrome.is_file() {
            eprintln!("real Chrome test skipped: {} is absent", chrome.display());
            return;
        }

        let profile = std::env::temp_dir().join(format!(
            "cerebellum-real-chrome-handshake-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&profile).expect("create real Chrome profile");
        let arguments = vec![
            OsString::from("--remote-debugging-pipe"),
            OsString::from("--no-first-run"),
            OsString::from("--no-default-browser-check"),
            OsString::from(format!("--user-data-dir={}", profile.display())),
        ];

        let (probe_command_child, _probe_command_parent) =
            UnixStream::pair().expect("probe command pipe");
        let (_probe_response_parent, probe_response_child) =
            UnixStream::pair().expect("probe response pipe");
        let probe = cerebellum_macos::spawn_barred(
            &chrome,
            &arguments,
            &[],
            probe_command_child.as_raw_fd(),
            probe_response_child.as_raw_fd(),
        )
        .expect("spawn barred identity probe");
        let observed = cerebellum_macos::executed_image_identity(probe.generation().pid)
            .expect("attest real Chrome image");
        probe.terminate_and_reap().expect("reap identity probe");

        let (command_child, command_parent) = UnixStream::pair().expect("command pipe");
        let (response_parent, response_child) = UnixStream::pair().expect("response pipe");
        let mut launcher =
            MacOsProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let request = request(
            chrome,
            arguments,
            VerifiedExecutableIdentity::CodeSignedFile {
                signing_identifier: observed.signing_identifier,
                slice_code_hashes: std::collections::BTreeSet::from([observed.unique_code_hash]),
            },
            &profile,
        );
        let released = crate::browser_launch::launch_attested_with(
            &mut PassingJournal,
            &mut launcher,
            &request,
        )
        .expect("release attested real Chrome");
        drop(command_child);
        drop(response_child);

        let pipe = UnixCdpPipe::new(command_parent, response_parent).expect("configure pipe");
        let mut clock = SystemHandshakeClock;
        let mut rollback = NoopFailedLaunchRollback;
        let ready = complete_pipe_handshake(
            released,
            pipe,
            NonZeroU64::new(5_000).expect("deadline"),
            &mut clock,
            &mut rollback,
        )
        .unwrap_or_else(|error| panic!("real Chrome handshake failed: {error:?}"));

        assert!(!ready.browser_version.product.is_empty());
        assert!(!ready.browser_version.protocol_version.is_empty());
        eprintln!(
            "real Chrome handshake ready: product={}, protocolVersion={}",
            ready.browser_version.product, ready.browser_version.protocol_version
        );
        ready
            .process
            .terminate_and_reap()
            .expect("reap real Chrome");
        fs::remove_dir_all(&profile).expect("remove real Chrome profile");
    }
}
