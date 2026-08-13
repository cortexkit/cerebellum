//! Production browser launch composition from accepted route facts.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::num::NonZeroU64;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::browser_config::BrowserConfig;
use cerebellum_core::identity::{AcceptedBindFacts, ProfileDisposition};
use serde_json::{json, Value};

use crate::browser_launch::{
    AttestedLaunchError, AttestedLaunchRequest, BrowserLaunchOutcome, DurableLaunchJournal,
    ExecutableIdentity, LaunchProfileIdentity, LaunchRouteIdentity, MacOsProcessLauncher,
    ProfileBoundLaunch,
};
use crate::browser_launch_readiness::{
    launch_attested_to_readiness_with, AttestedReadinessError, HandshakeClock, UnixCdpPipe,
};
use crate::browser_session::{
    BrowserSessionLauncher, CleanupStage, LaunchedBrowser, OwnedBrowserProcess,
    ProcessControlFailure, SessionCleanup,
};
use crate::profile::{
    BindFacts, DispatchCommitmentToken, InvocationToken, JournalReservationHandle,
    ProfileLifecycle, RegistryConfig, StampedBindContext,
};
use crate::profile_custody::{
    FilesystemProfileCustodyJournal, KernelSupervisorLiveness, ProfileCustodyKey,
    ProfileCustodyLocks,
};

pub struct ProductionLaunchService {
    config: BrowserConfig,
}

impl ProductionLaunchService {
    pub fn open(config: BrowserConfig) -> Self {
        Self { config }
    }

    pub fn launch(
        &self,
        accepted: &AcceptedBindFacts,
        browser_session_id: &str,
    ) -> Result<ReadyProductionBrowser, Value> {
        let Some(executable) = self.config.executable_path.as_ref() else {
            return Err(json!({"outcome": "executable_missing"}));
        };
        if !executable.is_file() {
            return Err(json!({
                "outcome": "executable_missing",
                "expected_path": executable,
            }));
        }
        let expected = self
            .config
            .expected_identity
            .as_deref()
            .ok_or_else(|| json!({"outcome": "internal_failure"}))?;
        let expected_identity = verify_configured_executable(executable, expected)?;
        let context =
            stamped_context(accepted).map_err(|_| json!({"outcome": "authorization_denied"}))?;
        if context.profile_disposition() == crate::profile::ProfileDisposition::None {
            return Err(json!({"outcome": "no_profile", "profile_disposition": "none"}));
        }

        record_profile_admission(accepted, browser_session_id, executable, &expected_identity)?;
        let root =
            browser_data_root().map_err(|_| json!({"outcome": "profile_storage_unavailable"}))?;
        let registry = RegistryConfig {
            uuid_protocol_compatible: true,
            grant_verifier_available: true,
            grant_accepted: true,
            sealing_available: true,
            ..RegistryConfig::default()
        };
        let lifecycle = Arc::new(Mutex::new(
            ProfileLifecycle::open_with_config(&root, registry)
                .map_err(|_| json!({"outcome": "profile_storage_unavailable"}))?,
        ));
        let locks = Arc::new(Mutex::new(
            ProfileCustodyLocks::open_filesystem(&root)
                .map_err(|_| json!({"outcome": "profile_storage_unavailable"}))?,
        ));
        let invocation =
            InvocationToken::from_trusted_invocation(format!("invocation-{browser_session_id}"));
        let reservation = JournalReservationHandle::from_recorded_reservation(
            &invocation,
            format!("reservation-{browser_session_id}"),
        );
        let commitment = DispatchCommitmentToken::from_durable_commitment(
            &invocation,
            &reservation,
            format!("commitment-{browser_session_id}"),
        );
        let key = match accepted.identity.profile_disposition {
            ProfileDisposition::Durable => {
                ProfileCustodyKey::durable(&accepted.identity.agent_project_id)
            }
            ProfileDisposition::Disposable => ProfileCustodyKey::disposable_route(
                &accepted.identity.agent_project_id,
                &accepted.identity.conversation_key,
                browser_session_id,
            ),
            // Refused rather than asserted impossible. It is unreachable only
            // because the check above reads a disposition that this same field
            // produced, so the two agree by construction — an invariant held in
            // another module's validator rather than here. A panic on a wire
            // path takes the module loop down and every unrelated capability
            // with it, which is a heavy price for a condition whose honest
            // answer already exists one branch up.
            ProfileDisposition::None => {
                return Err(json!({"outcome": "no_profile", "profile_disposition": "none"}))
            }
        };

        let mut lifecycle_guard = lifecycle
            .lock()
            .map_err(|_| json!({"outcome": "internal_failure"}))?;
        let mut locks_guard = locks
            .lock()
            .map_err(|_| json!({"outcome": "internal_failure"}))?;
        let mut bound = ProfileBoundLaunch::new(&mut lifecycle_guard, &mut locks_guard);
        let prepared = bound
            .acquire_and_prepare(key, &invocation, &reservation, &context)
            .map_err(|outcome| outcome.as_json())?;
        let opened = bound
            .launch_prepared(prepared, &commitment)
            .map_err(|outcome| outcome.as_json())?;
        let profile_directory = opened.profile_directory().to_path_buf();
        let holder_id = opened.holder_id().as_str().to_string();
        let Some(profile_uuid) = lifecycle_guard
            .current_open(&accepted.identity.conversation_key)
            .profile_uuid
        else {
            let _ = ProfileBoundLaunch::new(&mut lifecycle_guard, &mut locks_guard)
                .rollback_opened(opened);
            return Err(json!({"outcome": "internal_failure"}));
        };

        let arguments = vec![
            OsString::from("--remote-debugging-pipe"),
            OsString::from(format!(
                "--user-data-dir={}",
                profile_directory.to_string_lossy()
            )),
            OsString::from("--no-first-run"),
            OsString::from("--no-default-browser-check"),
        ];
        if !crate::custody::arguments_are_quarantinable(
            &arguments
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
        ) {
            let _ = ProfileBoundLaunch::new(&mut lifecycle_guard, &mut locks_guard)
                .rollback_opened(opened);
            return Err(json!({"outcome": "internal_failure"}));
        }

        let rollback = SharedRollback::new(
            Arc::clone(&lifecycle),
            Arc::clone(&locks),
            Box::new(move |lifecycle, locks| {
                ProfileBoundLaunch::new(lifecycle, locks).rollback_opened(opened)
            }),
        );
        drop(locks_guard);
        drop(lifecycle_guard);

        let route = LaunchRouteIdentity {
            principal: accepted
                .principal
                .as_ref()
                .map(|principal| format!("{principal:?}"))
                .unwrap_or_default(),
            conversation_key: accepted.identity.conversation_key.clone(),
            agent_project_id: accepted.identity.agent_project_id.clone(),
            session_kind: accepted.identity.session_kind,
        };
        let request = AttestedLaunchRequest {
            launch_attempt_id: browser_session_id.to_string(),
            holder_id,
            route,
            profile: LaunchProfileIdentity {
                profile_uuid,
                canonical_profile_path: path_bytes(&profile_directory),
                disposition: accepted.identity.profile_disposition,
            },
            executable: executable.clone(),
            arguments,
            environment: Vec::new(),
            verified_executable_identity: expected_identity,
        };
        let (command_parent, command_child) = match pipe_pair() {
            Ok(pair) => pair,
            Err(outcome) => return Err(cleanup_before_spawn(rollback.clone(), outcome)),
        };
        let (response_parent, response_child) = match pipe_pair() {
            Ok(pair) => pair,
            Err(outcome) => return Err(cleanup_before_spawn(rollback.clone(), outcome)),
        };
        let mut launcher =
            MacOsProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let pipe = match UnixCdpPipe::new(command_parent, response_parent) {
            Ok(pipe) => pipe,
            Err(_) => {
                return Err(cleanup_before_spawn(
                    rollback.clone(),
                    json!({"outcome": "internal_failure"}),
                ))
            }
        };
        let mut journal =
            match DurableLaunchJournal::open_filesystem(cerebellum_core::journal::JournalConfig {
                journal_retention_bytes: 16 * 1024 * 1024,
                journal_max_entry_bytes: 1024 * 1024,
            }) {
                Ok(journal) => journal,
                Err(_) => {
                    return Err(cleanup_before_spawn(
                        rollback.clone(),
                        json!({"outcome": "internal_failure"}),
                    ))
                }
            };
        let mut clock = SystemLaunchClock;
        let mut readiness_rollback = rollback.clone();
        let ready = launch_attested_to_readiness_with(
            &mut journal,
            &mut launcher,
            &request,
            pipe,
            NonZeroU64::new(self.config.launch_handshake_deadline_ms)
                .expect("validated browser duration is positive"),
            &mut clock,
            &mut readiness_rollback,
        )
        .map_err(map_readiness_error)?;

        Ok(ReadyProductionBrowser {
            process: Some(ready.process),
            pipe: Some(ready.pipe),
            cleanup: Some(rollback),
        })
    }
}

impl BrowserSessionLauncher for ProductionLaunchService {
    fn launch(
        &self,
        accepted: &AcceptedBindFacts,
        browser_session_id: &str,
    ) -> Result<LaunchedBrowser, Value> {
        ProductionLaunchService::launch(self, accepted, browser_session_id)
            .map(ReadyProductionBrowser::into_parts)
    }
}

pub struct ReadyProductionBrowser {
    process: Option<cerebellum_macos::ReleasedChild>,
    pipe: Option<UnixCdpPipe>,
    cleanup: Option<SharedRollback>,
}

impl ReadyProductionBrowser {
    pub fn into_parts(self) -> LaunchedBrowser {
        (
            Box::new(ProductionProcess {
                process: self.process,
                pipe: self.pipe,
                reaped: false,
            }),
            Box::new(self.cleanup.expect("ready browser owns profile cleanup")),
        )
    }
}

struct ProductionProcess {
    process: Option<cerebellum_macos::ReleasedChild>,
    pipe: Option<UnixCdpPipe>,
    reaped: bool,
}

impl OwnedBrowserProcess for ProductionProcess {
    fn generation_matches(&self) -> bool {
        self.process.as_ref().is_some_and(|process| {
            let generation = process.generation();
            cerebellum_macos::process_start_time_micros(generation.pid)
                == Some(generation.start_time_micros)
        })
    }

    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        use crate::browser_launch_readiness::CdpPipeIo;
        self.pipe
            .as_mut()
            .ok_or(ProcessControlFailure)?
            .write_frame(b"{\"id\":18446744073709551614,\"method\":\"Browser.close\"}\0")
            .map_err(|_| ProcessControlFailure)
    }

    fn wait_for_exit(&mut self, grace_period: Duration) -> Result<bool, ProcessControlFailure> {
        let Some(process) = self.process.as_ref() else {
            return Ok(true);
        };
        let generation = process.generation();
        let deadline = Instant::now() + grace_period;
        while Instant::now() < deadline {
            if cerebellum_macos::process_start_time_micros(generation.pid)
                != Some(generation.start_time_micros)
            {
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(false)
    }

    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        let process = self.process.take().ok_or(ProcessControlFailure)?;
        process
            .terminate_and_reap()
            .map_err(|_| ProcessControlFailure)?;
        self.reaped = true;
        Ok(())
    }

    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        if self.reaped {
            return Ok(());
        }
        let process = self.process.take().ok_or(ProcessControlFailure)?;
        process.wait().map_err(|_| ProcessControlFailure)?;
        self.reaped = true;
        Ok(())
    }
}

#[derive(Clone)]
struct SharedRollback {
    state: Arc<Mutex<Option<SharedRollbackState>>>,
}

struct SharedRollbackState {
    lifecycle: Arc<Mutex<ProfileLifecycle>>,
    locks:
        Arc<Mutex<ProfileCustodyLocks<FilesystemProfileCustodyJournal, KernelSupervisorLiveness>>>,
    rollback: Option<ErasedRollback>,
}

type ErasedRollback = Box<
    dyn FnOnce(
            &mut ProfileLifecycle,
            &mut ProfileCustodyLocks<FilesystemProfileCustodyJournal, KernelSupervisorLiveness>,
        ) -> Result<(), BrowserLaunchOutcome>
        + Send,
>;

impl SharedRollback {
    fn new(
        lifecycle: Arc<Mutex<ProfileLifecycle>>,
        locks: Arc<
            Mutex<ProfileCustodyLocks<FilesystemProfileCustodyJournal, KernelSupervisorLiveness>>,
        >,
        rollback: ErasedRollback,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(Some(SharedRollbackState {
                lifecycle,
                locks,
                rollback: Some(rollback),
            }))),
        }
    }
}

impl crate::browser_launch_readiness::FailedLaunchRollback for SharedRollback {
    fn rollback(
        &mut self,
        _failure: &crate::browser_launch_readiness::ProfileStartupIndeterminate,
    ) -> Result<(), crate::browser_launch::PlatformLaunchError> {
        self.after_reap()
            .map_err(|_| crate::browser_launch::PlatformLaunchError::ProcessControl)
    }
}

impl SessionCleanup for SharedRollback {
    fn after_reap(&mut self) -> Result<(), CleanupStage> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| CleanupStage::CustodyRelease)?;
        let Some(mut state) = guard.take() else {
            return Ok(());
        };
        let mut lifecycle = state
            .lifecycle
            .lock()
            .map_err(|_| CleanupStage::CustodyRelease)?;
        let mut locks = state
            .locks
            .lock()
            .map_err(|_| CleanupStage::CustodyRelease)?;
        let Some(rollback) = state.rollback.take() else {
            return Err(CleanupStage::CustodyRelease);
        };
        rollback(&mut lifecycle, &mut locks).map_err(|outcome| match outcome {
            BrowserLaunchOutcome::CleanupFailure { stage } => match stage {
                crate::browser_launch::LaunchCleanupStage::RecordTerminalization => {
                    CleanupStage::RecordTerminalization
                }
                crate::browser_launch::LaunchCleanupStage::CustodyRelease => {
                    CleanupStage::CustodyRelease
                }
                crate::browser_launch::LaunchCleanupStage::DisposableDelete => {
                    CleanupStage::DisposableDelete
                }
            },
            _ => CleanupStage::CustodyRelease,
        })
    }
}

struct SystemLaunchClock;

impl HandshakeClock for SystemLaunchClock {
    fn now(&mut self) -> Instant {
        Instant::now()
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

fn stamped_context(accepted: &AcceptedBindFacts) -> Result<StampedBindContext, ()> {
    StampedBindContext::validate(BindFacts {
        principal: accepted
            .principal
            .as_ref()
            .map(|principal| format!("{principal:?}"))
            .unwrap_or_default(),
        conversation_key: accepted.identity.conversation_key.clone(),
        agent_project_id: accepted.identity.agent_project_id.clone(),
        session_kind: Some(accepted.identity.session_kind.as_str().to_string()),
        profile_disposition: Some(accepted.identity.profile_disposition.as_str().to_string()),
        effective_capability_scope: accepted
            .effective_capability_scope
            .clone()
            .or(Some(vec!["*".to_string()])),
        provenance: if accepted.agent_project_id_attested {
            "daemon_attested_spec_a".to_string()
        } else {
            "compatibility_fallback".to_string()
        },
    })
    .map_err(|_| ())
}

fn verify_configured_executable(path: &Path, expected: &str) -> Result<ExecutableIdentity, Value> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(path)
        .output()
        .map_err(|_| {
            json!({
                "outcome": "executable_identity_mismatch",
                "expected_identity": expected,
                "observed_identity": "unavailable",
            })
        })?;
    let details = String::from_utf8_lossy(&output.stderr);
    let mut signing_identifier = None;
    let mut unique_code_hash = None;
    for line in details.lines() {
        if let Some(value) = line.strip_prefix("Identifier=") {
            signing_identifier = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("CDHash=") {
            unique_code_hash = Some(value.to_ascii_lowercase());
        }
    }
    let observed = ExecutableIdentity {
        signing_identifier: signing_identifier.unwrap_or_else(|| "unavailable".to_string()),
        unique_code_hash: unique_code_hash.unwrap_or_else(|| "unavailable".to_string()),
    };
    let configured_matches = expected == observed.signing_identifier
        || expected
            == format!(
                "identifier={};cdhash={}",
                observed.signing_identifier, observed.unique_code_hash
            );
    if !output.status.success() || !configured_matches {
        return Err(json!({
            "outcome": "executable_identity_mismatch",
            "expected_identity": expected,
            "observed_identity": observed.display_identity(),
        }));
    }
    Ok(observed)
}

fn record_profile_admission(
    accepted: &AcceptedBindFacts,
    browser_session_id: &str,
    executable: &Path,
    identity: &ExecutableIdentity,
) -> Result<(), Value> {
    let path = cerebellum_core::journal::journal_data_path("browser-launch-admission.jsonl")
        .map_err(|_| json!({"outcome": "profile_storage_unavailable"}))?;
    let directory = path
        .parent()
        .ok_or_else(|| json!({"outcome": "profile_storage_unavailable"}))?;
    std::fs::create_dir_all(directory)
        .map_err(|_| json!({"outcome": "profile_storage_unavailable"}))?;
    let record = json!({
        "browser_session_id": browser_session_id,
        "principal": accepted.principal.as_ref().map(|principal| format!("{principal:?}")),
        "conversation_key": accepted.identity.conversation_key,
        "agent_project_id": accepted.identity.agent_project_id,
        "session_kind": accepted.identity.session_kind,
        "profile_disposition": accepted.identity.profile_disposition,
        "executable_path": path_bytes(executable),
        "verified_executable_identity": identity,
    });
    let mut bytes =
        serde_json::to_vec(&record).map_err(|_| json!({"outcome": "internal_failure"}))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| json!({"outcome": "profile_storage_unavailable"}))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| json!({"outcome": "profile_storage_unavailable"}))
}

fn map_readiness_error(error: AttestedReadinessError) -> Value {
    match error {
        AttestedReadinessError::AttestedLaunch(
            AttestedLaunchError::ExecutableIdentityMismatch {
                expected_identity,
                observed_identity,
            },
        ) => json!({
            "outcome": "executable_identity_mismatch",
            "expected_identity": expected_identity,
            "observed_identity": observed_identity,
        }),
        AttestedReadinessError::Readiness(
            crate::browser_launch_readiness::LaunchReadinessError::ProfileStartupIndeterminate(
                failure,
            ),
        ) => {
            serde_json::to_value(failure).unwrap_or_else(|_| json!({"outcome":"internal_failure"}))
        }
        AttestedReadinessError::Readiness(
            crate::browser_launch_readiness::LaunchReadinessError::CleanupFailed { .. },
        )
        | AttestedReadinessError::CleanupFailed { .. }
        | AttestedReadinessError::AttestedLaunch(AttestedLaunchError::TerminationOrReapFailed) => {
            json!({"outcome":"cleanup_failure","stage":"reap"})
        }
        _ => json!({"outcome": "internal_failure"}),
    }
}

fn browser_data_root() -> Result<PathBuf, ()> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or(())?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("cortexkit")
        .join("browser"))
}

fn cleanup_before_spawn(mut cleanup: SharedRollback, primary: Value) -> Value {
    match cleanup.after_reap() {
        Ok(()) => primary,
        Err(stage) => json!({"outcome": "cleanup_failure", "stage": stage.as_str()}),
    }
}

fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

fn pipe_pair() -> Result<
    (
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    ),
    Value,
> {
    std::os::unix::net::UnixStream::pair().map_err(|_| json!({"outcome":"internal_failure"}))
}
