//! Production browser launch composition from accepted route facts.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::num::NonZeroU64;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::browser::navigation::{
    BrowserScreenshotObservation, BrowserSnapshotObservation, CdpNavigationDriver,
};
use crate::browser::Tracker;
use crate::browser_config::BrowserConfig;
use crate::browser_executable_identity::verify_configured_executable;
use cerebellum_core::identity::{AcceptedBindFacts, ProfileDisposition};
use serde_json::{json, Value};

#[cfg(target_os = "linux")]
use crate::browser_launch::LinuxProcessLauncher;
#[cfg(target_os = "macos")]
use crate::browser_launch::MacOsProcessLauncher;
use crate::browser_launch::{
    recover_browser_launches, AttestedLaunchError, AttestedLaunchRequest, BrowserLaunchOutcome,
    BrowserLaunchRecoveryFailure, BrowserProcessGeneration, DurableLaunchJournal,
    LaunchAttestationRecord, LaunchProfile, LaunchProfileIdentity, LaunchRouteIdentity,
    OrphanBrowserProcessControl, OrphanProcessControlFailure, OrphanProfileCustody,
    OrphanProfileCustodyFailure, ProfileBoundLaunch,
};
use crate::browser_launch_readiness::{
    launch_attested_to_readiness_with, AttestedReadinessError, HandshakeClock, UnixCdpPipe,
};
use crate::browser_session::{
    BrowserClickOutcome, BrowserClickPosition, BrowserInputEvent, BrowserSessionLauncher,
    BrowserSessionTerminalOutcome, CleanupStage, ClickDriveError, ClickPointDriveError,
    LaunchedBrowser, NavigationDriveError, NavigationWait, OwnedBrowserProcess,
    ProcessControlFailure, SessionCleanup, SessionCleanupOutcome,
};
use crate::cdp::{CdpFrameDecoder, CdpTransport};
use crate::profile::{
    BindFacts, DispatchCommitmentToken, InvocationToken, JournalReservationHandle,
    ProfileLifecycle, RegistryConfig, RegistryError, StampedBindContext,
};
#[cfg(target_os = "linux")]
use crate::profile_custody::SupervisorLiveness;
use crate::profile_custody::{
    current_supervisor_generation, FilesystemProfileCustodyJournal, KernelSupervisorLiveness,
    ProfileCustodyAcquisition, ProfileCustodyEvent, ProfileCustodyEventKind, ProfileCustodyJournal,
    ProfileCustodyKey, ProfileCustodyLocks, ProfileCustodyRelease,
};
use crate::snapshot_store::{BackendNodeIdentity, SnapshotKind};

type ProductionLaunchJournal =
    DurableLaunchJournal<cerebellum_core::journal::FilesystemJournalStorage>;

type SharedLaunchJournal = Arc<Mutex<Option<ProductionLaunchJournal>>>;

fn map_poisoned_mutex<T>(
    result: Result<T, std::sync::PoisonError<T>>,
    stage: &'static str,
) -> Result<T, Value> {
    crate::browser_session::refuse_poisoned(result, stage)
}

const BROWSER_LAUNCH_RECOVERY_FAILED: &str = "browser_launch_recovery_failed";
const PROFILE_CUSTODY_DIRECTORY: &str = ".ck-browser-profile-custody";

#[derive(Debug)]
#[doc(hidden)]
pub enum ProductionProfileLifecycleError {
    DataRoot,
    Registry(RegistryError),
}

impl ProductionProfileLifecycleError {
    pub const fn stage(&self) -> &'static str {
        match self {
            Self::DataRoot => "data_root",
            Self::Registry(_) => "profile_registry",
        }
    }

    /// No free-text detail: a registry error's Debug text can carry filesystem
    /// paths, and a profile directory is named by its profile UUID, which must
    /// never reach the wire. The one cause a caller acts on differently -- a
    /// root the registry no longer trusts, which has its own remedy -- keeps
    /// the typed outcome the acquire path already renders for it; every other
    /// registry failure is a storage problem the stage already names.
    fn into_launch_refusal(self) -> Value {
        match self {
            Self::DataRoot => {
                json!({"outcome": "profile_storage_unavailable", "stage": "data_root"})
            }
            Self::Registry(RegistryError::Untrustworthy(reason)) => {
                crate::browser_launch::BrowserLaunchOutcome::ProfileRegistryUntrustedRoot { reason }
                    .as_json()
            }
            Self::Registry(_) => json!({
                "outcome": "profile_storage_unavailable",
                "stage": "profile_registry",
            }),
        }
    }
}

pub struct ProductionLaunchService {
    config: BrowserConfig,
    journal: SharedLaunchJournal,
    startup_failure: Option<BrowserLaunchRecoveryFailure>,
}

impl ProductionLaunchService {
    /// Open and recover the launch journal before returning a service that can be
    /// published to request handlers. Keeping recovery synchronous here means no
    /// caller can obtain the service while an orphan still contends with a fresh
    /// spawn for the same profile.
    pub fn open(config: BrowserConfig) -> Self {
        Self::open_with_recovery(config, |config| {
            let mut startup_failure = None;
            let journal = match DurableLaunchJournal::open_filesystem(launch_journal_config()) {
                Ok(mut journal) => {
                    let mut process = ProductionOrphanProcessControl {
                        reap_deadline: Duration::from_millis(config.termination_grace_period_ms),
                    };
                    let mut custody = ProductionOrphanProfileCustody;
                    if let Err(failure) =
                        recover_browser_launches(&mut journal, &mut process, &mut custody)
                    {
                        startup_failure = Some(failure);
                    }
                    Some(journal)
                }
                Err(_) => {
                    startup_failure = Some(BrowserLaunchRecoveryFailure::JournalOpen);
                    None
                }
            };
            (journal, startup_failure)
        })
    }

    fn require_recovered_startup(&self) -> Result<(), Value> {
        match self.startup_failure {
            Some(failure) => Err(launch_recovery_refusal(failure)),
            None => Ok(()),
        }
    }

    fn open_with_recovery<F>(config: BrowserConfig, recover: F) -> Self
    where
        F: FnOnce(
            &BrowserConfig,
        ) -> (
            Option<ProductionLaunchJournal>,
            Option<BrowserLaunchRecoveryFailure>,
        ),
    {
        let (journal, startup_failure) = recover(&config);
        Self {
            config,
            journal: Arc::new(Mutex::new(journal)),
            startup_failure,
        }
    }

    pub fn launch(
        &self,
        accepted: &AcceptedBindFacts,
        browser_session_id: &str,
    ) -> Result<ReadyProductionBrowser, Value> {
        self.require_recovered_startup()?;
        let Some(executable) = self.config.executable_path.as_ref() else {
            return Err(json!({"outcome": "executable_missing"}));
        };
        if !executable.is_file() {
            return Err(json!({
                "outcome": "executable_missing",
                "expected_path": executable,
            }));
        }
        let expected = self.config.expected_identity.as_deref().ok_or_else(|| {
            json!({
                "outcome": "internal_failure",
                "stage": "expected_identity",
            })
        })?;
        let (expected_identity, pre_spawn_identity_verification) =
            verify_configured_executable(executable, expected)?;
        let context =
            stamped_context(accepted).map_err(|_| json!({"outcome": "authorization_denied"}))?;
        if context.profile_disposition() == crate::profile::ProfileDisposition::None {
            return Err(json!({"outcome": "no_profile", "profile_disposition": "none"}));
        }

        // Three distinct failures follow, and a caller's next move differs for
        // each: a data root that cannot be resolved is an environment problem,
        // a registry that will not open is profile state, and custody locks
        // that refuse are a supervisor-identity problem that has nothing to do
        // with storage at all. They shared one reason code, so an operator was
        // told to check a disk whichever one fired.
        // browser_data_root reports only failure, so this stage cannot say more
        // than which stage it was -- which is still the fact that was missing.
        let lifecycle = production_profile_lifecycle()
            .map_err(ProductionProfileLifecycleError::into_launch_refusal)?;
        let root = lifecycle.registry().root().canonical_path().to_path_buf();
        let lifecycle = Arc::new(Mutex::new(lifecycle));
        let locks = Arc::new(Mutex::new(
            // The lock error's Debug text is dropped: it names paths under the
            // profile root and says nothing the stage does not.
            ProfileCustodyLocks::open_filesystem(&root).map_err(
                |_| json!({"outcome": "custody_locks_unavailable", "stage": "custody_locks"}),
            )?,
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

        let mut lifecycle_guard = map_poisoned_mutex(lifecycle.lock(), "profile_registry_lock")?;
        let mut locks_guard = map_poisoned_mutex(locks.lock(), "custody_locks_lock")?;
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
            return Err(json!({
                "outcome": "internal_failure",
                "stage": "profile_uuid_lookup",
                "rollback": "rollback_opened",
            }));
        };

        let crash_dumps_directory = profile_directory.join("crash-dumps");
        let arguments = browser_launch_arguments(&profile_directory, &crash_dumps_directory);
        if !crate::custody::arguments_are_quarantinable(
            &arguments
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
        ) {
            let _ = ProfileBoundLaunch::new(&mut lifecycle_guard, &mut locks_guard)
                .rollback_opened(opened);
            return Err(json!({
                "outcome": "internal_failure",
                "stage": "argument_quarantine",
                "rollback": "rollback_opened",
            }));
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
                disposition: LaunchProfile::Registry(accepted.identity.profile_disposition),
            },
            executable: executable.clone(),
            arguments,
            environment: browser_launch_environment(&profile_directory),
            verified_executable_identity: expected_identity,
            pre_spawn_identity_verification,
        };
        let (command_parent, command_child) = match pipe_pair("command") {
            Ok(pair) => pair,
            Err(outcome) => return Err(cleanup_before_spawn(rollback.clone(), outcome)),
        };
        let (response_parent, response_child) = match pipe_pair("response") {
            Ok(pair) => pair,
            Err(outcome) => return Err(cleanup_before_spawn(rollback.clone(), outcome)),
        };
        #[cfg(target_os = "macos")]
        let mut launcher =
            MacOsProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        #[cfg(target_os = "linux")]
        let mut launcher =
            LinuxProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let pipe = match UnixCdpPipe::new(command_parent, response_parent) {
            Ok(pipe) => pipe,
            Err(_) => {
                return Err(cleanup_before_spawn(
                    rollback.clone(),
                    json!({
                        "outcome": "internal_failure",
                        "stage": "spawn_preparation",
                        "pipe": "cdp",
                    }),
                ))
            }
        };
        let mut journal_guard = self.journal.lock().map_err(|_| {
            cleanup_before_spawn(
                rollback.clone(),
                crate::browser_session::internal_failure_reply("launch_journal_lock"),
            )
        })?;
        let journal = journal_guard.as_mut().ok_or_else(|| {
            json!({
                "outcome": "internal_failure",
                "stage": "launch_journal",
            })
        })?;
        let mut clock = SystemLaunchClock;
        let mut readiness_rollback = rollback.clone();
        let launch_started_at = SystemTime::now();
        let ready = launch_attested_to_readiness_with(
            journal,
            &mut launcher,
            &request,
            pipe,
            NonZeroU64::new(self.config.launch_handshake_deadline_ms)
                .expect("validated browser duration is positive"),
            &mut clock,
            &mut readiness_rollback,
        )
        .map_err(map_readiness_error)?;
        drop(journal_guard);

        Ok(ReadyProductionBrowser {
            attestation: ready.attestation,
            process: Some(ready.process),
            pipe: Some(ready.pipe),
            transport: Some(ready.transport),
            decoder: Some(ready.decoder),
            cleanup: Some(ProductionSessionCleanup {
                journal: Arc::clone(&self.journal),
                launch_attempt_id: browser_session_id.to_string(),
                terminal_outcome: None,
                persistence: ProfilePersistenceCheck {
                    disposition: accepted.identity.profile_disposition,
                    profile_directory,
                    launch_started_at,
                },
                profile: rollback,
            }),
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

/// The launch composition for `browser.capture_login`, and only for it.
///
/// It keeps what makes a launch trustworthy -- the executable identity check,
/// the barred spawn and attestation recorded in the launch journal, and CDP
/// readiness -- and leaves out the profile registry: the throwaway profile
/// lives in the capture directory, which is excluded from backups, while the
/// registry root is not. The one relaxation is the profile directory, admitted
/// only through `capture_user_data_dir_admitted`.
impl crate::login_capture::CaptureLauncher for ProductionLaunchService {
    fn launch_capture(
        &self,
        accepted: &AcceptedBindFacts,
        launch_attempt_id: &str,
        placement: &crate::login_capture::CapturePlacement,
    ) -> Result<
        Box<dyn crate::login_capture::CaptureBrowser>,
        crate::login_capture::CaptureLaunchRefusal,
    > {
        self.launch_capture_browser(accepted, launch_attempt_id, placement)
            .map_err(|refusal| crate::login_capture::CaptureLaunchRefusal {
                stage: refusal
                    .get("stage")
                    .or_else(|| refusal.get("outcome"))
                    .and_then(Value::as_str)
                    .unwrap_or("launch")
                    .to_string(),
            })
    }
}

impl ProductionLaunchService {
    fn launch_capture_browser(
        &self,
        accepted: &AcceptedBindFacts,
        launch_attempt_id: &str,
        placement: &crate::login_capture::CapturePlacement,
    ) -> Result<Box<dyn crate::login_capture::CaptureBrowser>, Value> {
        self.require_recovered_startup()?;
        let Some(executable) = self.config.executable_path.as_ref() else {
            return Err(json!({"outcome": "executable_missing"}));
        };
        if !executable.is_file() {
            return Err(json!({"outcome": "executable_missing"}));
        }
        let expected =
            self.config.expected_identity.as_deref().ok_or_else(
                || json!({"outcome": "internal_failure", "stage": "expected_identity"}),
            )?;
        let (expected_identity, pre_spawn_identity_verification) =
            verify_configured_executable(executable, expected)?;

        let profile_directory = placement.profile_directory().to_path_buf();
        let crash_dumps_directory = profile_directory.join("crash-dumps");
        let arguments = browser_launch_arguments(&profile_directory, &crash_dumps_directory);
        let argument_text = arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        if !crate::custody::capture_user_data_dir_admitted(
            &argument_text,
            placement.root(),
            &profile_directory,
        ) {
            return Err(json!({"outcome": "internal_failure", "stage": "capture_profile_path"}));
        }
        if !crate::custody::arguments_are_quarantinable(&argument_text) {
            return Err(json!({"outcome": "internal_failure", "stage": "argument_quarantine"}));
        }

        let request = AttestedLaunchRequest {
            launch_attempt_id: launch_attempt_id.to_string(),
            holder_id: launch_attempt_id.to_string(),
            route: LaunchRouteIdentity {
                principal: accepted
                    .principal
                    .as_ref()
                    .map(|principal| format!("{principal:?}"))
                    .unwrap_or_default(),
                conversation_key: accepted.identity.conversation_key.clone(),
                agent_project_id: accepted.identity.agent_project_id.clone(),
                session_kind: accepted.identity.session_kind,
            },
            profile: LaunchProfileIdentity {
                profile_uuid: launch_attempt_id.to_string(),
                canonical_profile_path: path_bytes(&profile_directory),
                disposition: LaunchProfile::Capture,
            },
            executable: executable.clone(),
            arguments,
            environment: browser_launch_environment(&profile_directory),
            verified_executable_identity: expected_identity,
            pre_spawn_identity_verification,
        };
        let (command_parent, command_child) = pipe_pair("command")?;
        let (response_parent, response_child) = pipe_pair("response")?;
        #[cfg(target_os = "macos")]
        let mut launcher =
            MacOsProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        #[cfg(target_os = "linux")]
        let mut launcher =
            LinuxProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let pipe = UnixCdpPipe::new(command_parent, response_parent)
            .map_err(|_| json!({"outcome": "internal_failure", "stage": "spawn_preparation"}))?;
        let handshake_deadline = NonZeroU64::new(self.config.launch_handshake_deadline_ms)
            .ok_or_else(|| json!({"outcome": "internal_failure", "stage": "handshake_deadline"}))?;
        let mut journal_guard = map_poisoned_mutex(self.journal.lock(), "launch_journal_lock")?;
        let journal = journal_guard
            .as_mut()
            .ok_or_else(|| json!({"outcome": "internal_failure", "stage": "launch_journal"}))?;
        let mut clock = SystemLaunchClock;
        // The capture directory is the capture's to delete, on every path, so
        // a failed launch has no profile custody to roll back here.
        let mut rollback = NoCaptureRollback;
        let ready = launch_attested_to_readiness_with(
            journal,
            &mut launcher,
            &request,
            pipe,
            handshake_deadline,
            &mut clock,
            &mut rollback,
        )
        .map_err(map_readiness_error)?;
        drop(journal_guard);

        Ok(Box::new(ProductionCaptureBrowser {
            process: ProductionProcess {
                process: Some(ready.process),
                driver: Some(CdpNavigationDriver::new(
                    ready.pipe,
                    ready.transport,
                    ready.decoder,
                )),
                reaped: false,
            },
            journal: Arc::clone(&self.journal),
            launch_attempt_id: launch_attempt_id.to_string(),
            grace_period: Duration::from_millis(self.config.termination_grace_period_ms),
            closed: false,
        }))
    }
}

struct NoCaptureRollback;

impl crate::browser_launch_readiness::FailedLaunchRollback for NoCaptureRollback {
    fn rollback(
        &mut self,
        _failure: &crate::browser_launch_readiness::ProfileStartupIndeterminate,
    ) -> Result<(), crate::browser_launch::PlatformLaunchError> {
        Ok(())
    }
}

/// The CDP context key a capture browser's single page is driven under.
const CAPTURE_CONTEXT_KEY: &str = "browser.capture_login";

struct ProductionCaptureBrowser {
    process: ProductionProcess,
    journal: SharedLaunchJournal,
    launch_attempt_id: String,
    grace_period: Duration,
    closed: bool,
}

fn capture_drive<T>(
    result: Result<T, NavigationDriveError>,
) -> Result<T, crate::login_capture::CaptureDriveError> {
    result.map_err(|_| crate::login_capture::CaptureDriveError)
}

impl crate::login_capture::CaptureBrowser for ProductionCaptureBrowser {
    fn navigate(
        &mut self,
        url: &str,
        deadline_ms: u64,
    ) -> Result<(), crate::login_capture::CaptureDriveError> {
        let mut tracker = Tracker::default();
        capture_drive(self.process.navigate(
            CAPTURE_CONTEXT_KEY,
            url,
            NavigationWait::None,
            deadline_ms,
            &mut tracker,
        ))
    }

    fn present(&mut self, deadline_ms: u64) -> Result<(), crate::login_capture::CaptureDriveError> {
        capture_drive(self.process.present(CAPTURE_CONTEXT_KEY, deadline_ms))
    }

    fn main_frame_url(
        &mut self,
        deadline_ms: u64,
    ) -> Result<String, crate::login_capture::CaptureDriveError> {
        capture_drive(
            self.process
                .main_frame_url(CAPTURE_CONTEXT_KEY, deadline_ms),
        )
    }

    fn has_credential_field(
        &mut self,
        deadline_ms: u64,
    ) -> Result<bool, crate::login_capture::CaptureDriveError> {
        capture_drive(
            self.process
                .has_credential_field(CAPTURE_CONTEXT_KEY, deadline_ms),
        )
    }

    fn cookie_names_for_origin(
        &mut self,
        origin: &str,
        deadline_ms: u64,
    ) -> Result<std::collections::BTreeSet<String>, crate::login_capture::CaptureDriveError> {
        capture_drive(self.process.cookie_names_for_origin(
            CAPTURE_CONTEXT_KEY,
            origin,
            deadline_ms,
        ))
    }

    fn cookie_request_header(
        &mut self,
        url: &str,
        deadline_ms: u64,
    ) -> Result<
        Result<crate::login_capture::CookieHeader, crate::login_capture::CookieHeaderError>,
        crate::login_capture::CaptureDriveError,
    > {
        let driver = self
            .process
            .driver
            .as_mut()
            .ok_or(crate::login_capture::CaptureDriveError)?;
        capture_drive(driver.cookie_request_header_for_url(CAPTURE_CONTEXT_KEY, url, deadline_ms))
    }

    fn exited(&mut self) -> bool {
        self.process.process.as_ref().is_none_or(|process| {
            platform_generation_exited(BrowserProcessGeneration::from(process.generation()))
        })
    }

    fn close(&mut self) -> Result<(), crate::login_capture::CaptureDriveError> {
        if self.closed {
            return Ok(());
        }
        let _ = self.process.request_graceful_termination();
        let reaped = match self.process.wait_for_exit(self.grace_period) {
            Ok(true) => self.process.wait_until_reaped(),
            _ => self.process.force_terminate(),
        };
        // The launch record is closed whatever the reap did, so a failed reap
        // is not also reported as a launch nobody finished.
        let recorded = ProductionSessionCleanup::finalize_journal(
            &self.journal,
            &self.launch_attempt_id,
            &mut Some(BrowserSessionTerminalOutcome::Closed),
        );
        self.closed = true;
        match (reaped, recorded) {
            (Ok(()), Ok(())) => Ok(()),
            _ => Err(crate::login_capture::CaptureDriveError),
        }
    }
}

impl Drop for ProductionCaptureBrowser {
    /// A capture that ends without closing its browser (a panicked task) must
    /// not leave the browser running with a live session in it.
    fn drop(&mut self) {
        let _ = crate::login_capture::CaptureBrowser::close(self);
    }
}

/// The recovery failure's variant and journal sequence stay out of the reply:
/// they are internal state, and every variant asks the same of a caller -- the
/// module must be restarted once an operator has looked at the launch journal.
fn launch_recovery_refusal(_failure: BrowserLaunchRecoveryFailure) -> Value {
    json!({
        "outcome": "internal_failure",
        "stage": "startup_recovery",
        "reason_code": BROWSER_LAUNCH_RECOVERY_FAILED,
    })
}

/// Exposed so the live probe can call it rather than mirroring it.
///
/// Two hand-written mirrors of launch inputs have drifted from production: the
/// argument shape, and this environment. The second drift made the probe's
/// discovery walk run a browser with no display -- so it measured a process the
/// real launch never runs, and reported a clean failure about the wrong thing.
/// A probe that diverges from production in a way that makes it PASS is worse
/// than one that fails, because it certifies something nobody built.
///
/// Not part of the module's supported surface; it exists for the probe.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn browser_launch_environment(profile_directory: &Path) -> Vec<(OsString, OsString)> {
    linux_browser_launch_environment_from(profile_directory, std::env::vars_os())
}

/// Exposed so the live probe can call it rather than mirroring it.
///
/// Two hand-written mirrors of launch inputs have drifted from production: the
/// argument shape, and this environment. The second drift made the probe's
/// discovery walk run a browser with no display -- so it measured a process the
/// real launch never runs, and reported a clean failure about the wrong thing.
/// A probe that diverges from production in a way that makes it PASS is worse
/// than one that fails, because it certifies something nobody built.
///
/// Not part of the module's supported surface; it exists for the probe.
#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn browser_launch_environment(_profile_directory: &Path) -> Vec<(OsString, OsString)> {
    Vec::new()
}

#[cfg(any(target_os = "linux", test))]
fn linux_browser_launch_environment_from(
    profile_directory: &Path,
    parent_environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    const ALLOWED_PARENT_VARIABLES: [&str; 5] = [
        "DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "WAYLAND_DISPLAY",
        "HOME",
    ];

    let mut parent_environment = parent_environment
        .into_iter()
        .collect::<std::collections::HashMap<_, _>>();
    let mut environment = vec![(
        OsString::from("XDG_CONFIG_HOME"),
        profile_directory.join("config").into_os_string(),
    )];

    // This must remain an allowlist. Inheriting the launcher's environment, or
    // trying to deny known injection variables, could pass LD_PRELOAD (or a new
    // equivalent) and make the attested executable's behaviour externally
    // controlled without falsifying its recorded image identity.
    environment.extend(ALLOWED_PARENT_VARIABLES.into_iter().filter_map(|name| {
        parent_environment
            .remove(std::ffi::OsStr::new(name))
            .map(|value| (OsString::from(name), value))
    }));
    environment
}

#[doc(hidden)]
pub fn browser_launch_arguments(
    profile_directory: &Path,
    crash_dumps_directory: &Path,
) -> Vec<OsString> {
    // Config-load probing uses this constructor too: wrappers may branch on
    // flags, so a probe must preserve the production argument shape exactly.
    vec![
        OsString::from("--remote-debugging-pipe"),
        OsString::from(format!(
            "--user-data-dir={}",
            profile_directory.to_string_lossy()
        )),
        OsString::from(format!(
            "--crash-dumps-dir={}",
            crash_dumps_directory.to_string_lossy()
        )),
        OsString::from("--no-first-run"),
        OsString::from("--no-default-browser-check"),
    ]
}

/// Default capacity for durable browser-launch audit records.
///
/// Sized from a 1,000-launch audit horizon, against entries measured on a real
/// journal rather than a fixture. Twenty-six field-written v2 entries run 8,782
/// to 10,963 bytes with a median of 9,018 -- about 44% larger than the 6,266-byte
/// test fixture, because a real launch carries longer paths and fuller
/// attestations. 64 MiB therefore buys roughly 7,400 launches at the median and
/// 6,100 at the largest entry seen, both comfortably past the horizon.
///
/// Quote the field numbers when re-sizing this. The fixture is representative of
/// shape and not of size, and sizing against it would overstate capacity by that
/// 44% in the direction that runs out sooner than the comment promises.
const LAUNCH_JOURNAL_RETENTION_BYTES: u64 = 64 * 1024 * 1024;

/// Public for the restore drill, for the same reason as
/// `production_profile_lifecycle`: the drill opens the launch journal with the
/// bounds production uses, not a copy of them.
#[doc(hidden)]
pub fn launch_journal_config() -> cerebellum_core::journal::JournalConfig {
    cerebellum_core::journal::JournalConfig {
        journal_retention_bytes: LAUNCH_JOURNAL_RETENTION_BYTES,
        journal_max_entry_bytes: 1024 * 1024,
    }
}

#[cfg(target_os = "macos")]
struct MacOsOrphanProcessControl {
    reap_deadline: Duration,
}

#[cfg(target_os = "macos")]
impl MacOsOrphanProcessControl {
    fn generation_still_matches(generation: BrowserProcessGeneration) -> Result<bool, ()> {
        match cerebellum_macos::process_start_time(generation.pid) {
            cerebellum_macos::ProcessStartTime::Started(start_time) => {
                Ok(start_time == generation.start_time_micros)
            }
            cerebellum_macos::ProcessStartTime::NoSuchProcess => Ok(false),
            cerebellum_macos::ProcessStartTime::NotPermitted
            | cerebellum_macos::ProcessStartTime::LayoutMismatch
            | cerebellum_macos::ProcessStartTime::Unclassified(_)
            | cerebellum_macos::ProcessStartTime::NoStartTime => Err(()),
        }
    }
}

#[cfg(target_os = "macos")]
impl OrphanBrowserProcessControl for MacOsOrphanProcessControl {
    fn observed_start_time_micros(
        &mut self,
        pid: u32,
    ) -> Result<Option<u64>, OrphanProcessControlFailure> {
        match cerebellum_macos::process_start_time(pid) {
            cerebellum_macos::ProcessStartTime::Started(start_time) => Ok(Some(start_time)),
            cerebellum_macos::ProcessStartTime::NoSuchProcess => Ok(None),
            cerebellum_macos::ProcessStartTime::NotPermitted
            | cerebellum_macos::ProcessStartTime::LayoutMismatch
            | cerebellum_macos::ProcessStartTime::Unclassified(_)
            | cerebellum_macos::ProcessStartTime::NoStartTime => Err(OrphanProcessControlFailure),
        }
    }

    fn terminate_and_reap(
        &mut self,
        generation: BrowserProcessGeneration,
    ) -> Result<(), OrphanProcessControlFailure> {
        // The seam owns the signal, because it owns every raw system call in
        // this workspace. Spawning `/bin/kill` from here would reach the same
        // process while stepping outside the boundary that makes such calls
        // auditable in one place — and it would re-implement the generation
        // check that decides whether signalling is safe at all.
        //
        // The check is repeated inside that call, immediately before the
        // signal: the journal read authorizes this attempt, and the second read
        // closes the interval in which the recorded process could exit and its
        // pid be taken by something else.
        match cerebellum_macos::terminate_exact_generation(cerebellum_macos::ProcessGeneration {
            pid: generation.pid,
            start_time_micros: generation.start_time_micros,
        }) {
            Ok(cerebellum_macos::TerminationOutcome::Signalled) => {}
            Ok(cerebellum_macos::TerminationOutcome::AlreadyGoneOrReplaced) => return Ok(()),
            Err(_) => return Err(OrphanProcessControlFailure),
        }

        let deadline = Instant::now() + self.reap_deadline;
        loop {
            if !Self::generation_still_matches(generation)
                .map_err(|_| OrphanProcessControlFailure)?
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(OrphanProcessControlFailure);
            }
            // The surviving guardian owns `waitpid` authority. Waiting until the
            // exact generation disappears observes its reap without pretending a
            // restarted module can reap a process that is not its child.
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(target_os = "macos")]
type ProductionOrphanProcessControl = MacOsOrphanProcessControl;

#[cfg(target_os = "linux")]
type ProductionOrphanProcessControl = LinuxOrphanProcessControl;

#[cfg(target_os = "macos")]
type PlatformReleasedChild = cerebellum_macos::ReleasedChild;

#[cfg(target_os = "linux")]
type PlatformReleasedChild = cerebellum_linux::ReleasedChild;

#[cfg(target_os = "macos")]
fn platform_generation_matches(generation: BrowserProcessGeneration) -> bool {
    cerebellum_macos::process_start_time_micros(generation.pid)
        == Some(generation.start_time_micros)
}

#[cfg(target_os = "linux")]
fn platform_generation_matches(generation: BrowserProcessGeneration) -> bool {
    linux_generation_liveness(generation) == SupervisorLiveness::Live
}

/// Classify a recorded browser generation against what procfs reports now,
/// reading it in the unit the record was written in.
#[cfg(target_os = "linux")]
fn linux_generation_liveness(generation: BrowserProcessGeneration) -> SupervisorLiveness {
    crate::profile_custody::classify_process_generation(
        generation.start_time_micros,
        generation.boot_id,
        crate::profile_custody::linux_generation_observation(generation.pid, generation.boot_id),
    )
}

#[cfg(target_os = "macos")]
fn platform_generation_exited(generation: BrowserProcessGeneration) -> bool {
    !platform_generation_matches(generation)
}

#[cfg(target_os = "linux")]
fn platform_generation_exited(generation: BrowserProcessGeneration) -> bool {
    // Unchanged from before the boot ID: anything but an exact match counts as
    // exited here, and the caller's next step is a generation-checked
    // termination that refuses an unreadable generation on its own.
    !platform_generation_matches(generation)
}

#[cfg(target_os = "linux")]
struct LinuxOrphanProcessControl {
    reap_deadline: Duration,
}

#[cfg(target_os = "linux")]
impl OrphanBrowserProcessControl for LinuxOrphanProcessControl {
    /// The epoch start time, which only a record written before the boot ID
    /// existed can be compared with. Recovery reads through
    /// [`Self::observe_generation`], which picks the reading the record needs.
    fn observed_start_time_micros(
        &mut self,
        pid: u32,
    ) -> Result<Option<u64>, OrphanProcessControlFailure> {
        match cerebellum_linux::process_start_time(pid) {
            cerebellum_linux::ProcessStartTime::Started(start_time) => Ok(Some(start_time)),
            cerebellum_linux::ProcessStartTime::NoSuchProcess => Ok(None),
            cerebellum_linux::ProcessStartTime::NotPermitted
            | cerebellum_linux::ProcessStartTime::StatReadFailed
            | cerebellum_linux::ProcessStartTime::SystemTimeBaseUnavailable
            | cerebellum_linux::ProcessStartTime::LayoutMismatch
            | cerebellum_linux::ProcessStartTime::NoStartTime => Err(OrphanProcessControlFailure),
        }
    }

    fn observe_generation(
        &mut self,
        generation: BrowserProcessGeneration,
    ) -> crate::profile_custody::GenerationObservation {
        crate::profile_custody::linux_generation_observation(generation.pid, generation.boot_id)
    }

    fn terminate_and_reap(
        &mut self,
        generation: BrowserProcessGeneration,
    ) -> Result<(), OrphanProcessControlFailure> {
        // The seam signals only on `Exact`, and asks again if the signal
        // fails. A record with a boot ID matches after a wall-clock step, so a
        // live orphan is terminated; an older record whose epoch start time
        // moved answers `Unreadable` and is refused rather than read as gone.
        match cerebellum_linux::terminate_exact_generation(
            generation.pid,
            Instant::now() + self.reap_deadline,
            || match linux_generation_liveness(generation) {
                SupervisorLiveness::Live => cerebellum_linux::GenerationMatch::Exact,
                SupervisorLiveness::NotLive => cerebellum_linux::GenerationMatch::GoneOrReplaced,
                SupervisorLiveness::Unavailable => cerebellum_linux::GenerationMatch::Unreadable,
            },
        ) {
            Ok(cerebellum_linux::TerminationOutcome::AlreadyGoneOrReplaced) => return Ok(()),
            Ok(cerebellum_linux::TerminationOutcome::Signalled) => {}
            Err(_) => return Err(OrphanProcessControlFailure),
        }
        let deadline = Instant::now() + self.reap_deadline;
        loop {
            match linux_generation_liveness(generation) {
                SupervisorLiveness::NotLive => return Ok(()),
                SupervisorLiveness::Live => {}
                SupervisorLiveness::Unavailable => return Err(OrphanProcessControlFailure),
            }
            if Instant::now() >= deadline {
                return Err(OrphanProcessControlFailure);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

struct ExactRecoveryCustodyJournal {
    durable: FilesystemProfileCustodyJournal,
    expected_holder_id: String,
}

impl ProfileCustodyJournal for ExactRecoveryCustodyJournal {
    fn record(&mut self, event: &ProfileCustodyEvent) -> io::Result<()> {
        // A profile key can outlive several launch attempts. Refuse the stale
        // break before mutation unless the installed lock names the same holder
        // as the launch journal, so recovery cannot release a later attempt's
        // lock merely because it selected the same durable profile.
        if event.kind == ProfileCustodyEventKind::StaleBreak
            && event.holder_id.as_str() != self.expected_holder_id.as_str()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "profile custody holder differs from launch attestation",
            ));
        }
        self.durable.record(event)
    }
}

struct ProductionOrphanProfileCustody;

impl OrphanProfileCustody for ProductionOrphanProfileCustody {
    fn release(
        &mut self,
        intent: &crate::browser_launch::AuthorizedLaunchIntent,
    ) -> Result<(), OrphanProfileCustodyFailure> {
        let root = browser_data_root().map_err(|_| OrphanProfileCustodyFailure)?;
        release_orphan_profile_custody_at(&root, intent).map_err(|_| OrphanProfileCustodyFailure)
    }
}

fn release_orphan_profile_custody_at(
    root: &Path,
    intent: &crate::browser_launch::AuthorizedLaunchIntent,
) -> Result<(), ()> {
    let supervisor = current_supervisor_generation().map_err(|_| ())?;
    let durable = FilesystemProfileCustodyJournal::open(root.join(PROFILE_CUSTODY_DIRECTORY))
        .map_err(|_| ())?;
    let journal = ExactRecoveryCustodyJournal {
        durable,
        expected_holder_id: intent.holder_id.clone(),
    };
    let mut locks = ProfileCustodyLocks::open(root, supervisor, journal, KernelSupervisorLiveness)
        .map_err(|_| ())?;
    let key = match intent.profile.disposition {
        LaunchProfile::Registry(ProfileDisposition::Durable) => {
            ProfileCustodyKey::durable(&intent.route.agent_project_id)
        }
        LaunchProfile::Registry(ProfileDisposition::Disposable) => {
            ProfileCustodyKey::disposable_route(
                &intent.route.agent_project_id,
                &intent.route.conversation_key,
                &intent.launch_attempt_id,
            )
        }
        // Recovery skips capture records before reaching custody, so arriving
        // here with one is a caller error; refusing is the honest answer, as it
        // is for a record with no profile at all.
        LaunchProfile::Registry(ProfileDisposition::None) | LaunchProfile::Capture => {
            return Err(())
        }
    };
    let temporary_holder = locks.mint_holder().map_err(|_| ())?;
    let claim = match locks.acquire(key, temporary_holder).map_err(|_| ())? {
        ProfileCustodyAcquisition::Acquired(claim) => claim,
        ProfileCustodyAcquisition::ProfileBusy { .. } => return Err(()),
    };
    match locks.release_exact(&claim).map_err(|_| ())? {
        ProfileCustodyRelease::Released => Ok(()),
        ProfileCustodyRelease::HolderMismatch { .. } | ProfileCustodyRelease::Missing => Err(()),
    }
}

pub struct ReadyProductionBrowser {
    attestation: LaunchAttestationRecord,
    process: Option<PlatformReleasedChild>,
    pipe: Option<UnixCdpPipe>,
    transport: Option<CdpTransport>,
    decoder: Option<CdpFrameDecoder>,
    cleanup: Option<ProductionSessionCleanup>,
}

impl ReadyProductionBrowser {
    pub fn attestation(&self) -> &LaunchAttestationRecord {
        &self.attestation
    }

    pub fn into_parts(self) -> LaunchedBrowser {
        LaunchedBrowser {
            executable_identity_checkpoints: self.attestation.executable_identity_checkpoints,
            process: Box::new(ProductionProcess {
                process: self.process,
                driver: Some(CdpNavigationDriver::new(
                    self.pipe.expect("ready browser owns its CDP pipe"),
                    self.transport
                        .expect("ready browser owns its CDP correlator"),
                    self.decoder.expect("ready browser owns its CDP decoder"),
                )),
                reaped: false,
            }),
            cleanup: Box::new(self.cleanup.expect("ready browser owns profile cleanup")),
        }
    }
}

struct ProductionProcess {
    process: Option<PlatformReleasedChild>,
    driver: Option<CdpNavigationDriver<UnixCdpPipe>>,
    reaped: bool,
}

impl OwnedBrowserProcess for ProductionProcess {
    fn present(&mut self, context_key: &str, deadline_ms: u64) -> Result<(), NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .present(context_key, deadline_ms)
    }

    fn cookie_names_for_origin(
        &mut self,
        context_key: &str,
        origin: &str,
        deadline_ms: u64,
    ) -> Result<std::collections::BTreeSet<String>, NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .cookie_names_for_origin(context_key, origin, deadline_ms)
    }

    fn main_frame_url(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<String, NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .main_frame_url(context_key, deadline_ms)
    }

    fn has_credential_field(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<bool, NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .has_credential_field(context_key, deadline_ms)
    }

    fn navigate(
        &mut self,
        context_key: &str,
        url: &str,
        wait: NavigationWait,
        deadline_ms: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .navigate(context_key, url, wait, deadline_ms, tracker)
    }

    fn snapshot(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .snapshot(context_key, mode, deadline_ms)
    }

    fn snapshot_classified(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        document_epoch: u64,
        current_origin: &str,
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .snapshot_classified(
                context_key,
                mode,
                document_epoch,
                current_origin,
                deadline_ms,
            )
    }

    fn screenshot(
        &mut self,
        context_key: &str,
        document_epoch: u64,
        deadline_ms: u64,
        full: bool,
    ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .screenshot(context_key, document_epoch, deadline_ms, full)
    }

    fn click_point(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickPointDriveError> {
        self.driver
            .as_mut()
            .ok_or(ClickPointDriveError::Navigation(
                NavigationDriveError::Unavailable,
            ))?
            .click_point(context_key, position, deadline_ms, input_dispatched)
    }

    fn click_classified(
        &mut self,
        context_key: &str,
        identity: &BackendNodeIdentity,
        document_epoch: u64,
        current_origin: &str,
        expected: Option<&crate::classification::NonTypeClassificationRecord>,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.driver
            .as_mut()
            .ok_or(ClickDriveError::Navigation(
                NavigationDriveError::Unavailable,
            ))?
            .click_classified(
                context_key,
                identity,
                document_epoch,
                current_origin,
                expected,
                deadline_ms,
                input_dispatched,
            )
    }

    fn generation_matches(&self) -> bool {
        self.process.as_ref().is_some_and(|process| {
            let generation = process.generation();
            platform_generation_matches(BrowserProcessGeneration::from(generation))
        })
    }

    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        self.driver
            .as_mut()
            .ok_or(ProcessControlFailure)?
            .request_browser_close()
            .map_err(|_| ProcessControlFailure)
    }

    fn wait_for_exit(&mut self, grace_period: Duration) -> Result<bool, ProcessControlFailure> {
        let Some(process) = self.process.as_ref() else {
            return Ok(true);
        };
        let generation = process.generation();
        let deadline = Instant::now() + grace_period;
        while Instant::now() < deadline {
            if platform_generation_exited(BrowserProcessGeneration::from(generation)) {
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

impl SharedRollback {
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

struct ProfilePersistenceCheck {
    disposition: ProfileDisposition,
    profile_directory: PathBuf,
    launch_started_at: SystemTime,
}

impl ProfilePersistenceCheck {
    fn observe(&self) -> SessionCleanupOutcome {
        if self.disposition != ProfileDisposition::Durable {
            return SessionCleanupOutcome::Complete;
        }

        let local_state_written_since_launch =
            std::fs::metadata(self.profile_directory.join("Local State"))
                .and_then(|metadata| metadata.modified())
                .is_ok_and(|modified| modified >= self.launch_started_at);
        let profile_writable = profile_directory_is_writable(&self.profile_directory);

        if local_state_written_since_launch && profile_writable {
            SessionCleanupOutcome::Complete
        } else {
            SessionCleanupOutcome::DurableStateAtRisk {
                local_state_not_written_since_launch: !local_state_written_since_launch,
                profile_not_writable: !profile_writable,
            }
        }
    }
}

fn profile_directory_is_writable(profile_directory: &Path) -> bool {
    static NEXT_PROBE: AtomicU64 = AtomicU64::new(1);

    let sequence = NEXT_PROBE.fetch_add(1, Ordering::Relaxed);
    let probe_path = profile_directory.join(format!(
        ".cerebellum-write-probe-{}-{sequence}",
        std::process::id()
    ));
    let result = (|| -> io::Result<()> {
        let mut probe = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe_path)?;
        probe.write_all(b"profile writable probe")?;
        drop(probe);
        std::fs::remove_file(&probe_path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(probe_path);
    }
    result.is_ok()
}

fn run_cleanup_obligations<P, J, C>(
    persistence_check: P,
    journal_finalization: J,
    profile_cleanup: C,
) -> Result<SessionCleanupOutcome, CleanupStage>
where
    P: FnOnce() -> SessionCleanupOutcome,
    J: FnOnce() -> Result<(), CleanupStage>,
    C: FnOnce() -> Result<(), CleanupStage>,
{
    let persistence_outcome = persistence_check();
    let journal_result = journal_finalization();
    let profile_result = profile_cleanup();
    journal_result
        .and(profile_result)
        .map(|()| persistence_outcome)
}

struct ProductionSessionCleanup {
    journal: SharedLaunchJournal,
    launch_attempt_id: String,
    terminal_outcome: Option<BrowserSessionTerminalOutcome>,
    persistence: ProfilePersistenceCheck,
    profile: SharedRollback,
}

impl ProductionSessionCleanup {
    /// Record how this session ended, releasing the journal charge it reserved.
    ///
    /// Separate from profile cleanup so that neither can skip the other: they
    /// are independent obligations over different resources, and a single `?`
    /// chain between them silently makes the second conditional on the first.
    fn finalize_journal(
        journal: &SharedLaunchJournal,
        launch_attempt_id: &str,
        terminal_outcome: &mut Option<BrowserSessionTerminalOutcome>,
    ) -> Result<(), CleanupStage> {
        let outcome = terminal_outcome
            .take()
            .ok_or(CleanupStage::RecordTerminalization)?;
        let mut journal_guard = journal
            .lock()
            .map_err(|_| CleanupStage::RecordTerminalization)?;
        let journal = journal_guard
            .as_mut()
            .ok_or(CleanupStage::RecordTerminalization)?;
        journal
            .finalize_session(launch_attempt_id, outcome)
            .map_err(|_| CleanupStage::RecordTerminalization)
    }
}

impl SessionCleanup for ProductionSessionCleanup {
    fn set_terminal_outcome(&mut self, outcome: BrowserSessionTerminalOutcome) {
        self.terminal_outcome = Some(outcome);
    }

    fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
        // All obligations run even when an earlier one fails. Custody release
        // permits this agent's next launch, while journal finalization accounts
        // for the completed one; neither may depend on a persistence warning or
        // on the other obligation succeeding.
        let Self {
            journal,
            launch_attempt_id,
            terminal_outcome,
            persistence,
            profile,
        } = self;
        run_cleanup_obligations(
            || persistence.observe(),
            || Self::finalize_journal(journal, launch_attempt_id, terminal_outcome),
            || profile.after_reap(),
        )
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
        session_kind_attested: accepted.session_kind_attested,
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

fn map_readiness_error(error: AttestedReadinessError) -> Value {
    match error {
        // Preserve the startup failure as well as the journal error so callers know why
        // launch failed and that its record may remain open. Other cleanup stages keep
        // their existing generic payload, which does not include the primary failure.
        AttestedReadinessError::Readiness(
            crate::browser_launch_readiness::LaunchReadinessError::CleanupFailed {
                primary,
                stage: crate::browser_launch_readiness::ReadinessCleanupStage::JournalFinalization,
            },
        ) => {
            // Omitted rather than null when there is no startup failure to
            // carry: the launch schema declares `primary` as an object only.
            let mut refusal =
                json!({"outcome": "internal_failure", "stage": "journal_finalization"});
            if let Some(primary) = primary.and_then(|primary| serde_json::to_value(primary).ok()) {
                refusal["primary"] = primary;
            }
            refusal
        }
        AttestedReadinessError::AttestedLaunch(
            AttestedLaunchError::ExecutableIdentityMismatch {
                claim_kind,
                expected_identity,
                observed_identity,
            },
        ) => json!({
            "outcome": "executable_identity_mismatch",
            "claim_kind": claim_kind,
            "expected_identity": expected_identity,
            "observed_identity": observed_identity,
        }),
        AttestedReadinessError::AttestedLaunch(AttestedLaunchError::PlatformRefused { error }) => {
            error.refusal()
        }
        AttestedReadinessError::Readiness(
            crate::browser_launch_readiness::LaunchReadinessError::ProfileStartupIndeterminate(
                failure,
            ),
        ) => serde_json::to_value(failure).unwrap_or_else(|_| {
            json!({
                "outcome": "internal_failure",
                "stage": "readiness_error_serialization",
            })
        }),
        AttestedReadinessError::Readiness(
            crate::browser_launch_readiness::LaunchReadinessError::CleanupFailed { .. },
        )
        | AttestedReadinessError::CleanupFailed { .. }
        | AttestedReadinessError::AttestedLaunch(AttestedLaunchError::TerminationOrReapFailed) => {
            json!({"outcome":"cleanup_failure","stage":"reap"})
        }
        // The error's Debug text is internal state and may name launch paths;
        // the stage is what a caller can act on.
        _ => json!({
            "outcome": "internal_failure",
            "stage": "readiness_error_mapping",
        }),
    }
}

fn production_registry_config() -> RegistryConfig {
    RegistryConfig {
        uuid_protocol_compatible: true,
        grant_verifier_available: true,
        grant_accepted: true,
        sealing_available: true,
        ..RegistryConfig::default()
    }
}

/// Open the exact registry configuration used by production browser launches.
///
/// Public for the restore drill (`examples/launch_restore_drill.rs`), which
/// must open the registry the way a launch does rather than carry a copy of
/// this configuration that would drift from it.
#[doc(hidden)]
pub fn production_profile_lifecycle() -> Result<ProfileLifecycle, ProductionProfileLifecycleError> {
    let root = browser_data_root().map_err(|()| ProductionProfileLifecycleError::DataRoot)?;
    ProfileLifecycle::open_with_config(root, production_registry_config())
        .map_err(ProductionProfileLifecycleError::Registry)
}

fn browser_data_root() -> Result<PathBuf, ()> {
    // The daemon's data-home ladder (XDG_DATA_HOME first), not a bare HOME
    // read, for the same reason the journal uses it: the backup catalog
    // resolves against the daemon's root, and profiles written under a
    // different one are undeclarable.
    let root = cerebellum_core::platform_dirs::data_home()
        .ok_or(())?
        .join("cortexkit")
        // Under the module's own directory rather than beside it: the fleet's
        // backup enrollment resolves declared paths against
        // `<data home>/cortexkit/<module id>/` and refuses `..`, so a sibling
        // directory cannot be declared at all -- neither captured nor
        // deliberately excluded, and indistinguishable from an oversight.
        .join("cerebellum")
        .join("browser");
    // Created here because the registry deliberately refuses to: it opens an
    // existing directory and rejects a symlink or a non-directory, which is the
    // right posture for something that will hold logged-in profiles. Nothing
    // else creates it, so without this the FIRST launch on a machine fails and
    // every later one fails identically — a permanent refusal that no test can
    // see, because every fixture supplies a directory it made itself.
    //
    // Not created at boot: a module that never launches a browser has no reason
    // to leave a directory behind, and the failure to create is reported at the
    // moment a caller asked for something that needs it.
    std::fs::create_dir_all(&root).map_err(|_| ())?;
    Ok(root)
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

fn pipe_pair(
    pipe: &'static str,
) -> Result<
    (
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    ),
    Value,
> {
    std::os::unix::net::UnixStream::pair().map_err(|_| {
        json!({
            "outcome": "internal_failure",
            "stage": "spawn_preparation",
            "pipe": pipe,
        })
    })
}

#[cfg(test)]
mod executable_identity_launch_tests {
    use super::*;
    use cerebellum_core::identity::{RouteIdentity, RouteSurface, SessionKind};

    #[test]
    fn linux_browser_launch_environment_allows_only_display_prerequisites() {
        let profile = Path::new("/tmp/browser-profile");
        let parent_environment = [
            (OsString::from("DISPLAY"), OsString::from(":7")),
            (
                OsString::from("XAUTHORITY"),
                OsString::from("/run/user/1000/xauthority"),
            ),
            (
                OsString::from("XDG_RUNTIME_DIR"),
                OsString::from("/run/user/1000"),
            ),
            (
                OsString::from("WAYLAND_DISPLAY"),
                OsString::from("wayland-1"),
            ),
            (OsString::from("HOME"), OsString::from("/home/operator")),
            (
                OsString::from("XDG_CONFIG_HOME"),
                OsString::from("/home/operator/.config"),
            ),
            (
                OsString::from("LD_PRELOAD"),
                OsString::from("/tmp/inject.so"),
            ),
        ];

        assert_eq!(
            linux_browser_launch_environment_from(profile, parent_environment),
            vec![
                (
                    OsString::from("XDG_CONFIG_HOME"),
                    OsString::from("/tmp/browser-profile/config"),
                ),
                (OsString::from("DISPLAY"), OsString::from(":7")),
                (
                    OsString::from("XAUTHORITY"),
                    OsString::from("/run/user/1000/xauthority"),
                ),
                (
                    OsString::from("XDG_RUNTIME_DIR"),
                    OsString::from("/run/user/1000"),
                ),
                (
                    OsString::from("WAYLAND_DISPLAY"),
                    OsString::from("wayland-1"),
                ),
                (OsString::from("HOME"), OsString::from("/home/operator")),
            ]
        );

        let without_display = linux_browser_launch_environment_from(
            profile,
            [(OsString::from("HOME"), OsString::from("/home/operator"))],
        );
        assert!(!without_display.iter().any(|(name, _)| name == "DISPLAY"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_browser_launch_environment_remains_empty() {
        assert!(browser_launch_environment(Path::new("/tmp/browser-profile")).is_empty());
    }

    #[test]
    fn browser_probe_arguments_include_a_separate_throwaway_crash_dumps_path() {
        let profile = Path::new("/tmp/probe-profile");
        let crash_dumps = profile.join("crash");
        assert_eq!(
            browser_launch_arguments(profile, &crash_dumps),
            vec![
                OsString::from("--remote-debugging-pipe"),
                OsString::from("--user-data-dir=/tmp/probe-profile"),
                OsString::from("--crash-dumps-dir=/tmp/probe-profile/crash"),
                OsString::from("--no-first-run"),
                OsString::from("--no-default-browser-check"),
            ]
        );
    }

    struct UnsignedExecutable(PathBuf);

    impl UnsignedExecutable {
        fn new() -> Self {
            // NOT under `std::env::temp_dir()`. Measured on macOS 27.0: these
            // exact bytes under `$TMPDIR` make `codesign -d` never return,
            // while the same bytes under `/tmp` answer instantly -- the
            // system-policy evaluation that applies to the per-user temp
            // directory does not apply here. Left in `$TMPDIR`, this fixture
            // measured the host's `syspolicyd` instead of our refusal path, and
            // it hung the whole suite indefinitely rather than failing.
            let path = Path::new("/tmp").join(format!(
                "ck-unsigned-browser-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::write(&path, b"not a signed executable").expect("write unsigned executable");
            Self(path)
        }
    }

    impl Drop for UnsignedExecutable {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn accepted_facts(project_root: &Path) -> AcceptedBindFacts {
        AcceptedBindFacts {
            identity: RouteIdentity {
                conversation_key: "conversation-1".to_string(),
                agent_project_id: "project-1".to_string(),
                session_kind: SessionKind::Primary,
                profile_disposition: ProfileDisposition::Durable,
                project_root: project_root.to_path_buf(),
            },
            principal: None,
            agent_project_id_attested: true,
            session_kind_attested: true,
            control_operations: Vec::new(),
            effective_capability_scope: None,
            consumer_capabilities: Vec::new(),
            surface: RouteSurface::Tools,
        }
    }

    #[test]
    fn launch_reports_missing_expected_identity_by_stage() {
        let executable = UnsignedExecutable::new();
        let config = BrowserConfig {
            executable_path: Some(executable.0.clone()),
            expected_identity: None,
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
            browser_idle_timeout_ms: 30_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 1_000,
        };
        let service = ProductionLaunchService::open_with_recovery(config, |_| (None, None));
        let refusal = match service.launch(&accepted_facts(Path::new("/tmp")), "session-1") {
            Err(refusal) => refusal,
            Ok(_) => panic!("launch proceeded without a configured expected identity"),
        };

        assert_eq!(refusal["outcome"], "internal_failure");
        assert_eq!(refusal["stage"], "expected_identity");
        assert!(refusal.get("detail").is_none());
    }

    #[test]
    fn launch_refuses_when_executable_identity_cannot_be_established() {
        let executable = UnsignedExecutable::new();
        let config = BrowserConfig {
            executable_path: Some(executable.0.clone()),
            expected_identity: Some("com.example.browser".to_string()),
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
            browser_idle_timeout_ms: 30_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 1_000,
        };
        let service = ProductionLaunchService::open_with_recovery(config, |_| (None, None));
        let refusal = match service.launch(&accepted_facts(Path::new("/tmp")), "session-1") {
            Err(refusal) => refusal,
            Ok(_) => panic!("launch proceeded without an executable identity"),
        };

        assert_eq!(refusal["outcome"], "identity_unverifiable");
        assert_ne!(refusal["outcome"], "executable_identity_mismatch");
        #[cfg(target_os = "macos")]
        assert_eq!(refusal["reason"], "verifier_failed");
        #[cfg(not(target_os = "macos"))]
        assert_eq!(refusal["reason"], "configured_digest_invalid");
    }

    #[test]
    fn poisoned_profile_registry_lock_reports_named_stage() {
        let lock = Arc::new(Mutex::new(()));
        let poisoned_lock = Arc::clone(&lock);
        let panic = std::thread::spawn(move || {
            let _guard = poisoned_lock.lock().expect("acquire lock for poisoning");
            panic!("poison the fixture lock");
        });
        assert!(panic.join().is_err());

        let refusal = match map_poisoned_mutex(lock.lock(), "profile_registry_lock") {
            Ok(_) => panic!("poisoned lock was recovered"),
            Err(refusal) => refusal,
        };
        assert_eq!(
            refusal,
            json!({"outcome": "internal_failure", "stage": "profile_registry_lock"})
        );
    }

    /// A launch refusal is only useful if it reaches the caller. The wire
    /// boundary withholds any reply its closed schema does not declare, and
    /// browser.launch declares `detail` as the invalid-request object, so the
    /// free-text `detail` this refusal used to carry got it withheld as a
    /// schema violation instead of delivered.
    #[test]
    fn poisoned_profile_registry_lock_refusal_passes_the_launch_reply_schema() {
        let lock = Arc::new(Mutex::new(()));
        let poisoned_lock = Arc::clone(&lock);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned_lock.lock();
            panic!("poison the fixture lock");
        })
        .join();

        let Err(refusal) = map_poisoned_mutex(lock.lock(), "profile_registry_lock") else {
            panic!("poisoned lock was recovered");
        };
        assert_eq!(
            crate::browser::validate_browser_result(
                crate::browser_session::BROWSER_LAUNCH,
                &refusal
            ),
            Ok(()),
            "{refusal}"
        );
    }
}

#[cfg(test)]
mod cleanup_ordering_tests {
    use super::*;

    /// A journal failure must not strand the profile custody lock.
    ///
    /// The two obligations cover different resources and neither may be skipped
    /// by the other's failure. The lock released by profile cleanup is what
    /// permits this agent's NEXT launch, so chaining the steps with `?`
    /// converts a lost audit record into an agent locked out of its own browser
    /// until someone deletes a file by hand — far worse than the failure that
    /// caused it.
    ///
    /// Reproduced against a real browser before the fix: a launch whose journal
    /// step failed left a `.lock` file behind, and the next launch was refused
    /// `profile_busy` naming a holder that no longer existed.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_journal_failure_still_releases_the_profile_lock() {
        let root = std::env::temp_dir().join(format!(
            "ck-cleanup-order-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("root");

        let lifecycle = Arc::new(Mutex::new(
            ProfileLifecycle::open_with_config(&root, RegistryConfig::default())
                .expect("lifecycle"),
        ));
        let locks = Arc::new(Mutex::new(
            ProfileCustodyLocks::open_filesystem(&root).expect("locks"),
        ));

        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&released);
        let rollback = SharedRollback {
            state: Arc::new(Mutex::new(Some(SharedRollbackState {
                lifecycle,
                locks,
                rollback: Some(Box::new(move |_lifecycle, _locks| {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                })),
            }))),
        };

        let mut cleanup = ProductionSessionCleanup {
            // No journal bound, so the finalize step cannot succeed.
            journal: Arc::new(Mutex::new(None)),
            launch_attempt_id: "attempt-under-test".to_string(),
            terminal_outcome: Some(BrowserSessionTerminalOutcome::Closed),
            persistence: ProfilePersistenceCheck {
                disposition: ProfileDisposition::Disposable,
                profile_directory: root.clone(),
                launch_started_at: SystemTime::now(),
            },
            profile: rollback,
        };

        let result = cleanup.after_reap();

        assert_eq!(
            result,
            Err(CleanupStage::RecordTerminalization),
            "the journal failure must still be reported"
        );
        assert!(
            released.load(std::sync::atomic::Ordering::SeqCst),
            "the profile lock was stranded by a journal failure"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn persistence_warning_still_finalizes_the_journal_and_releases_custody() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let persistence_events = Arc::clone(&events);
        let journal_events = Arc::clone(&events);
        let custody_events = Arc::clone(&events);

        let result = run_cleanup_obligations(
            move || {
                persistence_events.lock().unwrap().push("persistence");
                SessionCleanupOutcome::DurableStateAtRisk {
                    local_state_not_written_since_launch: false,
                    profile_not_writable: true,
                }
            },
            move || {
                journal_events.lock().unwrap().push("journal");
                Ok(())
            },
            move || {
                custody_events.lock().unwrap().push("custody");
                Ok(())
            },
        );

        assert_eq!(
            result,
            Ok(SessionCleanupOutcome::DurableStateAtRisk {
                local_state_not_written_since_launch: false,
                profile_not_writable: true,
            })
        );
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["persistence", "journal", "custody"]
        );
    }
}

#[cfg(test)]
mod profile_persistence_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    use cerebellum_core::clock::FakeClock;
    use serde_json::json;

    use crate::browser_session::{BrowserSessions, OwnedBrowserProcess, ProcessControlFailure};

    struct PersistenceTestRoot(PathBuf);

    impl PersistenceTestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "ck-profile-persistence-{label}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).expect("create profile test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for PersistenceTestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct PermissionRestore {
        path: PathBuf,
        mode: u32,
    }

    impl PermissionRestore {
        fn make_unwritable(path: &Path) -> Self {
            let mode = std::fs::metadata(path)
                .expect("profile metadata")
                .permissions()
                .mode();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500))
                .expect("make profile unwritable");
            Self {
                path: path.to_path_buf(),
                mode,
            }
        }
    }

    impl Drop for PermissionRestore {
        fn drop(&mut self) {
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode))
                .expect("restore profile permissions");
        }
    }

    struct AlreadyReapedProcess;

    impl OwnedBrowserProcess for AlreadyReapedProcess {
        fn generation_matches(&self) -> bool {
            false
        }

        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }

        fn wait_for_exit(
            &mut self,
            _grace_period: Duration,
        ) -> Result<bool, ProcessControlFailure> {
            Ok(true)
        }

        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }

        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }
    }

    struct PersistenceOnlyCleanup(ProfilePersistenceCheck);

    impl SessionCleanup for PersistenceOnlyCleanup {
        fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
            Ok(self.0.observe())
        }
    }

    fn close_with_check(check: ProfilePersistenceCheck) -> Value {
        let disposition = check.disposition;
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let config = BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 1,
            termination_grace_period_ms: 1,
            browser_idle_timeout_ms: 1,
            browser_exit_observation_deadline_ms: 1,
            navigation_settle_deadline_ms: 1,
        };
        let _ = sessions.acquire_launch_slot("persistence-test");
        let (session_id, _, cancelled) = sessions
            .establish_ready(
                "persistence-test",
                disposition,
                &config,
                &clock,
                Box::new(AlreadyReapedProcess),
                Box::new(PersistenceOnlyCleanup(check)),
            )
            .expect("establish test session");
        assert!(!cancelled);
        sessions.close("persistence-test", &session_id, &config)
    }

    fn durable_check(path: &Path, launch_started_at: SystemTime) -> ProfilePersistenceCheck {
        ProfilePersistenceCheck {
            disposition: ProfileDisposition::Durable,
            profile_directory: path.to_path_buf(),
            launch_started_at,
        }
    }

    #[test]
    fn local_state_signal_reports_when_chrome_write_was_not_observed() {
        let root = PersistenceTestRoot::new("old-local-state");
        std::fs::write(root.path().join("Local State"), b"before launch")
            .expect("write old Local State");

        let result = close_with_check(durable_check(
            root.path(),
            SystemTime::now() + Duration::from_secs(60),
        ));

        assert_eq!(
            result,
            json!({
                "outcome": "durable_state_at_risk",
                "browser_session_id": result["browser_session_id"],
                "failed_signals": ["local_state_not_written_since_launch"],
            })
        );
    }

    #[test]
    fn writable_probe_reports_when_profile_becomes_unwritable_after_launch() {
        let root = PersistenceTestRoot::new("unwritable");
        std::fs::write(root.path().join("Local State"), b"written after launch")
            .expect("write Local State");
        let restore = PermissionRestore::make_unwritable(root.path());

        let result = close_with_check(durable_check(root.path(), std::time::UNIX_EPOCH));
        drop(restore);

        assert_eq!(
            result,
            json!({
                "outcome": "durable_state_at_risk",
                "browser_session_id": result["browser_session_id"],
                "failed_signals": ["profile_not_writable"],
            })
        );
    }

    #[test]
    fn healthy_durable_teardown_adds_no_persistence_claim_or_warning() {
        let root = PersistenceTestRoot::new("healthy");
        std::fs::write(root.path().join("Local State"), b"written after launch")
            .expect("write Local State");

        let result = close_with_check(durable_check(root.path(), std::time::UNIX_EPOCH));

        assert_eq!(result["outcome"], "closed");
        assert!(result.get("failed_signals").is_none());
        assert!(result.get("persisted").is_none());
    }

    #[test]
    fn disposable_teardown_reports_no_persistence_outcome() {
        let root = PersistenceTestRoot::new("disposable");
        let result = close_with_check(ProfilePersistenceCheck {
            disposition: ProfileDisposition::Disposable,
            profile_directory: root.path().join("already-discarded"),
            launch_started_at: SystemTime::now() + Duration::from_secs(60),
        });

        assert_eq!(result["outcome"], "closed");
        assert!(result.get("failed_signals").is_none());
        assert!(result.get("persisted").is_none());
    }
}

#[cfg(all(test, target_os = "macos"))]
mod orphan_recovery_tests {
    use super::*;
    use crate::browser_launch::{
        AuthorizedLaunchIntent, LaunchProfileIdentity, LaunchRouteIdentity, VerifiedLaunchVector,
    };
    use crate::profile_custody::{
        SupervisorGeneration, SupervisorLiveness, SupervisorLivenessProbe,
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "cerebellum-orphan-recovery-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).expect("create test root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Copy)]
    struct NoLiveSupervisor;

    impl SupervisorLivenessProbe for NoLiveSupervisor {
        fn observe(&self, _generation: SupervisorGeneration) -> SupervisorLiveness {
            SupervisorLiveness::NotLive
        }
    }

    fn installed_durable_claim(root: &Path) -> AuthorizedLaunchIntent {
        let old_supervisor = SupervisorGeneration {
            pid: u32::MAX,
            start_time: 17,
            boot_id: None,
        };
        let journal = FilesystemProfileCustodyJournal::open(root.join(PROFILE_CUSTODY_DIRECTORY))
            .expect("open custody journal");
        let mut locks = ProfileCustodyLocks::open(root, old_supervisor, journal, NoLiveSupervisor)
            .expect("open old custody locks");
        let holder = locks.mint_holder().expect("mint holder");
        let claim = match locks
            .acquire(ProfileCustodyKey::durable("project-1"), holder)
            .expect("acquire old claim")
        {
            ProfileCustodyAcquisition::Acquired(claim) => claim,
            ProfileCustodyAcquisition::ProfileBusy { .. } => panic!("empty root was busy"),
        };
        AuthorizedLaunchIntent {
            format_version: "ck-browser-launch-attestation/v2".to_string(),
            launch_attempt_id: "attempt-1".to_string(),
            holder_id: claim.holder_id().as_str().to_string(),
            route: LaunchRouteIdentity {
                principal: "direct:agent".to_string(),
                conversation_key: "conversation-1".to_string(),
                agent_project_id: "project-1".to_string(),
                session_kind: cerebellum_core::identity::SessionKind::Primary,
            },
            profile: LaunchProfileIdentity {
                profile_uuid: "profile-1".to_string(),
                canonical_profile_path: path_bytes(&root.join("profiles/profile-1")),
                disposition: crate::browser_launch::LaunchProfile::Registry(
                    ProfileDisposition::Durable,
                ),
            },
            verified_executable_identity:
                crate::browser_launch::VerifiedExecutableIdentity::CodeSignedFile {
                    signing_identifier: "com.example.browser".to_string(),
                    slice_code_hashes: std::collections::BTreeSet::from(["abc123".to_string()]),
                },
            launch_vector: VerifiedLaunchVector {
                executable: b"/Applications/Browser".to_vec(),
                arguments: Vec::new(),
                environment: Vec::new(),
            },
        }
    }

    fn test_config() -> BrowserConfig {
        BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
            browser_idle_timeout_ms: 30_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 100,
        }
    }

    fn lock_count(root: &Path) -> usize {
        std::fs::read_dir(root.join(PROFILE_CUSTODY_DIRECTORY))
            .expect("read custody directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.len() == 69 && name.ends_with(".lock"))
            })
            .count()
    }

    #[test]
    fn startup_recovery_releases_the_exact_recorded_profile_holder() {
        let root = TestRoot::new("exact-holder");
        let intent = installed_durable_claim(&root.0);
        assert_eq!(lock_count(&root.0), 1);

        let result = release_orphan_profile_custody_at(&root.0, &intent);

        assert_eq!(result, Ok(()));
        assert_eq!(lock_count(&root.0), 0);
    }

    #[test]
    fn startup_recovery_never_releases_a_different_profile_holder() {
        let root = TestRoot::new("different-holder");
        let mut intent = installed_durable_claim(&root.0);
        intent.holder_id = "holder-from-another-attempt".to_string();
        assert_eq!(lock_count(&root.0), 1);

        let result = release_orphan_profile_custody_at(&root.0, &intent);

        assert_eq!(result, Err(()));
        assert_eq!(lock_count(&root.0), 1);
    }

    #[test]
    fn launch_service_is_not_published_while_startup_recovery_is_running() {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (service_tx, service_rx) = std::sync::mpsc::channel();

        let worker = std::thread::spawn(move || {
            let service = ProductionLaunchService::open_with_recovery(test_config(), |_| {
                entered_tx.send(()).expect("announce recovery start");
                release_rx.recv().expect("finish recovery");
                (
                    None,
                    Some(BrowserLaunchRecoveryFailure::JournalTerminalization),
                )
            });
            service_tx.send(service).expect("publish recovered service");
        });

        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("startup recovery did not begin");
        assert!(matches!(
            service_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        release_tx.send(()).expect("release startup recovery");
        let service = service_rx.recv().expect("receive recovered service");
        worker.join().expect("join recovery worker");
        assert_eq!(
            service.startup_failure,
            Some(BrowserLaunchRecoveryFailure::JournalTerminalization)
        );
    }

    #[test]
    fn failed_startup_recovery_has_an_exact_named_launch_refusal() {
        let service = ProductionLaunchService::open_with_recovery(test_config(), |_| {
            (
                None,
                Some(BrowserLaunchRecoveryFailure::JournalTerminalization),
            )
        });

        assert_eq!(
            service.require_recovered_startup(),
            Err(json!({
                "outcome": "internal_failure",
                "stage": "startup_recovery",
                "reason_code": "browser_launch_recovery_failed",
            }))
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_orphan_recovery_tests {
    use super::*;
    use crate::profile_custody::{BootId, GenerationObservation};

    fn sleeping_fixture() -> (std::process::Child, BrowserProcessGeneration) {
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn orphan-control fixture");
        let pid = child.id();
        let (boot_id, start_ticks) = crate::profile_custody::linux_current_generation(pid)
            .expect("fixture generation is readable");
        (
            child,
            BrowserProcessGeneration {
                pid,
                start_time_micros: start_ticks,
                boot_id: Some(boot_id),
            },
        )
    }

    fn still_running(generation: BrowserProcessGeneration) -> bool {
        linux_generation_liveness(generation) == SupervisorLiveness::Live
    }

    #[test]
    fn linux_orphan_control_observes_and_reaps_the_exact_generation() {
        let (mut child, generation) = sleeping_fixture();
        let mut control = LinuxOrphanProcessControl {
            reap_deadline: Duration::from_secs(1),
        };

        assert_eq!(
            control.observe_generation(generation),
            GenerationObservation::BootTicks {
                boot_id: generation.boot_id.unwrap(),
                start_ticks: generation.start_time_micros,
            }
        );
        control
            .terminate_and_reap(generation)
            .expect("terminate exact orphan generation");
        assert_eq!(
            cerebellum_linux::process_generation(generation.pid),
            cerebellum_linux::ProcessGenerationReading::NoSuchProcess
        );
        let _ = child.wait();
    }

    #[test]
    fn linux_orphan_control_does_not_signal_a_different_generation() {
        let (mut child, generation) = sleeping_fixture();
        let mut control = LinuxOrphanProcessControl {
            reap_deadline: Duration::from_secs(1),
        };

        control
            .terminate_and_reap(BrowserProcessGeneration {
                start_time_micros: generation.start_time_micros.saturating_sub(1),
                ..generation
            })
            .expect("mismatched generation is already gone-or-replaced");
        assert!(still_running(generation));
        child.kill().expect("clean up mismatch fixture");
        let _ = child.wait();
    }

    #[test]
    fn linux_orphan_control_does_not_signal_a_generation_from_another_boot() {
        let (mut child, generation) = sleeping_fixture();
        let mut other_boot = *generation.boot_id.unwrap().as_bytes();
        other_boot[0] ^= 0xff;
        let mut control = LinuxOrphanProcessControl {
            reap_deadline: Duration::from_secs(1),
        };

        control
            .terminate_and_reap(BrowserProcessGeneration {
                boot_id: Some(BootId::from_bytes(other_boot)),
                ..generation
            })
            .expect("a previous boot's process is gone");
        assert!(still_running(generation));
        child.kill().expect("clean up cross-boot fixture");
        let _ = child.wait();
    }

    #[test]
    fn linux_orphan_control_refuses_a_legacy_record_whose_start_time_moved() {
        let (mut child, generation) = sleeping_fixture();
        let micros = match cerebellum_linux::process_start_time(generation.pid) {
            cerebellum_linux::ProcessStartTime::Started(start_time) => start_time,
            other => panic!("unexpected fixture start-time reading: {other:?}"),
        };
        let mut control = LinuxOrphanProcessControl {
            reap_deadline: Duration::from_secs(1),
        };

        // A pre-boot-ID record that differs from the live epoch reading may be
        // a clock step over this very process, so it is neither signalled nor
        // reported as gone.
        assert_eq!(
            control.terminate_and_reap(BrowserProcessGeneration {
                pid: generation.pid,
                start_time_micros: micros - 7_201_000_000,
                boot_id: None,
            }),
            Err(OrphanProcessControlFailure)
        );
        assert!(still_running(generation));
        child.kill().expect("clean up legacy fixture");
        let _ = child.wait();
    }
}

#[cfg(test)]
#[test]
fn journal_finalization_refusal_preserves_primary_startup_payload() {
    use crate::browser_launch_readiness::{
        LaunchReadinessError, ProfileStartupCause, ProfileStartupIndeterminate,
        ReadinessCleanupStage,
    };
    let value = map_readiness_error(AttestedReadinessError::Readiness(
        LaunchReadinessError::CleanupFailed {
            primary: Some(ProfileStartupIndeterminate::new(
                ProfileStartupCause::DeadlineExpired,
            )),
            stage: ReadinessCleanupStage::JournalFinalization,
        },
    ));
    assert_eq!(
        value,
        json!({
            "outcome": "internal_failure", "stage": "journal_finalization",
            "primary": { "outcome": "profile_startup_indeterminate", "cause": "deadline_expired",
                "ambiguity": "indeterminate_startup_failure", "possible_reasons": [
                    "external_profile_holder", "profile_unopenable_or_corrupt", "browser_startup_failure",
                    "invalid_browser_invocation", "platform_or_sandbox_denial"
                ] }
        })
    );
}

#[cfg(test)]
mod launch_refusal_schema_tests {
    use super::*;
    use crate::browser_launch::{BrowserLaunchRecoveryFailure, LaunchRecordStage};
    use crate::browser_launch_readiness::{
        LaunchReadinessError, ProfileStartupCause, ProfileStartupIndeterminate,
        ReadinessCleanupStage,
    };
    use crate::profile::{ArtifactError, RootError, UntrustworthyRegistryReason};

    fn assert_declared(reply: &Value) {
        assert_eq!(
            crate::browser::validate_browser_result(crate::browser_session::BROWSER_LAUNCH, reply),
            Ok(()),
            "{reply} is a browser.launch reply the launch schema does not declare"
        );
    }

    fn registry_errors() -> Vec<RegistryError> {
        let all = vec![
            RegistryError::Root(RootError::NotDirectory),
            RegistryError::Artifact(ArtifactError::InvalidJson),
            RegistryError::Io(io::Error::other("fixture")),
            RegistryError::UnknownField("/profiles/0000-uuid".to_string()),
            RegistryError::UnsupportedState,
            RegistryError::Conflict,
            RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts,
            ),
            RegistryError::Untrustworthy(UntrustworthyRegistryReason::MalformedRegistry),
            RegistryError::InvalidTransition,
        ];
        // Exhaustive without a wildcard: a new registry error does not compile
        // until it is rendered above.
        for error in &all {
            match error {
                RegistryError::Root(_)
                | RegistryError::Artifact(_)
                | RegistryError::Io(_)
                | RegistryError::UnknownField(_)
                | RegistryError::UnsupportedState
                | RegistryError::Conflict
                | RegistryError::Untrustworthy(_)
                | RegistryError::InvalidTransition => {}
            }
        }
        all
    }

    #[test]
    fn every_profile_lifecycle_refusal_passes_the_launch_reply_schema() {
        let mut replies = vec![ProductionProfileLifecycleError::DataRoot.into_launch_refusal()];
        for error in registry_errors() {
            replies.push(ProductionProfileLifecycleError::Registry(error).into_launch_refusal());
        }
        for reply in &replies {
            assert_declared(reply);
            // Registry errors can carry paths, and profile directories are
            // named by profile UUID; neither may reach the wire as text.
            assert!(reply.get("detail").is_none(), "{reply}");
            assert!(!reply.to_string().contains("uuid"), "{reply}");
        }
    }

    /// A registry that no longer trusts its root has its own remedy, so it is
    /// rendered as that typed refusal rather than as a storage failure.
    #[test]
    fn an_untrusted_registry_at_open_keeps_its_typed_outcome_and_remedy() {
        let reply = ProductionProfileLifecycleError::Registry(RegistryError::Untrustworthy(
            UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts,
        ))
        .into_launch_refusal();
        assert_eq!(
            reply["outcome"], "profile_registry_untrusted_root",
            "{reply}"
        );
        assert!(reply["remedy"].is_string(), "{reply}");
    }

    #[test]
    fn every_startup_recovery_refusal_passes_the_launch_reply_schema() {
        let failures = [
            BrowserLaunchRecoveryFailure::JournalOpen,
            BrowserLaunchRecoveryFailure::JournalRead { sequence: 7 },
            BrowserLaunchRecoveryFailure::ProcessObservation { sequence: 7 },
            BrowserLaunchRecoveryFailure::ProcessTermination { sequence: 7 },
            BrowserLaunchRecoveryFailure::JournalTerminalization,
            BrowserLaunchRecoveryFailure::ProfileCustodyRelease { sequence: 7 },
            BrowserLaunchRecoveryFailure::InvalidIntent { sequence: 7 },
        ];
        for failure in failures {
            match failure {
                BrowserLaunchRecoveryFailure::JournalOpen
                | BrowserLaunchRecoveryFailure::JournalRead { .. }
                | BrowserLaunchRecoveryFailure::ProcessObservation { .. }
                | BrowserLaunchRecoveryFailure::ProcessTermination { .. }
                | BrowserLaunchRecoveryFailure::JournalTerminalization
                | BrowserLaunchRecoveryFailure::ProfileCustodyRelease { .. }
                | BrowserLaunchRecoveryFailure::InvalidIntent { .. } => {}
            }
            assert_declared(&launch_recovery_refusal(failure));
        }
    }

    #[test]
    fn every_readiness_refusal_passes_the_launch_reply_schema() {
        let causes = [
            ProfileStartupCause::ChildExit,
            ProfileStartupCause::PipeClosed,
            ProfileStartupCause::DeadlineExpired,
        ];
        let mut errors = Vec::new();
        for cause in causes {
            errors.push(AttestedReadinessError::Readiness(
                LaunchReadinessError::ProfileStartupIndeterminate(
                    ProfileStartupIndeterminate::new(cause),
                ),
            ));
            errors.push(AttestedReadinessError::Readiness(
                LaunchReadinessError::CleanupFailed {
                    primary: Some(ProfileStartupIndeterminate::new(cause)),
                    stage: ReadinessCleanupStage::JournalFinalization,
                },
            ));
        }
        for stage in [
            ReadinessCleanupStage::Reap,
            ReadinessCleanupStage::Rollback,
            ReadinessCleanupStage::JournalFinalization,
        ] {
            errors.push(AttestedReadinessError::Readiness(
                LaunchReadinessError::CleanupFailed {
                    primary: None,
                    stage,
                },
            ));
        }
        errors.push(AttestedReadinessError::Readiness(
            LaunchReadinessError::HandshakeSetupFailed,
        ));
        errors.push(AttestedReadinessError::CleanupFailed {
            primary: AttestedLaunchError::SpawnFailed,
            stage: ReadinessCleanupStage::Reap,
        });
        for claim_kind in ["code_signed", "image_digest"] {
            errors.push(AttestedReadinessError::AttestedLaunch(
                AttestedLaunchError::ExecutableIdentityMismatch {
                    claim_kind: claim_kind.to_string(),
                    expected_identity: "expected".to_string(),
                    observed_identity: "observed".to_string(),
                },
            ));
        }
        errors.push(AttestedReadinessError::AttestedLaunch(
            AttestedLaunchError::PlatformRefused {
                error: crate::browser_launch::PlatformLaunchError::Spawn,
            },
        ));
        for error in [
            AttestedLaunchError::JournalRecordFailed {
                stage: LaunchRecordStage::Intent,
            },
            AttestedLaunchError::SpawnFailed,
            AttestedLaunchError::ImageAttestationFailed {
                expected_identity: "/Applications/Browser.app".to_string(),
            },
            AttestedLaunchError::TerminationOrReapFailed,
            AttestedLaunchError::ReleaseFailed,
        ] {
            errors.push(AttestedReadinessError::AttestedLaunch(error));
        }
        for error in errors {
            let rendered = format!("{error:?}");
            let reply = map_readiness_error(error);
            assert_declared(&reply);
            assert!(
                !reply.to_string().contains("/Applications"),
                "{rendered} leaked its Debug text into {reply}"
            );
        }
    }
}
