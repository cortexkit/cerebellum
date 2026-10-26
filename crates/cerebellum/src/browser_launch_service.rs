//! Production browser launch composition from accepted route facts.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::num::NonZeroU64;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::browser::navigation::{
    BrowserScreenshotObservation, BrowserSnapshotObservation, CdpNavigationDriver,
};
use crate::browser::Tracker;
use crate::browser_config::BrowserConfig;
use crate::browser_crash_reports::CrashReportDirectory;
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
    BrowserClickOutcome, BrowserClickPosition, BrowserExitProbe, BrowserInputEvent, BrowserKiller,
    BrowserSessionLauncher, BrowserSessionTerminalOutcome, CleanupStage, ClickDriveError,
    ClickPointDriveError, KillOutcome, LaunchedBrowser, NavigationDriveError, NavigationWait,
    OwnedBrowserProcess, ProcessControlFailure, ProcessControlStep, SessionCleanup,
    SessionCleanupOutcome,
};
use crate::cdp::{CdpFrameDecoder, CdpTransport};
use crate::profile::{
    BindFacts, DispatchCommitmentToken, InvocationToken, JournalReservationHandle,
    ProfileLifecycle, RegistryConfig, RegistryError, StampedBindContext,
};
#[cfg(target_os = "linux")]
use crate::profile_custody::SupervisorLiveness;
use crate::profile_custody::{
    current_supervisor_generation, FilesystemProfileCustodyJournal, HolderId,
    KernelSupervisorLiveness, ProfileCustodyAcquisition, ProfileCustodyClaim, ProfileCustodyEvent,
    ProfileCustodyEventKind, ProfileCustodyJournal, ProfileCustodyKey, ProfileCustodyLocks,
    ProfileCustodyRelease, SupervisorGeneration, SupervisorLivenessProbe,
};
use crate::snapshot_store::{BackendNodeIdentity, SnapshotKind};

type ProductionLaunchJournal = DurableLaunchJournal<crate::PlaneJournalStorage>;

type SharedLaunchJournal = Arc<Mutex<Option<ProductionLaunchJournal>>>;

#[cfg(target_os = "linux")]
use cerebellum_linux::ProcessControlError as PlatformProcessControlError;
#[cfg(target_os = "macos")]
use cerebellum_macos::ProcessControlError as PlatformProcessControlError;

fn process_control_failure(
    step: ProcessControlStep,
    error: PlatformProcessControlError,
) -> ProcessControlFailure {
    let (step, error_kind) = match error {
        PlatformProcessControlError::Reap(kind) => (ProcessControlStep::ReapWait, Some(kind)),
        PlatformProcessControlError::Signal(kind) => (step, Some(kind)),
        #[cfg(target_os = "linux")]
        PlatformProcessControlError::Ptrace(kind) => (step, Some(kind)),
        _ => (step, None),
    };
    ProcessControlFailure { step, error_kind }
}

#[cfg(test)]
#[path = "browser_launch_service_reap_tests.rs"]
mod failed_reap_tests;

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
    profile_root: ProfileStateRoot,
    /// The profiles startup recovery kept, and the operator's way to clear
    /// them. Built before this service exists, so a launch never sees a
    /// partial set.
    recovery: Arc<RecoveryClearState>,
    signed_in: Option<Arc<crate::browser_signed_in::SignedInDomains>>,
}

/// Where a launch service keeps profile state: the profile registry, the
/// custody locks a launch takes, and the custody startup recovery releases or
/// re-takes for an orphaned browser.
///
/// That state follows the same `JournalPersistence` as the launch journal. The
/// data home holds the operator's real, backed-up browser profiles and their
/// custody locks, so a service built for a test must never resolve it: a launch
/// through it would take real custody and write into the real registry.
enum ProfileStateRoot {
    /// The operator's data home, which production uses.
    DataHome,
    /// A private directory created for this service and removed with it.
    Scratch(ScratchProfileRoot),
    /// Isolation was asked for but the private directory could not be
    /// created. Launches refuse at the data-root stage; falling back to the
    /// data home would break the promise isolation makes.
    ScratchUnavailable,
}

impl ProfileStateRoot {
    fn for_persistence(persistence: crate::JournalPersistence) -> Self {
        match persistence {
            crate::JournalPersistence::Durable => Self::DataHome,
            crate::JournalPersistence::Isolated => match ScratchProfileRoot::create() {
                Ok(scratch) => Self::Scratch(scratch),
                Err(_) => Self::ScratchUnavailable,
            },
        }
    }

    /// The directory to open the registry and custody locks in. Reports only
    /// failure, like `browser_data_root`, so a path never reaches a refusal.
    fn resolve(&self) -> Result<PathBuf, ()> {
        match self {
            Self::DataHome => browser_data_root(),
            Self::Scratch(scratch) => Ok(scratch.path.clone()),
            Self::ScratchUnavailable => Err(()),
        }
    }
}

/// A fresh directory under the per-user temporary directory, removed on drop.
///
/// Created with `create`, not `create_dir_all`, so a name that already exists
/// is an error rather than a directory shared with someone else, and under the
/// canonicalized temporary directory because the registry compares its root by
/// real path (on macOS the temporary directory sits behind the `/var` symlink).
struct ScratchProfileRoot {
    path: PathBuf,
}

impl ScratchProfileRoot {
    fn create() -> io::Result<Self> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().canonicalize()?.join(format!(
            "ck-cerebellum-isolated-profiles-{}-{nanos}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        // Owner-only, as profiles and their locks are wherever they live.
        cerebellum_core::private_fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for ScratchProfileRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A launch's profile, opened in the registry and held in custody, with the
/// rollback that gives both back.
struct HeldLaunchProfile {
    profile_directory: PathBuf,
    holder_id: String,
    profile_uuid: String,
    arguments: Vec<OsString>,
    rollback: SharedRollback,
}

impl ProductionLaunchService {
    pub fn with_signed_in_domains(
        mut self,
        signed_in: Arc<crate::browser_signed_in::SignedInDomains>,
    ) -> Self {
        self.signed_in = Some(signed_in);
        self
    }
    /// Open and recover the launch journal before returning a service that can be
    /// published to request handlers. Keeping recovery synchronous here means no
    /// caller can obtain the service while an orphan still contends with a fresh
    /// spawn for the same profile.
    ///
    /// `persistence` decides where the launch journal lives. Recovery acts on
    /// whatever that journal records -- it terminates browsers and moves
    /// profile custody -- so an isolated service must not read the operator's
    /// journal: it gets one in memory, which starts empty and gives recovery
    /// nothing to act on.
    ///
    /// Profile state follows `persistence` too; see [`ProfileStateRoot`].
    pub fn open(config: BrowserConfig, persistence: crate::JournalPersistence) -> Self {
        Self::open_publishing(
            config,
            persistence,
            &crate::launch_recovery::LaunchRecoveryRegistry::new(),
        )
    }

    /// Open as [`Self::open`] does, then publish the operator's clear of what
    /// startup recovery kept into `registry`, which the management plane
    /// consults. Until this returns the registry stays empty, and a clear
    /// refuses `not_ready`.
    pub fn open_publishing(
        config: BrowserConfig,
        persistence: crate::JournalPersistence,
        registry: &crate::launch_recovery::LaunchRecoveryRegistry,
    ) -> Self {
        let profile_root = ProfileStateRoot::for_persistence(persistence);
        let service = Self::open_with_recovery(config, profile_root, |config, profile_root| {
            match open_launch_journal(persistence) {
                Ok(mut journal) => {
                    let mut process = ProductionOrphanProcessControl {
                        reap_deadline: Duration::from_millis(config.termination_grace_period_ms),
                    };
                    let (startup_failure, retained) =
                        recover_and_retain(&mut journal, &mut process, profile_root);
                    // After the orphaned browsers are stopped, so none of them
                    // is still writing into a directory being deleted. Only for
                    // the durable service: an isolated one (a test) must not act
                    // on state that other processes on this machine share.
                    #[cfg(target_os = "macos")]
                    if persistence == crate::JournalPersistence::Durable {
                        crate::browser_crash_reports::remove_leftover_directories();
                    }
                    (Some(journal), startup_failure, retained)
                }
                Err(_) => (
                    None,
                    Some(BrowserLaunchRecoveryFailure::JournalOpen),
                    Vec::new(),
                ),
            }
        });
        registry.publish(service.recovery.clone());
        service
    }

    fn require_recovered_startup(&self) -> Result<(), Value> {
        match self.startup_failure {
            Some(failure) => Err(launch_recovery_refusal(failure)),
            None => Ok(()),
        }
    }

    fn open_with_recovery<F>(
        config: BrowserConfig,
        profile_root: ProfileStateRoot,
        recover: F,
    ) -> Self
    where
        F: FnOnce(
            &BrowserConfig,
            &ProfileStateRoot,
        ) -> (
            Option<ProductionLaunchJournal>,
            Option<BrowserLaunchRecoveryFailure>,
            Vec<RetainedRecoveryClaim>,
        ),
    {
        let (journal, startup_failure, retained) = recover(&config, &profile_root);
        let root = profile_root.resolve().ok();
        if let Some(root) = root.clone() {
            // Opening the registry runs attachment recovery even before the
            // first launch. An unreadable registry stays unchanged; launch
            // retries the open and returns its typed storage refusal.
            let _ = profile_lifecycle_at(root);
        }
        let journal = Arc::new(Mutex::new(journal));
        let recovery = Arc::new(RecoveryClearState {
            journal: Arc::clone(&journal),
            root,
            configured_executable: config.executable_path.clone(),
            retained: Mutex::new(
                retained
                    .into_iter()
                    .map(|claim| (claim.claim.holder_id().as_str().to_string(), claim))
                    .collect(),
            ),
            clearing: Mutex::new(()),
            process_table: Arc::new(crate::launch_recovery::SystemProcessTable),
            #[cfg(test)]
            stage_hook: Mutex::new(None),
        });
        Self {
            config,
            journal,
            startup_failure,
            profile_root,
            recovery,
            signed_in: None,
        }
    }

    /// Open the registry and take profile custody exactly as a launch does,
    /// then give both back, without spawning a browser.
    ///
    /// Public so a test can prove where a service keeps profile state: a real
    /// launch first needs a verified browser executable, which a test machine
    /// may not have. Returns the profile directory the launch would have used.
    #[doc(hidden)]
    pub fn take_and_return_profile_custody(
        &self,
        accepted: &AcceptedBindFacts,
        browser_session_id: &str,
    ) -> Result<PathBuf, Value> {
        let held = self.take_launch_profile(accepted, browser_session_id)?;
        let mut rollback = held.rollback;
        rollback
            .after_reap()
            .map_err(|_| json!({"outcome": "internal_failure", "stage": "custody_release"}))?;
        Ok(held.profile_directory)
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
        let HeldLaunchProfile {
            profile_directory,
            holder_id,
            profile_uuid,
            arguments,
            rollback,
        } = self.take_launch_profile(accepted, browser_session_id)?;
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
        let (environment, crash_reports) = match prepare_launch_environment(&profile_directory) {
            Ok(prepared) => prepared,
            Err(refusal) => return Err(cleanup_before_spawn(rollback.clone(), refusal)),
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
            environment,
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
                reap_recovery: Some(SessionRecovery {
                    evidence: Arc::clone(&self.recovery),
                    durable_project: (accepted.identity.profile_disposition
                        == ProfileDisposition::Durable)
                        .then(|| accepted.identity.agent_project_id.clone()),
                    journal_settled: false,
                    cleanup_result: None,
                }),
                journal: Arc::clone(&self.journal),
                launch_attempt_id: browser_session_id.to_string(),
                terminal_outcome: None,
                persistence: ProfilePersistenceCheck {
                    disposition: accepted.identity.profile_disposition,
                    profile_directory,
                    launch_started_at,
                },
                profile: rollback,
                crash_reports,
            }),
        })
    }

    /// Open the registry and take custody of the profile a launch for
    /// `accepted` uses, returning it with the rollback that gives both back.
    ///
    /// The launch path and [`Self::take_and_return_profile_custody`] share
    /// this, so a test of where profile state lives tests the launch's own path.
    fn take_launch_profile(
        &self,
        accepted: &AcceptedBindFacts,
        browser_session_id: &str,
    ) -> Result<HeldLaunchProfile, Value> {
        // A head not acting for its agent has no durable profile authority.
        if accepted.agent_project_id_attested
            && !accepted.acts_as_agent
            && accepted.identity.session_kind == cerebellum_core::identity::SessionKind::Primary
        {
            return Err(json!({"outcome": "no_profile", "profile_disposition": "none"}));
        }
        if accepted.identity.agent_project_id.is_empty() {
            let refusal =
                cerebellum_core::identity::ControlOperationRefusal::AgentProjectIdUnattested;
            return Err(json!({
                "outcome": "authorization_denied",
                "reason": refusal.reason_code(),
                "remedy": accepted.control_refusal_remedy(refusal),
            }));
        }
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
        // The root reports only failure, so this stage cannot say more than
        // which stage it was -- which is still the fact that was missing.
        let lifecycle = self
            .profile_root
            .resolve()
            .map_err(|()| ProductionProfileLifecycleError::DataRoot)
            .and_then(profile_lifecycle_at)
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
        let mut bound = ProfileBoundLaunch::new(&mut lifecycle_guard, &mut locks_guard)
            .with_launch_timeout(self.config.launch_handshake_deadline_ms);
        let holder = accepted
            .flow_id
            .as_ref()
            .map_or_else(cortexkit_resource_busy::Holder::head, |flow_id| {
                cortexkit_resource_busy::Holder::flow(flow_id.clone())
            });
        let prepared = crate::profile_custody::with_lease_holder(holder, || {
            bound.acquire_and_prepare(key, &invocation, &reservation, &context)
        })
        .map_err(|outcome| self.recovery.name_recovery_hold(outcome).as_json())?;
        let freshly_created = prepared.attempt().freshly_created();
        let profile_name = match prepared.attempt().disposition() {
            crate::profile::ProfileDisposition::Durable => "default".to_string(),
            _ => format!("disposable:{}", context.conversation_key()),
        };
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

        if let Some(signed_in) = &self.signed_in {
            // A new empty profile has no earlier login events that could be
            // missing. If recording its history coverage fails, typing still
            // needs a grant while observation remains available.
            let _ = signed_in.initialize_profile(
                context.agent_project_id(),
                &profile_name,
                &profile_uuid,
                freshly_created,
            );
        }

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

        let mut rollback = SharedRollback::new(
            Arc::clone(&lifecycle),
            Arc::clone(&locks),
            Box::new(move |lifecycle, locks| {
                ProfileBoundLaunch::new(lifecycle, locks).rollback_opened(opened)
            }),
        );
        rollback.holder_id = Some(holder_id.clone());
        drop(locks_guard);
        drop(lifecycle_guard);
        Ok(HeldLaunchProfile {
            profile_directory,
            holder_id,
            profile_uuid,
            arguments,
            rollback,
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
        let (environment, crash_reports) = prepare_launch_environment(&profile_directory)?;

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
            environment,
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
                shutdown_kill: Arc::default(),
            },
            journal: Arc::clone(&self.journal),
            launch_attempt_id: launch_attempt_id.to_string(),
            grace_period: Duration::from_millis(self.config.termination_grace_period_ms),
            closed: false,
            crash_reports,
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
    /// Deleted when the capture browser is closed; see [`CrashReportDirectory`].
    crash_reports: Option<CrashReportDirectory>,
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

    fn verify_session(
        &mut self,
        url: &str,
        deadline_ms: u64,
    ) -> Result<crate::login_capture::SessionProbe, crate::login_capture::CaptureDriveError> {
        let driver = self
            .process
            .driver
            .as_mut()
            .ok_or(crate::login_capture::CaptureDriveError)?;
        capture_drive(driver.load_in_background_tab(url, deadline_ms))
    }

    fn liveness(&mut self) -> crate::browser_launch::BrowserProcessLiveness {
        match self.process.process.as_ref() {
            Some(process) => {
                platform_generation_liveness(BrowserProcessGeneration::from(process.generation()))
            }
            // The child was already reaped, so it has certainly gone.
            None => crate::browser_launch::BrowserProcessLiveness::Gone,
        }
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
        // The crash-report directory is deleted whether or not the reap
        // succeeded, and a failure to delete it is reported with the others
        // rather than dropped.
        let crash_reports_deleted = self
            .crash_reports
            .take()
            .map_or(Ok(()), CrashReportDirectory::remove);
        self.closed = true;
        match (reaped, recorded, crash_reports_deleted) {
            (Ok(()), Ok(()), Ok(())) => Ok(()),
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
///
/// Unlike macOS, this sets no crash-report location: `XDG_CONFIG_HOME` below
/// already points into the agent's own profile directory, and Chromium on
/// Linux derives its crash database from it, so crash reports stay inside the
/// profile the agent owns rather than reaching the person's own Chrome folder.
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
///
/// The one variable moves Chrome's crash database into `crash_reports`. Without
/// it, macOS Chrome writes crash reports into the person's own Chrome folder
/// whatever `--user-data-dir` says; see [`crate::browser_crash_reports`].
#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn browser_launch_environment(
    _profile_directory: &Path,
    crash_reports: &CrashReportDirectory,
) -> Vec<(OsString, OsString)> {
    vec![(
        OsString::from(crate::browser_crash_reports::BREAKPAD_DUMP_LOCATION),
        crash_reports.path().as_os_str().to_os_string(),
    )]
}

/// A launch's environment, and the crash-report directory it names (macOS
/// only), which the launch's session cleanup deletes.
type PreparedLaunchEnvironment = (Vec<(OsString, OsString)>, Option<CrashReportDirectory>);

/// A launch's environment, with the crash-report directory it names (macOS),
/// or the refusal when no directory safe from backup could be made. The
/// directory is deleted when the returned value is dropped, so a launch that
/// fails after this does not leave it behind.
#[cfg(target_os = "macos")]
fn prepare_launch_environment(
    profile_directory: &Path,
) -> Result<PreparedLaunchEnvironment, Value> {
    let crash_reports = CrashReportDirectory::create()
        .map_err(crate::browser_crash_reports::CrashReportRefusal::launch_refusal)?;
    Ok((
        browser_launch_environment(profile_directory, &crash_reports),
        Some(crash_reports),
    ))
}

/// Linux needs no crash-report directory of its own; see its
/// [`browser_launch_environment`].
#[cfg(target_os = "linux")]
fn prepare_launch_environment(
    profile_directory: &Path,
) -> Result<PreparedLaunchEnvironment, Value> {
    Ok((browser_launch_environment(profile_directory), None))
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
        // Chrome's own startup window opens in the foreground and takes focus
        // from the user's frontmost application (measured on macOS 27 with
        // Chrome 153: at 3.7 s after launch). Without it the browser runs with
        // no window until navigation creates the route's page as a background
        // target, which opens a visible window without taking focus. The
        // readiness handshake is `Browser.getVersion` and needs no page. The
        // flag has the same meaning for Chromium on Linux.
        OsString::from("--no-startup-window"),
        // `--remote-debugging-pipe` alone turns on Blink's AutomationControlled
        // feature, which sets `navigator.webdriver` to true on every page, and
        // Cloudflare's human verification refuses such a browser. A person
        // signing in through `browser.capture_login` or `browser.present`
        // then cannot get past it. Measured on macOS with Chrome 154
        // (2026-10-01), on a real Cloudflare challenge page
        // (scrapingcourse.com/cloudflare-challenge), one change at a time:
        // without this flag `navigator.webdriver` was true and the page stayed
        // on "Just a moment..." in every run, with no polling, with
        // browser-level polling only, and with nothing attached to the page at
        // all. With it, `navigator.webdriver` was false and the page passed in
        // every run, including with the handoff's page-level polling and
        // with `Runtime.enable`. The flag changes only that feature;
        // `examples/turnstile_probe.rs` repeats the measurement.
        OsString::from("--disable-blink-features=AutomationControlled"),
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

/// Open the launch journal where `persistence` says.
///
/// The durable arm is `DurableLaunchJournal::open_filesystem` with the storage
/// wrapped, so production opens the same file with the same writability check.
fn open_launch_journal(
    persistence: crate::JournalPersistence,
) -> Result<ProductionLaunchJournal, cerebellum_core::journal::BindingError> {
    let storage = match persistence {
        crate::JournalPersistence::Durable => {
            let path = cerebellum_core::journal::journal_data_path(
                crate::browser_launch::LAUNCH_JOURNAL_FILE_NAME,
            )
            .map_err(cerebellum_core::journal::BindingError::Storage)?;
            crate::PlaneJournalStorage::Filesystem(
                cerebellum_core::journal::FilesystemJournalStorage::prepare(path)
                    .map_err(cerebellum_core::journal::BindingError::Storage)?,
            )
        }
        crate::JournalPersistence::Isolated => crate::PlaneJournalStorage::InMemory(
            cerebellum_core::journal::InMemoryJournalStorage::new(),
        ),
    };
    DurableLaunchJournal::open(launch_journal_config(), storage)
}

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

/// Whether the recorded browser generation is running, gone, or cannot be told.
#[cfg(target_os = "macos")]
fn platform_generation_liveness(
    generation: BrowserProcessGeneration,
) -> crate::browser_launch::BrowserProcessLiveness {
    macos_generation_liveness(
        generation.start_time_micros,
        cerebellum_macos::process_start_time(generation.pid),
    )
}

/// Read one start-time reading against the recorded start time.
///
/// Only a reading that names the pid's current process can say "gone": none
/// at all, or one with a different start time. A refused or malformed read
/// says nothing about the browser, so it is `Unreadable`, never `Gone`;
/// counting it as gone is what would end a handoff on a browser still on
/// screen.
#[cfg(target_os = "macos")]
fn macos_generation_liveness(
    recorded_start_time_micros: u64,
    reading: cerebellum_macos::ProcessStartTime,
) -> crate::browser_launch::BrowserProcessLiveness {
    use crate::browser_launch::BrowserProcessLiveness;
    use cerebellum_macos::ProcessStartTime;
    match reading {
        ProcessStartTime::Started(start) if start == recorded_start_time_micros => {
            BrowserProcessLiveness::Live
        }
        ProcessStartTime::Started(_) | ProcessStartTime::NoSuchProcess => {
            BrowserProcessLiveness::Gone
        }
        ProcessStartTime::NotPermitted
        | ProcessStartTime::LayoutMismatch
        | ProcessStartTime::Unclassified(_)
        | ProcessStartTime::NoStartTime => BrowserProcessLiveness::Unreadable,
    }
}

#[cfg(target_os = "linux")]
fn platform_generation_liveness(
    generation: BrowserProcessGeneration,
) -> crate::browser_launch::BrowserProcessLiveness {
    use crate::browser_launch::BrowserProcessLiveness;
    match linux_generation_liveness(generation) {
        SupervisorLiveness::Live => BrowserProcessLiveness::Live,
        SupervisorLiveness::NotLive => BrowserProcessLiveness::Gone,
        SupervisorLiveness::Unavailable => BrowserProcessLiveness::Unreadable,
    }
}

/// Whether the recorded generation has positively gone. An unreadable
/// generation is not gone: the callers of this wait for an exit or end a
/// handoff, and either would be wrong about a browser that is still running.
fn platform_generation_gone(generation: BrowserProcessGeneration) -> bool {
    platform_generation_liveness(generation) == crate::browser_launch::BrowserProcessLiveness::Gone
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

struct ProductionOrphanProfileCustody<'a> {
    root: &'a ProfileStateRoot,
    /// The claims `retain` took, with the launch intent each was taken for,
    /// so the operator's clear can later release exactly these.
    retained: Vec<(
        crate::browser_launch::AuthorizedLaunchIntent,
        ProfileCustodyClaim,
    )>,
}

impl OrphanProfileCustody for ProductionOrphanProfileCustody<'_> {
    fn release(
        &mut self,
        intent: &crate::browser_launch::AuthorizedLaunchIntent,
    ) -> Result<(), OrphanProfileCustodyFailure> {
        let root = self
            .root
            .resolve()
            .map_err(|_| OrphanProfileCustodyFailure)?;
        let supervisor =
            current_supervisor_generation().map_err(|_| OrphanProfileCustodyFailure)?;
        release_orphan_profile_custody_at(&root, intent, supervisor, KernelSupervisorLiveness)
            .map_err(|_| OrphanProfileCustodyFailure)
    }

    fn retain(
        &mut self,
        intent: &crate::browser_launch::AuthorizedLaunchIntent,
    ) -> Result<(), OrphanProfileCustodyFailure> {
        let root = self
            .root
            .resolve()
            .map_err(|_| OrphanProfileCustodyFailure)?;
        let supervisor =
            current_supervisor_generation().map_err(|_| OrphanProfileCustodyFailure)?;
        let claim =
            retake_orphan_profile_custody_at(&root, intent, supervisor, KernelSupervisorLiveness)
                .map_err(|_| OrphanProfileCustodyFailure)?;
        if let Some(claim) = claim {
            self.retained.push((intent.clone(), claim));
        }
        Ok(())
    }
}

/// Run startup recovery over production custody at `profile_root`. Returns its
/// failure, or, when it succeeded, every profile it kept that this process can
/// later release.
///
/// A kept profile is listed only when three facts agree: recovery's own
/// outcome says the record stayed active and why, the journal still holds that
/// record with its intent, and this process holds the custody claim it took
/// for exactly that intent.
fn recover_and_retain<P: OrphanBrowserProcessControl>(
    journal: &mut ProductionLaunchJournal,
    process: &mut P,
    profile_root: &ProfileStateRoot,
) -> (
    Option<BrowserLaunchRecoveryFailure>,
    Vec<RetainedRecoveryClaim>,
) {
    let mut custody = ProductionOrphanProfileCustody {
        root: profile_root,
        retained: Vec::new(),
    };
    let outcomes = match recover_browser_launches(journal, process, &mut custody) {
        Ok(outcomes) => outcomes,
        // A failed pass refuses every launch before any profile is looked at,
        // so a clear would unblock nothing: none is offered, and the profiles
        // it did retain stay held by their claims.
        Err(failure) => return (Some(failure), Vec::new()),
    };
    let mut retained = Vec::new();
    for (sequence, reason) in outcomes
        .iter()
        .filter(|outcome| outcome.journal_action.is_none())
        .filter_map(|outcome| Some((outcome.sequence, outcome.process.pending_reason()?)))
    {
        let Ok(Some(record)) = journal.active_launch_record(sequence) else {
            continue;
        };
        let Some((_, claim)) = custody
            .retained
            .iter()
            .find(|(intent, _)| *intent == record.intent)
        else {
            continue;
        };
        retained.push(RetainedRecoveryClaim {
            sequence,
            intent: record.intent.clone(),
            reason,
            claim: claim.clone(),
        });
    }
    (None, retained)
}

fn release_orphan_profile_custody_at<P: SupervisorLivenessProbe>(
    root: &Path,
    intent: &crate::browser_launch::AuthorizedLaunchIntent,
    supervisor: SupervisorGeneration,
    liveness: P,
) -> Result<(), ()> {
    let (mut locks, key) = orphan_profile_custody_locks(root, intent, supervisor, liveness)?;
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

/// [`retake_orphan_profile_custody_at`] for tests that only need to know it
/// succeeded.
#[cfg(all(test, target_os = "macos"))]
fn retain_orphan_profile_custody_at<P: SupervisorLivenessProbe>(
    root: &Path,
    intent: &crate::browser_launch::AuthorizedLaunchIntent,
    supervisor: SupervisorGeneration,
    liveness: P,
) -> Result<(), ()> {
    retake_orphan_profile_custody_at(root, intent, supervisor, liveness).map(|_| ())
}

/// Re-take an orphaned launch's profile claim under this process, keeping the
/// holder its launch journal recorded.
///
/// The claim a crashed module left behind names a supervisor that is no longer
/// running, and a fresh launch breaks such a claim as stale. Re-taking it under
/// the running supervisor makes launches see the profile as held instead. The
/// holder is kept, not minted, because the next start's recovery may break a
/// stale claim only when it names the holder the launch journal recorded.
///
/// Returns the claim when this call took it, so the operator's clear can later
/// release exactly it. `Ok(None)` when a running supervisor already holds it
/// under the recorded holder, so the profile is refused without this call
/// owning the claim.
fn retake_orphan_profile_custody_at<P: SupervisorLivenessProbe>(
    root: &Path,
    intent: &crate::browser_launch::AuthorizedLaunchIntent,
    supervisor: SupervisorGeneration,
    liveness: P,
) -> Result<Option<ProfileCustodyClaim>, ()> {
    let (mut locks, key) = orphan_profile_custody_locks(root, intent, supervisor, liveness)?;
    let recorded_holder = HolderId::from_recorded(intent.holder_id.clone());
    match locks.acquire(key, recorded_holder).map_err(|_| ())? {
        // The claim is deliberately not released: its lock file is the refusal.
        ProfileCustodyAcquisition::Acquired(claim) => Ok(Some(claim)),
        // Already held by a running supervisor under the recorded holder, so
        // the profile is refused already.
        ProfileCustodyAcquisition::ProfileBusy { holder_id }
            if holder_id.as_str() == intent.holder_id =>
        {
            Ok(None)
        }
        ProfileCustodyAcquisition::ProfileBusy { .. } => Err(()),
    }
}

/// Open the custody locks as `supervisor`, with a journal that lets a stale
/// claim be broken only when it names the holder `intent` recorded.
fn orphan_profile_custody_locks<P: SupervisorLivenessProbe>(
    root: &Path,
    intent: &crate::browser_launch::AuthorizedLaunchIntent,
    supervisor: SupervisorGeneration,
    liveness: P,
) -> Result<
    (
        ProfileCustodyLocks<ExactRecoveryCustodyJournal, P>,
        ProfileCustodyKey,
    ),
    (),
> {
    let durable = FilesystemProfileCustodyJournal::open(root.join(PROFILE_CUSTODY_DIRECTORY))
        .map_err(|_| ())?;
    let journal = ExactRecoveryCustodyJournal {
        durable,
        expected_holder_id: intent.holder_id.clone(),
    };
    let locks = ProfileCustodyLocks::open(root, supervisor, journal, liveness).map_err(|_| ())?;
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
    Ok((locks, key))
}

/// One profile startup recovery kept for a browser it could not prove gone,
/// with the custody claim it took so an operator's clear can release exactly
/// that claim.
#[derive(Debug, Clone)]
struct RetainedRecoveryClaim {
    sequence: u64,
    intent: crate::browser_launch::AuthorizedLaunchIntent,
    reason: crate::browser_launch::RecoveryPendingReason,
    claim: ProfileCustodyClaim,
}

/// Points in an operator's clear, for tests that must look at the profile
/// between two steps or stop there as a crash would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClearStage {
    Rechecked,
    Recorded,
    Terminalized,
}

/// What startup recovery kept, and the operator's clear of it.
///
/// `retained` is a cache built only by startup recovery: it tells a launch
/// refused by a recovery claim apart from one refused by a live session, and
/// holds the claim a clear releases. It is never the authority for a clear;
/// the journal is read again for that.
struct RecoveryClearState {
    journal: SharedLaunchJournal,
    root: Option<PathBuf>,
    configured_executable: Option<PathBuf>,
    /// Keyed by custody holder id, the one fact a refused launch can see.
    retained: Mutex<std::collections::BTreeMap<String, RetainedRecoveryClaim>>,
    /// One clear at a time, so two answers cannot both act on one record.
    clearing: Mutex<()>,
    process_table: Arc<dyn crate::launch_recovery::ProcessTable + Send + Sync>,
    #[cfg(test)]
    stage_hook: Mutex<Option<ClearStageHook>>,
}

/// Called at each [`ClearStage`]; returning `false` stops the clear there.
#[cfg(test)]
type ClearStageHook = Box<dyn FnMut(ClearStage) -> bool + Send>;

impl RecoveryClearState {
    /// A launch refused because a holder has the profile is refused by name
    /// when that holder is startup recovery: no session holds it, so telling
    /// the caller to close one or retry would send it round a loop.
    fn name_recovery_hold(&self, outcome: BrowserLaunchOutcome) -> BrowserLaunchOutcome {
        let BrowserLaunchOutcome::ProfileBusy { holder_id } = &outcome else {
            return outcome;
        };
        let reason = self.retained.lock().ok().and_then(|retained| {
            retained
                .get(holder_id.as_str())
                .map(|retained| retained.reason)
        });
        match reason {
            Some(reason) => BrowserLaunchOutcome::ProfileRecoveryPending { reason },
            None => outcome,
        }
    }

    /// Whether the journal still describes `retained` as recovery kept it:
    /// the record active, with the same intent, not cleared already, and
    /// in the state that gives recovery's reason.
    fn journal_agrees(
        journal: &ProductionLaunchJournal,
        retained: &RetainedRecoveryClaim,
    ) -> Result<crate::browser_launch::ActiveLaunchRecord, crate::launch_recovery::ClearRefusal>
    {
        use crate::browser_launch::RecoveryPendingReason;
        use crate::launch_recovery::ClearRefusal;
        let record = journal
            .active_launch_record(retained.sequence)
            .map_err(|_| ClearRefusal::JournalUnavailable)?
            .ok_or(ClearRefusal::JournalDisagrees)?;
        let reason_agrees = match retained.reason {
            RecoveryPendingReason::AttestationUntrusted => {
                record.dispatched && !record.attestation_trusted
            }
            RecoveryPendingReason::TerminationFailed
            | RecoveryPendingReason::GenerationUnobservable => record.attestation_trusted,
        };
        if record.intent != retained.intent || record.cleared || !reason_agrees {
            return Err(ClearRefusal::JournalDisagrees);
        }
        Ok(record)
    }

    fn evidence(
        &self,
        retained: &RetainedRecoveryClaim,
    ) -> crate::launch_recovery::ProfileEvidence {
        use std::os::unix::ffi::OsStringExt;
        let directory = PathBuf::from(OsString::from_vec(
            retained.intent.profile.canonical_profile_path.clone(),
        ));
        crate::launch_recovery::read_profile_evidence(
            &directory,
            self.configured_executable.as_deref(),
            self.process_table.as_ref(),
        )
    }

    /// Test seam: whether to go on past `stage`. Production always goes on.
    fn continue_after(&self, stage: ClearStage) -> bool {
        #[cfg(test)]
        if let Ok(mut hook) = self.stage_hook.lock() {
            if let Some(hook) = hook.as_mut() {
                return hook(stage);
            }
        }
        let _ = stage;
        true
    }
}

impl crate::launch_recovery::LaunchRecoveryClearer for RecoveryClearState {
    fn preview(
        &self,
        agent_project_id: &str,
        sequence: Option<u64>,
    ) -> Result<crate::launch_recovery::ClearPreview, crate::launch_recovery::ClearRefusal> {
        use crate::launch_recovery::ClearRefusal;
        let retained = {
            let retained = self
                .retained
                .lock()
                .map_err(|_| ClearRefusal::JournalUnavailable)?;
            let mut candidates: Vec<RetainedRecoveryClaim> = retained
                .values()
                .filter(|retained| retained.intent.route.agent_project_id == agent_project_id)
                .filter(|retained| sequence.is_none_or(|sequence| sequence == retained.sequence))
                .cloned()
                .collect();
            match candidates.len() {
                0 => return Err(ClearRefusal::NotRetained),
                1 => candidates.remove(0),
                _ => {
                    let mut sequences: Vec<u64> = candidates
                        .iter()
                        .map(|retained| retained.sequence)
                        .collect();
                    sequences.sort_unstable();
                    return Err(ClearRefusal::Ambiguous { sequences });
                }
            }
        };
        let record = {
            let journal = self
                .journal
                .lock()
                .map_err(|_| ClearRefusal::JournalUnavailable)?;
            let journal = journal.as_ref().ok_or(ClearRefusal::JournalUnavailable)?;
            Self::journal_agrees(journal, &retained)?
        };
        let evidence = self.evidence(&retained);
        evidence.permits_clear()?;
        Ok(crate::launch_recovery::ClearPreview {
            agent_project_id: agent_project_id.to_string(),
            profile_uuid: retained.intent.profile.profile_uuid.clone(),
            sequence: retained.sequence,
            reason: retained.reason,
            launched_at: crate::launch_recovery::launched_at(record.browser_started_at_micros),
            evidence,
        })
    }

    /// INVARIANT: from the re-check until `release_exact`, the profile's
    /// custody stays held under the holder recovery took it for, and the
    /// claim stays in `retained`. A launch in that window therefore still
    /// refuses `profile_recovery_pending`. The order is record, then consume,
    /// then release: a crash after the durable record leaves a record the next
    /// start finishes, and a crash after consuming it leaves a claim whose
    /// supervisor is gone, which the next launch breaks as stale. Releasing
    /// first would open the profile with a record still saying a browser may
    /// be using it.
    fn clear(
        &self,
        preview: &crate::launch_recovery::ClearPreview,
        ask_id: &str,
    ) -> Result<(), crate::launch_recovery::ClearFailure> {
        use crate::launch_recovery::{ClearFailure, ClearRefusal};
        let refused = ClearFailure::Refused;
        let _one_at_a_time = self
            .clearing
            .lock()
            .map_err(|_| refused(ClearRefusal::JournalUnavailable))?;
        let retained = self
            .retained
            .lock()
            .map_err(|_| refused(ClearRefusal::JournalUnavailable))?
            .values()
            .find(|retained| retained.sequence == preview.sequence)
            .cloned()
            .ok_or(refused(ClearRefusal::NotRetained))?;
        if retained.reason != preview.reason
            || retained.intent.route.agent_project_id != preview.agent_project_id
        {
            return Err(refused(ClearRefusal::JournalDisagrees));
        }
        let root = self
            .root
            .clone()
            .ok_or(refused(ClearRefusal::JournalUnavailable))?;

        {
            let mut journal = self
                .journal
                .lock()
                .map_err(|_| refused(ClearRefusal::JournalUnavailable))?;
            let journal = journal
                .as_mut()
                .ok_or(refused(ClearRefusal::JournalUnavailable))?;
            Self::journal_agrees(journal, &retained).map_err(refused)?;
            // Both readings again: the person answered minutes after the
            // question showed them, and a browser may have opened since.
            self.evidence(&retained).permits_clear().map_err(refused)?;
            if !self.continue_after(ClearStage::Rechecked) {
                return Err(refused(ClearRefusal::JournalUnavailable));
            }
            journal
                .record_recovery_clear(&crate::browser_launch::LaunchRecoveryClearRecord::new(
                    retained.sequence,
                    &retained.intent,
                    retained.reason,
                    ask_id,
                ))
                .map_err(|_| refused(ClearRefusal::JournalUnavailable))?;
            if !self.continue_after(ClearStage::Recorded) {
                return Err(ClearFailure::Terminalization {
                    sequence: retained.sequence,
                });
            }
            if journal.terminalize_recovered(retained.sequence).is_none() {
                return Err(ClearFailure::Terminalization {
                    sequence: retained.sequence,
                });
            }
        }
        if !self.continue_after(ClearStage::Terminalized) {
            return Err(ClearFailure::CustodyRelease {
                sequence: retained.sequence,
            });
        }

        let released = current_supervisor_generation()
            .map_err(|_| ())
            .and_then(|supervisor| {
                orphan_profile_custody_locks(
                    &root,
                    &retained.intent,
                    supervisor,
                    KernelSupervisorLiveness,
                )
            })
            .and_then(|(mut locks, _)| locks.release_exact(&retained.claim).map_err(|_| ()));
        match released {
            Ok(ProfileCustodyRelease::Released) => {
                if let Ok(mut map) = self.retained.lock() {
                    map.remove(retained.claim.holder_id().as_str());
                }
                Ok(())
            }
            Ok(ProfileCustodyRelease::HolderMismatch { .. } | ProfileCustodyRelease::Missing)
            | Err(()) => Err(ClearFailure::CustodyRelease {
                sequence: retained.sequence,
            }),
        }
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
                shutdown_kill: Arc::default(),
            }),
            cleanup: Box::new(self.cleanup.expect("ready browser owns profile cleanup")),
        }
    }
}

struct ProductionProcess {
    process: Option<PlatformReleasedChild>,
    driver: Option<CdpNavigationDriver<UnixCdpPipe>>,
    reaped: bool,
    /// Shared with this browser's shutdown killer, so the reap path knows the
    /// browser was already killed (and, on Linux, possibly reaped) out of band.
    shutdown_kill: Arc<ShutdownKillState>,
}

#[derive(Default)]
struct ShutdownKillState {
    dead: AtomicBool,
}

/// Kills one production browser by its exact process generation, for module
/// shutdown when a browser call is holding the session registry lock.
struct ProductionShutdownKiller {
    generation: BrowserProcessGeneration,
    state: Arc<ShutdownKillState>,
}

impl BrowserKiller for ProductionShutdownKiller {
    fn kill_exact_generation(&self) -> KillOutcome {
        if self.state.dead.load(Ordering::Acquire) {
            return KillOutcome::Dead;
        }
        if !platform_kill_exact_generation(self.generation) {
            return KillOutcome::Refused;
        }
        self.state.dead.store(true, Ordering::Release);
        KillOutcome::Dead
    }
}

/// SIGKILL the recorded generation only if the pid still names it; `true` when
/// the browser is now dead or had already gone. Reuses the same generation
/// check that orphan recovery signals through, and never reaps on macOS.
#[cfg(target_os = "macos")]
fn platform_kill_exact_generation(generation: BrowserProcessGeneration) -> bool {
    cerebellum_macos::terminate_exact_generation(cerebellum_macos::ProcessGeneration {
        pid: generation.pid,
        start_time_micros: generation.start_time_micros,
    })
    .is_ok()
}

/// As on macOS, except that Linux's generation-checked kill also reaps the
/// child when this process owns it, waiting at most this long for that.
#[cfg(target_os = "linux")]
const SHUTDOWN_KILL_REAP_WAIT: Duration = Duration::from_secs(1);

#[cfg(target_os = "linux")]
fn platform_kill_exact_generation(generation: BrowserProcessGeneration) -> bool {
    cerebellum_linux::terminate_exact_generation(
        generation.pid,
        Instant::now() + SHUTDOWN_KILL_REAP_WAIT,
        || match linux_generation_liveness(generation) {
            SupervisorLiveness::Live => cerebellum_linux::GenerationMatch::Exact,
            SupervisorLiveness::NotLive => cerebellum_linux::GenerationMatch::GoneOrReplaced,
            SupervisorLiveness::Unavailable => cerebellum_linux::GenerationMatch::Unreadable,
        },
    )
    .is_ok()
}

impl OwnedBrowserProcess for ProductionProcess {
    fn release_held_input(&mut self, deadline_ms: u64) -> Result<(), NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .release_held_input(deadline_ms)
    }

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

    fn committed_document(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<crate::snapshot_store::CommittedDocument, NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .committed_document(context_key, deadline_ms)
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

    fn snapshot_subtree_classified(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        reference: &crate::snapshot_store::RefRecord,
        document_epoch: u64,
        current_origin: &str,
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .snapshot_subtree_classified(
                context_key,
                mode,
                reference,
                document_epoch,
                current_origin,
                deadline_ms,
            )
    }

    fn frame_documents(
        &mut self,
        context: &str,
        deadline_ms: u64,
    ) -> Result<Vec<crate::snapshot_store::FrameDocument>, NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .frame_documents(context, deadline_ms)
    }
    fn set_read_frames(
        &mut self,
        frames: Vec<crate::snapshot_store::FrameDocument>,
    ) -> Result<(), NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .set_read_frames(frames);
        Ok(())
    }
    fn prepare_frame(
        &mut self,
        context: &str,
        frame: &crate::snapshot_store::FrameDocument,
        deadline_ms: u64,
    ) -> Result<bool, NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .prepare_frame(context, frame, deadline_ms)
    }
    fn point_frame_document(&mut self) -> Option<crate::snapshot_store::FrameDocument> {
        self.driver
            .as_ref()
            .and_then(|driver| driver.point_frame_document())
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

    fn scroll(
        &mut self,
        context_key: &str,
        target: &crate::browser_session::BrowserScrollTarget,
        deadline_ms: u64,
    ) -> Result<(), NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .scroll(context_key, target, deadline_ms)
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

    fn classify_point(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        document_epoch: u64,
        document_url: &str,
        deadline_ms: u64,
    ) -> Result<
        Result<
            crate::classification::NonTypeClassificationRecord,
            crate::classification::ClassificationUnavailable,
        >,
        NavigationDriveError,
    > {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .classify_point(
                context_key,
                position,
                document_epoch,
                document_url,
                deadline_ms,
            )
    }

    fn click_point_classified(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        document_epoch: u64,
        document_url: &str,
        expected: &crate::classification::NonTypeClassificationRecord,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.driver
            .as_mut()
            .ok_or(ClickDriveError::Navigation(
                NavigationDriveError::Unavailable,
            ))?
            .click_point_classified(
                context_key,
                position,
                document_epoch,
                document_url,
                expected,
                deadline_ms,
                input_dispatched,
            )
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

    fn type_classified(
        &mut self,
        context_key: &str,
        target: &crate::browser_type::TypeDispatch,
        text: &str,
        clear_first: bool,
        deadline_ms: u64,
    ) -> Result<crate::browser_type::BrowserTypeResult, NavigationDriveError> {
        self.driver
            .as_mut()
            .ok_or(NavigationDriveError::Unavailable)?
            .type_classified(context_key, target, text, clear_first, deadline_ms)
    }

    fn generation_matches(&self) -> bool {
        self.process.as_ref().is_some_and(|process| {
            let generation = process.generation();
            platform_generation_matches(BrowserProcessGeneration::from(generation))
        })
    }

    fn generation_gone(&self) -> bool {
        self.process.as_ref().is_none_or(|process| {
            platform_generation_gone(BrowserProcessGeneration::from(process.generation()))
        })
    }

    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        self.driver
            .as_mut()
            .ok_or(ProcessControlFailure::new(
                ProcessControlStep::GracefulCloseRequest,
            ))?
            .request_browser_close()
            .map_err(|_| ProcessControlFailure::new(ProcessControlStep::GracefulCloseRequest))
    }

    fn wait_for_exit(&mut self, grace_period: Duration) -> Result<bool, ProcessControlFailure> {
        let Some(process) = self.process.as_ref() else {
            return Ok(true);
        };
        let generation = process.generation();
        let deadline = Instant::now() + grace_period;
        while Instant::now() < deadline {
            if platform_generation_gone(BrowserProcessGeneration::from(generation)) {
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(false)
    }

    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        let process = self.process.take().ok_or(ProcessControlFailure::new(
            ProcessControlStep::ForcedTermination,
        ))?;
        process.terminate_and_reap().map_err(|error| {
            process_control_failure(ProcessControlStep::ForcedTermination, error)
        })?;
        self.reaped = true;
        Ok(())
    }

    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        if self.reaped {
            return Ok(());
        }
        let process = self
            .process
            .take()
            .ok_or(ProcessControlFailure::new(ProcessControlStep::ReapWait))?;
        if let Err(error) = process.wait() {
            if !self.shutdown_kill.dead.load(Ordering::Acquire) {
                return Err(process_control_failure(ProcessControlStep::ReapWait, error));
            }
        }
        // A failed wait after the shutdown killer confirmed this generation
        // dead means the child was already reaped (Linux reaps inside the
        // kill), so there is nothing left to wait for.
        self.reaped = true;
        Ok(())
    }

    fn shutdown_killer(&self) -> Option<Arc<dyn BrowserKiller>> {
        let generation = BrowserProcessGeneration::from(self.process.as_ref()?.generation());
        Some(Arc::new(ProductionShutdownKiller {
            generation,
            state: Arc::clone(&self.shutdown_kill),
        }))
    }

    fn exit_probe(&self) -> Option<Arc<dyn BrowserExitProbe>> {
        let generation = BrowserProcessGeneration::from(self.process.as_ref()?.generation());
        Some(Arc::new(ProductionExitProbe { generation }))
    }
}

/// Answers whether one production browser generation is still running,
/// through the same generation check `generation_matches` uses, so exit
/// observation need not wait for a call in progress on its driver.
struct ProductionExitProbe {
    generation: BrowserProcessGeneration,
}

impl BrowserExitProbe for ProductionExitProbe {
    fn generation_matches(&self) -> bool {
        platform_generation_matches(self.generation)
    }

    fn generation_gone(&self) -> bool {
        platform_generation_gone(self.generation)
    }
}

#[derive(Clone)]
struct SharedRollback {
    holder_id: Option<String>,
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
            holder_id: None,
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

fn run_cleanup_obligations<P, J, C, R>(
    persistence_check: P,
    journal_finalization: J,
    profile_cleanup: C,
    crash_reports_cleanup: R,
) -> Result<SessionCleanupOutcome, CleanupStage>
where
    P: FnOnce() -> SessionCleanupOutcome,
    J: FnOnce() -> Result<(), CleanupStage>,
    C: FnOnce() -> Result<(), CleanupStage>,
    R: FnOnce() -> Result<(), CleanupStage>,
{
    let persistence_outcome = persistence_check();
    let journal_result = journal_finalization();
    let profile_result = profile_cleanup();
    let crash_reports_result = crash_reports_cleanup();
    journal_result
        .and(profile_result)
        .and(crash_reports_result)
        .map(|()| persistence_outcome)
}

/// Delete a session's crash-report directory, once, naming the stage when it
/// could not be deleted.
fn delete_crash_reports(
    crash_reports: &mut Option<CrashReportDirectory>,
) -> Result<(), CleanupStage> {
    crash_reports.take().map_or(Ok(()), |directory| {
        directory
            .remove()
            .map_err(|_| CleanupStage::CrashReportsDelete)
    })
}

struct ProductionSessionCleanup {
    reap_recovery: Option<SessionRecovery>,
    journal: SharedLaunchJournal,
    launch_attempt_id: String,
    terminal_outcome: Option<BrowserSessionTerminalOutcome>,
    persistence: ProfilePersistenceCheck,
    profile: SharedRollback,
    /// Deleted after the browser is reaped, whichever way the session ended.
    crash_reports: Option<CrashReportDirectory>,
}

struct SessionRecovery {
    evidence: Arc<RecoveryClearState>,
    durable_project: Option<String>,
    journal_settled: bool,
    cleanup_result: Option<Result<SessionCleanupOutcome, CleanupStage>>,
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
    fn durable_profile_project(&self) -> Option<&str> {
        self.reap_recovery
            .as_ref()
            .and_then(|recovery| recovery.durable_project.as_deref())
    }

    fn prove_profile_unused(&self) -> Result<(), String> {
        let recovery = &self.reap_recovery.as_ref().ok_or_else(||
            "profile recovery evidence is unavailable; restart the module to run startup recovery".to_string())?.evidence;
        crate::launch_recovery::read_profile_evidence(
            &self.persistence.profile_directory,
            recovery.configured_executable.as_deref(),
            recovery.process_table.as_ref(),
        )
        .permits_clear()
        .map_err(|refusal| refusal.remedy().to_string())
    }

    fn after_proven_exit(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
        // A retry must settle the old launch before making its profile
        // available to a new one. Remember settlement if later cleanup fails.
        let recovery = self.reap_recovery.as_mut().ok_or(CleanupStage::Reap)?;
        if let Some(result) = recovery.cleanup_result {
            return result;
        }
        if !recovery.journal_settled {
            Self::finalize_journal(
                &self.journal,
                &self.launch_attempt_id,
                &mut self.terminal_outcome,
            )?;
            recovery.journal_settled = true;
        }
        let outcome = self.persistence.observe();
        // The profile rollback consumes its attachment handle even on error;
        // retrying it would mistake the missing handle for successful release.
        let result = self
            .profile
            .after_reap()
            .and_then(|()| delete_crash_reports(&mut self.crash_reports))
            .map(|()| outcome);
        recovery.cleanup_result = Some(result);
        result
    }
    fn custody_holder_id(&self) -> Option<&str> {
        self.profile.holder_id.as_deref()
    }

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
            crash_reports,
            ..
        } = self;
        run_cleanup_obligations(
            || persistence.observe(),
            || Self::finalize_journal(journal, launch_attempt_id, terminal_outcome),
            || profile.after_reap(),
            || delete_crash_reports(crash_reports),
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
    profile_lifecycle_at(root)
}

/// The production registry configuration opened at `root`, which is the data
/// home for production and a private directory for an isolated service.
fn profile_lifecycle_at(
    root: PathBuf,
) -> Result<ProfileLifecycle, ProductionProfileLifecycleError> {
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
    cerebellum_core::private_fs::create_dir_all(&root).map_err(|_| ())?;
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

/// A browser liveness check names a browser gone only on a reading that shows
/// it gone. These are the readings the kernel can give for the recorded pid.
#[cfg(all(test, target_os = "macos"))]
mod generation_liveness_tests {
    use super::macos_generation_liveness;
    use crate::browser_launch::BrowserProcessLiveness;
    use cerebellum_macos::ProcessStartTime;

    const RECORDED: u64 = 1_790_860_017_410_598;

    #[test]
    fn the_recorded_start_time_reads_live() {
        assert_eq!(
            macos_generation_liveness(RECORDED, ProcessStartTime::Started(RECORDED)),
            BrowserProcessLiveness::Live
        );
    }

    #[test]
    fn an_empty_or_reused_pid_reads_gone() {
        assert_eq!(
            macos_generation_liveness(RECORDED, ProcessStartTime::NoSuchProcess),
            BrowserProcessLiveness::Gone
        );
        assert_eq!(
            macos_generation_liveness(RECORDED, ProcessStartTime::Started(RECORDED + 1)),
            BrowserProcessLiveness::Gone
        );
    }

    #[test]
    fn a_failed_reading_is_unreadable_and_never_gone() {
        for reading in [
            ProcessStartTime::NotPermitted,
            ProcessStartTime::LayoutMismatch,
            ProcessStartTime::Unclassified(35),
            ProcessStartTime::NoStartTime,
        ] {
            assert_eq!(
                macos_generation_liveness(RECORDED, reading),
                BrowserProcessLiveness::Unreadable,
                "{reading:?}"
            );
        }
    }
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
            // The daemon starts this module with its launch nonce in the
            // environment; the browser must not receive it.
            (
                OsString::from("SUBC_LAUNCH_NONCE"),
                OsString::from("0123456789abcdef"),
            ),
            (
                OsString::from("SUBC_LAUNCH_NONCE_FD"),
                OsString::from("3:12345"),
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

    /// Without the variable, macOS Chrome writes its crash reports into the
    /// person's own `~/Library/Application Support/Google/Chrome/Crashpad`,
    /// whatever `--user-data-dir` says.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_browser_launch_environment_moves_crash_reports_into_a_per_launch_temporary_directory()
    {
        use crate::browser_crash_reports::{
            test_support::excluded_directory, BREAKPAD_DUMP_LOCATION,
            CRASH_REPORTS_DIRECTORY_PREFIX,
        };
        let crash_reports = excluded_directory();
        let environment =
            browser_launch_environment(Path::new("/tmp/browser-profile"), &crash_reports);

        let location = environment
            .iter()
            .find(|(name, _)| name == BREAKPAD_DUMP_LOCATION)
            .map(|(_, value)| PathBuf::from(value))
            .expect("the macOS launch environment must relocate Chrome's crash database");
        let temporary = std::env::temp_dir()
            .canonicalize()
            .expect("resolve the temporary directory");
        assert_eq!(location.parent(), Some(temporary.as_path()));
        assert!(location
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(CRASH_REPORTS_DIRECTORY_PREFIX)));
        assert!(location.is_dir());
        if let Some(home) = std::env::var_os("HOME") {
            assert!(!location.starts_with(Path::new(&home).join("Library")));
        }
        assert!(!location.to_string_lossy().contains("/Library/"));
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
                OsString::from("--no-startup-window"),
                OsString::from("--disable-blink-features=AutomationControlled"),
            ]
        );
    }

    /// `--disable-blink-features=AutomationControlled`, like every other launch
    /// argument, must pass the custody quarantine's refused-argument list;
    /// otherwise every launch would be refused there.
    #[test]
    fn every_launch_argument_passes_the_custody_quarantine() {
        let profile = Path::new("/tmp/probe-profile");
        let arguments = browser_launch_arguments(profile, &profile.join("crash"))
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(crate::custody::arguments_are_quarantinable(&arguments));
    }

    struct UnsignedExecutable(PathBuf);

    impl UnsignedExecutable {
        fn new() -> Self {
            // Keep this under /tmp: on macOS 27, codesign can hang inspecting
            // these bytes under the per-user $TMPDIR while /tmp returns promptly.
            // Reusing the content-named file also avoids a new policy assessment
            // on each test run.
            let path = crate::content_named_fixture::content_named_fixture(
                "unsigned-browser",
                "browser",
                b"not a signed executable",
                0o600,
            );
            Self(path)
        }
    }

    #[test]
    fn flow_profile_holder_names_flow_and_head_in_both_directions() {
        let vector: cortexkit_resource_busy::ResourceBusy =
            serde_json::from_str(include_str!("../tests/vectors/flow-browser-profile.json"))
                .unwrap();
        vector.validate().unwrap();
        for flow_holds in [true, false] {
            let service = ProductionLaunchService::open(
                crate::Planes::short_test_browser_config(),
                crate::JournalPersistence::Isolated,
            );
            let mut head = accepted_facts(Path::new("/test/project"));
            head.identity.conversation_key = "head-holder".into();
            head.principal = Some(subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".into(),
            });
            let mut flow = head.clone();
            flow.flow_id = Some("flow-7".into());
            flow.principal = Some(subc_protocol::Principal::Reserved {
                module_id: "basal".into(),
            });
            flow.identity.conversation_key = "flow:flow-7".into();
            let (holder, contender) = if flow_holds {
                (&flow, &head)
            } else {
                (&head, &flow)
            };
            let held = service
                .take_launch_profile(holder, "holder-session")
                .unwrap_or_else(|reply| panic!("{reply}"));
            crate::profile_custody::lease_deadline(
                &held.holder_id,
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            );
            let refusal = service
                .take_launch_profile(contender, "contender-session")
                .err()
                .expect("same agent profile is held");
            assert_eq!(refusal["outcome"], "resource_busy", "{refusal}");
            let detail: cortexkit_resource_busy::ResourceBusy =
                serde_json::from_value(refusal["detail"].clone()).unwrap();
            detail.validate().unwrap();
            assert_eq!(
                detail.holder,
                if flow_holds {
                    vector.holder.clone()
                } else {
                    cortexkit_resource_busy::Holder::head()
                }
            );
            let mut rollback = held.rollback;
            rollback.after_reap().unwrap();
        }
    }

    fn accepted_facts(_project_root: &Path) -> AcceptedBindFacts {
        AcceptedBindFacts {
            identity: RouteIdentity {
                witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
                conversation_key: "conversation-1".to_string(),
                agent_project_id: "project-1".to_string(),
                session_kind: SessionKind::Primary,
                profile_disposition: ProfileDisposition::Durable,
                origin: Default::default(),
            },
            principal: None,
            agent_project_id_attested: true,
            acts_as_agent: true,
            session_kind_attested: true,
            control_operations: Vec::new(),
            effective_capability_scope: None,
            consumer_capabilities: Vec::new(),
            surface: RouteSurface::Tools,
            scope: None,
            call_mode: subc_protocol::call_mode::CallMode::Classic,
            codemode_head: None,
            flow_id: None,
        }
    }

    #[test]
    fn an_empty_project_is_refused_by_name_before_profile_custody() {
        let config = BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
            browser_idle_timeout_ms: 30_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 1_000,
        };
        let service = ProductionLaunchService::open_with_recovery(
            config,
            ProfileStateRoot::for_persistence(crate::JournalPersistence::Isolated),
            |_, _| (None, None, Vec::new()),
        );
        let mut accepted = accepted_facts(Path::new("/tmp"));
        accepted.identity.agent_project_id.clear();

        let refusal = service
            .take_and_return_profile_custody(&accepted, "empty-project")
            .unwrap_err();

        assert_eq!(refusal["outcome"], "authorization_denied", "{refusal}");
        assert_eq!(
            refusal["reason"], "agent_project_id_unattested",
            "{refusal}"
        );
        assert!(refusal["remedy"].as_str().is_some_and(|s| !s.is_empty()));
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
        let service = ProductionLaunchService::open_with_recovery(
            config,
            ProfileStateRoot::for_persistence(crate::JournalPersistence::Isolated),
            |_, _| (None, None, Vec::new()),
        );
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
        let service = ProductionLaunchService::open_with_recovery(
            config,
            ProfileStateRoot::for_persistence(crate::JournalPersistence::Isolated),
            |_, _| (None, None, Vec::new()),
        );
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
            holder_id: None,
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
            reap_recovery: None,
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
            crash_reports: None,
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
        let crash_reports_events = Arc::clone(&events);

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
            move || {
                crash_reports_events.lock().unwrap().push("crash_reports");
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
            ["persistence", "journal", "custody", "crash_reports"]
        );
    }

    /// The crash-report directory can hold page memory from the session, so
    /// failing to delete it is a cleanup failure with its own stage, reported
    /// even when every other obligation succeeded.
    #[test]
    fn a_crash_reports_delete_failure_is_reported_when_everything_else_succeeds() {
        let result = run_cleanup_obligations(
            || SessionCleanupOutcome::Complete,
            || Ok(()),
            || Ok(()),
            || Err(CleanupStage::CrashReportsDelete),
        );
        assert_eq!(result, Err(CleanupStage::CrashReportsDelete));
    }
}

/// The crash-report directory of a launch is deleted however its session ends.
///
/// Each ending is driven through the session registry with production's own
/// session cleanup. The fixture binds no launch journal, so every ending also
/// reports `record_terminalization`; that failure is independent of the
/// directory, which is the point: the delete must not depend on it.
///
/// Each test checks the directory is gone the moment the cleanup's after-reap
/// step returns, not merely by the end of the test: dropping the cleanup also
/// deletes it as a last resort, and a delete that happened only there would
/// leave a failure unreported.
#[cfg(all(test, target_os = "macos"))]
mod crash_reports_teardown_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    use cerebellum_core::clock::FakeClock;

    use crate::browser_crash_reports::test_support::excluded_directory;
    use crate::browser_session::{BrowserSessions, OwnedBrowserProcess, ProcessControlFailure};

    /// A browser that exits as soon as it is asked to. `alive` is what an
    /// exit observation sees, so `false` makes the session read as crashed.
    struct ExitingProcess {
        alive: bool,
    }

    impl OwnedBrowserProcess for ExitingProcess {
        fn generation_matches(&self) -> bool {
            self.alive
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

    fn config() -> BrowserConfig {
        BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 10,
            termination_grace_period_ms: 10,
            browser_idle_timeout_ms: 100,
            browser_exit_observation_deadline_ms: 10,
            navigation_settle_deadline_ms: 10,
        }
    }

    fn cleanup_owning(crash_reports: CrashReportDirectory) -> ProductionSessionCleanup {
        ProductionSessionCleanup {
            reap_recovery: None,
            journal: Arc::new(Mutex::new(None)),
            launch_attempt_id: "crash-reports-teardown".to_string(),
            terminal_outcome: None,
            persistence: ProfilePersistenceCheck {
                disposition: ProfileDisposition::Disposable,
                profile_directory: PathBuf::from("/nonexistent/profile"),
                launch_started_at: SystemTime::now(),
            },
            // No profile custody to give back.
            profile: SharedRollback {
                holder_id: None,
                state: Arc::new(Mutex::new(None)),
            },
            crash_reports: Some(crash_reports),
        }
    }

    /// What the after-reap step left: `None` until it ran, then whether the
    /// crash-report directory still existed when it returned.
    type AfterReapObservation = Arc<Mutex<Option<bool>>>;

    /// Production's cleanup, observed right after its after-reap step.
    struct ObservedCleanup {
        inner: ProductionSessionCleanup,
        path: PathBuf,
        observed: AfterReapObservation,
    }

    impl SessionCleanup for ObservedCleanup {
        fn set_terminal_outcome(&mut self, outcome: BrowserSessionTerminalOutcome) {
            self.inner.set_terminal_outcome(outcome);
        }

        fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
            let result = self.inner.after_reap();
            *self.observed.lock().unwrap() = Some(self.path.exists());
            result
        }
    }

    /// A ready session on `route` whose cleanup owns a fresh crash-report
    /// directory holding a report, returned with the session id, the
    /// directory's path, and what the after-reap step will observe.
    fn session_with_crash_reports(
        sessions: &BrowserSessions,
        route: &str,
        clock: &FakeClock,
        alive: bool,
    ) -> (String, PathBuf, AfterReapObservation) {
        let crash_reports = excluded_directory();
        let path = crash_reports.path().to_path_buf();
        std::fs::write(path.join("minidump"), b"page memory").expect("write a report");
        let observed = AfterReapObservation::default();
        let _ = sessions.acquire_launch_slot(route);
        let (id, _, cancelled) = sessions
            .establish_ready(
                route,
                ProfileDisposition::Disposable,
                &config(),
                clock,
                Box::new(ExitingProcess { alive }),
                Box::new(ObservedCleanup {
                    inner: cleanup_owning(crash_reports),
                    path: path.clone(),
                    observed: Arc::clone(&observed),
                }),
            )
            .expect("establish test session");
        assert!(!cancelled);
        assert!(path.is_dir());
        (id, path, observed)
    }

    fn assert_deleted_by_after_reap(ending: &str, path: &Path, observed: &AfterReapObservation) {
        assert_eq!(
            *observed.lock().unwrap(),
            Some(false),
            "{ending}: the crash-report directory was still there when the session's \
             after-reap step returned (None: the step never ran)"
        );
        assert!(!path.exists(), "{ending} left the crash-report directory");
    }

    #[test]
    fn crash_reports_are_deleted_when_a_session_is_closed() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (id, path, observed) = session_with_crash_reports(&sessions, "close", &clock, true);
        sessions.close("close", &id, &config());
        assert_deleted_by_after_reap("close", &path, &observed);
    }

    #[test]
    fn crash_reports_are_deleted_when_an_idle_session_is_swept() {
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let (_, path, observed) = session_with_crash_reports(&sessions, "idle", &clock, true);
        clock.advance(Duration::from_millis(config().browser_idle_timeout_ms));
        assert!(sessions.expire_idle("idle", &clock, &config()));
        assert_deleted_by_after_reap("idle sweep", &path, &observed);
    }

    #[test]
    fn crash_reports_are_deleted_when_the_browser_crashes() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (_, path, observed) = session_with_crash_reports(&sessions, "crash", &clock, false);
        sessions.observe_exits_all(&config());
        sessions.observe_exits_all(&config());
        assert_deleted_by_after_reap("crash", &path, &observed);
    }

    #[test]
    fn crash_reports_are_deleted_at_module_shutdown() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (_, path, observed) = session_with_crash_reports(&sessions, "shutdown", &clock, true);
        sessions.teardown_all(&config());
        assert_deleted_by_after_reap("shutdown", &path, &observed);
    }

    #[test]
    fn a_crash_reports_directory_that_cannot_be_deleted_is_a_named_cleanup_failure() {
        let crash_reports = excluded_directory();
        let path = crash_reports.path().to_path_buf();
        std::fs::write(path.join("minidump"), b"page memory").expect("write a report");
        // Without write permission on the directory its report cannot be
        // unlinked, so the delete fails.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))
            .expect("make the directory unwritable");
        let mut owned = Some(crash_reports);

        let result = delete_crash_reports(&mut owned);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("restore permissions");
        std::fs::remove_dir_all(&path).expect("remove the fixture directory");
        assert_eq!(result, Err(CleanupStage::CrashReportsDelete));
        assert!(
            owned.is_none(),
            "the delete is attempted once, not again on drop"
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
    use crate::test_support::HANG_GUARD;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            // The counter keeps two roots made in the same clock tick apart:
            // tests run in parallel, and one removing the other's shared
            // directory on drop fails it with a missing path.
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "cerebellum-orphan-recovery-{label}-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
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

        let result = release_orphan_profile_custody_at(
            &root.0,
            &intent,
            current_supervisor_generation().expect("current supervisor"),
            KernelSupervisorLiveness,
        );

        assert_eq!(result, Ok(()));
        assert_eq!(lock_count(&root.0), 0);
    }

    /// Drive the custody acquisition a real launch performs: the same
    /// filesystem locks `ProductionLaunchService::launch` opens, through
    /// `ProfileBoundLaunch::acquire_and_prepare`, on the profile `intent` names.
    fn launch_on_intent_profile(
        root: &Path,
        attempt: &str,
    ) -> Result<crate::browser_launch::HeldPreparedProfile, BrowserLaunchOutcome> {
        let mut lifecycle = crate::profile::ProfileLifecycle::open_with_config(
            root,
            crate::profile::RegistryConfig {
                uuid_protocol_compatible: true,
                grant_verifier_available: true,
                sealing_available: true,
                ..crate::profile::RegistryConfig::default()
            },
        )
        .expect("open profile registry");
        let mut locks = ProfileCustodyLocks::open_filesystem(root).expect("open custody locks");
        let context = crate::profile::stamped_bind_context(crate::profile::BindFacts {
            principal: "direct:agent".into(),
            conversation_key: "conversation-2".into(),
            agent_project_id: "project-1".into(),
            session_kind: Some("primary".into()),
            session_kind_attested: true,
            profile_disposition: Some("durable".into()),
            effective_capability_scope: Some(vec!["browser.launch".into()]),
            provenance: "daemon_attested_spec_a".into(),
        })
        .expect("stamp bind context");
        let invocation = InvocationToken::for_test(attempt);
        let reservation =
            JournalReservationHandle::for_test(&invocation, format!("reservation-{attempt}"));
        ProfileBoundLaunch::new(&mut lifecycle, &mut locks).acquire_and_prepare(
            ProfileCustodyKey::durable("project-1"),
            &invocation,
            &reservation,
            &context,
        )
    }

    /// A claim left by a module that has exited is stale, and a launch breaks
    /// it. This is why recovery must re-take, not merely keep, the claim of a
    /// browser it could not stop.
    #[test]
    fn a_launch_breaks_an_orphaned_claim_that_recovery_did_not_retain() {
        let root = TestRoot::new("unretained");
        installed_durable_claim(&root.0);

        assert!(launch_on_intent_profile(&root.0, "fresh").is_ok());
    }

    /// Recovery that could not prove a browser gone retains its profile, and
    /// the launch path then refuses that profile as busy under the recorded
    /// holder. The next start, once this process has exited, can still break
    /// and release that claim because it names the recorded holder.
    #[test]
    fn a_retained_orphan_claim_refuses_launches_until_a_later_start_releases_it() {
        let root = TestRoot::new("retained");
        let intent = installed_durable_claim(&root.0);
        let this_process = current_supervisor_generation().expect("current supervisor");

        assert_eq!(
            retain_orphan_profile_custody_at(
                &root.0,
                &intent,
                this_process,
                KernelSupervisorLiveness
            ),
            Ok(())
        );
        assert_eq!(lock_count(&root.0), 1);
        // Retaining twice in one process is idempotent.
        assert_eq!(
            retain_orphan_profile_custody_at(
                &root.0,
                &intent,
                this_process,
                KernelSupervisorLiveness
            ),
            Ok(())
        );

        match launch_on_intent_profile(&root.0, "contender") {
            Err(BrowserLaunchOutcome::ProfileBusy { holder_id }) => {
                assert_eq!(holder_id.as_str(), intent.holder_id);
            }
            Err(other) => panic!("expected profile_busy, got {other:?}"),
            Ok(_) => panic!("a launch opened a profile whose browser may still be running"),
        }
        assert_eq!(lock_count(&root.0), 1);

        // The next start runs in a new process, so this one reads as gone.
        let next_process = SupervisorGeneration {
            pid: u32::MAX - 1,
            start_time: 19,
            boot_id: None,
        };
        assert_eq!(
            release_orphan_profile_custody_at(&root.0, &intent, next_process, NoLiveSupervisor),
            Ok(())
        );
        assert_eq!(lock_count(&root.0), 0);
    }

    #[test]
    fn startup_recovery_never_releases_a_different_profile_holder() {
        let root = TestRoot::new("different-holder");
        let mut intent = installed_durable_claim(&root.0);
        intent.holder_id = "holder-from-another-attempt".to_string();
        assert_eq!(lock_count(&root.0), 1);

        let result = release_orphan_profile_custody_at(
            &root.0,
            &intent,
            current_supervisor_generation().expect("current supervisor"),
            KernelSupervisorLiveness,
        );

        assert_eq!(result, Err(()));
        assert_eq!(lock_count(&root.0), 1);
    }

    /// Production custody over a test root, as a chosen supervisor.
    struct RootCustody<P> {
        root: PathBuf,
        supervisor: SupervisorGeneration,
        liveness: P,
    }

    impl<P: SupervisorLivenessProbe + Copy> OrphanProfileCustody for RootCustody<P> {
        fn release(
            &mut self,
            intent: &AuthorizedLaunchIntent,
        ) -> Result<(), OrphanProfileCustodyFailure> {
            release_orphan_profile_custody_at(&self.root, intent, self.supervisor, self.liveness)
                .map_err(|_| OrphanProfileCustodyFailure)
        }

        fn retain(
            &mut self,
            intent: &AuthorizedLaunchIntent,
        ) -> Result<(), OrphanProfileCustodyFailure> {
            retain_orphan_profile_custody_at(&self.root, intent, self.supervisor, self.liveness)
                .map_err(|_| OrphanProfileCustodyFailure)
        }
    }

    /// An orphan that is running under its recorded generation, and whose
    /// kill works only when told to.
    struct LiveOrphan {
        kill_succeeds: bool,
    }

    impl OrphanBrowserProcessControl for LiveOrphan {
        fn observed_start_time_micros(
            &mut self,
            _pid: u32,
        ) -> Result<Option<u64>, OrphanProcessControlFailure> {
            Ok(Some(ORPHAN_START_TIME))
        }

        fn terminate_and_reap(
            &mut self,
            _generation: BrowserProcessGeneration,
        ) -> Result<(), OrphanProcessControlFailure> {
            if self.kill_succeeds {
                Ok(())
            } else {
                Err(OrphanProcessControlFailure)
            }
        }
    }

    const ORPHAN_START_TIME: u64 = 7;

    /// Journal `intent` as a launch that reached release, with an attestation
    /// recovery trusts.
    fn dispatched_launch_journal(
        intent: &AuthorizedLaunchIntent,
    ) -> cerebellum_core::journal::InMemoryJournalStorage {
        use crate::browser_launch::{
            ExecutableIdentityChain, ExecutableIdentityCheckpoints, ExecutableIdentityClaim,
            ExecutableIdentityRecord, LaunchGenerationRecord, LaunchJournalPort,
        };
        let storage = cerebellum_core::journal::InMemoryJournalStorage::new();
        let mut journal = DurableLaunchJournal::open(launch_journal_config(), storage.clone())
            .expect("open launch journal");
        let mut handle = journal.record_intent(intent).expect("record intent");
        let generation = LaunchGenerationRecord {
            intent: intent.clone(),
            process_generation: BrowserProcessGeneration {
                pid: 4242,
                start_time_micros: ORPHAN_START_TIME,
                boot_id: None,
            },
        };
        journal
            .record_generation(&mut handle, &generation)
            .expect("record generation");
        let claim = ExecutableIdentityClaim::CodeSigned {
            signing_identifier: "com.example.browser".to_string(),
            unique_code_hash: "abc123".to_string(),
        };
        journal
            .commit_attestation(
                &mut handle,
                &LaunchAttestationRecord {
                    generation,
                    observed_executable_identity: claim.clone(),
                    executable_identity_chain: ExecutableIdentityChain::NoWalkPerformed {
                        attestation: ExecutableIdentityRecord { claim, path: None },
                    },
                    executable_identity_checkpoints:
                        ExecutableIdentityCheckpoints::BeforeSpawnAndAfterExec,
                },
            )
            .expect("commit attestation");
        storage
    }

    /// The whole cycle through `recover_browser_launches` and production
    /// custody: a browser whose kill fails keeps its profile refused to the
    /// real launch path's acquisition, and the next start, whose kill works,
    /// releases it so a launch succeeds again.
    #[test]
    fn a_browser_recovery_could_not_stop_keeps_its_profile_refused_until_a_later_start() {
        let root = TestRoot::new("recovery-cycle");
        let intent = installed_durable_claim(&root.0);
        let storage = dispatched_launch_journal(&intent);

        let mut journal = DurableLaunchJournal::open(launch_journal_config(), storage.clone())
            .expect("reopen launch journal");
        let mut custody = RootCustody {
            root: root.0.clone(),
            supervisor: current_supervisor_generation().expect("current supervisor"),
            liveness: KernelSupervisorLiveness,
        };
        let outcomes = recover_browser_launches(
            &mut journal,
            &mut LiveOrphan {
                kill_succeeds: false,
            },
            &mut custody,
        )
        .expect("a browser that survived its kill refuses only its own profile");
        assert_eq!(
            outcomes[0].process,
            crate::browser_launch::RecoveredBrowserProcess::TerminationFailed
        );
        assert_eq!(outcomes[0].journal_action, None);
        drop(journal);

        match launch_on_intent_profile(&root.0, "contender") {
            Err(BrowserLaunchOutcome::ProfileBusy { holder_id }) => {
                assert_eq!(holder_id.as_str(), intent.holder_id);
            }
            Err(other) => panic!("expected profile_busy, got {other:?}"),
            Ok(_) => panic!("a launch opened a profile whose browser may still be running"),
        }

        // The next start runs in a new process, so this one reads as gone.
        let mut journal = DurableLaunchJournal::open(launch_journal_config(), storage)
            .expect("reopen launch journal at the next start");
        let mut custody = RootCustody {
            root: root.0.clone(),
            supervisor: SupervisorGeneration {
                pid: u32::MAX - 1,
                start_time: 19,
                boot_id: None,
            },
            liveness: NoLiveSupervisor,
        };
        let outcomes = recover_browser_launches(
            &mut journal,
            &mut LiveOrphan {
                kill_succeeds: true,
            },
            &mut custody,
        )
        .expect("the retried recovery succeeds");
        assert_eq!(
            outcomes[0].process,
            crate::browser_launch::RecoveredBrowserProcess::TerminatedAndReaped
        );
        assert!(outcomes[0].journal_action.is_some());
        assert_eq!(lock_count(&root.0), 0);
        assert!(launch_on_intent_profile(&root.0, "after-recovery").is_ok());
    }

    /// Retention re-takes only the claim the launch journal recorded; a claim
    /// installed by another attempt is not adopted, and the failure is
    /// reported so recovery can refuse every launch instead.
    #[test]
    fn startup_recovery_never_retains_a_different_profile_holder() {
        let root = TestRoot::new("retain-different-holder");
        let mut intent = installed_durable_claim(&root.0);
        intent.holder_id = "holder-from-another-attempt".to_string();

        let result = retain_orphan_profile_custody_at(
            &root.0,
            &intent,
            current_supervisor_generation().expect("current supervisor"),
            KernelSupervisorLiveness,
        );

        assert_eq!(result, Err(()));
        assert_eq!(lock_count(&root.0), 1);
    }

    #[test]
    fn launch_service_is_not_published_while_startup_recovery_is_running() {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (service_tx, service_rx) = std::sync::mpsc::channel();

        let worker = std::thread::spawn(move || {
            let service = ProductionLaunchService::open_with_recovery(
                test_config(),
                ProfileStateRoot::for_persistence(crate::JournalPersistence::Isolated),
                |_, _| {
                    entered_tx.send(()).expect("announce recovery start");
                    release_rx.recv().expect("finish recovery");
                    (
                        None,
                        Some(BrowserLaunchRecoveryFailure::JournalTerminalization),
                        Vec::new(),
                    )
                },
            );
            service_tx.send(service).expect("publish recovered service");
        });

        entered_rx
            .recv_timeout(HANG_GUARD)
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
        let service = ProductionLaunchService::open_with_recovery(
            test_config(),
            ProfileStateRoot::for_persistence(crate::JournalPersistence::Isolated),
            |_, _| {
                (
                    None,
                    Some(BrowserLaunchRecoveryFailure::JournalTerminalization),
                    Vec::new(),
                )
            },
        );

        assert_eq!(
            service.require_recovered_startup(),
            Err(json!({
                "outcome": "internal_failure",
                "stage": "startup_recovery",
                "reason_code": "browser_launch_recovery_failed",
            }))
        );
    }

    /// An operator's clear of a launch record startup recovery kept, driven
    /// through the launch service's own recovery, launch path and custody, and
    /// the management plane's question and answer.
    mod launch_recovery_clear {
        use super::*;
        use crate::browser_launch::{
            ExecutableIdentityChain, ExecutableIdentityCheckpoints, ExecutableIdentityClaim,
            ExecutableIdentityRecord, LaunchGenerationRecord, LaunchJournalPort,
            RecoveredBrowserProcess, RecoveryPendingReason,
        };
        use crate::cingulate_client::desk::Ending;
        use crate::launch_recovery::{
            ClearFailure, ClearRefusal, ProcessFact, ProcessTable, ProcessUsers,
            SystemProcessTable, Unreadable,
        };
        use crate::management::{ClearSettlement, ManagementPlane, TargetResolver};
        use crate::test_support::HANG_GUARD;
        use cerebellum_core::identity::{
            AcceptedBindFacts, RouteIdentity, RouteSurface, SessionKind,
        };
        use cerebellum_core::journal::InMemoryJournalStorage;
        use std::collections::{HashMap, HashSet};

        struct NoTargets;

        impl TargetResolver for NoTargets {
            fn resolve(
                &self,
                _bundle_identity: &str,
            ) -> cerebellum_computer::platform::TargetResolution {
                cerebellum_computer::platform::TargetResolution::NotRunning
            }
        }

        /// A recorded browser whose generation cannot be read.
        struct UnobservableOrphan;

        impl OrphanBrowserProcessControl for UnobservableOrphan {
            fn observed_start_time_micros(
                &mut self,
                _pid: u32,
            ) -> Result<Option<u64>, OrphanProcessControlFailure> {
                Err(OrphanProcessControlFailure)
            }

            fn terminate_and_reap(
                &mut self,
                _generation: BrowserProcessGeneration,
            ) -> Result<(), OrphanProcessControlFailure> {
                panic!("an unobservable generation is never signalled")
            }
        }

        /// Read real process facts only for this test binary's descendants.
        /// Unrelated host processes can temporarily hide their arguments during
        /// exec, and must not decide tests about the processes spawned here.
        struct ScopedTable<T = SystemProcessTable>(T);

        impl ScopedTable {
            fn system() -> Self {
                Self(SystemProcessTable)
            }
        }

        impl<T: ProcessTable> ProcessTable for ScopedTable<T> {
            fn this_user(&self) -> Option<u32> {
                self.0.this_user()
            }

            fn process_ids(&self) -> Result<Vec<u32>, Unreadable> {
                // Parent pids do not require reading command lines. Keep forks
                // as well as direct children, even when a shell has not execed.
                let output = std::process::Command::new("/bin/ps")
                    .args(["-A", "-o", "pid=,ppid="])
                    .output()
                    .map_err(|_| Unreadable)?;
                if !output.status.success() {
                    return Err(Unreadable);
                }
                let parents = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(|line| {
                        let mut fields = line.split_whitespace();
                        let pid = fields
                            .next()
                            .ok_or(Unreadable)?
                            .parse()
                            .map_err(|_| Unreadable)?;
                        let parent = fields
                            .next()
                            .ok_or(Unreadable)?
                            .parse()
                            .map_err(|_| Unreadable)?;
                        Ok((pid, parent))
                    })
                    .collect::<Result<HashMap<u32, u32>, Unreadable>>()?;
                let root = std::process::id();
                let mut descendants = HashSet::from([root]);
                loop {
                    let before = descendants.len();
                    for (pid, parent) in &parents {
                        if descendants.contains(parent) {
                            descendants.insert(*pid);
                        }
                    }
                    if descendants.len() == before {
                        break;
                    }
                }
                let mut pids = self.0.process_ids()?;
                pids.retain(|pid| *pid != root && descendants.contains(pid));
                Ok(pids)
            }

            fn users(&self, pid: u32) -> ProcessFact<ProcessUsers> {
                self.0.users(pid)
            }

            fn arguments(&self, pid: u32) -> ProcessFact<Vec<OsString>> {
                self.0.arguments(pid)
            }

            fn executable(&self, pid: u32) -> Result<Option<PathBuf>, Unreadable> {
                self.0.executable(pid)
            }

            fn host_name(&self) -> Option<String> {
                self.0.host_name()
            }
        }

        /// The scoped real process table plus one planted process, whose users
        /// and arguments read as the test says, even outside the descendant set.
        struct PlantedTable {
            pid: u32,
            users: ProcessFact<ProcessUsers>,
            arguments: ProcessFact<Vec<OsString>>,
        }

        /// A pid above macOS's limit, so no real process has it.
        const PLANTED_PID: u32 = 4_000_001;

        impl PlantedTable {
            fn this_user() -> u32 {
                ScopedTable::system().this_user().expect("this user")
            }

            fn run_by(uid: u32, arguments: ProcessFact<Vec<OsString>>) -> Self {
                Self {
                    pid: PLANTED_PID,
                    users: ProcessFact::Read(ProcessUsers { uid, zombie: false }),
                    arguments,
                }
            }
        }

        impl ProcessTable for PlantedTable {
            fn this_user(&self) -> Option<u32> {
                Some(Self::this_user())
            }

            fn process_ids(&self) -> Result<Vec<u32>, Unreadable> {
                let mut pids = ScopedTable::system().process_ids()?;
                pids.push(self.pid);
                Ok(pids)
            }

            fn users(&self, pid: u32) -> ProcessFact<ProcessUsers> {
                if pid == self.pid {
                    self.users.clone()
                } else {
                    ScopedTable::system().users(pid)
                }
            }

            fn arguments(&self, pid: u32) -> ProcessFact<Vec<OsString>> {
                if pid == self.pid {
                    self.arguments.clone()
                } else {
                    ScopedTable::system().arguments(pid)
                }
            }

            fn executable(&self, pid: u32) -> Result<Option<PathBuf>, Unreadable> {
                ScopedTable::system().executable(pid)
            }

            fn host_name(&self) -> Option<String> {
                ScopedTable::system().host_name()
            }
        }

        /// A process table whose pid list cannot be read.
        struct UnlistableTable;

        impl ProcessTable for UnlistableTable {
            fn this_user(&self) -> Option<u32> {
                Some(PlantedTable::this_user())
            }

            fn process_ids(&self) -> Result<Vec<u32>, Unreadable> {
                Err(Unreadable)
            }

            fn users(&self, _pid: u32) -> ProcessFact<ProcessUsers> {
                ProcessFact::Unreadable
            }

            fn arguments(&self, _pid: u32) -> ProcessFact<Vec<OsString>> {
                ProcessFact::Unreadable
            }

            fn executable(&self, _pid: u32) -> Result<Option<PathBuf>, Unreadable> {
                Err(Unreadable)
            }

            fn host_name(&self) -> Option<String> {
                None
            }
        }

        const PROJECT: &str = "project-1";
        const SEQUENCE: u64 = 1;

        struct Fixture {
            service: Arc<ProductionLaunchService>,
            plane: ManagementPlane,
            storage: InMemoryJournalStorage,
            root: PathBuf,
            profile_directory: TestRoot,
        }

        impl Fixture {
            fn launch(&self, attempt: &str) -> Result<PathBuf, Value> {
                self.service
                    .take_and_return_profile_custody(&accepted(), attempt)
            }

            fn record_is_active(&self) -> bool {
                DurableLaunchJournal::open(launch_journal_config(), self.storage.clone())
                    .expect("reopen launch journal")
                    .active_launch_record(SEQUENCE)
                    .expect("read launch journal")
                    .is_some()
            }

            /// Still refused by name, with the record and custody untouched.
            fn assert_still_held(&self, reason: RecoveryPendingReason, attempt: &str) {
                assert_eq!(
                    self.launch(attempt)
                        .map_err(|reply| reply["reason"].clone()),
                    Err(json!(reason.as_str()))
                );
                assert!(self.record_is_active());
                assert_eq!(lock_count(&self.root), 1);
            }

            async fn ask(&self) -> (Value, String) {
                let (reply, question) = self
                    .plane
                    .open_launch_recovery_clear(PROJECT, None, true)
                    .await;
                let question = question.unwrap_or_else(|| panic!("no question: {reply}"));
                self.plane
                    .record_prepared_consent(&question, &question.ask_id);
                assert_eq!(reply["outcome"], "consent_pending", "{reply}");
                (question.body, question.ask_id)
            }

            async fn refusal(&self) -> Value {
                let (reply, question) = self
                    .plane
                    .open_launch_recovery_clear(PROJECT, None, true)
                    .await;
                assert!(question.is_none(), "a refused clear asked anyway: {reply}");
                assert_eq!(reply["outcome"], "refused", "{reply}");
                reply
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                // A hook may hold the service; break that cycle so the
                // scratch root is removed.
                if let Ok(mut hook) = self.service.recovery.stage_hook.lock() {
                    hook.take();
                }
            }
        }

        fn accepted() -> AcceptedBindFacts {
            AcceptedBindFacts {
                identity: RouteIdentity {
                    witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
                    conversation_key: "conversation-2".to_string(),
                    agent_project_id: PROJECT.to_string(),
                    session_kind: SessionKind::Primary,
                    profile_disposition: ProfileDisposition::Durable,
                    origin: Default::default(),
                },
                principal: Some(subc_protocol::Principal::Direct),
                agent_project_id_attested: true,
                acts_as_agent: true,
                session_kind_attested: true,
                control_operations: Vec::new(),
                effective_capability_scope: None,
                consumer_capabilities: Vec::new(),
                surface: RouteSurface::Tools,
                scope: None,
                call_mode: subc_protocol::call_mode::CallMode::Classic,
                codemode_head: None,
                flow_id: None,
            }
        }

        /// Journal `intent` as a launch that reached release. Its attestation
        /// is one recovery trusts unless `reason` is an untrusted attestation.
        fn record_released_launch(
            storage: &InMemoryJournalStorage,
            intent: &AuthorizedLaunchIntent,
            reason: RecoveryPendingReason,
        ) {
            let mut journal = DurableLaunchJournal::open(launch_journal_config(), storage.clone())
                .expect("open launch journal");
            let mut handle = journal.record_intent(intent).expect("record intent");
            assert_eq!(handle.sequence(), SEQUENCE);
            let generation = LaunchGenerationRecord {
                intent: intent.clone(),
                process_generation: BrowserProcessGeneration {
                    pid: 4242,
                    start_time_micros: ORPHAN_START_TIME,
                    boot_id: None,
                },
            };
            journal
                .record_generation(&mut handle, &generation)
                .expect("record generation");
            let code_hash = match reason {
                RecoveryPendingReason::AttestationUntrusted => "not-the-verified-hash",
                _ => "abc123",
            };
            let claim = ExecutableIdentityClaim::CodeSigned {
                signing_identifier: "com.example.browser".to_string(),
                unique_code_hash: code_hash.to_string(),
            };
            journal
                .commit_attestation(
                    &mut handle,
                    &LaunchAttestationRecord {
                        generation,
                        observed_executable_identity: claim.clone(),
                        executable_identity_chain: ExecutableIdentityChain::NoWalkPerformed {
                            attestation: ExecutableIdentityRecord { claim, path: None },
                        },
                        executable_identity_checkpoints:
                            ExecutableIdentityCheckpoints::BeforeSpawnAndAfterExec,
                    },
                )
                .expect("commit attestation");
        }

        /// A module start whose recovery kept `project-1`'s profile for
        /// `reason`, published to a management plane.
        fn retained(reason: RecoveryPendingReason) -> Fixture {
            let profile_directory = TestRoot::new("clear-profile");
            let storage = InMemoryJournalStorage::new();
            let mut service = ProductionLaunchService::open_with_recovery(
                test_config(),
                ProfileStateRoot::for_persistence(crate::JournalPersistence::Isolated),
                |_, profile_root| {
                    let root = profile_root.resolve().expect("scratch profile root");
                    let mut intent = installed_durable_claim(&root);
                    intent.profile.canonical_profile_path = path_bytes(&profile_directory.0);
                    record_released_launch(&storage, &intent, reason);
                    let mut journal = DurableLaunchJournal::open(
                        launch_journal_config(),
                        crate::PlaneJournalStorage::InMemory(storage.clone()),
                    )
                    .expect("reopen launch journal");
                    let (failure, retained) = match reason {
                        RecoveryPendingReason::TerminationFailed => recover_and_retain(
                            &mut journal,
                            &mut LiveOrphan {
                                kill_succeeds: false,
                            },
                            profile_root,
                        ),
                        RecoveryPendingReason::GenerationUnobservable => {
                            recover_and_retain(&mut journal, &mut UnobservableOrphan, profile_root)
                        }
                        RecoveryPendingReason::AttestationUntrusted => recover_and_retain(
                            &mut journal,
                            &mut LiveOrphan {
                                kill_succeeds: true,
                            },
                            profile_root,
                        ),
                    };
                    assert_eq!(failure, None);
                    assert_eq!(retained.len(), 1, "recovery kept the profile");
                    (Some(journal), failure, retained)
                },
            );
            let root = service
                .profile_root
                .resolve()
                .expect("scratch profile root");
            Arc::get_mut(&mut service.recovery)
                .expect("sole recovery owner")
                .process_table = Arc::new(ScopedTable::system());
            let plane = ManagementPlane::new(Arc::new(NoTargets));
            assert!(plane
                .launch_recovery_registry()
                .publish(service.recovery.clone()));
            let fixture = Fixture {
                service: Arc::new(service),
                plane,
                storage,
                root,
                profile_directory,
            };
            assert_eq!(lock_count(&fixture.root), 1);
            fixture
        }

        fn clear() -> Value {
            json!({"decision": "clear"})
        }

        /// A shell whose arguments carry `--user-data-dir=<dir>`, the way
        /// every Chrome process does, running `script`.
        ///
        /// The shell forks to run the script's commands, and a fork carries
        /// its parent's arguments until it execs, so for that moment (or, for
        /// a subshell, for as long as it runs) a second process names the
        /// directory. The evidence reader reports the first naming process it
        /// meets and macOS lists the newest process first, so a refusal may
        /// rightly name the fork: check a reported pid with `started`, never
        /// against the shell's pid alone.
        struct ProfileNamer {
            shell: std::process::Child,
        }

        impl ProfileNamer {
            fn spawn(directory: &Path, script: &str) -> Self {
                use std::os::unix::process::CommandExt;
                let shell = std::process::Command::new("/bin/sh")
                    .arg("-c")
                    .arg(script)
                    .arg(format!("--user-data-dir={}", directory.display()))
                    // Its own process group, which every fork inherits, so
                    // its processes can be told apart and stopped together.
                    .process_group(0)
                    .spawn()
                    .expect("spawn a process naming the profile");
                Self { shell }
            }

            /// A shell that sleeps; `; true` keeps the shell from replacing
            /// itself with `sleep`, so it stays running under its arguments.
            fn sleeping(directory: &Path) -> Self {
                Self::spawn(directory, "sleep 30; true")
            }

            /// Whether `pid` is the shell or a process it started.
            fn started(&self, pid: u32) -> bool {
                let group = std::process::Command::new("/bin/ps")
                    .args(["-o", "pgid=", "-p", &pid.to_string()])
                    .output()
                    .expect("run ps");
                String::from_utf8_lossy(&group.stdout).trim() == self.shell.id().to_string()
            }

            /// Wait until `count` processes name `directory`, and return them.
            fn wait_for_namers(&self, directory: &Path, count: usize) -> Vec<u32> {
                let mut naming = OsString::from("--user-data-dir=");
                naming.push(directory);
                let deadline = std::time::Instant::now() + HANG_GUARD;
                loop {
                    let namers: Vec<u32> =
                        crate::launch_recovery::user_process_arguments(&ScopedTable::system())
                            .expect("read the process table")
                            .into_iter()
                            .filter(|(_, arguments)| arguments.contains(&naming))
                            .map(|(pid, _)| pid)
                            .collect();
                    if namers.len() >= count {
                        return namers;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "only {namers:?} name the profile"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }

        impl Drop for ProfileNamer {
            fn drop(&mut self) {
                // The whole group: a fork left running would outlive the
                // test, holding the test binary's output open.
                let _ = std::process::Command::new("/bin/kill")
                    .args(["-KILL", "--", &format!("-{}", self.shell.id())])
                    .status();
                let _ = self.shell.kill();
                let _ = self.shell.wait();
            }
        }

        /// A running process whose executable is named like Chromium.
        fn chromium_named_process() -> std::process::Child {
            // A copy of this test binary, because macOS kills a copy of a
            // system binary such as /bin/sleep moments after it starts; this
            // binary's own signature survives the copy. It runs only the
            // sleeper below. The copy is content-named, so the same test build
            // reuses one path and macOS assesses the new executable once, not
            // on every run.
            let bytes = std::fs::read(std::env::current_exe().expect("test binary"))
                .expect("read test binary");
            let executable = crate::content_named_fixture::content_named_fixture(
                "chromium-named",
                "Chromium",
                &bytes,
                0o755,
            );
            let child = std::process::Command::new(&executable)
                .args(["--ignored", "--exact", "--nocapture"])
                .arg(format!(
                    "{}::chromium_named_sleeper",
                    module_path!()
                        .split_once("::")
                        .map_or(module_path!(), |(_, path)| path)
                ))
                .env(SLEEPER, "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn a Chromium-named process");
            // Wait until it is really sleeping: alive, and not killed at start.
            std::thread::sleep(Duration::from_millis(300));
            assert_eq!(
                ScopedTable::system()
                    .executable(child.id())
                    .expect("read the sleeper"),
                Some(executable.canonicalize().expect("canonical sleeper path")),
                "the Chromium-named sleeper is not running"
            );
            child
        }

        const SLEEPER: &str = "CK_CHROMIUM_NAMED_SLEEPER";

        /// Only sleeps when started by `chromium_named_process`; an ordinary
        /// run of ignored tests returns at once.
        #[test]
        #[ignore = "started by chromium_named_process as a stand-in browser"]
        fn chromium_named_sleeper() {
            if std::env::var_os(SLEEPER).is_some() {
                std::thread::sleep(Duration::from_secs(30));
            }
        }

        fn stop(mut child: std::process::Child) {
            let _ = child.kill();
            let _ = child.wait();
        }

        fn singleton_lock_to(directory: &Path, target: &str) {
            std::os::unix::fs::symlink(target, directory.join("SingletonLock"))
                .expect("plant SingletonLock");
        }

        fn this_host() -> String {
            ScopedTable::system().host_name().expect("host name")
        }

        #[test]
        fn a_profile_recovery_kept_refuses_launches_by_name_for_each_reason() {
            for reason in RecoveryPendingReason::ALL {
                let fixture = retained(reason);
                let reply = fixture
                    .launch("contender")
                    .expect_err("a launch opened a profile recovery kept");
                assert_eq!(
                    reply,
                    json!({
                        "outcome": "profile_recovery_pending",
                        "reason": reason.as_str(),
                        "remedy": reason.remedy(),
                    })
                );
                assert!(reason.remedy().contains("browser.clear_launch_recovery"));
                assert_eq!(
                    crate::browser::validate_browser_result(
                        crate::browser_session::BROWSER_LAUNCH,
                        &reply
                    ),
                    Ok(())
                );
            }
        }

        #[tokio::test]
        async fn a_clear_refuses_before_startup_recovery_has_published() {
            let fixture = retained(RecoveryPendingReason::AttestationUntrusted);
            // A plane whose launch service has not finished recovery: its
            // registry is empty, which means "not looked yet".
            let unpublished = ManagementPlane::new(Arc::new(NoTargets));
            let (reply, question) = unpublished
                .open_launch_recovery_clear(PROJECT, None, true)
                .await;
            assert!(question.is_none());
            assert_eq!(reply["reason"], "not_ready", "{reply}");
            fixture.assert_still_held(RecoveryPendingReason::AttestationUntrusted, "after");
        }

        #[tokio::test]
        async fn a_clear_refuses_a_project_recovery_did_not_keep() {
            let fixture = retained(RecoveryPendingReason::AttestationUntrusted);
            let (reply, question) = fixture
                .plane
                .open_launch_recovery_clear("project-2", None, true)
                .await;
            assert!(question.is_none());
            assert_eq!(reply["reason"], "not_retained", "{reply}");
            let (reply, _) = fixture
                .plane
                .open_launch_recovery_clear(PROJECT, Some(SEQUENCE + 1), true)
                .await;
            assert_eq!(reply["reason"], "not_retained", "{reply}");
        }

        #[test]
        fn an_unreadable_foreign_process_is_ignored_but_a_test_child_is_read() {
            let directory = TestRoot::new("scoped-processes");
            let namer = ProfileNamer::sleeping(&directory.0);
            // PID 1 is outside this test binary's descendants. Model it
            // as this user's process with unreadable arguments: an unscoped
            // read cannot rule out a browser and must refuse the clear.
            let foreign = PlantedTable {
                pid: 1,
                users: ProcessFact::Read(ProcessUsers {
                    uid: PlantedTable::this_user(),
                    zombie: false,
                }),
                arguments: ProcessFact::Unreadable,
            };
            assert!(crate::launch_recovery::user_process_arguments(&foreign).is_err());
            let scoped = ScopedTable(foreign);
            let processes = crate::launch_recovery::user_process_arguments(&scoped)
                .expect("only owned processes are read");
            assert!(!processes.iter().any(|(pid, _)| *pid == 1));
            let arguments = &processes
                .iter()
                .find(|(pid, _)| *pid == namer.shell.id())
                .expect("the test's shell is still read")
                .1;
            assert!(arguments.contains(&OsString::from(format!(
                "--user-data-dir={}",
                directory.0.display()
            ))));
        }

        #[tokio::test]
        async fn a_clear_refuses_while_a_process_names_the_profile_directory() {
            let fixture = retained(RecoveryPendingReason::AttestationUntrusted);
            let namer = ProfileNamer::sleeping(&fixture.profile_directory.0);
            let reply = fixture.refusal().await;
            assert_eq!(reply["reason"], "profile_in_use", "{reply}");
            let pid = reply["pid"].as_u64().expect("a pid") as u32;
            assert!(namer.started(pid), "{pid} is not the namer's: {reply}");
            fixture.assert_still_held(RecoveryPendingReason::AttestationUntrusted, "after");
        }

        /// A shell naming the profile forks to run its commands, and the fork
        /// also names the profile until it execs, so a clear read in that
        /// window is refused naming the fork, not the shell (on macOS, whose
        /// process table lists the newest process first). The script runs its
        /// sleep in a subshell, a fork that never execs, so two processes name
        /// the profile for the whole test instead of for a moment. The refusal
        /// must name one of the namer's processes, whichever is listed first.
        #[tokio::test]
        async fn a_fork_still_naming_the_profile_refuses_a_clear() {
            let fixture = retained(RecoveryPendingReason::AttestationUntrusted);
            let directory = &fixture.profile_directory.0;
            let namer = ProfileNamer::spawn(directory, "(sleep 30; true); true");
            let namers = namer.wait_for_namers(directory, 2);
            let reply = fixture.refusal().await;
            assert_eq!(reply["reason"], "profile_in_use", "{reply}");
            let pid = reply["pid"].as_u64().expect("a pid") as u32;
            assert!(namers.contains(&pid), "{pid} is not in {namers:?}: {reply}");
            assert!(namer.started(pid), "{pid} is not the namer's: {reply}");
            fixture.assert_still_held(RecoveryPendingReason::AttestationUntrusted, "after");
        }

        /// Chrome's own lock is the second, independent reading: a running
        /// Chrome named there refuses, and so does a lock that cannot be read.
        #[tokio::test]
        async fn a_clear_refuses_what_chrome_s_singleton_lock_does_not_rule_out() {
            let fixture = retained(RecoveryPendingReason::AttestationUntrusted);
            let directory = &fixture.profile_directory.0;

            let child = chromium_named_process();
            singleton_lock_to(directory, &format!("{}-{}", this_host(), child.id()));
            let reply = fixture.refusal().await;
            let pid = child.id();
            stop(child);
            assert_eq!(reply["reason"], "singleton_lock_held", "{reply}");
            assert_eq!(reply["pid"], pid);

            std::fs::remove_file(directory.join("SingletonLock")).expect("remove lock");
            singleton_lock_to(directory, "no-pid-here");
            assert_eq!(
                fixture.refusal().await["reason"],
                "singleton_lock_unreadable"
            );

            std::fs::remove_file(directory.join("SingletonLock")).expect("remove lock");
            std::fs::write(directory.join("SingletonLock"), b"not a link").expect("write");
            assert_eq!(
                fixture.refusal().await["reason"],
                "singleton_lock_unreadable"
            );
            fixture.assert_still_held(RecoveryPendingReason::AttestationUntrusted, "after");
        }

        /// A kept profile whose clear reads processes through `table`.
        fn retained_reading(table: impl ProcessTable + Send + Sync + 'static) -> Fixture {
            let mut fixture = retained(RecoveryPendingReason::AttestationUntrusted);
            // The plane holds the only other reference; swap the table in a
            // fresh plane so the service's state can be changed first.
            fixture.plane = ManagementPlane::new(Arc::new(NoTargets));
            let service = Arc::get_mut(&mut fixture.service).expect("sole service owner");
            let state = Arc::get_mut(&mut service.recovery).expect("sole recovery owner");
            state.process_table = Arc::new(table);
            fixture
                .plane
                .launch_recovery_registry()
                .publish(service.recovery.clone());
            fixture
        }

        #[tokio::test]
        async fn a_clear_refuses_when_the_process_table_cannot_be_read() {
            let fixture = retained_reading(UnlistableTable);
            assert_eq!(
                fixture.refusal().await["reason"],
                "process_table_unreadable"
            );
            fixture.assert_still_held(RecoveryPendingReason::AttestationUntrusted, "after");
        }

        /// A process of this module's user whose arguments the system refuses
        /// to show could be the browser, so the clear is refused.
        #[tokio::test]
        async fn a_clear_refuses_when_a_process_of_this_user_hides_its_arguments() {
            for hidden in [ProcessFact::NotPermitted, ProcessFact::Unreadable] {
                let fixture =
                    retained_reading(PlantedTable::run_by(PlantedTable::this_user(), hidden));
                assert_eq!(
                    fixture.refusal().await["reason"],
                    "process_table_unreadable"
                );
                fixture.assert_still_held(RecoveryPendingReason::AttestationUntrusted, "after");
            }
        }

        /// A process whose user cannot be read might be this user's, so the
        /// clear is refused rather than the process skipped.
        #[tokio::test]
        async fn a_clear_refuses_when_a_process_s_user_cannot_be_read() {
            for users in [ProcessFact::NotPermitted, ProcessFact::Unreadable] {
                let fixture = retained_reading(PlantedTable {
                    pid: PLANTED_PID,
                    users,
                    arguments: ProcessFact::NotPermitted,
                });
                assert_eq!(
                    fixture.refusal().await["reason"],
                    "process_table_unreadable"
                );
            }
        }

        /// A process whose user was read as another user's is skipped, even
        /// though its arguments cannot be read.
        #[tokio::test]
        async fn another_user_s_process_with_hidden_arguments_is_skipped() {
            let other_user = PlantedTable::this_user().wrapping_add(1);
            let fixture =
                retained_reading(PlantedTable::run_by(other_user, ProcessFact::NotPermitted));
            let (reply, _) = fixture.ask().await;
            assert!(reply["params"]["facts"][1]["value"]
                .as_str()
                .unwrap()
                .contains("none of the"));
        }

        #[tokio::test]
        async fn a_denied_clear_changes_nothing() {
            let fixture = retained(RecoveryPendingReason::AttestationUntrusted);
            let (_, ask_id) = fixture.ask().await;
            assert_eq!(
                fixture
                    .plane
                    .settle_launch_recovery_clear(&ask_id, Some(&json!({"decision": "keep"})))
                    .await,
                ClearSettlement::Kept
            );
            fixture.assert_still_held(RecoveryPendingReason::AttestationUntrusted, "after");
            let (reply, _) = fixture
                .plane
                .open_launch_recovery_clear(PROJECT, None, true)
                .await;
            assert_eq!(reply["previous_answer"]["outcome"], "kept", "{reply}");
        }

        /// Each way a clear question can end without an answer to clear is
        /// reported on the next request as that ending, not folded into
        /// `kept`, and clears nothing.
        ///
        /// `kept` says the person decided; silence says they may answer next
        /// time; a question nobody was shown will be shown to nobody next time
        /// either. A silence that arrives with the question's own deadline is
        /// still silence, not a late answer.
        #[tokio::test]
        async fn a_clear_question_that_ended_unanswered_is_reported_as_its_ending() {
            let deadline_passed = Instant::now() + Duration::from_secs(31 * 60);
            let cases = [
                (
                    Ending::Declined {
                        choice_id: "keep".into(),
                    },
                    ClearSettlement::Kept,
                    "kept",
                ),
                (Ending::NoAnswer, ClearSettlement::NoAnswer, "no_answer"),
                (
                    Ending::NotPutToAnyone,
                    ClearSettlement::NotPutToAnyone,
                    "not_put_to_anyone",
                ),
                (
                    Ending::DeliveryFailed,
                    ClearSettlement::Undeliverable,
                    "undeliverable",
                ),
                (
                    Ending::Declined {
                        choice_id: "some_future_word".into(),
                    },
                    ClearSettlement::UnrecognizedAnswer,
                    "unrecognized_answer",
                ),
            ];
            for (ending, settlement, outcome) in cases {
                let fixture = retained(RecoveryPendingReason::AttestationUntrusted);
                let (_, ask_id) = fixture.ask().await;
                let ended_at = if matches!(ending, Ending::NoAnswer) {
                    deadline_passed
                } else {
                    Instant::now()
                };
                assert_eq!(
                    fixture
                        .plane
                        .settle_launch_recovery_clear_ending_at(&ask_id, &ending, ended_at)
                        .await,
                    settlement,
                    "{outcome}"
                );
                fixture.assert_still_held(RecoveryPendingReason::AttestationUntrusted, outcome);
                let (reply, _) = fixture
                    .plane
                    .open_launch_recovery_clear(PROJECT, None, true)
                    .await;
                let previous = &reply["previous_answer"];
                assert_eq!(previous["outcome"], outcome, "{reply}");
                let remedy = previous["remedy"].as_str().unwrap().to_lowercase();
                assert!(remedy.starts_with("nothing was cleared"), "{remedy}");
                if outcome == "not_put_to_anyone" {
                    for loop_word in ["ask again", "retry", "wait"] {
                        assert!(
                            !remedy.contains(loop_word),
                            "a question nobody was shown sends the caller round a loop: {remedy}"
                        );
                    }
                }
            }
        }

        #[tokio::test]
        async fn an_arbitrarily_late_answer_rechecks_evidence_but_an_earlier_start_grants_nothing()
        {
            let fixture = retained(RecoveryPendingReason::AttestationUntrusted);
            let (_, ask_id) = fixture.ask().await;
            let late = Instant::now() + Duration::from_secs(2 * 24 * 60 * 60);
            assert_eq!(
                fixture
                    .plane
                    .settle_launch_recovery_clear_at(&ask_id, Some(&clear()), late)
                    .await,
                ClearSettlement::Cleared { sequence: SEQUENCE }
            );

            // The module restarted: a new plane with a new startup identity
            // receives an answer to the old question.
            let fixture = retained(RecoveryPendingReason::AttestationUntrusted);
            let (_, ask_id) = fixture.ask().await;
            let restarted = ManagementPlane::new(Arc::new(NoTargets));
            restarted
                .launch_recovery_registry()
                .publish(fixture.service.recovery.clone());
            assert_eq!(
                restarted
                    .settle_launch_recovery_clear(&ask_id, Some(&clear()))
                    .await,
                ClearSettlement::UnknownAsk
            );
            assert_eq!(
                restarted
                    .settle_launch_recovery_clear("browser-grant-consent-1", Some(&clear()))
                    .await,
                ClearSettlement::UnknownAsk
            );
            // The consent service's opaque card id does not encode which module
            // start asked. The pending record carries the module's startup id,
            // so an old answer cannot clear a launch record that the current
            // startup recovery kept active.
            restarted.copy_pending_clear_for_test(&fixture.plane, &ask_id, "el_previous_start");
            assert_eq!(
                restarted
                    .settle_launch_recovery_clear("el_previous_start", Some(&clear()))
                    .await,
                ClearSettlement::AskedByEarlierStart
            );
            fixture.assert_still_held(RecoveryPendingReason::AttestationUntrusted, "restarted");
        }

        #[tokio::test]
        async fn an_allowed_clear_releases_the_profile_and_a_launch_proceeds() {
            let fixture = retained(RecoveryPendingReason::AttestationUntrusted);
            // A lock left by a crashed browser names a pid nobody holds, which
            // does not stand in the way.
            singleton_lock_to(
                &fixture.profile_directory.0,
                &format!("{}-4000000", this_host()),
            );
            let (question, ask_id) = fixture.ask().await;
            crate::consent_card::assert_contract(&question, &["clear", "keep"], "keep");
            assert_eq!(question["params"]["urgency"], "normal");
            assert_eq!(question["params"]["scope"]["profile_uuid"], "profile-1");
            let message = question["params"]["facts"].to_string();
            assert!(!message.contains(PROJECT), "{message}");
            assert!(!message.contains("attestation_untrusted"), "{message}");
            assert!(message.contains("1970-01-01T00:00:00.000Z"), "{message}");
            assert!(
                message.contains("names process 4000000, which is not running"),
                "{message}"
            );

            assert_eq!(
                fixture
                    .plane
                    .settle_launch_recovery_clear(&ask_id, Some(&clear()))
                    .await,
                ClearSettlement::Cleared { sequence: SEQUENCE }
            );
            assert!(!fixture.record_is_active());
            assert_eq!(lock_count(&fixture.root), 0);
            assert!(fixture.launch("after-clear").is_ok());
            let (reply, _) = fixture
                .plane
                .open_launch_recovery_clear(PROJECT, None, true)
                .await;
            assert_eq!(reply["reason"], "not_retained", "{reply}");
            assert_eq!(reply["previous_answer"]["outcome"], "cleared", "{reply}");
        }

        /// The profile stays held under recovery's holder from the answer's
        /// re-check until the release, so a launch in that window is still
        /// refused by name.
        #[tokio::test]
        async fn a_launch_during_a_clear_is_refused_until_the_release() {
            let fixture = retained(RecoveryPendingReason::TerminationFailed);
            let seen = Arc::new(Mutex::new(Vec::new()));
            let service = Arc::clone(&fixture.service);
            let root = fixture.root.clone();
            let record = Arc::clone(&seen);
            fixture
                .service
                .recovery
                .stage_hook
                .lock()
                .expect("hook")
                .replace(Box::new(move |stage| {
                    let launch = service
                        .take_and_return_profile_custody(&accepted(), "during-clear")
                        .map_err(|reply| reply["outcome"].clone());
                    record.lock().expect("record").push((
                        stage,
                        launch.map(|_| ()),
                        lock_count(&root),
                    ));
                    true
                }));
            let (_, ask_id) = fixture.ask().await;
            assert_eq!(
                fixture
                    .plane
                    .settle_launch_recovery_clear(&ask_id, Some(&clear()))
                    .await,
                ClearSettlement::Cleared { sequence: SEQUENCE }
            );
            let refused: Result<(), Value> = Err(json!("profile_recovery_pending"));
            assert_eq!(
                *seen.lock().expect("seen"),
                vec![
                    (ClearStage::Rechecked, refused.clone(), 1),
                    (ClearStage::Recorded, refused.clone(), 1),
                    (ClearStage::Terminalized, refused, 1),
                ]
            );
            assert!(fixture.launch("after-clear").is_ok());
        }

        /// The person answered minutes after the question; a browser that
        /// opened the profile since stops the clear.
        #[tokio::test]
        async fn the_evidence_is_read_again_when_the_answer_arrives() {
            let fixture = retained(RecoveryPendingReason::GenerationUnobservable);
            let (_, ask_id) = fixture.ask().await;
            let namer = ProfileNamer::sleeping(&fixture.profile_directory.0);
            let settlement = fixture
                .plane
                .settle_launch_recovery_clear(&ask_id, Some(&clear()))
                .await;
            let ClearSettlement::Failed(ClearFailure::Refused(ClearRefusal::ProfileInUse { pid })) =
                settlement
            else {
                panic!("not refused as in use: {settlement:?}");
            };
            assert!(namer.started(pid), "{pid} is not the namer's");
            fixture.assert_still_held(RecoveryPendingReason::GenerationUnobservable, "after");
        }

        /// A clear that stopped after its durable record, as a crash would,
        /// is finished by the next start's recovery: the record is consumed
        /// and the profile released without observing the browser again.
        #[tokio::test]
        async fn a_clear_stopped_after_its_record_is_finished_by_the_next_start() {
            let fixture = retained(RecoveryPendingReason::TerminationFailed);
            fixture
                .service
                .recovery
                .stage_hook
                .lock()
                .expect("hook")
                .replace(Box::new(|stage| stage != ClearStage::Recorded));
            let (_, ask_id) = fixture.ask().await;
            assert_eq!(
                fixture
                    .plane
                    .settle_launch_recovery_clear(&ask_id, Some(&clear()))
                    .await,
                ClearSettlement::Failed(ClearFailure::Terminalization { sequence: SEQUENCE })
            );
            assert!(fixture.record_is_active());
            assert_eq!(lock_count(&fixture.root), 1);

            // The next start runs in a new process, so this one reads as gone.
            let mut journal =
                DurableLaunchJournal::open(launch_journal_config(), fixture.storage.clone())
                    .expect("reopen launch journal at the next start");
            let mut custody = RootCustody {
                root: fixture.root.clone(),
                supervisor: SupervisorGeneration {
                    pid: u32::MAX - 1,
                    start_time: 19,
                    boot_id: None,
                },
                liveness: NoLiveSupervisor,
            };
            // Its kill would fail; a cleared record must not reach it.
            let outcomes = recover_browser_launches(
                &mut journal,
                &mut LiveOrphan {
                    kill_succeeds: false,
                },
                &mut custody,
            )
            .expect("the next start finishes the clear");
            assert_eq!(
                outcomes[0].process,
                RecoveredBrowserProcess::OperatorCleared
            );
            assert!(outcomes[0].journal_action.is_some());
            assert_eq!(lock_count(&fixture.root), 0);
            assert!(!fixture.record_is_active());
        }
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
            BrowserLaunchRecoveryFailure::JournalTerminalization,
            BrowserLaunchRecoveryFailure::ProfileCustodyRelease { sequence: 7 },
            BrowserLaunchRecoveryFailure::ProfileCustodyRetain { sequence: 7 },
            BrowserLaunchRecoveryFailure::InvalidIntent { sequence: 7 },
            BrowserLaunchRecoveryFailure::NewerWriter {
                sequence: 7,
                newer: cerebellum_core::format_floor::NewerWriter {
                    format: "launch-attestation",
                    found: 6,
                    supported: 5,
                },
            },
        ];
        for failure in failures {
            match failure {
                BrowserLaunchRecoveryFailure::JournalOpen
                | BrowserLaunchRecoveryFailure::JournalRead { .. }
                | BrowserLaunchRecoveryFailure::JournalTerminalization
                | BrowserLaunchRecoveryFailure::ProfileCustodyRelease { .. }
                | BrowserLaunchRecoveryFailure::ProfileCustodyRetain { .. }
                | BrowserLaunchRecoveryFailure::InvalidIntent { .. }
                | BrowserLaunchRecoveryFailure::NewerWriter { .. } => {}
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
