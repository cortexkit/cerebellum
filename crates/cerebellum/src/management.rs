//! Management operations: asking for permission, and the operator's own tools.
//!
//! Separate from tool calls because the two surfaces take different request
//! envelopes and because what they do differs in kind. A tool call acts; a
//! management operation arranges the authority under which acting is possible.
//!
//! For the computer plane the authority is the app grant and the takeover
//! grant (see [`crate::computer_grants`]). A computer action asks for the grant
//! it needs itself and waits for the answer, so no separate opening call is
//! required before acting; `computer.open_target` remains for an operator who
//! wants to settle an application's grant ahead of time, and the grant
//! listing and revoking operations live here because they are the operator's,
//! never a model's.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cerebellum_computer::app_state::session::AppStateSessions;
use cerebellum_computer::platform::{ProcessGrant, TargetCandidate, TargetResolution};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::authorization::{
    ActionGrant, GrantStore, HazardClass, Severity, COMPOSE, MUTATE_DURABLE, MUTATE_REVERSIBLE,
    OBSERVE,
};
use crate::classification::canonical_grant_origin;
use crate::computer_grants::{ComputerGrants, ConsentContext, GrantNeed};
use crate::launch_recovery::{ClearFailure, ClearPreview, LaunchRecoveryRegistry};
use crate::profile::{ProfileLifecycle, RebindProvenance, RebindRefusal, RebindReport};
use crate::CancelHandle;

/// Settle an application's app grant ahead of any action on it.
pub const OPEN_TARGET: &str = "computer.open_target";
/// List the durable "always allow" app grants. Operator-only.
pub const LIST_APP_GRANTS: &str = "computer.list_app_grants";
/// Remove a durable "always allow" app grant. Operator-only.
pub const REVOKE_APP_GRANT: &str = "computer.revoke_app_grant";
/// Ask a person to issue a hazard-scoped browser action grant.
pub const OPEN_GRANT: &str = "browser.open_grant";
/// Copy persistent encrypted login rows from the person's matching browser.
pub const IMPORT_LOGIN: &str = "browser.import_login";
/// Hand the route-owned browser window to the person for login.
pub const PRESENT: &str = "browser.present";
/// End or collect the result of a browser login handoff.
pub const RESUME: &str = "browser.resume";
/// Re-identify a moved or restored browser profile root without adopting profiles.
pub const REBIND_PROFILE_ROOT: &str = "browser.rebind_profile_root";
/// Capture a fresh login in a throwaway profile, for the operator to store.
pub const CAPTURE_LOGIN: &str = "browser.capture_login";
/// Clear a launch record startup recovery kept because it could not prove a
/// browser from before a restart gone. Operator-only: it is a management
/// operation, never a tool, so no model sees it in a tool catalog.
pub const CLEAR_LAUNCH_RECOVERY: &str = "browser.clear_launch_recovery";
pub const OPERATIONS: [&str; 10] = [
    OPEN_TARGET,
    LIST_APP_GRANTS,
    REVOKE_APP_GRANT,
    OPEN_GRANT,
    IMPORT_LOGIN,
    PRESENT,
    RESUME,
    REBIND_PROFILE_ROOT,
    CAPTURE_LOGIN,
    CLEAR_LAUNCH_RECOVERY,
];

/// How long a question the person usually answers from a phone may stay open:
/// a browser grant, or re-identifying the profile root.
///
/// Both are scoped decisions that change nothing until answered, and the agent
/// is only waiting, so the deadline is sized to how long a person takes to
/// notice a phone prompt rather than to a desk session. Measured: an operator
/// answered a grant after about 12 minutes, after a 5-minute deadline had
/// already expired it.
const PHONE_CONSENT_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// Resolving an application name to the process that answers to it.
///
/// Behind a trait because the resolution reads the window server, which exists
/// only on the platform this plane drives — while everything above it is
/// ordinary logic that should be exercised wherever the tests run. A concrete
/// dependency here would put the consent flow in the half no continuous build
/// compiles.
pub trait TargetResolver: Send + Sync {
    fn resolve(&self, bundle_identity: &str) -> TargetResolution;

    /// The name the resolved process runs under, for showing to a person.
    /// `None` where it cannot be read; the bundle identity is shown instead.
    fn display_name(&self, _grant: &ProcessGrant) -> Option<String> {
        None
    }
}

/// Resolves application names against this machine.
///
/// macOS and Windows each supply a window-owner reading to the platform-neutral
/// [`TargetResolution::decide`]. A host with no enumerator cannot say an
/// application is absent, only that it cannot look, and reporting "not running"
/// would be a claim rather than a reading.
#[derive(Debug, Default)]
pub struct PlatformResolver {
    timeout: Duration,
}

impl PlatformResolver {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }
}

/// Turn an unreadable-target reason into the remedy a caller can act on.
///
/// One word ("unreadable") used to carry every cause, and the remedy attached
/// to it named a macOS screen-recording grant -- which is what a Windows caller
/// running in the wrong session was told to check. The reasons are distinct
/// because the remedies are, and the wire carries the reason itself so a
/// caller need not parse the prose.
fn unreadable_remedy(reason: &cerebellum_computer::platform::UnreadableReason) -> &'static str {
    use cerebellum_computer::platform::UnreadableReason;
    match reason {
        UnreadableReason::WindowListUnavailable => {
            "the window list could not be read, so nothing is known about this application; \
             retry, and if it persists check that the process that launched this module still \
             holds the platform's window-reading permission (screen recording on macOS)"
        }
        UnreadableReason::SessionNotInteractive { .. } => {
            "this module is running in a session that cannot see the user's desktop, so \
             nothing is known about this application; run it from the console session"
        }
        UnreadableReason::NoConsoleSession { .. } => {
            "no user is logged in at the console, so no desktop exists to read; log a user in \
             at the console"
        }
        UnreadableReason::PartialWindowList { .. } => {
            "some windows' owners could not be read, so this name may belong to a window that \
             could not be attributed; retry, and if it persists the application may be a \
             protected process this module cannot inspect"
        }
        UnreadableReason::GenerationUnreadable { .. } => {
            "exactly one instance is running but its start time could not be read, so no grant \
             can be bound to it safely; do NOT start another instance -- retry, and if it \
             persists the process is one this module cannot inspect"
        }
    }
}

impl TargetResolver for PlatformResolver {
    #[cfg(target_os = "macos")]
    fn resolve(&self, bundle_identity: &str) -> TargetResolution {
        cerebellum_computer::platform::native::resolve_target(bundle_identity, self.timeout)
    }

    #[cfg(target_os = "macos")]
    fn display_name(&self, grant: &ProcessGrant) -> Option<String> {
        cerebellum_computer::platform::native::application_name(grant.pid, self.timeout)
    }

    /// On macOS a caller names a bundle identifier (`com.apple.TextEdit`). On
    /// Windows the same caller names an executable basename (`notepad.exe`).
    /// Windows has no bundle identifier; the two identities are deliberately
    /// asymmetric.
    ///
    /// Measured on Windows 11 ARM64, console session: one Notepad resolves,
    /// two are refused as ambiguous with both pids and window counts, an
    /// absent name is NotRunning over a complete 95-window reading, and the
    /// same command from the service session refuses by provenance -- where
    /// the reading SUCCEEDS with six service-desktop windows and would
    /// otherwise have called two open Notepads not running.
    ///
    /// UWP applications resolve by their OWN executable basename, the same as
    /// classic ones: Calculator running as the console user is
    /// `calculatorapp.exe`, Resolved to its own pid, stable across repeated
    /// reads. An earlier note here said the opposite; that run had never
    /// launched Calculator (AppX activation is per-user and the launcher ran as
    /// SYSTEM), so its NotRunning was true and proved nothing about UWP.
    ///
    /// Do not name `applicationframehost.exe` for a UWP app. It also resolves,
    /// but to the frame host that owns the title bars of EVERY open UWP app --
    /// two windows before Calculator, five after -- so it is the wrong process
    /// for actuation and is ambiguous across apps in a way the count cannot
    /// show. The app's content, and its accessibility tree, live in its own
    /// process.
    #[cfg(target_os = "windows")]
    fn resolve(&self, bundle_identity: &str) -> TargetResolution {
        let _ = self.timeout;
        cerebellum_computer::platform::windows::resolve_target(bundle_identity)
    }

    // No enumerator exists for these platforms, so the answer is that the
    // module could not look. `NotRunning` here would assert an absence about a
    // machine nobody inspected.
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        let _ = self.timeout;
        TargetResolution::Unreadable(
            cerebellum_computer::platform::UnreadableReason::WindowListUnavailable,
        )
    }
}

/// The state a management route needs.
pub struct ManagementPlane {
    /// The computer plane's app and takeover grants, and the questions out
    /// for them.
    computer_grants: Arc<ComputerGrants>,
    /// Each conversation's element ids and the diff baselines behind them.
    /// Held beside the grants because both belong to a conversation and end
    /// with it.
    app_state_sessions: Arc<AppStateSessions>,
    resolver: Arc<dyn TargetResolver>,
    browser_grants: Arc<Mutex<GrantStore>>,
    pending_browser_grants: Mutex<BTreeMap<String, PendingBrowserGrant>>,
    profile_lifecycle: Option<Arc<ProfileLifecycle>>,
    pending_profile_root_rebinds: Mutex<BTreeMap<String, PendingProfileRootRebind>>,
    /// Where the launch service publishes what startup recovery kept.
    launch_recovery: Arc<LaunchRecoveryRegistry>,
    pending_launch_recovery_clears: Mutex<BTreeMap<String, PendingLaunchRecoveryClear>>,
    /// The last answer to a clear question, by project, reported on the next
    /// request for that project. The answer arrives on a task nobody waits
    /// on, so this is where an answer that did nothing says so.
    launch_recovery_settlements: Mutex<BTreeMap<String, Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingBrowserGrant {
    conversation_key: String,
    authorized_origins: Vec<String>,
    disclosed_hazards: BTreeSet<HazardClass>,
    severity: Severity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingProfileRootRebind {
    conversation_key: String,
    preview: RebindReport,
}

#[derive(Debug, Clone)]
struct PendingLaunchRecoveryClear {
    preview: ClearPreview,
    /// The module startup that asked. An answer is acted on only by the same
    /// one: after a restart, recovery has run again and the question no
    /// longer describes what it kept.
    incarnation: String,
    asked_at: Instant,
}

/// What one answer to a clear question did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearSettlement {
    Cleared {
        sequence: u64,
    },
    /// The person chose to keep the record, or gave no usable answer.
    Kept,
    /// Answered after the question's deadline.
    Expired,
    /// Asked by an earlier start of this module; nothing was done.
    AskedByEarlierStart,
    /// No question with this identity is pending.
    UnknownAsk,
    /// The re-check at answer time, or a later step, stopped the clear.
    Failed(ClearFailure),
}

impl ClearSettlement {
    pub fn as_json(&self) -> Value {
        match self {
            Self::Cleared { sequence } => json!({"outcome": "cleared", "sequence": sequence}),
            Self::Kept => json!({"outcome": "kept"}),
            Self::Expired => json!({
                "outcome": "expired",
                "remedy": "the answer arrived after the question's deadline and did nothing; ask again",
            }),
            Self::AskedByEarlierStart => json!({
                "outcome": "stale_incarnation",
                "remedy": "the question was asked before the module restarted and did nothing; ask again",
            }),
            Self::UnknownAsk => json!({"outcome": "unknown_ask"}),
            Self::Failed(ClearFailure::Refused(refusal)) => refusal.as_json(),
            Self::Failed(ClearFailure::Terminalization { sequence }) => json!({
                "outcome": "clear_unfinished",
                "stage": "record_terminalization",
                "sequence": sequence,
                "remedy": "the clear is recorded; the next module start finishes it",
            }),
            Self::Failed(ClearFailure::CustodyRelease { sequence }) => json!({
                "outcome": "clear_unfinished",
                "stage": "custody_release",
                "sequence": sequence,
                "remedy": "the record is cleared but the profile is still held; restarting the module releases it",
            }),
        }
    }
}

impl ManagementPlane {
    /// A plane whose computer grants live in memory and are never offered
    /// "always". For tests and isolated callers.
    pub fn new(resolver: Arc<dyn TargetResolver>) -> Self {
        Self::with_computer_grants(resolver, Arc::new(ComputerGrants::in_memory()))
    }

    /// A plane over computer grants the caller opened, which is how a running
    /// module attaches the operator's durable store.
    pub fn with_computer_grants(
        resolver: Arc<dyn TargetResolver>,
        computer_grants: Arc<ComputerGrants>,
    ) -> Self {
        Self {
            computer_grants,
            app_state_sessions: Arc::new(AppStateSessions::new()),
            resolver,
            browser_grants: Arc::new(Mutex::new(GrantStore::default())),
            pending_browser_grants: Mutex::new(BTreeMap::new()),
            profile_lifecycle: None,
            pending_profile_root_rebinds: Mutex::new(BTreeMap::new()),
            launch_recovery: Arc::new(LaunchRecoveryRegistry::new()),
            pending_launch_recovery_clears: Mutex::new(BTreeMap::new()),
            launch_recovery_settlements: Mutex::new(BTreeMap::new()),
        }
    }

    /// The computer plane's grants.
    pub fn computer_grants(&self) -> &Arc<ComputerGrants> {
        &self.computer_grants
    }

    /// Every conversation's application-state sessions.
    pub fn app_state_sessions(&self) -> &Arc<AppStateSessions> {
        &self.app_state_sessions
    }

    /// Forget everything the computer plane holds for a conversation whose
    /// last route unbound: its grants, its remembered refusals, its open
    /// questions, and its element ids. An id outliving its conversation would
    /// let a later conversation with the same key act on elements it never
    /// read.
    pub fn end_conversation(&self, conversation_key: &str) {
        self.computer_grants.end_conversation(conversation_key);
        self.app_state_sessions.end_conversation(conversation_key);
    }

    /// Resolve an application name to the one process answering to it now,
    /// or the refusal that says why there is not exactly one.
    ///
    /// Called for every action, and again after a call waited for consent:
    /// a grant says the person agreed, and resolving says the process they
    /// agreed about is still the one answering to that name. A process that
    /// exited and had its identifier reused would otherwise inherit a grant
    /// made for something else.
    pub fn resolve_process(&self, bundle_identity: &str) -> Result<ProcessGrant, Value> {
        match self.resolver.resolve(bundle_identity) {
            TargetResolution::Resolved(grant) => Ok(grant),
            TargetResolution::NotRunning => Err(json!({
                "outcome": "not_running",
                "bundle_identity": bundle_identity,
                "remedy": "start the application, then retry",
            })),
            TargetResolution::Ambiguous(candidates) => Err(json!({
                "outcome": "ambiguous",
                "bundle_identity": bundle_identity,
                "instances": describe(&candidates),
                // Named rather than chosen between: picking one would act on a
                // process the person never selected.
                "remedy": "quit all but one instance, then retry",
            })),
            // Separate from `not_running` because that answer is a claim about
            // the world and this one is only about our own sight. Telling
            // someone their running application is not running sends them to
            // start a second copy.
            TargetResolution::Unreadable(reason) => Err(json!({
                "outcome": "targets_unreadable",
                "bundle_identity": bundle_identity,
                "unreadable": reason,
                "remedy": unreadable_remedy(&reason),
            })),
        }
    }

    /// What the person sees an application called, for the consent question:
    /// its running name, or its bundle identity when no name can be read.
    pub fn application_name(&self, grant: &ProcessGrant) -> String {
        self.resolver
            .display_name(grant)
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| grant.bundle_identity.clone())
    }

    /// Resolve an application and hold its app grant, asking the person and
    /// waiting for the answer when it is not held.
    ///
    /// The process is resolved before asking, so nobody is asked about an
    /// application that is not running, and again after a wait, so the call
    /// acts on the process that answers to the name now.
    pub async fn admit_app(
        &self,
        bundle_identity: &str,
        consent: &ConsentContext,
        cancel: &CancelHandle,
    ) -> Result<(ProcessGrant, crate::computer_grants::GrantAdmission), AppRefusal> {
        let grant = self
            .resolve_process(bundle_identity)
            .map_err(AppRefusal::Resolution)?;
        let need = GrantNeed::App {
            bundle_identity: bundle_identity.to_string(),
            display_name: self.application_name(&grant),
        };
        let admission = self
            .computer_grants
            .require(&need, consent, cancel)
            .await
            .map_err(AppRefusal::Consent)?;
        let grant = if admission.waited {
            self.resolve_process(bundle_identity)
                .map_err(AppRefusal::Resolution)?
        } else {
            grant
        };
        Ok((grant, admission))
    }

    /// `computer.open_target`: settle an application's app grant now.
    ///
    /// Blocks exactly as an action does, and replies `granted` once the grant
    /// is held; nothing is done in the application.
    pub async fn open_target(
        &self,
        bundle_identity: &str,
        consent: &ConsentContext,
        cancel: &CancelHandle,
    ) -> Value {
        match self.admit_app(bundle_identity, consent, cancel).await {
            Ok((grant, admission)) => {
                let mut reply = json!({
                    "outcome": "granted",
                    "bundle_identity": bundle_identity,
                    "pid": grant.pid,
                });
                admission.decorate(&mut reply);
                reply
            }
            Err(refusal) => refusal.reply(bundle_identity),
        }
    }

    /// Build a plane against an explicitly held registry, for isolated callers and tests.
    pub fn with_profile_lifecycle(
        resolver: Arc<dyn TargetResolver>,
        profile_lifecycle: Arc<ProfileLifecycle>,
    ) -> Self {
        let mut plane = Self::new(resolver);
        plane.profile_lifecycle = Some(profile_lifecycle);
        plane
    }

    pub(crate) fn browser_grants(&self) -> Arc<Mutex<GrantStore>> {
        Arc::clone(&self.browser_grants)
    }

    /// Prepare an attributed browser grant question without waiting for a person.
    pub async fn open_browser_grant(
        &self,
        conversation_key: &str,
        origins: Vec<String>,
        hazards: Vec<HazardClass>,
        can_relay_to_a_person: bool,
    ) -> Result<(Value, Option<Question>), BrowserGrantRequestError> {
        self.open_browser_grant_at_tier(
            conversation_key,
            origins,
            hazards,
            None,
            can_relay_to_a_person,
        )
        .await
    }

    /// Prepare a browser grant question whose ceiling tier is at least
    /// `severity_tier`. The tier can only raise the ceiling the hazards already
    /// imply; the credential and financial flags still come only from disclosed
    /// hazards, so a number alone never lets the agent submit a sign-in or
    /// payment form.
    pub async fn open_browser_grant_at_tier(
        &self,
        conversation_key: &str,
        origins: Vec<String>,
        hazards: Vec<HazardClass>,
        severity_tier: Option<u8>,
        can_relay_to_a_person: bool,
    ) -> Result<(Value, Option<Question>), BrowserGrantRequestError> {
        if severity_tier.is_some_and(|tier| {
            !(crate::authorization::OBSERVE..=crate::authorization::MAX_GRANTABLE_TIER)
                .contains(&tier)
        }) {
            return Err(BrowserGrantRequestError::InvalidSeverityTier);
        }
        if conversation_key.is_empty()
            || origins.is_empty()
            || origins.len() > crate::authorization::MAX_ORIGINS
        {
            return Err(BrowserGrantRequestError::InvalidOrigins);
        }
        let mut seen_origins = HashSet::new();
        let mut authorized_origins = Vec::with_capacity(origins.len());
        for origin in origins {
            // Only an http(s) origin already in canonical form can be granted,
            // so the person is shown exactly the site the grant will match.
            // The opaque origin `null` is refused here too: it names no site.
            if canonical_grant_origin(&origin).as_deref() != Some(origin.as_str()) {
                return Err(BrowserGrantRequestError::UngrantableOrigin { value: origin });
            }
            if !seen_origins.insert(origin.clone()) {
                return Err(BrowserGrantRequestError::InvalidOrigins);
            }
            authorized_origins.push(origin);
        }
        let mut disclosed_hazards = BTreeSet::new();
        let mut disclosed_hazards_wire = Vec::with_capacity(hazards.len());
        for hazard in hazards {
            if !disclosed_hazards.insert(hazard) {
                return Err(BrowserGrantRequestError::InvalidHazards);
            }
            disclosed_hazards_wire.push(hazard.as_str().to_string());
        }
        let severity = browser_grant_minted_severity(&disclosed_hazards, severity_tier);
        let severity_value = browser_grant_severity_value(severity);

        if !can_relay_to_a_person {
            return Ok((
                json!({
                    "outcome": "consent_unavailable",
                    "origins": authorized_origins,
                    "hazards": disclosed_hazards_wire,
                    "severity_ceiling": severity_value,
                    "remedy": "reconnect declaring the ability to relay a question to a person",
                }),
                None,
            ));
        }

        let ask_id = new_browser_grant_ask_id();
        let pending = PendingBrowserGrant {
            conversation_key: conversation_key.to_string(),
            authorized_origins: authorized_origins.clone(),
            disclosed_hazards,
            severity,
        };
        self.pending_browser_grants
            .lock()
            .await
            .insert(ask_id.clone(), pending);
        let question = Question {
            ask_id: ask_id.clone(),
            body: browser_grant_question(
                &ask_id,
                &authorized_origins,
                &disclosed_hazards_wire,
                severity,
            ),
            deadline: PHONE_CONSENT_DEADLINE,
        };
        Ok((
            json!({
                "outcome": "consent_pending",
                "ask_id": ask_id,
                "origins": authorized_origins,
                "hazards": disclosed_hazards_wire,
                "severity_ceiling": severity_value,
                "remedy": "retry the browser action after the request has been answered",
            }),
            Some(question),
        ))
    }

    /// Apply exactly one human answer to the browser scope recorded at ask time.
    pub async fn settle_browser_grant(&self, ask_id: &str, answer: Option<&Value>) -> bool {
        let Some(pending) = self.pending_browser_grants.lock().await.remove(ask_id) else {
            return false;
        };
        if answer
            .and_then(|body| body.get("decision"))
            .and_then(Value::as_str)
            != Some("allow")
        {
            return true;
        }

        let grant = ActionGrant::new(
            format!("grant-{ask_id}"),
            1,
            pending.conversation_key,
            pending.severity,
            pending.authorized_origins,
        )
        .with_disclosed_hazards(pending.disclosed_hazards);
        self.browser_grants.lock().await.replace(grant).is_ok()
    }

    pub async fn browser_grant_question_for_test(
        &self,
        conversation_key: &str,
        origins: Vec<String>,
        hazards: Vec<HazardClass>,
    ) -> Question {
        let (_, question) = self
            .open_browser_grant(conversation_key, origins, hazards, true)
            .await
            .expect("test browser grant scope is valid");
        question.expect("an elicitable browser grant produces a question")
    }

    pub async fn browser_grant_count(&self) -> usize {
        self.browser_grants.lock().await.current_grants().count()
    }

    fn profile_lifecycle_for_rebind(&self) -> Result<Arc<ProfileLifecycle>, &'static str> {
        if let Some(lifecycle) = self.profile_lifecycle.as_ref() {
            return Ok(Arc::clone(lifecycle));
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            crate::browser_launch_service::production_profile_lifecycle()
                .map(Arc::new)
                .map_err(|error| error.stage())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err("profile_registry_platform_unavailable")
        }
    }

    /// Resolve the existing durable profile selected by the route's project identity.
    pub fn durable_login_profile_location(
        &self,
        project_id: &str,
    ) -> Result<Option<crate::login_import::DurableProfileLocation>, &'static str> {
        let lifecycle = self.profile_lifecycle_for_rebind()?;
        let registry = lifecycle.registry();
        let resolution = registry
            .resolve_durable(project_id)
            .map_err(|_| "profile_registry_unavailable")?;
        match resolution {
            crate::profile::DurableResolution::TrustworthyExisting(record) => {
                let profile = registry
                    .root()
                    .open_target(Path::new(&record.target))
                    .map_err(|_| "profile_registry_unavailable")?;
                Ok(Some(crate::login_import::DurableProfileLocation {
                    managed_root: registry.root().canonical_path().to_path_buf(),
                    profile_directory: profile.canonical_path().to_path_buf(),
                }))
            }
            crate::profile::DurableResolution::AffirmativeAbsence
            | crate::profile::DurableResolution::Unavailable => Ok(None),
            crate::profile::DurableResolution::Untrustworthy(_) => {
                Err("profile_registry_unavailable")
            }
        }
    }

    /// Preflight a profile-root rebind and prepare an attributed consent question.
    pub async fn open_profile_root_rebind(
        &self,
        conversation_key: &str,
        can_relay_to_a_person: bool,
    ) -> (Value, Option<Question>) {
        let lifecycle = match self.profile_lifecycle_for_rebind() {
            Ok(lifecycle) => lifecycle,
            Err(stage) => return (json!({"outcome": "internal_failure", "stage": stage}), None),
        };
        let root_path = lifecycle
            .registry()
            .root()
            .canonical_path()
            .display()
            .to_string();
        let preview = match lifecycle.registry().preview_rebind() {
            Ok(preview) => preview,
            Err(RebindRefusal::AlreadyBound) => {
                return (
                    json!({
                        "outcome": "rebind_not_needed",
                        "root_path": root_path,
                        "remedy": "the registry is already bound to the current browser root; no action is required",
                    }),
                    None,
                )
            }
            Err(refusal) => return (rebind_refusal_reply(refusal), None),
        };

        if !can_relay_to_a_person {
            return (
                json!({
                    "outcome": "consent_unavailable",
                    "root_path": root_path,
                    "old_identity": preview.old_identity,
                    "new_identity": preview.new_identity,
                    "generation": preview.generation_before,
                    "record_count": preview.record_count,
                    "remedy": "reconnect declaring the ability to relay a question to a person",
                }),
                None,
            );
        }

        let ask_id = new_profile_root_rebind_ask_id();
        self.pending_profile_root_rebinds.lock().await.insert(
            ask_id.clone(),
            PendingProfileRootRebind {
                conversation_key: conversation_key.to_string(),
                preview: preview.clone(),
            },
        );
        let question = Question {
            ask_id: ask_id.clone(),
            body: profile_root_rebind_question(&ask_id, &root_path, &preview),
            deadline: PHONE_CONSENT_DEADLINE,
        };
        (
            json!({
                "outcome": "consent_pending",
                "ask_id": ask_id,
                "root_path": root_path,
                "old_identity": preview.old_identity,
                "new_identity": preview.new_identity,
                "generation": preview.generation_before,
                "record_count": preview.record_count,
                "remedy": "wait for the person to answer before retrying browser launch",
            }),
            Some(question),
        )
    }

    /// Apply one answer only when the registry situation still matches the question.
    pub async fn settle_profile_root_rebind(&self, ask_id: &str, answer: Option<&Value>) -> bool {
        let Some(pending) = self
            .pending_profile_root_rebinds
            .lock()
            .await
            .remove(ask_id)
        else {
            return false;
        };
        if answer
            .and_then(|body| body.get("decision"))
            .and_then(Value::as_str)
            != Some("allow")
        {
            return true;
        }
        let Ok(lifecycle) = self.profile_lifecycle_for_rebind() else {
            return true;
        };
        let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return true;
        };
        let Ok(at_unix_ms) = u64::try_from(elapsed.as_millis()) else {
            return true;
        };
        let provenance = RebindProvenance {
            ask_id: ask_id.to_string(),
            conversation_key: pending.conversation_key,
            at_unix_ms,
        };
        let _ = lifecycle
            .registry()
            .rebind_managed_root_from_preview(&provenance, &pending.preview);
        true
    }

    pub async fn profile_root_rebind_pending_count(&self) -> usize {
        self.pending_profile_root_rebinds.lock().await.len()
    }

    /// The registry the launch service publishes its clear into once startup
    /// recovery has finished.
    pub fn launch_recovery_registry(&self) -> Arc<LaunchRecoveryRegistry> {
        Arc::clone(&self.launch_recovery)
    }

    /// Read what startup recovery kept for `agent_project_id` and the evidence
    /// that no browser uses its profile, and prepare the consent question.
    /// Nothing changes until a person answers.
    pub async fn open_launch_recovery_clear(
        &self,
        agent_project_id: &str,
        sequence: Option<u64>,
        can_relay_to_a_person: bool,
    ) -> (Value, Option<Question>) {
        let previous = self
            .launch_recovery_settlements
            .lock()
            .await
            .get(agent_project_id)
            .cloned();
        let with_previous = |mut reply: Value| {
            if let Some(previous) = previous.as_ref() {
                reply["previous_answer"] = previous.clone();
            }
            reply
        };
        let preview = match self.launch_recovery.preview(agent_project_id, sequence) {
            Ok(preview) => preview,
            Err(refusal) => return (with_previous(refusal.as_json()), None),
        };
        let described = json!({
            "agent_project_id": preview.agent_project_id,
            "sequence": preview.sequence,
            "reason": preview.reason.as_str(),
            "launched_at": preview.launched_at,
            "evidence": preview.evidence.as_json(),
        });
        if !can_relay_to_a_person {
            let mut reply = described;
            reply["outcome"] = json!("consent_unavailable");
            reply["remedy"] =
                json!("reconnect declaring the ability to relay a question to a person");
            return (with_previous(reply), None);
        }

        let incarnation = self.launch_recovery.incarnation().to_string();
        let ask_id = new_launch_recovery_clear_ask_id(&incarnation);
        let question = Question {
            ask_id: ask_id.clone(),
            body: launch_recovery_clear_question(&ask_id, &preview),
            deadline: PHONE_CONSENT_DEADLINE,
        };
        self.pending_launch_recovery_clears.lock().await.insert(
            ask_id.clone(),
            PendingLaunchRecoveryClear {
                preview,
                incarnation,
                asked_at: Instant::now(),
            },
        );
        let mut reply = described;
        reply["outcome"] = json!("consent_pending");
        reply["ask_id"] = json!(ask_id);
        reply["remedy"] = json!(
            "wait for the person to answer; the evidence is read again before anything is cleared"
        );
        (with_previous(reply), Some(question))
    }

    /// Apply one answer to a clear question.
    pub async fn settle_launch_recovery_clear(
        &self,
        ask_id: &str,
        answer: Option<&Value>,
    ) -> ClearSettlement {
        self.settle_launch_recovery_clear_at(ask_id, answer, Instant::now())
            .await
    }

    /// [`Self::settle_launch_recovery_clear`] as if answered at `answered_at`,
    /// so a test can answer after the deadline without waiting for it.
    pub async fn settle_launch_recovery_clear_at(
        &self,
        ask_id: &str,
        answer: Option<&Value>,
        answered_at: Instant,
    ) -> ClearSettlement {
        let incarnation = self.launch_recovery.incarnation();
        let pending = self
            .pending_launch_recovery_clears
            .lock()
            .await
            .remove(ask_id);
        let (settlement, project) = match pending {
            // A question this start never asked. One whose identity names
            // another start was asked before a restart: say so, since the
            // person may believe they cleared something.
            None => {
                let settlement = if ask_id.starts_with(LAUNCH_RECOVERY_CLEAR_ASK_PREFIX)
                    && !ask_id
                        .starts_with(&format!("{LAUNCH_RECOVERY_CLEAR_ASK_PREFIX}{incarnation}-"))
                {
                    ClearSettlement::AskedByEarlierStart
                } else {
                    ClearSettlement::UnknownAsk
                };
                return settlement;
            }
            Some(pending) => {
                let project = pending.preview.agent_project_id.clone();
                let settlement = if pending.incarnation != incarnation {
                    ClearSettlement::AskedByEarlierStart
                } else if answered_at.saturating_duration_since(pending.asked_at)
                    > PHONE_CONSENT_DEADLINE
                {
                    ClearSettlement::Expired
                } else if answer
                    .and_then(|body| body.get("decision"))
                    .and_then(Value::as_str)
                    != Some("clear")
                {
                    ClearSettlement::Kept
                } else {
                    match self.launch_recovery.clear(&pending.preview, ask_id) {
                        Ok(()) => ClearSettlement::Cleared {
                            sequence: pending.preview.sequence,
                        },
                        Err(failure) => ClearSettlement::Failed(failure),
                    }
                };
                (settlement, project)
            }
        };
        self.launch_recovery_settlements
            .lock()
            .await
            .insert(project, settlement.as_json());
        settlement
    }

    pub async fn launch_recovery_clear_pending_count(&self) -> usize {
        self.pending_launch_recovery_clears.lock().await.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserGrantRequestError {
    /// The origin list is empty, too long, or names an origin twice.
    InvalidOrigins,
    /// One origin is not a canonical http(s) origin a grant can name. Carries
    /// the value as sent so the refusal can show the caller which one.
    UngrantableOrigin {
        value: String,
    },
    InvalidHazards,
    /// A `severity_tier` outside the tiers a browser grant may carry.
    InvalidSeverityTier,
}

/// The ceiling tier of a browser grant that discloses no hazard and names no
/// tier: ordinary browsing, reading pages and clicking plain links and buttons.
/// A caller asking for a lower tier still gets this one, so anything that
/// predicts the tier a grant will be minted at must start from here.
pub(crate) const NO_HAZARD_GRANT_TIER: u8 = COMPOSE;

/// The ceiling `browser.open_grant` mints for these disclosed hazards and this
/// optional requested tier. The requested tier can only raise the ceiling the
/// hazards imply; the credential and financial flags come only from hazards.
/// Refusals that suggest `open_grant` arguments call this too, so the tier they
/// name is the tier the grant will really carry.
pub(crate) fn browser_grant_minted_severity(
    hazards: &BTreeSet<HazardClass>,
    severity_tier: Option<u8>,
) -> Severity {
    let hazard_severity = browser_grant_severity(hazards);
    Severity {
        tier: hazard_severity
            .tier
            .max(severity_tier.unwrap_or(hazard_severity.tier)),
        ..hazard_severity
    }
}

fn browser_grant_severity(hazards: &BTreeSet<HazardClass>) -> Severity {
    if hazards.is_empty() {
        Severity::new(NO_HAZARD_GRANT_TIER, false, false)
    } else {
        Severity::new(
            MUTATE_DURABLE,
            hazards.contains(&HazardClass::CredentialFormSubmit)
                || hazards.contains(&HazardClass::UnverifiedFormContents),
            hazards.contains(&HazardClass::FinancialFormSubmit)
                || hazards.contains(&HazardClass::UnverifiedFormContents),
        )
    }
}

/// The consent question's text, written for the person answering, often on a
/// phone. It states what the grant allows and, just as plainly, what it still
/// refuses, because that is what the person is deciding. The structured
/// `origins`, `hazards` and `severity_ceiling` beside it stay the exact scope.
fn browser_grant_message(origins: &[String], hazards: &[String], ceiling_tier: u8) -> String {
    // Each hazard class unlocks submitting one kind of form. Listed in a fixed
    // order so the sentence does not change with the order a caller sent them.
    const FORM_KINDS: [(&str, &str); 3] = [
        ("credential_form_submit", "sign-in forms"),
        ("financial_form_submit", "payment forms"),
        (
            "unverified_form_contents",
            "forms whose purpose it couldn't check",
        ),
    ];
    let mut allowed: Vec<&str> = Vec::new();
    let mut refused: Vec<&str> = Vec::new();
    for (class, kind) in FORM_KINDS {
        if hazards.iter().any(|hazard| hazard == class) {
            allowed.push(kind);
        } else {
            refused.push(kind);
        }
    }

    let mut message = format!(
        "Let this agent use its own browser on {}? It can open and read pages there \
         and click ordinary buttons and links.",
        join_words(
            &origins.iter().map(String::as_str).collect::<Vec<_>>(),
            "and"
        )
    );
    // The sentence follows the ceiling the grant is minted at, whatever raised
    // it. A disclosed hazard also lifts the ceiling to the durable tier, and
    // that tier admits every lasting-change click, not only the one form kind
    // the hazard names; describing only the form kind would ask the person to
    // approve less than the grant allows.
    match ceiling_tier {
        MUTATE_DURABLE => message.push_str(
            " It can also follow links that lead to other sites and submit other forms, \
             which can make lasting changes such as posting, saving or sending something.",
        ),
        MUTATE_REVERSIBLE => message
            .push_str(" It can also make changes on those sites that can be undone afterwards."),
        _ => {}
    }
    if !allowed.is_empty() {
        message.push_str(&format!(
            " It can also submit {}.",
            join_words(&allowed, "and")
        ));
    }
    if !refused.is_empty() {
        message.push_str(&format!(" It can't submit {}.", join_words(&refused, "or")));
    }
    message
}

/// `a`, `a and b`, `a, b and c`, with the given final conjunction.
fn join_words(items: &[&str], conjunction: &str) -> String {
    match items {
        [] => String::new(),
        [only] => (*only).to_string(),
        [head @ .., last] => format!("{} {conjunction} {last}", head.join(", ")),
    }
}

fn browser_grant_severity_value(severity: Severity) -> Value {
    json!({
        "tier": severity.tier,
        "name": match severity.tier {
            OBSERVE => "observe",
            COMPOSE => "compose",
            MUTATE_REVERSIBLE => "mutate_reversible",
            MUTATE_DURABLE => "mutate_durable",
            _ => "actuate",
        },
        "credential": severity.credential,
        "financial": severity.financial,
    })
}

fn browser_grant_question(
    ask_id: &str,
    origins: &[String],
    hazards: &[String],
    severity: Severity,
) -> Value {
    let severity_value = browser_grant_severity_value(severity);
    json!({
        "jsonrpc": "2.0",
        "id": ask_id,
        "method": "elicitation/create",
        "params": {
            "message": browser_grant_message(origins, hazards, severity.tier),
            // These values are the exact scope that an affirmative answer mints.
            // Keeping them beside the prose lets a relay render structured scope
            // without translating or reconstructing the grant.
            "origins": origins,
            "hazards": hazards,
            "severity_ceiling": severity_value,
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "decision": {
                        "type": "string",
                        "enum": ["allow", "deny"],
                    }
                },
                "required": ["decision"],
                "additionalProperties": false,
            },
        },
    })
}

fn profile_root_rebind_question(ask_id: &str, root_path: &str, preview: &RebindReport) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": ask_id,
        "method": "elicitation/create",
        "params": {
            "message": format!(
                "Re-identify browser profile root {root_path} from identity {} to {}? \
                 The registry has {} record(s) at generation {}; allowing advances it to generation {}. \
                 This operation refuses rather than adopts any profile directory the registry did not mint.",
                preview.old_identity,
                preview.new_identity,
                preview.record_count,
                preview.generation_before,
                preview.generation_after,
            ),
            "root_path": root_path,
            "old_identity": preview.old_identity,
            "new_identity": preview.new_identity,
            "generation_before": preview.generation_before,
            "generation_after": preview.generation_after,
            "record_count": preview.record_count,
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "decision": {
                        "type": "string",
                        "enum": ["allow", "deny"],
                    }
                },
                "required": ["decision"],
                "additionalProperties": false,
            },
        },
    })
}

/// The consent question for clearing a launch record, worded like the
/// profile-root rebind: it names what will change and shows the evidence, and
/// asks for consent. The person is not asked to judge whether a browser is
/// running; the module read that, and reads it again before acting.
fn launch_recovery_clear_question(ask_id: &str, preview: &ClearPreview) -> Value {
    let launched_at = preview
        .launched_at
        .clone()
        .unwrap_or_else(|| "an unrecorded time".to_string());
    json!({
        "jsonrpc": "2.0",
        "id": ask_id,
        "method": "elicitation/create",
        "params": {
            "message": format!(
                "Clear the stuck browser record for project {}? Its browser was launched at {} \
                 and, after the module restarted, recovery could not prove it gone ({}). \
                 Evidence now: {}. Clearing lets the agent open its browser on that profile \
                 again; the evidence is read again before anything is cleared.",
                preview.agent_project_id,
                launched_at,
                preview.reason.as_str(),
                preview.evidence.describe(),
            ),
            "agent_project_id": preview.agent_project_id,
            "sequence": preview.sequence,
            "reason": preview.reason.as_str(),
            "launched_at": preview.launched_at,
            "evidence": preview.evidence.as_json(),
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "decision": {
                        "type": "string",
                        "enum": ["clear", "keep"],
                    }
                },
                "required": ["decision"],
                "additionalProperties": false,
            },
        },
    })
}

fn rebind_refusal_reply(refusal: RebindRefusal) -> Value {
    match refusal {
        RebindRefusal::RegistryMissing => json!({
            "outcome": "refused",
            "reason": "registry_missing",
            "remedy": "there is no browser profile registry to re-identify; launch once to mint one or restore the registry together with its profiles",
        }),
        RebindRefusal::MalformedRegistry => json!({
            "outcome": "refused",
            "reason": "malformed_registry",
            "remedy": "restore a parseable registry from backup; this operation will not rewrite malformed registry data",
        }),
        RebindRefusal::UnsupportedRegistrySchema => json!({
            "outcome": "refused",
            "reason": "unsupported_registry_schema",
            "remedy": "use a cerebellum build that supports the stored registry schema",
        }),
        RebindRefusal::IntegrityMismatch => json!({
            "outcome": "refused",
            "reason": "integrity_mismatch",
            "remedy": "restore the registry exactly as written; this operation will not heal an edited or swapped registry",
        }),
        RebindRefusal::AlreadyBound => json!({
            "outcome": "rebind_not_needed",
            "remedy": "the registry is already bound to the current browser root; no action is required",
        }),
        RebindRefusal::PossiblyManagedPath { unaccounted } => json!({
            "outcome": "refused",
            "reason": "possibly_managed_path",
            "unaccounted": unaccounted,
            "remedy": "the operator must move or account for these directories before the root can be re-identified; browser.rebind_profile_root will never adopt them",
        }),
        RebindRefusal::RootUnstable => json!({
            "outcome": "refused",
            "reason": "root_unstable",
            "remedy": "stop modifying or replacing the browser root, then retry the rebind preflight",
        }),
        RebindRefusal::BirthTimeUnavailable { root_path } => json!({
            "outcome": "refused",
            "reason": "birth_time_unavailable",
            "root_path": root_path.display().to_string(),
            "remedy": "the filesystem holding this browser root cannot report a directory birth time, so the root cannot be identified; move the browser root to a filesystem that reports birth time (APFS, ext4, btrfs, xfs)",
        }),
        RebindRefusal::Io(error) => json!({
            "outcome": "refused",
            "reason": "io",
            "detail": error.to_string(),
            "remedy": "restore filesystem access to the browser root and retry",
        }),
    }
}

/// A question to put to the user, and how long it stays one.
#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    pub ask_id: String,
    pub body: Value,
    pub deadline: Duration,
}

/// Why an action on a named application did not proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppRefusal {
    /// The name did not resolve to exactly one running process.
    Resolution(Value),
    /// The app grant was not held and the question did not grant it.
    Consent(crate::computer_grants::ConsentRefusal),
}

impl AppRefusal {
    /// The reply for this refusal in the shared consent envelope.
    pub fn reply(&self, bundle_identity: &str) -> Value {
        match self {
            Self::Resolution(reply) => reply.clone(),
            Self::Consent(refusal) => refusal.reply(Some(bundle_identity)),
        }
    }
}

fn describe(candidates: &[TargetCandidate]) -> Vec<Value> {
    candidates
        .iter()
        .map(|candidate| {
            json!({
                "pid": candidate.pid,
                "window_count": candidate.window_count,
            })
        })
        .collect()
}

/// A fresh identity for a question, unique across this module's lifetime.
fn new_browser_grant_ask_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "browser-grant-consent-{}",
        NEXT.fetch_add(1, Ordering::Relaxed) + 1
    )
}

fn new_profile_root_rebind_ask_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "browser-profile-root-rebind-consent-{}",
        NEXT.fetch_add(1, Ordering::Relaxed) + 1
    )
}

const LAUNCH_RECOVERY_CLEAR_ASK_PREFIX: &str = "browser-launch-recovery-clear-";

/// Carries the asking start's identity, so an answer that reaches a later
/// start is recognised as belonging to an earlier one.
fn new_launch_recovery_clear_ask_id(incarnation: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{LAUNCH_RECOVERY_CLEAR_ASK_PREFIX}{incarnation}-{}",
        NEXT.fetch_add(1, Ordering::Relaxed) + 1
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(TargetResolution);

    impl TargetResolver for Fixed {
        fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
            self.0.clone()
        }
    }

    fn plane(resolution: TargetResolution) -> ManagementPlane {
        ManagementPlane::new(Arc::new(Fixed(resolution)))
    }

    #[tokio::test]
    async fn browser_grant_question_renders_and_mints_the_exact_disclosed_scope() {
        let plane = plane(TargetResolution::NotRunning);
        let (reply, question) = plane
            .open_browser_grant(
                "conversation",
                vec![
                    "https://login.example".to_string(),
                    "https://pay.example".to_string(),
                ],
                vec![
                    HazardClass::CredentialFormSubmit,
                    HazardClass::FinancialFormSubmit,
                ],
                true,
            )
            .await
            .unwrap();
        let question = question.unwrap();
        assert_eq!(reply["outcome"], "consent_pending");
        assert_eq!(question.body["params"]["origins"], reply["origins"]);
        assert_eq!(question.body["params"]["hazards"], reply["hazards"]);
        assert_eq!(
            question.body["params"]["severity_ceiling"],
            reply["severity_ceiling"]
        );
        // The prose is for the person; the structured fields above are the
        // scope. It must say what the grant allows AND what it still refuses.
        assert_eq!(
            question.body["params"]["message"],
            "Let this agent use its own browser on https://login.example and \
             https://pay.example? It can open and read pages there and click ordinary \
             buttons and links. It can also follow links that lead to other sites and \
             submit other forms, which can make lasting changes such as posting, saving \
             or sending something. It can also submit sign-in forms and payment forms. \
             It can't submit forms whose purpose it couldn't check."
        );
        // Answered from a phone, so its deadline is the phone one, not the
        // five minutes an application-control question gets.
        assert_eq!(question.deadline, Duration::from_secs(30 * 60));

        assert!(
            plane
                .settle_browser_grant(&question.ask_id, Some(&json!({"decision": "allow"})))
                .await
        );
        let grants = plane.browser_grants.lock().await;
        let grant = grants.current_grants().next().unwrap();
        assert_eq!(
            grant.authorized_origins,
            vec!["https://login.example", "https://pay.example",]
        );
        assert_eq!(
            grant.disclosed_hazards,
            BTreeSet::from([
                HazardClass::CredentialFormSubmit,
                HazardClass::FinancialFormSubmit,
            ])
        );
        assert_eq!(grant.severity, Severity::new(MUTATE_DURABLE, true, true));
    }

    #[tokio::test]
    async fn a_grant_with_no_hazards_says_which_forms_it_still_refuses() {
        let plane = plane(TargetResolution::NotRunning);
        let (_, question) = plane
            .open_browser_grant(
                "conversation",
                vec!["https://example.com".to_string()],
                vec![],
                true,
            )
            .await
            .unwrap();
        assert_eq!(
            question.unwrap().body["params"]["message"],
            "Let this agent use its own browser on https://example.com? It can open and \
             read pages there and click ordinary buttons and links. It can't submit \
             sign-in forms, payment forms or forms whose purpose it couldn't check."
        );
    }

    /// A requested tier above the default must be spelled out for the person,
    /// must raise only the tier, and must never turn on the credential or
    /// financial flags, which only a disclosed hazard can grant.
    #[tokio::test]
    async fn a_requested_tier_is_told_to_the_person_and_raises_only_the_tier() {
        let plane = plane(TargetResolution::NotRunning);
        let (reply, question) = plane
            .open_browser_grant_at_tier(
                "conversation",
                vec!["https://example.com".to_string()],
                vec![],
                Some(MUTATE_DURABLE),
                true,
            )
            .await
            .unwrap();
        let question = question.unwrap();
        assert_eq!(
            reply["severity_ceiling"],
            json!({"tier": 4, "name": "mutate_durable", "credential": false, "financial": false})
        );
        assert_eq!(
            question.body["params"]["severity_ceiling"],
            reply["severity_ceiling"]
        );
        assert_eq!(
            question.body["params"]["message"],
            "Let this agent use its own browser on https://example.com? It can open and \
             read pages there and click ordinary buttons and links. It can also follow \
             links that lead to other sites and submit other forms, which can make \
             lasting changes such as posting, saving or sending something. It can't \
             submit sign-in forms, payment forms or forms whose purpose it couldn't check."
        );
        assert!(
            plane
                .settle_browser_grant(&question.ask_id, Some(&json!({"decision": "allow"})))
                .await
        );
        let grants = plane.browser_grants.lock().await;
        let grant = grants.current_grants().next().unwrap();
        assert_eq!(grant.severity, Severity::new(MUTATE_DURABLE, false, false));
        drop(grants);

        let (reply, question) = plane
            .open_browser_grant_at_tier(
                "conversation",
                vec!["https://example.com".to_string()],
                vec![],
                Some(MUTATE_REVERSIBLE),
                true,
            )
            .await
            .unwrap();
        assert_eq!(reply["severity_ceiling"]["name"], "mutate_reversible");
        assert_eq!(
            question.unwrap().body["params"]["message"],
            "Let this agent use its own browser on https://example.com? It can open and \
             read pages there and click ordinary buttons and links. It can also make \
             changes on those sites that can be undone afterwards. It can't submit \
             sign-in forms, payment forms or forms whose purpose it couldn't check."
        );

        // A tier at or below what the hazards imply changes neither the
        // ceiling nor the words.
        let (reply, question) = plane
            .open_browser_grant_at_tier(
                "conversation",
                vec!["https://example.com".to_string()],
                vec![],
                Some(OBSERVE),
                true,
            )
            .await
            .unwrap();
        assert_eq!(reply["severity_ceiling"]["tier"], 2);
        assert_eq!(
            question.unwrap().body["params"]["message"],
            "Let this agent use its own browser on https://example.com? It can open and \
             read pages there and click ordinary buttons and links. It can't submit \
             sign-in forms, payment forms or forms whose purpose it couldn't check."
        );
    }

    #[tokio::test]
    async fn a_requested_tier_outside_the_grantable_range_is_refused() {
        let plane = plane(TargetResolution::NotRunning);
        for tier in [0, crate::authorization::ACTUATE, u8::MAX] {
            assert_eq!(
                plane
                    .open_browser_grant_at_tier(
                        "conversation",
                        vec!["https://example.com".to_string()],
                        vec![],
                        Some(tier),
                        true,
                    )
                    .await
                    .unwrap_err(),
                BrowserGrantRequestError::InvalidSeverityTier,
                "tier {tier}"
            );
        }
        assert_eq!(plane.browser_grant_count().await, 0);
    }

    #[tokio::test]
    async fn browser_grant_refusal_and_no_relay_each_leave_the_store_empty() {
        let plane = plane(TargetResolution::NotRunning);
        let (reply, question) = plane
            .open_browser_grant(
                "conversation",
                vec!["https://example.test".to_string()],
                vec![HazardClass::CredentialFormSubmit],
                true,
            )
            .await
            .unwrap();
        assert_eq!(reply["outcome"], "consent_pending");
        assert!(
            plane
                .settle_browser_grant(
                    &question.unwrap().ask_id,
                    Some(&json!({"decision": "deny"}))
                )
                .await
        );
        assert_eq!(plane.browser_grant_count().await, 0);

        let (unavailable, question) = plane
            .open_browser_grant(
                "conversation",
                vec!["https://example.test".to_string()],
                vec![HazardClass::UnverifiedFormContents],
                false,
            )
            .await
            .unwrap();
        assert_eq!(unavailable["outcome"], "consent_unavailable");
        assert!(question.is_none());
        assert_eq!(plane.browser_grant_count().await, 0);
    }
}
