//! Management operations: asking for permission to reach an application.
//!
//! Separate from tool calls because the two surfaces take different request
//! envelopes and because what they do differs in kind. A tool call acts; a
//! management operation arranges the authority under which acting is possible.
//!
//! WHY OPENING A LEASE IS ITS OWN CALL rather than something the first action
//! does implicitly: an implicit prompt would ask the user to approve reaching an
//! application the agent is ALREADY MID-ACTION AGAINST, which turns consent into
//! ratification — the thing being consented to arrives pre-committed. Keeping
//! the ask ahead of the action costs a round trip and buys an approval the user
//! can refuse before anything has happened.
//!
//! The cost of an explicit step is that it can be forgotten. That is paid for at
//! the other end: an action against an unleased target refuses with the name of
//! this operation and the application it needs, so forgetting costs one round
//! trip and teaches.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cerebellum_computer::platform::{ProcessGrant, TargetCandidate, TargetResolution};
use cerebellum_core::clock::MonotonicClock;
use cerebellum_core::consent::{
    ActionKind, ConsentLeases, GrantKind, LeaseKey, OnceDispatchToken, Opening,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::authorization::{
    ActionGrant, GrantStore, HazardClass, Severity, COMPOSE, MUTATE_DURABLE, MUTATE_REVERSIBLE,
    OBSERVE,
};
use crate::classification::canonical_grant_origin;
use crate::launch_recovery::{ClearFailure, ClearPreview, LaunchRecoveryRegistry};
use crate::profile::{ProfileLifecycle, RebindProvenance, RebindRefusal, RebindReport};

/// The computer-target operation this surface serves.
pub const OPEN_TARGET: &str = "computer.open_target";
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
pub const OPERATIONS: [&str; 8] = [
    OPEN_TARGET,
    OPEN_GRANT,
    IMPORT_LOGIN,
    PRESENT,
    RESUME,
    REBIND_PROFILE_ROOT,
    CAPTURE_LOGIN,
    CLEAR_LAUNCH_RECOVERY,
];

/// Read an action kind from its wire spelling.
///
/// `None` for anything unrecognised, so a kind this module does not know is
/// refused rather than resolved to a default. Defaulting would put a request
/// under whichever gate the default names, and the plausible default is the
/// permissive one.
pub fn action_kind_from_wire(kind: &str) -> Option<ActionKind> {
    match kind {
        "observe" => Some(ActionKind::Observe),
        "compose" => Some(ActionKind::Compose),
        "mutate_durable" => Some(ActionKind::MutateDurable),
        _ => None,
    }
}

/// How an action kind is spelled on the wire.
///
/// The inverse of [`action_kind_from_wire`], so a refusal can name the value a
/// caller should send back. A refusal that describes the remedy in different
/// words than the request accepts is a remedy the caller cannot follow.
pub fn action_kind_to_wire(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::Observe => "observe",
        ActionKind::Compose => "compose",
        ActionKind::MutateDurable => "mutate_durable",
    }
}

/// How long a consent question for control of an application may stay
/// unanswered before it stops being one.
///
/// Kept short on purpose: this lease hands the agent the screen, and its
/// window starts when the person answers. A person answering a stale question
/// long after the agent asked may not be watching when the agent acts. Its
/// expiry is a definite not-granted rather than an unfinished wait; the caller
/// has long since been told the request is pending, so nothing is blocked on
/// it.
const CONSENT_DEADLINE: Duration = Duration::from_secs(300);

/// How long a question the person usually answers from a phone may stay open:
/// a browser grant, or re-identifying the profile root.
///
/// Both are scoped decisions that change nothing until answered, and the agent
/// is only waiting, so the deadline is sized to how long a person takes to
/// notice a phone prompt rather than to a desk session. Measured: an operator
/// answered a grant after about 12 minutes, after a 5-minute deadline had
/// already expired it.
const PHONE_CONSENT_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// How long a granted lease lasts when the user allows one.
///
/// The prompt offers a bounded grant rather than an open-ended one, so this is
/// the bound. It is not configurable here: a duration that can be raised toward
/// indefinite reintroduces the grant nobody could later say they issued.
const GRANT_DURATION: Duration = Duration::from_secs(600);

/// Resolving an application name to the process that answers to it.
///
/// Behind a trait because the resolution reads the window server, which exists
/// only on the platform this plane drives — while everything above it is
/// ordinary logic that should be exercised wherever the tests run. A concrete
/// dependency here would put the consent flow in the half no continuous build
/// compiles.
pub trait TargetResolver: Send + Sync {
    fn resolve(&self, bundle_identity: &str) -> TargetResolution;
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
    leases: Mutex<ConsentLeases>,
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
    /// Targets whose last consent question reached no person, by the ask that
    /// was never put.
    ///
    /// Kept so the NEXT request for the same target can say what became of the
    /// previous one. Without it every attempt looks identical to the first and
    /// the caller is told to await an answer that was never solicited. Not a
    /// refusal and not a cache of one: the question is still put each time,
    /// because a person who becomes reachable should simply be asked.
    unreached: Mutex<BTreeMap<LeaseKey, String>>,
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
    pub fn new(resolver: Arc<dyn TargetResolver>) -> Self {
        Self {
            leases: Mutex::new(ConsentLeases::new()),
            resolver,
            browser_grants: Arc::new(Mutex::new(GrantStore::default())),
            pending_browser_grants: Mutex::new(BTreeMap::new()),
            profile_lifecycle: None,
            pending_profile_root_rebinds: Mutex::new(BTreeMap::new()),
            launch_recovery: Arc::new(LaunchRecoveryRegistry::new()),
            pending_launch_recovery_clears: Mutex::new(BTreeMap::new()),
            launch_recovery_settlements: Mutex::new(BTreeMap::new()),
            unreached: Mutex::new(BTreeMap::new()),
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

    /// Resolve an application name and report what authority exists over it.
    ///
    /// Returns without waiting for the user. The operation's own deadline is
    /// seconds and a person's is minutes, so waiting would time out on almost
    /// every genuine ask and report a decision nobody made. The caller is told
    /// the request is pending and asks again later; the answer, when it comes,
    /// is applied by the task this spawns.
    pub async fn open_target<C: MonotonicClock>(
        &self,
        grantee: &str,
        bundle_identity: &str,
        action_kind: ActionKind,
        can_relay_to_a_person: bool,
        clock: &C,
    ) -> (Value, Option<Question>) {
        // Resolved BEFORE any lease is consulted, because a lease over an
        // application that is not running, or that names two processes, is not
        // something to act on even when it is held. The lease says the user
        // agreed; resolution says what they agreed about still exists.
        let resolution = self.resolver.resolve(bundle_identity);
        let grant = match resolution {
            TargetResolution::Resolved(grant) => grant,
            TargetResolution::NotRunning => {
                return (
                    json!({
                        "outcome": "not_running",
                        "bundle_identity": bundle_identity,
                        "remedy": "start the application, then ask again",
                    }),
                    None,
                );
            }
            TargetResolution::Ambiguous(candidates) => {
                return (
                    json!({
                        "outcome": "ambiguous",
                        "bundle_identity": bundle_identity,
                        "instances": describe(&candidates),
                        // Named rather than chosen between: picking one would
                        // grant access to a process the user never selected.
                        "remedy": "quit all but one instance, then ask again",
                    }),
                    None,
                );
            }
            // Separate from `not_running` because that answer is a claim about
            // the world and this one is only about our own sight. Telling
            // someone their running application is not running sends them to
            // start a second copy.
            TargetResolution::Unreadable(reason) => {
                return (
                    json!({
                        "outcome": "targets_unreadable",
                        "bundle_identity": bundle_identity,
                        "unreadable": reason,
                        "remedy": unreadable_remedy(&reason),
                    }),
                    None,
                );
            }
        };

        let key = LeaseKey {
            grantee: grantee.to_string(),
            bundle_identity: bundle_identity.to_string(),
            action_kind,
        };

        let opening = {
            let mut leases = self.leases.lock().await;
            leases.open(key.clone(), clock, new_ask_id)
        };
        // What became of the last question about this target, when the carrier
        // told us nobody was shown it. Carried into the pending replies below so
        // a caller can tell "the person has not answered yet" from "no person
        // was ever asked", which have opposite remedies and, without this, look
        // identical on the wire.
        let unreached = self.unreached.lock().await.get(&key).cloned();
        let previous_request = |reply: &mut Value| {
            if let (Some(ask_id), Some(object)) = (unreached.as_ref(), reply.as_object_mut()) {
                object.insert(
                    "previous_request".into(),
                    json!({
                        "ask_id": ask_id,
                        "disposition": "not_put_to_anyone",
                    }),
                );
            }
        };

        match opening {
            Opening::AlreadyHeld(lease) => {
                let remaining = {
                    let leases = self.leases.lock().await;
                    let _ = &*leases;
                    ConsentLeases::remaining(&lease, clock)
                };
                (
                    json!({
                        "outcome": "already_held",
                        "bundle_identity": bundle_identity,
                        "pid": grant.pid,
                        // A duration rather than the expiry instant, which is
                        // comparable only against this module's clock. Stale by
                        // however long it takes to arrive, so it is worth planning
                        // against and not worth relying on: the check made when the
                        // lease is used stays the authority.
                        "remaining_ms": remaining.map(|left| left.as_millis() as u64),
                    }),
                    None,
                )
            }
            // Already being asked: the caller waits for that answer. Putting the
            // question again would show the user a second prompt for something
            // already on their screen.
            Opening::AlreadyAsking(pending) => {
                let mut reply = json!({
                    "outcome": "consent_pending",
                    "bundle_identity": bundle_identity,
                    "ask_id": pending.ask_id,
                    "remedy": "ask again once the request has been answered",
                });
                previous_request(&mut reply);
                (reply, None)
            }
            Opening::AskNeeded(pending) => {
                if !can_relay_to_a_person {
                    // Nobody can be asked, so nothing can be granted. Reported
                    // as its own outcome rather than as a pending question:
                    // waiting for an answer that cannot be requested would
                    // report the user as unresponsive for a fault on this side.
                    let mut leases = self.leases.lock().await;
                    leases.settle(&pending.ask_id, None, clock);
                    return (
                        json!({
                            "outcome": "consent_unavailable",
                            "bundle_identity": bundle_identity,
                            "remedy":
                                "reconnect declaring the ability to relay a question to a person",
                        }),
                        None,
                    );
                }

                // The question travels back to the caller rather than being sent
                // here, so this type decides WHAT to ask without needing a wire
                // to ask on -- which is what lets the whole flow be exercised
                // where no window server and no route exist.
                let question = Question {
                    ask_id: pending.ask_id.clone(),
                    body: consent_question(&pending.ask_id, bundle_identity, action_kind),
                    deadline: CONSENT_DEADLINE,
                };
                let mut reply = json!({
                    "outcome": "consent_pending",
                    "bundle_identity": bundle_identity,
                    "ask_id": pending.ask_id,
                    "remedy": "ask again once the request has been answered",
                });
                previous_request(&mut reply);
                (reply, Some(question))
            }
        }
    }

    /// Apply a user's answer to the question it answers.
    ///
    /// An answer to a question this module is not holding grants nothing: it is
    /// either a reply to one already settled or an answer to something never
    /// asked, and neither may create authority.
    pub async fn settle<C: MonotonicClock>(
        &self,
        ask_id: &str,
        answer: Option<&Value>,
        clock: &C,
    ) -> bool {
        self.settle_target(ask_id, answer, true, clock).await
    }

    /// Settle a consent question, recording whether a person ever saw it.
    ///
    /// `put_to_a_person` false means the carrier reported that it could reach
    /// nobody. That grants nothing either way, so it does not change this
    /// answer -- it changes what the NEXT request for the same target is told,
    /// which is the difference between waiting for a person and waiting for one
    /// who was never asked.
    pub async fn settle_target<C: MonotonicClock>(
        &self,
        ask_id: &str,
        answer: Option<&Value>,
        put_to_a_person: bool,
        clock: &C,
    ) -> bool {
        let granted = answer.and_then(|answer| grant_from_answer(answer, clock));
        let mut leases = self.leases.lock().await;
        // Read before settling, because settling removes the pending ask and
        // with it the only link from this ask to the target it was about.
        let key = leases.pending_key(ask_id);
        let settled = leases.settle(ask_id, granted, clock).is_some();
        drop(leases);
        if let Some(key) = key {
            let mut unreached = self.unreached.lock().await;
            if put_to_a_person {
                // Someone was asked, whatever they said or did not say, so any
                // earlier report that nobody could be reached is now stale.
                unreached.remove(&key);
            } else {
                unreached.insert(key, ask_id.to_string());
            }
        }
        settled
    }

    /// Whether a lease currently admits an action, without spending one.
    pub async fn admits<C: MonotonicClock>(&self, key: &LeaseKey, clock: &C) -> bool {
        let mut leases = self.leases.lock().await;
        leases.admits(key, clock).is_admitted()
    }

    /// Consume an exact Once lease into the token required by global dispatch.
    ///
    /// The same write lock guards both lease minting and consumption, so a
    /// concurrent opening and dispatch cannot both observe one single-use grant.
    pub async fn admit_once_dispatch<C: MonotonicClock>(
        &self,
        key: &LeaseKey,
        clock: &C,
    ) -> Option<OnceDispatchToken> {
        let mut leases = self.leases.lock().await;
        leases.admit_once_dispatch(key, clock)
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

/// What authority an action has over an application, at the moment it asks.
///
/// The refusal carries the way out rather than only the diagnosis. An explicit
/// opening step can be forgotten, and an agent that forgot it learns from this
/// refusal in one round trip instead of needing to have read the manual first,
/// which is what makes requiring the explicit step affordable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionAuthority {
    /// A lease admits this action against the named process.
    Admitted(ProcessGrant),
    /// Nothing admits it. Carries the operation to call and what to name.
    Refused(Value),
}

impl ManagementPlane {
    /// Find the lease an action runs under, or refuse with the way to get one.
    ///
    /// Requests that carry no target of their own resolve to the application
    /// most recently opened for this action kind, which is the agent's own last
    /// deliberate act rather than a property of the machine.
    ///
    /// The target is resolved again here rather than carried from the opening: a
    /// lease records that the user agreed, and resolving says the process they
    /// agreed about is still the one answering to that name. A process that
    /// exited and had its identifier reused would otherwise inherit a grant made
    /// for something else.
    pub async fn authority_for<C: MonotonicClock>(
        &self,
        grantee: &str,
        action_kind: ActionKind,
        clock: &C,
    ) -> ActionAuthority {
        let focused = {
            let mut leases = self.leases.lock().await;
            leases.focused(grantee, action_kind, clock)
        };
        let Some(key) = focused else {
            return ActionAuthority::Refused(json!({
                "outcome": "no_lease",
                "remedy": format!(
                    "call {OPEN_TARGET} with the bundle_identity of the application and \
                     action_kind '{}', then retry",
                    action_kind_to_wire(action_kind)
                ),
            }));
        };

        match self.resolver.resolve(&key.bundle_identity) {
            TargetResolution::Resolved(grant) => ActionAuthority::Admitted(grant),
            // The lease is held and the thing it was granted over is gone. Not
            // reported as a missing lease: the remedy is to start the
            // application, and telling the agent to ask again for permission it
            // already holds would send it to the user for nothing.
            TargetResolution::NotRunning => ActionAuthority::Refused(json!({
                "outcome": "target_not_running",
                "bundle_identity": key.bundle_identity,
                "remedy": "start the application, then retry",
            })),
            TargetResolution::Ambiguous(candidates) => ActionAuthority::Refused(json!({
                "outcome": "ambiguous",
                "bundle_identity": key.bundle_identity,
                "instances": describe(&candidates),
                "remedy": "quit all but one instance, then retry",
            })),
            // Refused rather than admitted, because an action needs a target
            // this process can currently see: the grant identifies a process by
            // its generation, and that cannot be re-established from a window
            // list that did not answer. Distinct from `target_not_running` so a
            // caller is not sent to start an application that is already there.
            TargetResolution::Unreadable(reason) => ActionAuthority::Refused(json!({
                "outcome": "targets_unreadable",
                "bundle_identity": key.bundle_identity,
                "unreadable": reason,
                "remedy": unreadable_remedy(&reason),
            })),
        }
    }
}

/// The question put to the user.
///
/// The wording carries the scope in words because the prompt's attachment cannot:
/// a preview shows one window at one moment while the grant covers the whole
/// application for its duration, so a user deciding from the picture would be
/// deciding on something the grant does not preserve.
fn consent_question(ask_id: &str, bundle_identity: &str, action_kind: ActionKind) -> Value {
    let verb = match action_kind {
        ActionKind::Observe => "see",
        ActionKind::Compose => "control",
        ActionKind::MutateDurable => "make lasting changes in",
    };
    json!({
        "jsonrpc": "2.0",
        "id": ask_id,
        "method": "elicitation/create",
        "params": {
            "message": format!(
                "Allow this agent to {verb} {bundle_identity}? \
                 It will apply to that application's windows for the next 10 minutes, \
                 including windows and pages you open during that time."
            ),
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "decision": {
                        "type": "string",
                        // No indefinite option. An open-ended grant to reach an
                        // application is one nobody could later say they issued;
                        // durable permission is a configuration act instead.
                        "enum": ["allow_once", "allow_10_minutes", "deny"],
                    }
                },
                "required": ["decision"],
            },
        },
    })
}

/// Turn a user's answer into the grant it authorises, if any.
///
/// An answer this does not recognise is a refusal rather than a default: a reply
/// that cannot be read is not evidence that anyone agreed to anything.
pub fn grant_from_answer<C: MonotonicClock>(answer: &Value, clock: &C) -> Option<GrantKind> {
    match answer.get("decision").and_then(Value::as_str) {
        Some("allow_once") => Some(GrantKind::Once),
        // Computed against this module's clock, which is the only clock the
        // expiry will ever be compared to.
        Some("allow_10_minutes") => {
            Some(GrantKind::Until(clock.now().saturating_add(GRANT_DURATION)))
        }
        _ => None,
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

fn new_ask_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("consent-{}", NEXT.fetch_add(1, Ordering::Relaxed) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    use cerebellum_computer::platform::ProcessGrant;
    use cerebellum_core::clock::FakeClock;

    struct Fixed(TargetResolution);

    impl TargetResolver for Fixed {
        fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
            self.0.clone()
        }
    }

    fn plane(resolution: TargetResolution) -> ManagementPlane {
        ManagementPlane::new(Arc::new(Fixed(resolution)))
    }

    fn one_instance() -> TargetResolution {
        TargetResolution::Resolved(ProcessGrant {
            pid: 4242,
            bundle_identity: "com.apple.Safari".to_string(),
            process_generation_evidence: "1700000000000000".to_string(),
        })
    }

    async fn open(plane: &ManagementPlane, clock: &FakeClock) -> (Value, Option<Question>) {
        plane
            .open_target(
                "pj-example",
                "com.apple.Safari",
                ActionKind::Observe,
                true,
                clock,
            )
            .await
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

    /// An unleased application asks, and hands back the question to put.
    #[tokio::test]
    async fn an_unleased_application_produces_a_question() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (reply, question) = open(&plane, &clock).await;
        assert_eq!(reply["outcome"], "consent_pending");
        let question = question.expect("an unleased application must produce a question");
        assert_eq!(question.ask_id, reply["ask_id"].as_str().unwrap());

        // The wording carries the scope, because the grant outlives the moment
        // and covers more than whatever the user can see when they answer.
        let message = question.body["params"]["message"].as_str().unwrap();
        assert!(message.contains("com.apple.Safari"), "{message}");
        assert!(message.contains("10 minutes"), "{message}");
        assert!(message.contains("open during that time"), "{message}");

        // No indefinite option is offered.
        let options = question.body["params"]["requestedSchema"]["properties"]["decision"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(options.len(), 3);
        assert!(!options.iter().any(|option| {
            let option = option.as_str().unwrap_or_default();
            option.contains("always") || option.contains("forever")
        }));
    }

    /// A repeat request joins the question in flight rather than asking again.
    ///
    /// The reply is the same, and the ABSENCE of a second question is the
    /// property: a caller handed one puts it, and the user would then see two
    /// prompts for a single request.
    #[tokio::test]
    async fn a_repeat_request_does_not_produce_a_second_question() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (first, first_question) = open(&plane, &clock).await;
        let (second, second_question) = open(&plane, &clock).await;

        assert_eq!(first["ask_id"], second["ask_id"]);
        assert!(first_question.is_some());
        assert!(
            second_question.is_none(),
            "a repeat request would have prompted the user twice"
        );
    }

    /// Two instances refuse, name both, and ask nothing.
    ///
    /// Asking would be asking about a target that does not exist: the user
    /// cannot grant access to "Safari" when the name does not identify one.
    #[tokio::test]
    async fn two_instances_refuse_without_asking() {
        let plane = plane(TargetResolution::Ambiguous(vec![
            TargetCandidate {
                pid: 100,
                window_count: 2,
            },
            TargetCandidate {
                pid: 101,
                window_count: 1,
            },
        ]));
        let clock = FakeClock::new();

        let (reply, question) = open(&plane, &clock).await;
        assert_eq!(reply["outcome"], "ambiguous");
        assert!(question.is_none(), "an ambiguous target was asked about");

        let instances = reply["instances"].as_array().unwrap();
        assert_eq!(instances.len(), 2);
        assert_eq!(instances[0]["pid"], 100);
        assert_eq!(instances[0]["window_count"], 2);
        assert_eq!(instances[1]["pid"], 101);
    }

    /// An application that is not running refuses without asking.
    #[tokio::test]
    async fn a_missing_application_refuses_without_asking() {
        let plane = plane(TargetResolution::NotRunning);
        let clock = FakeClock::new();

        let (reply, question) = open(&plane, &clock).await;
        assert_eq!(reply["outcome"], "not_running");
        assert!(question.is_none());
    }

    /// With nobody to ask, the request fails rather than waiting.
    ///
    /// Reported as its own outcome: leaving a question outstanding for a
    /// consumer that cannot relay it would report the user as unresponsive for
    /// a fault on this side.
    #[tokio::test]
    async fn a_consumer_that_cannot_relay_gets_no_pending_question() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (reply, question) = plane
            .open_target(
                "pj-example",
                "com.apple.Safari",
                ActionKind::Observe,
                false,
                &clock,
            )
            .await;

        assert_eq!(reply["outcome"], "consent_unavailable");
        assert!(question.is_none());

        // And nothing is left pending, so a later request asks afresh rather
        // than joining a question that was never put.
        let (again, question) = open(&plane, &clock).await;
        assert_eq!(again["outcome"], "consent_pending");
        // Control of an application stays on the short deadline: its lease
        // starts when the person answers, and a stale answer should not hand
        // over the screen when they may no longer be watching.
        assert_eq!(
            question.expect("a question is put").deadline,
            Duration::from_secs(300)
        );
    }

    /// An allowed answer mints the lease, and a later request is already held.
    #[tokio::test]
    async fn an_allowed_answer_grants_a_bounded_lease() {
        let plane = plane(one_instance());
        let mut clock = FakeClock::new();

        let (reply, _) = open(&plane, &clock).await;
        let ask_id = reply["ask_id"].as_str().unwrap().to_string();

        assert!(
            plane
                .settle(
                    &ask_id,
                    Some(&json!({"decision": "allow_10_minutes"})),
                    &clock
                )
                .await
        );

        let (held, question) = open(&plane, &clock).await;
        assert_eq!(held["outcome"], "already_held");
        assert!(question.is_none(), "a held lease asked again");
        assert_eq!(held["remaining_ms"], 600_000);

        // The bound is real: the lease stops admitting once it passes.
        clock.advance(Duration::from_secs(600));
        let (expired, question) = open(&plane, &clock).await;
        assert_eq!(expired["outcome"], "consent_pending");
        assert!(question.is_some(), "an expired lease did not ask again");
    }

    /// A question nobody was shown is reported as such on the next request.
    ///
    /// The two ways a consent goes unanswered look identical on the wire
    /// otherwise, and their remedies are opposite: a person who ignored a
    /// prompt may answer the next one, while a question that reached nobody
    /// will not be answered however many times it is asked. A caller told to
    /// "ask again once the request has been answered" about a question no one
    /// was ever offered is in a loop -- which is exactly what a live consumer
    /// hit, its carrier reporting that no head session existed to consent.
    #[tokio::test]
    async fn a_question_that_reached_nobody_is_named_on_the_next_request() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (first, question) = open(&plane, &clock).await;
        assert_eq!(first["outcome"], "consent_pending");
        assert!(question.is_some());
        assert!(
            first.get("previous_request").is_none(),
            "a first request has no previous one to report"
        );
        let unreached_ask = first["ask_id"].as_str().unwrap().to_string();

        // The carrier reports it could put the question to no one.
        plane
            .settle_target(&unreached_ask, None, false, &clock)
            .await;

        // The question is still put -- a person who becomes reachable should
        // simply be asked -- but the caller is told about the one that was not.
        let (again, question) = open(&plane, &clock).await;
        assert_eq!(again["outcome"], "consent_pending");
        assert!(question.is_some(), "a reachable person would not be asked");
        assert_eq!(again["previous_request"]["ask_id"], unreached_ask);
        assert_eq!(
            again["previous_request"]["disposition"],
            "not_put_to_anyone"
        );
    }

    /// Silence from a person who WAS asked is not reported as unreached.
    ///
    /// The distinction is the whole point: if every unanswered question were
    /// reported this way, the field would mean "not answered yet" and the
    /// caller would be no better off than with the timing.
    #[tokio::test]
    async fn silence_from_someone_who_was_asked_is_not_reported_as_unreached() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (first, _) = open(&plane, &clock).await;
        let ask_id = first["ask_id"].as_str().unwrap().to_string();

        // Asked, and nobody replied inside the deadline.
        plane.settle_target(&ask_id, None, true, &clock).await;

        let (again, _) = open(&plane, &clock).await;
        assert_eq!(again["outcome"], "consent_pending");
        assert!(
            again.get("previous_request").is_none(),
            "silence from a person who was asked was reported as nobody asked"
        );
    }

    /// Reaching someone clears an earlier report that nobody was reachable.
    #[tokio::test]
    async fn reaching_a_person_clears_the_earlier_unreached_report() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (first, _) = open(&plane, &clock).await;
        let unreached_ask = first["ask_id"].as_str().unwrap().to_string();
        plane
            .settle_target(&unreached_ask, None, false, &clock)
            .await;

        let (second, _) = open(&plane, &clock).await;
        assert_eq!(second["previous_request"]["ask_id"], unreached_ask);
        let answered_ask = second["ask_id"].as_str().unwrap().to_string();

        // This one reached a person, who refused. Nothing is granted, but the
        // earlier report is now stale and must not keep being made.
        plane
            .settle_target(
                &answered_ask,
                Some(&json!({"decision": "deny"})),
                true,
                &clock,
            )
            .await;

        let (third, _) = open(&plane, &clock).await;
        assert!(
            third.get("previous_request").is_none(),
            "a stale unreached report survived reaching a person"
        );
    }

    /// A refusal grants nothing, and the next request asks afresh.
    #[tokio::test]
    async fn a_refusal_grants_nothing() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (reply, _) = open(&plane, &clock).await;
        let ask_id = reply["ask_id"].as_str().unwrap().to_string();

        assert!(
            !plane
                .settle(&ask_id, Some(&json!({"decision": "deny"})), &clock)
                .await
        );

        let (again, question) = open(&plane, &clock).await;
        assert_eq!(again["outcome"], "consent_pending");
        assert!(question.is_some(), "a refused request did not ask again");
    }

    /// An answer that cannot be read grants nothing.
    ///
    /// A reply this does not understand is not evidence that anyone agreed, so
    /// it is a refusal rather than a value to fall back from.
    #[tokio::test]
    async fn an_unreadable_answer_grants_nothing() {
        let clock = FakeClock::new();
        assert!(grant_from_answer(&json!({}), &clock).is_none());
        assert!(grant_from_answer(&json!({"decision": "yes"}), &clock).is_none());
        assert!(grant_from_answer(&json!({"decision": "allow_forever"}), &clock).is_none());
        assert!(grant_from_answer(&json!({"decision": "allow_once"}), &clock).is_some());
    }

    /// An action with no lease is refused with the way to get one.
    ///
    /// The remedy names the operation AND the exact value to send: a refusal
    /// that describes the remedy in different words than the request accepts is
    /// one the caller cannot follow.
    #[tokio::test]
    async fn an_unleased_action_is_refused_with_the_recipe() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let ActionAuthority::Refused(refusal) = plane
            .authority_for("pj-example", ActionKind::Observe, &clock)
            .await
        else {
            panic!("an action with no lease must be refused");
        };

        assert_eq!(refusal["outcome"], "no_lease");
        let remedy = refusal["remedy"].as_str().unwrap();
        assert!(remedy.contains(OPEN_TARGET), "{remedy}");
        assert!(remedy.contains("bundle_identity"), "{remedy}");
        // The wire spelling, so following the remedy produces a valid request.
        assert!(remedy.contains("'observe'"), "{remedy}");
        assert!(action_kind_from_wire("observe").is_some());
    }

    /// Once consent is given, the action runs against the process named by it.
    #[tokio::test]
    async fn a_granted_action_names_the_process_it_runs_against() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (reply, _) = open(&plane, &clock).await;
        let ask_id = reply["ask_id"].as_str().unwrap().to_string();
        plane
            .settle(
                &ask_id,
                Some(&json!({"decision": "allow_10_minutes"})),
                &clock,
            )
            .await;

        let ActionAuthority::Admitted(grant) = plane
            .authority_for("pj-example", ActionKind::Observe, &clock)
            .await
        else {
            panic!("a granted action must be admitted");
        };
        assert_eq!(grant.pid, 4242);
        assert_eq!(grant.bundle_identity, "com.apple.Safari");
    }

    /// A grant to look does not admit an action that touches.
    #[tokio::test]
    async fn looking_consent_does_not_admit_composing() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (reply, _) = open(&plane, &clock).await;
        let ask_id = reply["ask_id"].as_str().unwrap().to_string();
        plane
            .settle(
                &ask_id,
                Some(&json!({"decision": "allow_10_minutes"})),
                &clock,
            )
            .await;

        let ActionAuthority::Refused(refusal) = plane
            .authority_for("pj-example", ActionKind::Compose, &clock)
            .await
        else {
            panic!("permission to look admitted an action that touches");
        };
        assert_eq!(refusal["outcome"], "no_lease");
        assert!(refusal["remedy"].as_str().unwrap().contains("'compose'"));
    }

    /// A lease whose application has since quit is not reported as unleased.
    ///
    /// The remedy differs: this one is answered by starting the application, and
    /// sending the agent back to the user for permission it already holds would
    /// prompt for nothing.
    #[tokio::test]
    async fn a_lease_over_a_departed_application_says_so() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        let (reply, _) = open(&plane, &clock).await;
        let ask_id = reply["ask_id"].as_str().unwrap().to_string();
        plane
            .settle(
                &ask_id,
                Some(&json!({"decision": "allow_10_minutes"})),
                &clock,
            )
            .await;

        // The lease survives; the application does not.
        let departed = ManagementPlane::new(Arc::new(Fixed(TargetResolution::NotRunning)));
        {
            let mut from = plane.leases.lock().await;
            let mut into = departed.leases.lock().await;
            std::mem::swap(&mut *from, &mut *into);
        }

        let ActionAuthority::Refused(refusal) = departed
            .authority_for("pj-example", ActionKind::Observe, &clock)
            .await
        else {
            panic!("an action over a departed application must be refused");
        };
        assert_eq!(refusal["outcome"], "target_not_running");
        assert!(refusal["remedy"].as_str().unwrap().contains("start"));
    }

    /// An expired lease refuses, rather than admitting on a stale focus.
    #[tokio::test]
    async fn an_expired_lease_admits_nothing() {
        let plane = plane(one_instance());
        let mut clock = FakeClock::new();

        let (reply, _) = open(&plane, &clock).await;
        let ask_id = reply["ask_id"].as_str().unwrap().to_string();
        plane
            .settle(
                &ask_id,
                Some(&json!({"decision": "allow_10_minutes"})),
                &clock,
            )
            .await;

        clock.advance(Duration::from_secs(600));
        let ActionAuthority::Refused(refusal) = plane
            .authority_for("pj-example", ActionKind::Observe, &clock)
            .await
        else {
            panic!("an expired lease admitted an action");
        };
        assert_eq!(refusal["outcome"], "no_lease");
    }

    /// An answer to a question nobody asked grants nothing.
    #[tokio::test]
    async fn an_answer_to_an_unknown_question_grants_nothing() {
        let plane = plane(one_instance());
        let clock = FakeClock::new();

        assert!(
            !plane
                .settle(
                    "never-asked",
                    Some(&json!({"decision": "allow_once"})),
                    &clock
                )
                .await
        );
    }
}
