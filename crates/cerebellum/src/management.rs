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
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cerebellum_computer::app_state::session::AppStateSessions;
use cerebellum_computer::platform::{ProcessGrant, TargetCandidate, TargetResolution};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::authorization::{
    ActionGrant, GrantStore, HazardClass, Severity, COMPOSE, MUTATE_DURABLE, MUTATE_REVERSIBLE,
    OBSERVE,
};
use crate::browser_standing_grants::{
    origin_is_public, standing_browser_grant_covers, StandingBrowserGrants, StandingSubject,
    ALL_SITES_SHORT_GRANT_MS,
};
use crate::cingulate_client::desk::{ApplyFailed, Ending, NoCard};
use crate::classification::canonical_grant_origin;
use crate::computer_grants::{
    AppCode, ComputerGrants, ConsentContext, GrantNeed, NoIdentityReader,
};
#[cfg(target_os = "macos")]
use crate::computer_grants::{AppIdentity, AppIdentityUnreadable};
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
/// Check standing per-agent permissions without asking or touching a target.
pub const WOULD_ASK: &str = "grants.would_ask";
/// Remove the calling agent's own standing browser access, all of it or one
/// origin's. Only ever narrows, so it asks nobody.
pub const REVOKE_ACCESS: &str = "browser.revoke_access";
/// Remove a named agent's standing browser access. Operator-only.
pub const REVOKE_GRANT: &str = "browser.revoke_grant";
/// List a named agent's standing browser access and always-allow app grants.
/// Operator-only.
pub const LIST_GRANTS: &str = "grants.list";
/// Prefrontal core reports that a head session's turn ended, so that
/// session's agent cursor badge comes off the screen now. Prefrontal core
/// only. Interim: to be replaced by a subscription to the harness module's
/// turn-ended event, after which core's direct call goes away.
pub const SESSION_TURN_ENDED: &str = "session.turn_ended";
pub const OPERATIONS: [&str; 23] = [
    cortexkit_role_tool_display::DISPLAY_READ,
    crate::ability::DESCRIBE,
    crate::ability::SCOPE_CHOICES,
    crate::ability::SETUP,
    crate::ability::CALL,
    WOULD_ASK,
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
    REVOKE_ACCESS,
    REVOKE_GRANT,
    LIST_GRANTS,
    crate::permissions::LIST,
    crate::permissions::REVOKE,
    crate::private_content::QUERY,
    SESSION_TURN_ENDED,
];

/// Receive-to-terminal bounds for a Management-surface method. Flat browser
/// actions use the browser tool's larger park and maximum-work allowances.
pub fn call_limits(method: &str) -> Option<&'static crate::budgets::ManagementLimits> {
    crate::budgets::MANAGEMENT_LIMITS
        .iter()
        .find(|limits| limits.method == method)
}

/// How long a question the person usually answers from a phone may stay open:
/// a browser grant, or re-identifying the profile root.
///
/// Both are scoped decisions that change nothing until answered, and the agent
/// is only waiting, so the deadline is sized to how long a person takes to
/// notice a phone prompt rather than to a desk session. Measured: an operator
/// answered a grant after about 12 minutes, after a 5-minute deadline had
/// already expired it.
pub(crate) const PHONE_CONSENT_DEADLINE: Duration = Duration::from_secs(30 * 60);

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

    /// The application a process belongs to, with the start time that tells
    /// it apart from a later process given the same pid. `None` where the
    /// process cannot be identified; nothing may act on it then.
    fn process_for_pid(&self, _pid: u32) -> Option<ProcessGrant> {
        None
    }

    /// The code-signing identity of the resolved process, which every app
    /// grant is recorded against and checked against. Where no reader exists
    /// every reading is refused, so no app grant admits a process there.
    fn app_code(&self, _grant: &ProcessGrant) -> Arc<dyn AppCode> {
        Arc::new(NoIdentityReader)
    }
}

/// How long one code-signing reading may take before the process is refused
/// as unreadable.
///
/// Measured on Apple silicon: reading the identity took 9 ms for Finder,
/// 4 ms for TextEdit and 81 ms for Discord on first read, and checking a
/// requirement took 2 to 5 ms for each. The bound is far above that so a slow
/// disk does not refuse a real application, and still short enough that a
/// process whose image sits on a stalled volume cannot hold a call for long.
#[cfg(target_os = "macos")]
const CODE_SIGNING_BOUND: Duration = Duration::from_secs(2);

/// The code of one resolved process, read through Security.framework.
#[cfg(target_os = "macos")]
struct RunningCode {
    grant: ProcessGrant,
}

#[cfg(target_os = "macos")]
impl RunningCode {
    /// Confirm the pid still belongs to the process that was resolved.
    ///
    /// Checked after each reading: the framework looks the code up by pid,
    /// and a process that exited mid-reading could have handed its pid to
    /// another, whose signature would then have been read instead. The start
    /// time tells the two apart.
    fn same_process(&self) -> Result<(), AppIdentityUnreadable> {
        match cerebellum_macos::process_start_time_micros(self.grant.pid) {
            Some(micros) if micros.to_string() == self.grant.process_generation_evidence => Ok(()),
            _ => Err(AppIdentityUnreadable::Failed {
                detail: "the process changed while its signature was read".to_string(),
            }),
        }
    }
}

#[cfg(target_os = "macos")]
fn signing_failure(error: cerebellum_macos::CodeSigningError) -> AppIdentityUnreadable {
    AppIdentityUnreadable::Failed {
        detail: format!("{error:?}"),
    }
}

#[cfg(target_os = "macos")]
impl AppCode for RunningCode {
    fn identity(&self) -> Result<AppIdentity, AppIdentityUnreadable> {
        let pid = self.grant.pid;
        let reading = cerebellum_macos::code_signing_identity(pid, CODE_SIGNING_BOUND)
            .map_err(signing_failure)?;
        let designated_requirement = match reading.designated_requirement {
            Some(requirement) if reading.signed => requirement,
            _ => return Err(AppIdentityUnreadable::Unsigned),
        };
        // Evaluated rather than read off the requirement text, so that only a
        // signature that chains to Apple's own root counts as Apple's.
        let apple_anchored = !reading.ad_hoc
            && cerebellum_macos::code_satisfies_requirement(
                pid,
                "anchor apple",
                CODE_SIGNING_BOUND,
            )
            .map_err(signing_failure)?
                == cerebellum_macos::RequirementCheck::Satisfied;
        self.same_process()?;
        Ok(AppIdentity {
            team_id: reading.team_id,
            designated_requirement,
            ad_hoc: reading.ad_hoc,
            apple_anchored,
        })
    }

    fn satisfies(&self, designated_requirement: &str) -> Result<bool, AppIdentityUnreadable> {
        let check = cerebellum_macos::code_satisfies_requirement(
            self.grant.pid,
            designated_requirement,
            CODE_SIGNING_BOUND,
        )
        .map_err(signing_failure)?;
        self.same_process()?;
        Ok(check == cerebellum_macos::RequirementCheck::Satisfied)
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
    /// Whether the production resolver supplies an app-code identity reader.
    /// Keep this aligned with its `TargetResolver::app_code` implementation:
    /// the default reader refuses every identity, so it cannot mint app grants.
    pub(crate) const HAS_APP_IDENTITY_READER: bool = cfg!(target_os = "macos");

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
pub(crate) fn unreadable_remedy(
    reason: &cerebellum_computer::platform::UnreadableReason,
) -> &'static str {
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

    #[cfg(target_os = "macos")]
    fn process_for_pid(&self, pid: u32) -> Option<ProcessGrant> {
        cerebellum_computer::platform::native::grant_for_pid(pid, self.timeout)
    }

    #[cfg(target_os = "macos")]
    fn app_code(&self, grant: &ProcessGrant) -> Arc<dyn AppCode> {
        Arc::new(RunningCode {
            grant: grant.clone(),
        })
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
    pub(crate) abilities: crate::ability::AbilityPlane,
    unified_grants: Option<Arc<crate::agent_grants::AgentGrants>>,
    /// The computer plane's app and takeover grants, and the questions out
    /// for them.
    computer_grants: Arc<ComputerGrants>,
    /// Each conversation's element ids and the diff baselines behind them.
    /// Held beside the grants because both belong to a conversation and end
    /// with it.
    app_state_sessions: Arc<AppStateSessions>,
    resolver: Arc<dyn TargetResolver>,
    pub(crate) browser_consent: crate::browser_consent::BrowserCards,
    browser_grants: Arc<Mutex<GrantStore>>,
    /// Standing per-agent browser rows; the same store `browser_grants`
    /// consults.
    standing_browser_grants: Arc<StandingBrowserGrants>,
    signed_in_domains: Arc<crate::browser_signed_in::SignedInDomains>,
    pending_browser_grants: SyncMutex<BTreeMap<String, PendingBrowserGrant>>,
    profile_lifecycle: Option<Arc<ProfileLifecycle>>,
    isolated_storage: bool,
    pending_profile_root_rebinds: SyncMutex<BTreeMap<String, PendingProfileRootRebind>>,
    /// Where the launch service publishes what startup recovery kept.
    launch_recovery: Arc<LaunchRecoveryRegistry>,
    pending_launch_recovery_clears: SyncMutex<BTreeMap<String, PendingLaunchRecoveryClear>>,
    /// The result of answering a question about clearing a stuck launch record,
    /// by project. A later session call applies the answer, and another clear
    /// request reports what that application did.
    launch_recovery_settlements: SyncMutex<BTreeMap<String, Value>>,
    /// Browser grant questions that reached no person, by conversation and
    /// the sorted origins asked about, holding the ask id that was never put.
    ///
    /// Kept so the next request for the same grant can say what became of the
    /// previous one. Without it every attempt looks like the first, and the
    /// caller is told to wait for an answer nobody was offered the chance to
    /// give. Not a refusal: the question is still put each time, because a
    /// person who becomes reachable should simply be asked.
    unreached_browser_grants: SyncMutex<BTreeMap<(String, Vec<String>), String>>,
    /// Profile-root rebind questions that reached no person, by conversation,
    /// holding the ask id that was never put, so the next rebind request from
    /// that conversation can say the previous question was shown to nobody.
    unreached_profile_root_rebinds: SyncMutex<BTreeMap<String, String>>,
}

/// What a consent question settled by `ask_id` is reported as on the next
/// request for the same thing, when the carrier said it could put the question
/// to nobody. The remedy deliberately does not say to wait or to ask again:
/// the new question goes out anyway, and it reaches nobody either until the
/// caller's consent route can reach a person.
fn previous_request_not_put_to_anyone(ask_id: &str) -> Value {
    json!({
        "ask_id": ask_id,
        "disposition": "not_put_to_anyone",
        "remedy": "the previous question was shown to no one; this one is put the same way and reaches no one either until the caller's consent route can put it to a person",
    })
}

/// Note how a consent question about `key` ended, for the next request about
/// the same thing. Only a question nobody was shown is remembered. Any ending
/// that shows a person was reached (an answer, or silence from someone who was
/// asked) clears an earlier note, since it is now stale. A question that could
/// not be sent, or one withdrawn before it ended, says nothing about whether a
/// person is reachable, so it leaves the note as it was.
fn note_reachability<K: Ord>(
    unreached: &SyncMutex<BTreeMap<K, String>>,
    key: K,
    ask_id: &str,
    ending: Option<&Ending>,
) {
    match ending {
        Some(Ending::NotPutToAnyone) => {
            unreached.lock().unwrap().insert(key, ask_id.to_string());
        }
        Some(Ending::Granted { .. } | Ending::Declined { .. } | Ending::NoAnswer) => {
            unreached.lock().unwrap().remove(&key);
        }
        Some(Ending::DeliveryFailed | Ending::Withdrawn | Ending::NoCard(_)) | None => {}
    }
}

/// The key under which a browser grant question is remembered: the same
/// origins asked in another order are the same grant.
fn browser_grant_key(conversation_key: &str, origins: &[String]) -> (String, Vec<String>) {
    let mut origins = origins.to_vec();
    origins.sort();
    (conversation_key.to_string(), origins)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingBrowserGrant {
    can_record: bool,
    holder: Option<crate::agent_grants::GrantHolder>,
    conversation_key: String,
    authorized_origins: Vec<String>,
    disclosed_hazards: BTreeSet<HazardClass>,
    severity: Severity,
    /// The granting options the card offered, which are the only answers
    /// that grant anything.
    choices: Vec<BrowserGrantChoice>,
    /// The attested agent standing rows are recorded for, present only when
    /// the card offered a standing option.
    standing_agent: Option<String>,
}

/// One granting option of the browser site-access card, and what answering
/// it grants. The card sends only the option's id, label and detail; the rest
/// of what it means is kept here against the id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserGrantChoice {
    /// A site row that expires after thirty minutes.
    SiteThirtyMinutes,
    /// A standing row for each origin asked about.
    OriginAlways,
    /// An all-sites row that expires after thirty minutes.
    AllSitesThirtyMinutes,
    /// A standing all-sites row that lasts until revoked.
    AllSitesAlways,
}

impl BrowserGrantChoice {
    /// The option id on the card. The phone app renders these ids and
    /// Cingulate returns these exact ids when the person answers.
    pub const fn option_id(self) -> &'static str {
        match self {
            Self::SiteThirtyMinutes => "allow_30m",
            Self::OriginAlways => "allow_origin_always",
            Self::AllSitesThirtyMinutes => "allow_all_sites_30m",
            Self::AllSitesAlways => "allow_all_sites_always",
        }
    }
}

/// The id of the browser site-access card's decline option, its default.
pub const BROWSER_GRANT_DECLINE: &str = "deny";

/// The granting options a browser site-access card offers, in card order.
///
/// The per-site options require a daemon-attested head or worker and a store
/// that can record its answer. Both
/// all-sites options are further withheld from a request that needs lasting
/// changes, that discloses any hazard, or that names an origin which is not a
/// public website.
pub(crate) fn offered_browser_grant_choices(
    origins: &[String],
    hazards: &BTreeSet<HazardClass>,
    severity: Severity,
    standing_offered: bool,
) -> Vec<BrowserGrantChoice> {
    if !standing_offered {
        return vec![];
    }
    let mut choices = vec![BrowserGrantChoice::SiteThirtyMinutes];
    choices.push(BrowserGrantChoice::OriginAlways);
    if severity.tier < MUTATE_DURABLE
        && !severity.credential
        && !severity.financial
        && hazards.is_empty()
        && origins.iter().all(|origin| origin_is_public(origin))
    {
        choices.extend([
            BrowserGrantChoice::AllSitesThirtyMinutes,
            BrowserGrantChoice::AllSitesAlways,
        ]);
    }
    choices
}

/// How one answer to a browser site-access card was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserGrantSettlement {
    /// No question with this id was open.
    UnknownAsk,
    /// The answer chose this granting option and its grant is in force.
    Granted(BrowserGrantChoice),
    /// Declined, unanswered, shown to nobody, or withdrawn.
    NotGranted,
    /// An answer naming no option the card offered. It grants nothing.
    UnrecognizedAnswer,
    /// A granting option was chosen and its grant could not be recorded;
    /// `reason` says why.
    NotRecorded { reason: &'static str },
}

pub(crate) fn ending_choice(ending: &Ending) -> Option<&str> {
    match ending {
        Ending::Granted { choice_id } | Ending::Declined { choice_id } => Some(choice_id),
        _ => None,
    }
}

fn ending_from_answer(answer: &Value) -> Ending {
    Ending::Granted {
        choice_id: answer["decision"].as_str().unwrap_or_default().to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingProfileRootRebind {
    conversation_key: String,
    preview: RebindReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingLaunchRecoveryClear {
    preview: ClearPreview,
    /// The module startup that asked. An answer is acted on only by the same
    /// one: after a restart, recovery has run again and the question no
    /// longer describes what it kept.
    incarnation: String,
}

/// What one answer to a clear question did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearSettlement {
    Cleared {
        sequence: u64,
    },
    /// The person chose to keep the record.
    Kept,
    /// The person was asked and did not answer before the deadline.
    NoAnswer,
    /// The question was shown to nobody: the caller's consent route had no
    /// person to put it to, or refused it.
    NotPutToAnyone,
    /// The question could not be sent.
    Undeliverable,
    /// Withdrawn before an answer.
    Withdrawn,
    /// An answer with a word the question did not offer.
    UnrecognizedAnswer,
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
            // Each ending that cleared nothing has its own remedy, because they
            // call for opposite next steps: a refusal should not be asked
            // again, silence may be answered next time, and a question nobody
            // was shown will be shown to nobody next time either.
            Self::Kept => json!({
                "outcome": "kept",
                "remedy": "nothing was cleared; the person chose to keep the record. Ask again only if they now want it cleared",
            }),
            Self::NoAnswer => json!({
                "outcome": "no_answer",
                "remedy": "nothing was cleared; the person was asked but did not answer in time. Ask again when they are available",
            }),
            Self::NotPutToAnyone => json!({
                "outcome": "not_put_to_anyone",
                "remedy": "nothing was cleared; the question was shown to no one, and putting it again reaches no one either until the caller's consent route can put it to a person",
            }),
            Self::Undeliverable => json!({
                "outcome": "undeliverable",
                "remedy": "nothing was cleared; the question could not be sent. Retry once; if it fails again, the module needs attention",
            }),
            Self::Withdrawn => json!({"outcome":"question_withdrawn"}),
            Self::UnrecognizedAnswer => json!({
                "outcome": "unrecognized_answer",
                "remedy": "nothing was cleared; the answer was not one this question offered. Ask again",
            }),
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
    pub fn with_agent_grants(mut self, grants: Arc<crate::agent_grants::AgentGrants>) -> Self {
        self.unified_grants = Some(Arc::clone(&grants));
        self.computer_grants =
            Arc::new(ComputerGrants::in_memory().with_agent_grants(Arc::clone(&grants)));
        self.browser_grants = Arc::new(Mutex::new(
            GrantStore::default()
                .with_standing_grants(Arc::clone(&self.standing_browser_grants))
                .with_public_web_baseline(Arc::clone(&self.signed_in_domains))
                .with_agent_grants(grants),
        ));
        self
    }

    pub fn agent_grants(&self) -> &Arc<crate::agent_grants::AgentGrants> {
        self.computer_grants.agent_grants()
    }

    pub(crate) fn unified_agent_grants(&self) -> Option<&Arc<crate::agent_grants::AgentGrants>> {
        self.unified_grants.as_ref()
    }
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
        let standing_browser_grants = Arc::new(StandingBrowserGrants::in_memory());
        let signed_in_domains = Arc::new(crate::browser_signed_in::SignedInDomains::default());
        Self {
            abilities: crate::ability::AbilityPlane::default(),
            unified_grants: None,
            computer_grants,
            app_state_sessions: Arc::new(AppStateSessions::new()),
            resolver,
            browser_consent: crate::browser_consent::BrowserCards::default(),
            browser_grants: Arc::new(Mutex::new(
                GrantStore::default()
                    .with_standing_grants(Arc::clone(&standing_browser_grants))
                    .with_public_web_baseline(Arc::clone(&signed_in_domains)),
            )),
            standing_browser_grants,
            signed_in_domains,
            pending_browser_grants: SyncMutex::new(BTreeMap::new()),
            profile_lifecycle: None,
            isolated_storage: false,
            pending_profile_root_rebinds: SyncMutex::new(BTreeMap::new()),
            launch_recovery: Arc::new(LaunchRecoveryRegistry::new()),
            pending_launch_recovery_clears: SyncMutex::new(BTreeMap::new()),
            launch_recovery_settlements: SyncMutex::new(BTreeMap::new()),
            unreached_browser_grants: SyncMutex::new(BTreeMap::new()),
            unreached_profile_root_rebinds: SyncMutex::new(BTreeMap::new()),
        }
    }

    /// Install-time flow checks count implicit public browsing and durable
    /// permissions, but not conversation grants: a flow can outlive its conversation.
    pub(crate) fn would_ask(&self, request: &WouldAskRequest) -> Value {
        let items: Vec<Value> = request
            .items
            .iter()
            .map(|item| {
                if let Some(grant) = &item.grant {
                    let grant = match grant {
                        Ok(grant) => grant,
                        Err(field) => return json!({"tool":"unknown","target":"","verdict":"invalid_grant","reason":"invalid_grant","field":field}),
                    };
                    let tool = grant["tool"].as_str().unwrap();
                    let target = if tool == "browser_use" {
                        grant["subject"]["origin"].as_str().map(str::to_owned).unwrap_or_else(|| format!("https://{}", grant["subject"]["domain"].as_str().unwrap()))
                    } else { grant["target"].as_str().unwrap().to_owned() };
                    let (verdict, reason) = if tool == "browser_use" {
                        if self.unified_grants.is_some() { self.agent_browser_answer(&request.agent_id, &target, grant["level"].as_u64(), grant["subject"]["domain"].as_str()) } else { browser_token_grant_answer(&self.standing_browser_grants, &self.signed_in_domains, &request.agent_id, grant, &target) }
                    } else if self.computer_grants.has_exact_standing_app_grant(&request.agent_id, &target, grant["signer"].as_str().unwrap()) {
                        ("yes", "standing_grant")
                    } else { ("would_ask", "no_standing_grant") };
                    return json!({"tool":tool,"target":target,"verdict":verdict,"reason":reason});
                }
                let target = item.target.as_str().unwrap_or("null");
                let valid = if item.tool == "browser_use" {
                    canonical_grant_origin(target).as_deref() == Some(target)
                } else {
                    !target.is_empty()
                        && target != "null"
                        && target
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
                };
                let (verdict, reason) = if !valid {
                    ("no", "invalid_target")
                } else if item.tool == "browser_use" {
                    if self.unified_grants.is_some() { self.agent_browser_answer(&request.agent_id, target, item.level, None) } else {
                    browser_standing_grant_answer(
                        &self.standing_browser_grants,
                        &self.signed_in_domains,
                        &request.agent_id,
                        target,
                        item.level,
                    ) }
                } else if self
                    .computer_grants
                    .has_standing_app_grant(&request.agent_id, target)
                {
                    // The running app's signer is checked only at call time; this
                    // install-time query must not resolve or inspect a process.
                    ("yes", "standing_grant")
                } else {
                    ("would_ask", "no_standing_grant")
                };
                json!({"tool":item.tool,"target":target,"verdict":verdict,"reason":reason})
            })
            .collect();
        json!({"items":items})
    }

    /// Use `standing` for standing browser rows, which is how a running module
    /// attaches the operator's durable store. Replaces the browser grant store
    /// with an empty one consulting `standing`, so call it while building the
    /// plane, before the browser grants are shared.
    pub fn with_standing_browser_grants(mut self, standing: Arc<StandingBrowserGrants>) -> Self {
        self.browser_grants = Arc::new(Mutex::new(
            GrantStore::default()
                .with_standing_grants(Arc::clone(&standing))
                .with_public_web_baseline(Arc::clone(&self.signed_in_domains)),
        ));
        self.standing_browser_grants = standing;
        self
    }

    /// The standing per-agent browser rows.
    pub fn standing_browser_grants(&self) -> &Arc<StandingBrowserGrants> {
        &self.standing_browser_grants
    }

    /// The browser and permission planes must consult the same login history.
    /// Attach this store before handing the shared grants to the browser plane.
    pub fn with_signed_in_domains(
        mut self,
        signed_in: Arc<crate::browser_signed_in::SignedInDomains>,
    ) -> Self {
        self.browser_grants = Arc::new(Mutex::new(
            GrantStore::default()
                .with_standing_grants(Arc::clone(&self.standing_browser_grants))
                .with_public_web_baseline(Arc::clone(&signed_in)),
        ));
        self.signed_in_domains = signed_in;
        self
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

    /// Close the consent question `ask_id`, whichever plane asked it, so an
    /// answer that arrives afterwards writes no grant. Returns whether a
    /// question was open. Ask ids are unique across both planes.
    pub async fn withdraw_consent_question(&self, ask_id: &str) -> bool {
        let computer = self.computer_grants.withdraw_question_by_id(ask_id);
        let browser = self
            .pending_browser_grants
            .lock()
            .unwrap()
            .remove(ask_id)
            .is_some();
        computer || browser
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

    /// The app grant a call on this process needs, carrying the process's
    /// code so the grant is recorded and checked against its signature.
    pub fn app_need(
        &self,
        bundle_identity: &str,
        grant: &ProcessGrant,
        display_name: String,
    ) -> GrantNeed {
        GrantNeed::App {
            bundle_identity: bundle_identity.to_string(),
            display_name,
            code: self.resolver.app_code(grant),
        }
    }

    /// The application a process belongs to, identified by its start time,
    /// or `None` when it cannot be identified. Used where an action learns a
    /// pid rather than a name, such as the application under a point.
    pub fn process_for_pid(&self, pid: u32) -> Option<ProcessGrant> {
        self.resolver.process_for_pid(pid)
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
        let need = self.app_need(bundle_identity, &grant, self.application_name(&grant));
        let admission = self
            .computer_grants
            .require(&need, consent, cancel)
            .await
            .map_err(AppRefusal::Consent)?;
        let grant = if admission.waited {
            let current = self
                .resolve_process(bundle_identity)
                .map_err(AppRefusal::Resolution)?;
            // A different process may answer to the name after the wait. The
            // grant is then checked against it too, so a process that did not
            // satisfy the signature the person approved does not act under
            // the answer; its retry asks again.
            if current != grant
                && !self.computer_grants.holds(
                    &consent.caller,
                    &self.app_need(bundle_identity, &current, String::new()),
                )
            {
                return Err(AppRefusal::Consent(
                    crate::computer_grants::ConsentRefusal::Unavailable {
                        reason: "grant_not_recorded",
                        remedy: "retry this call",
                    },
                ));
            }
            current
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

    pub(crate) fn with_isolated_storage(mut self, isolated: bool) -> Self {
        self.isolated_storage = isolated;
        self
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
        can_raise_card: bool,
    ) -> Result<(Value, Option<Question>), BrowserGrantRequestError> {
        self.open_browser_grant_at_tier(
            conversation_key,
            origins,
            hazards,
            None,
            can_raise_card,
            None,
        )
        .await
    }

    /// Prepare a browser grant question whose ceiling tier is at least
    /// `severity_tier`. The tier can only raise the ceiling the hazards already
    /// imply; the credential and financial flags still come only from disclosed
    /// hazards, so a number alone never lets the agent submit a sign-in or
    /// payment form.
    ///
    /// For a question asked ahead of the browser call that needs it: the call
    /// asking returns `consent_pending` at once, so the card is sent at normal
    /// urgency.
    ///
    /// `standing_agent` is the attested agent of a primary session, for which
    /// the card may also offer standing options; `None` offers only this
    /// conversation.
    pub async fn open_browser_grant_at_tier(
        &self,
        conversation_key: &str,
        origins: Vec<String>,
        hazards: Vec<HazardClass>,
        severity_tier: Option<u8>,
        can_raise_card: bool,
        standing_agent: Option<&str>,
    ) -> Result<(Value, Option<Question>), BrowserGrantRequestError> {
        let holder = standing_agent.map(|agent| crate::agent_grants::GrantHolder::Head {
            agent_id: agent.into(),
        });
        self.open_browser_grant_for_holder(
            conversation_key,
            origins,
            hazards,
            severity_tier,
            can_raise_card,
            standing_agent,
            holder.as_ref(),
        )
        .await
    }

    /// Check the call's resolved holder, which can be a scoped worker, rather
    /// than the agent eligible for permanent choices on a new consent card.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_browser_grant_for_holder(
        &self,
        conversation_key: &str,
        origins: Vec<String>,
        hazards: Vec<HazardClass>,
        severity_tier: Option<u8>,
        can_raise_card: bool,
        standing_agent: Option<&str>,
        holder: Option<&crate::agent_grants::GrantHolder>,
    ) -> Result<(Value, Option<Question>), BrowserGrantRequestError> {
        let key = browser_grant_key(conversation_key, &origins);
        let (mut reply, question) = self
            .open_browser_grant_with_urgency(
                conversation_key,
                origins,
                hazards,
                severity_tier,
                can_raise_card,
                crate::consent_card::Urgency::Normal,
                standing_agent,
                holder,
            )
            .await?;
        // Only this reply carries the previous question's fate. A browser
        // action held open on its own question replies under the browser
        // action's closed result schema, and that question's ending is in its
        // own reply already.
        if question.is_some() {
            if let Some(ask_id) = self.unreached_browser_grants.lock().unwrap().get(&key) {
                reply["previous_request"] = previous_request_not_put_to_anyone(ask_id);
            }
        }
        Ok((reply, question))
    }

    /// [`Self::open_browser_grant_at_tier`] for a browser call that is held
    /// open while the person decides. The agent is blocked on the answer, so
    /// the card is sent at high urgency.
    pub async fn open_in_call_browser_grant(
        &self,
        conversation_key: &str,
        origins: Vec<String>,
        hazards: Vec<HazardClass>,
        severity_tier: Option<u8>,
        standing_agent: Option<&str>,
    ) -> Result<(Value, Option<Question>), BrowserGrantRequestError> {
        self.open_browser_grant_with_urgency(
            conversation_key,
            origins,
            hazards,
            severity_tier,
            true,
            crate::consent_card::Urgency::High,
            standing_agent,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_browser_grant_with_urgency(
        &self,
        conversation_key: &str,
        origins: Vec<String>,
        hazards: Vec<HazardClass>,
        severity_tier: Option<u8>,
        can_raise_card: bool,
        urgency: crate::consent_card::Urgency,
        standing_agent: Option<&str>,
        holder: Option<&crate::agent_grants::GrantHolder>,
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

        // A retry must read the authority dispatch would use, including grants
        // recorded by a late answer. Reusing the dispatch check keeps domain,
        // public-site, hazard and expiry rules identical without renewing rows.
        let mut already_covered_origins = Vec::new();
        if let (Some(store), Some(holder)) = (&self.unified_grants, holder) {
            authorized_origins.retain(|origin| {
                let demand = crate::agent_grants::GrantDemand::Browser {
                    target: crate::agent_grants::BrowserTarget::AgentProfile,
                    origin: origin.clone(),
                    severity,
                    hazards: disclosed_hazards.clone(),
                };
                if store.authorize(holder, demand).is_some() {
                    already_covered_origins.push(origin.clone());
                    false
                } else {
                    true
                }
            });
        }
        if authorized_origins.is_empty() {
            return Ok((
                json!({
                    "outcome": "granted",
                    "origins": already_covered_origins,
                    "hazards": disclosed_hazards_wire,
                    "severity_ceiling": severity_value,
                }),
                None,
            ));
        }

        if !can_raise_card {
            return Ok((
                json!({
                    "outcome": "consent_unavailable",
                    "origins": authorized_origins,
                    "hazards": disclosed_hazards_wire,
                    "severity_ceiling": severity_value,
                    "detail": {"reason": NoCard::NoAgentSession.reason()},
                    "remedy": NoCard::NoAgentSession.remedy(),
                }),
                None,
            ));
        }

        let standing_agent = standing_agent.filter(|agent| {
            !agent.is_empty()
                && self.unified_grants.as_ref().map_or_else(
                    || self.standing_browser_grants.can_record(),
                    |store| store.can_record(),
                )
        });
        let choices = offered_browser_grant_choices(
            &authorized_origins,
            &disclosed_hazards,
            severity,
            standing_agent.is_some(),
        );
        let ask_id = new_browser_grant_ask_id();
        let pending = PendingBrowserGrant {
            can_record: self.unified_grants.as_ref().map_or_else(
                || self.standing_browser_grants.can_record(),
                |store| store.can_record(),
            ),
            holder: standing_agent.map(|agent| crate::agent_grants::GrantHolder::Head {
                agent_id: agent.into(),
            }),
            conversation_key: conversation_key.to_string(),
            authorized_origins: authorized_origins.clone(),
            disclosed_hazards,
            severity,
            choices: choices.clone(),
            standing_agent: standing_agent.map(str::to_string),
        };
        let question = Question {
            prepared: PreparedConsent::Browser(pending),
            ask_id: ask_id.clone(),
            body: browser_grant_question(
                &authorized_origins,
                &disclosed_hazards_wire,
                severity,
                urgency,
                &choices,
            ),
            deadline: PHONE_CONSENT_DEADLINE,
        };
        let mut reply = json!({
            "outcome": "consent_pending",
            "ask_id": ask_id,
            "origins": authorized_origins,
            "hazards": disclosed_hazards_wire,
            "severity_ceiling": severity_value,
            "remedy": "retry the browser action after the request has been answered",
        });
        if !already_covered_origins.is_empty() {
            reply["already_covered_origins"] = json!(already_covered_origins);
        }
        Ok((reply, Some(question)))
    }

    /// Apply exactly one human answer to the browser scope recorded at ask time.
    ///
    /// `None` is a question withdrawn without an ending. For a question that
    /// ended, use [`Self::settle_browser_grant_ending`], which also records
    /// whether anyone was asked.
    pub async fn settle_browser_grant(&self, ask_id: &str, answer: Option<&Value>) -> bool {
        let answer = answer.map(ending_from_answer);
        self.settle_browser_grant_ending(ask_id, answer.as_ref())
            .await
    }

    /// Settle a browser grant question by how it ended; `None` means it was
    /// withdrawn (cancelled, route closed, draining) before it ended.
    ///
    /// Returns false when no such question was open or the chosen grant could
    /// not be recorded; see [`Self::settle_browser_grant_outcome`] for which.
    pub async fn settle_browser_grant_ending(&self, ask_id: &str, ending: Option<&Ending>) -> bool {
        !matches!(
            self.settle_browser_grant_outcome(ask_id, ending).await,
            BrowserGrantSettlement::UnknownAsk | BrowserGrantSettlement::NotRecorded { .. }
        )
    }

    /// Settle a browser grant question by how it ended, and say what that did.
    ///
    /// Only an answer naming a granting option the card offered grants
    /// anything, and it grants exactly what was recorded for that option when
    /// the card was filed: a conversation grant, a standing row per origin, or
    /// one all-sites row. The ending is also noted so that the next request
    /// for the same grant can say the previous question was shown to nobody.
    pub async fn settle_browser_grant_outcome(
        &self,
        ask_id: &str,
        ending: Option<&Ending>,
    ) -> BrowserGrantSettlement {
        self.settle_browser_grant_sync(ask_id, ending).unwrap_or(
            BrowserGrantSettlement::NotRecorded {
                reason: "grant_store_busy",
            },
        )
    }

    pub(crate) fn settle_browser_grant_sync(
        &self,
        ask_id: &str,
        ending: Option<&Ending>,
    ) -> Result<BrowserGrantSettlement, ApplyFailed> {
        let mut grants = if ending.and_then(ending_choice)
            == Some(BrowserGrantChoice::SiteThirtyMinutes.option_id())
        {
            Some(
                self.browser_grants
                    .try_lock()
                    .map_err(|_| ApplyFailed("the browser grant store is busy".into()))?,
            )
        } else {
            None
        };
        let Some(pending) = self.pending_browser_grants.lock().unwrap().remove(ask_id) else {
            return Ok(BrowserGrantSettlement::UnknownAsk);
        };
        note_reachability(
            &self.unreached_browser_grants,
            browser_grant_key(&pending.conversation_key, &pending.authorized_origins),
            ask_id,
            ending,
        );
        let decision = ending.and_then(ending_choice);
        if decision.is_none() {
            return Ok(BrowserGrantSettlement::NotGranted);
        }
        if decision == Some(BROWSER_GRANT_DECLINE) {
            return Ok(BrowserGrantSettlement::NotGranted);
        }
        if !matches!(ending, Some(Ending::Granted { .. })) {
            return Ok(BrowserGrantSettlement::UnrecognizedAnswer);
        }
        let Some(choice) = pending
            .choices
            .iter()
            .copied()
            .find(|choice| Some(choice.option_id()) == decision)
        else {
            return Ok(BrowserGrantSettlement::UnrecognizedAnswer);
        };

        if self.unified_grants.is_some() {
            return Ok(self.record_agent_browser_answer(&pending, ask_id, choice));
        }

        if choice == BrowserGrantChoice::SiteThirtyMinutes {
            let grant = ActionGrant::new(
                format!("grant-{ask_id}"),
                1,
                pending.conversation_key,
                pending.severity,
                pending.authorized_origins,
            )
            .with_disclosed_hazards(pending.disclosed_hazards);
            return Ok(
                match grants
                    .as_mut()
                    .expect("conversation grant lock")
                    .replace(grant)
                {
                    Ok(()) => BrowserGrantSettlement::Granted(choice),
                    Err(_) => BrowserGrantSettlement::NotRecorded {
                        reason: "grant_store_invalid",
                    },
                },
            );
        }

        let Some(agent) = pending.standing_agent.as_deref() else {
            return Ok(BrowserGrantSettlement::NotRecorded {
                reason: "agent_not_attested",
            });
        };
        let consent_ref = ask_id;
        let (subjects, hazards, lifetime_ms) = match choice {
            BrowserGrantChoice::OriginAlways => (
                pending
                    .authorized_origins
                    .iter()
                    .cloned()
                    .map(crate::browser_standing_grants::always_subject)
                    .collect::<Vec<_>>(),
                pending.disclosed_hazards.iter().copied().collect(),
                None,
            ),
            BrowserGrantChoice::AllSitesThirtyMinutes => (
                vec![StandingSubject::AllSites],
                Vec::new(),
                Some(ALL_SITES_SHORT_GRANT_MS),
            ),
            BrowserGrantChoice::AllSitesAlways => {
                (vec![StandingSubject::AllSites], Vec::new(), None)
            }
            BrowserGrantChoice::SiteThirtyMinutes => unreachable!("settled above"),
        };
        for subject in subjects {
            if let Err(error) = self.standing_browser_grants.record(
                agent,
                subject,
                pending.severity.tier,
                hazards.clone(),
                lifetime_ms,
                consent_ref,
            ) {
                return Ok(BrowserGrantSettlement::NotRecorded {
                    reason: error.reason_code(),
                });
            }
        }
        Ok(BrowserGrantSettlement::Granted(choice))
    }

    pub(crate) fn record_prepared_consent(&self, question: &Question, id: &str) {
        match &question.prepared {
            PreparedConsent::Browser(pending) => {
                self.pending_browser_grants
                    .lock()
                    .unwrap()
                    .insert(id.into(), pending.clone());
            }
            PreparedConsent::Rebind(pending) => {
                self.pending_profile_root_rebinds
                    .lock()
                    .unwrap()
                    .insert(id.into(), pending.clone());
            }
            PreparedConsent::Clear(pending) => {
                self.pending_launch_recovery_clears
                    .lock()
                    .unwrap()
                    .insert(id.into(), pending.clone());
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn consent_subject(
        &self,
        kind: crate::cingulate_client::card::CardKind,
        ask_id: &str,
    ) -> Option<String> {
        use crate::cingulate_client::{card::CardKind, subject};
        match kind {
            CardKind::WebsiteAccessInCall | CardKind::WebsiteAccessInAdvance => self
                .pending_browser_grants
                .lock()
                .unwrap()
                .get(ask_id)
                .map(|p| {
                    subject::website_access_in_call(&p.conversation_key, &p.authorized_origins)
                }),
            CardKind::ProfileReidentification => self
                .pending_profile_root_rebinds
                .lock()
                .unwrap()
                .get(ask_id)
                .map(|p| subject::profile_reidentification(&p.conversation_key)),
            CardKind::StuckProfileClearance => self
                .pending_launch_recovery_clears
                .lock()
                .unwrap()
                .get(ask_id)
                .map(|p| {
                    subject::stuck_profile_clearance(
                        &p.preview.agent_project_id,
                        p.preview.sequence,
                    )
                }),
            _ => None,
        }
    }

    pub(crate) fn rekey_consent(
        &self,
        kind: crate::cingulate_client::card::CardKind,
        old: &str,
        new: Option<&str>,
    ) {
        fn rekey<T>(map: &SyncMutex<BTreeMap<String, T>>, old: &str, new: Option<&str>) {
            let mut map = map.lock().unwrap();
            if let Some(pending) = map.remove(old) {
                if let Some(new) = new {
                    map.insert(new.to_string(), pending);
                }
            }
        }
        use crate::cingulate_client::card::CardKind;
        match kind {
            CardKind::WebsiteAccessInCall | CardKind::WebsiteAccessInAdvance => {
                rekey(&self.pending_browser_grants, old, new)
            }
            CardKind::ProfileReidentification => {
                rekey(&self.pending_profile_root_rebinds, old, new)
            }
            CardKind::StuckProfileClearance => {
                rekey(&self.pending_launch_recovery_clears, old, new)
            }
            _ => {}
        }
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
        let question = question.expect("an elicitable browser grant produces a question");
        self.record_prepared_consent(&question, &question.ask_id);
        question
    }

    /// How many browser grant questions are still waiting to be settled.
    pub async fn browser_grant_pending_count(&self) -> usize {
        self.pending_browser_grants.lock().unwrap().len()
    }

    pub async fn browser_grant_count(&self) -> usize {
        self.browser_grants.lock().await.current_grants().count()
    }

    /// Whether the browser grant question `ask_id` is still open, so that an
    /// answer arriving now would still be applied.
    pub async fn browser_grant_question_open(&self, ask_id: &str) -> bool {
        self.pending_browser_grants
            .lock()
            .unwrap()
            .contains_key(ask_id)
    }

    /// Forget the browser origin grants a conversation holds and close every
    /// browser grant question it has open, so an answer that arrives
    /// afterwards grants nothing.
    ///
    /// For a conversation whose session scope ended. An ordinary route close
    /// does not come here: browser grants outlive a route, and a session that
    /// reconnects keeps them.
    pub async fn end_browser_conversation(&self, conversation_key: &str) {
        self.pending_browser_grants
            .lock()
            .unwrap()
            .retain(|_, pending| pending.conversation_key != conversation_key);
        self.unreached_browser_grants
            .lock()
            .unwrap()
            .retain(|(conversation, _), _| conversation != conversation_key);
        let mut grants = self.browser_grants.lock().await;
        let held: Vec<String> = grants
            .current_grants()
            .filter(|grant| grant.conversation_key == conversation_key)
            .map(|grant| grant.grant_id().to_string())
            .collect();
        for grant_id in held {
            // A store that refuses a revocation is one that no longer
            // validates, and such a store authorizes nothing anyway.
            let _ = grants.revoke(&grant_id);
        }
    }

    fn profile_lifecycle_for_rebind(&self) -> Result<Arc<ProfileLifecycle>, &'static str> {
        if let Some(lifecycle) = self.profile_lifecycle.as_ref() {
            return Ok(Arc::clone(lifecycle));
        }
        if self.isolated_storage {
            return Err("profile_registry_unavailable");
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
        self.durable_login_profile_identity(project_id)
            .map(|value| value.map(|(location, _)| location))
    }

    pub(crate) fn durable_login_profile_identity(
        &self,
        project_id: &str,
    ) -> Result<Option<(crate::login_import::DurableProfileLocation, String)>, &'static str> {
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
                Ok(Some((
                    crate::login_import::DurableProfileLocation {
                        managed_root: registry.root().canonical_path().to_path_buf(),
                        profile_directory: profile.canonical_path().to_path_buf(),
                    },
                    record.profile_uuid,
                )))
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
        can_raise_card: bool,
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

        if !can_raise_card {
            return (
                json!({
                    "outcome": "consent_unavailable",
                    "root_path": root_path,
                    "old_identity": preview.old_identity,
                    "new_identity": preview.new_identity,
                    "generation": preview.generation_before,
                    "record_count": preview.record_count,
                    "detail": {"reason": NoCard::NoAgentSession.reason()},
                    "remedy": NoCard::NoAgentSession.remedy(),
                }),
                None,
            );
        }

        let ask_id = new_profile_root_rebind_ask_id();
        let question = Question {
            ask_id: ask_id.clone(),
            prepared: PreparedConsent::Rebind(PendingProfileRootRebind {
                conversation_key: conversation_key.to_string(),
                preview: preview.clone(),
            }),
            body: profile_root_rebind_question(&root_path, &preview),
            deadline: PHONE_CONSENT_DEADLINE,
        };
        let mut reply = json!({
            "outcome": "consent_pending",
            "ask_id": ask_id,
            "root_path": root_path,
            "old_identity": preview.old_identity,
            "new_identity": preview.new_identity,
            "generation": preview.generation_before,
            "record_count": preview.record_count,
            "remedy": "wait for the person to answer before retrying browser launch",
        });
        if let Some(previous) = self
            .unreached_profile_root_rebinds
            .lock()
            .unwrap()
            .get(conversation_key)
        {
            reply["previous_request"] = previous_request_not_put_to_anyone(previous);
        }
        (reply, Some(question))
    }

    /// Apply one answer only when the registry situation still matches the question.
    ///
    /// `None` is a question withdrawn without an ending. For a question that
    /// ended, use [`Self::settle_profile_root_rebind_ending`].
    pub async fn settle_profile_root_rebind(&self, ask_id: &str, answer: Option<&Value>) -> bool {
        let answer = answer.map(ending_from_answer);
        self.settle_profile_root_rebind_ending(ask_id, answer.as_ref())
            .await
    }

    /// Settle a rebind question by how it ended; `None` means it was withdrawn
    /// before it ended. Only an answer of `allow` rebinds anything, and the
    /// ending is noted for the next rebind request from the same conversation.
    pub async fn settle_profile_root_rebind_ending(
        &self,
        ask_id: &str,
        ending: Option<&Ending>,
    ) -> bool {
        self.settle_profile_root_rebind_sync(ask_id, ending)
    }

    pub(crate) fn settle_profile_root_rebind_sync(
        &self,
        ask_id: &str,
        ending: Option<&Ending>,
    ) -> bool {
        let Some(pending) = self
            .pending_profile_root_rebinds
            .lock()
            .unwrap()
            .remove(ask_id)
        else {
            return false;
        };
        note_reachability(
            &self.unreached_profile_root_rebinds,
            pending.conversation_key.clone(),
            ask_id,
            ending,
        );
        let decision = ending.and_then(ending_choice);
        if decision != Some("allow") {
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
        self.pending_profile_root_rebinds.lock().unwrap().len()
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
        can_raise_card: bool,
    ) -> (Value, Option<Question>) {
        let previous = self
            .launch_recovery_settlements
            .lock()
            .unwrap()
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
        if !can_raise_card {
            let mut reply = described;
            reply["outcome"] = json!("consent_unavailable");
            reply["detail"] = json!({"reason": NoCard::NoAgentSession.reason()});
            reply["remedy"] = json!(NoCard::NoAgentSession.remedy());
            return (with_previous(reply), None);
        }

        let incarnation = self.launch_recovery.incarnation().to_string();
        let ask_id = new_launch_recovery_clear_ask_id();
        let question = Question {
            ask_id: ask_id.clone(),
            prepared: PreparedConsent::Clear(PendingLaunchRecoveryClear {
                preview: preview.clone(),
                incarnation,
            }),
            body: launch_recovery_clear_question(&preview),
            deadline: PHONE_CONSENT_DEADLINE,
        };
        let mut reply = described;
        reply["outcome"] = json!("consent_pending");
        reply["ask_id"] = json!(ask_id);
        reply["remedy"] = json!(
            "wait for the person to answer; the evidence is read again before anything is cleared"
        );
        (with_previous(reply), Some(question))
    }

    /// Apply one answer to a clear question. `None` is read as no answer.
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
        let ending = answer.map_or(Ending::NoAnswer, ending_from_answer);
        self.settle_launch_recovery_clear_ending_at(ask_id, &ending, answered_at)
            .await
    }

    /// Settle a clear question by how it ended. What the ending did is kept
    /// and reported on the next clear request for the same project, naming
    /// the ending rather than folding every non-answer into `kept`.
    pub async fn settle_launch_recovery_clear_ending(
        &self,
        ask_id: &str,
        ending: &Ending,
    ) -> ClearSettlement {
        self.settle_launch_recovery_clear_ending_at(ask_id, ending, Instant::now())
            .await
    }

    /// [`Self::settle_launch_recovery_clear_ending`] with the time the question
    /// ended given explicitly, so a test can end it after the deadline without
    /// waiting for it.
    pub async fn settle_launch_recovery_clear_ending_at(
        &self,
        ask_id: &str,
        ending: &Ending,
        answered_at: Instant,
    ) -> ClearSettlement {
        self.settle_launch_recovery_clear_sync(ask_id, ending, answered_at)
    }

    pub(crate) fn settle_launch_recovery_clear_sync(
        &self,
        ask_id: &str,
        ending: &Ending,
        _answered_at: Instant,
    ) -> ClearSettlement {
        let incarnation = self.launch_recovery.incarnation();
        let pending = self
            .pending_launch_recovery_clears
            .lock()
            .unwrap()
            .remove(ask_id);
        let (settlement, project) = match pending {
            None => return ClearSettlement::UnknownAsk,
            Some(pending) => {
                let project = pending.preview.agent_project_id.clone();
                // The consent service decides whether the card can still be
                // answered. Recheck the retained recovery evidence, not its age.
                let settlement = if pending.incarnation != incarnation {
                    ClearSettlement::AskedByEarlierStart
                } else {
                    match ending {
                        Ending::NoAnswer => ClearSettlement::NoAnswer,
                        Ending::Withdrawn => ClearSettlement::Withdrawn,
                        Ending::NotPutToAnyone => ClearSettlement::NotPutToAnyone,
                        Ending::DeliveryFailed | Ending::NoCard(_) => {
                            ClearSettlement::Undeliverable
                        }
                        Ending::Granted { choice_id } | Ending::Declined { choice_id } => {
                            match Some(choice_id.as_str()) {
                                Some("clear") => {
                                    match self.launch_recovery.clear(&pending.preview, ask_id) {
                                        Ok(()) => ClearSettlement::Cleared {
                                            sequence: pending.preview.sequence,
                                        },
                                        Err(failure) => ClearSettlement::Failed(failure),
                                    }
                                }
                                Some("keep") => ClearSettlement::Kept,
                                _ => ClearSettlement::UnrecognizedAnswer,
                            }
                        }
                    }
                };
                (settlement, project)
            }
        };
        self.launch_recovery_settlements
            .lock()
            .unwrap()
            .insert(project, settlement.as_json());
        settlement
    }

    #[cfg(test)]
    pub(crate) fn copy_pending_clear_for_test(
        &self,
        source: &Self,
        source_id: &str,
        target_id: &str,
    ) {
        let pending = source
            .pending_launch_recovery_clears
            .lock()
            .unwrap()
            .get(source_id)
            .cloned()
            .unwrap();
        self.pending_launch_recovery_clears
            .lock()
            .unwrap()
            .insert(target_id.to_string(), pending);
    }

    pub async fn launch_recovery_clear_pending_count(&self) -> usize {
        self.pending_launch_recovery_clears.lock().unwrap().len()
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
/// refuses, because that is what the person is deciding. The card keeps the
/// exact origins, hazards and severity ceiling in its scope.
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

    // The sentence follows the ceiling the grant is minted at, whatever raised
    // it. A disclosed hazard also lifts the ceiling to the durable tier, and
    // that tier admits every lasting-change click, not only the one form kind
    // the hazard names; describing only the form kind would ask the person to
    // approve less than the grant allows.
    let mut message = format!(
        "Let this agent use its own browser on {}? {}",
        join_words(
            &origins.iter().map(String::as_str).collect::<Vec<_>>(),
            "and"
        ),
        browser_grant_capabilities(ceiling_tier, true)
    );
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

pub(crate) fn browser_grant_capabilities(tier: u8, beyond_site: bool) -> String {
    let mut text =
        "It can open and read pages there and click ordinary buttons and links.".to_string();
    match tier {
        MUTATE_DURABLE if beyond_site => text.push_str(
            " It can also follow links that lead to other sites and submit other forms, \
             which can make lasting changes such as posting, saving or sending something.",
        ),
        MUTATE_DURABLE => text.push_str(
            " It can also submit forms that make lasting changes, such as posting, saving or sending something.",
        ),
        MUTATE_REVERSIBLE if beyond_site => {
            text.push_str(" It can also make changes on those sites that can be undone afterwards.")
        }
        MUTATE_REVERSIBLE => {
            text.push_str(" It can also make changes there that can be undone afterwards.")
        }
        _ => {}
    }
    text
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

/// What a grant at this ceiling lets the agent do, as an option's detail.
fn browser_grant_level_words(tier: u8) -> &'static str {
    match tier {
        OBSERVE => "Up to reading pages.",
        COMPOSE => "Up to clicking ordinary links and buttons.",
        MUTATE_REVERSIBLE => "Up to filling in forms and other changes that can be undone.",
        _ => "Up to making lasting changes.",
    }
}

/// What an all-sites option adds to its level words: how far it reaches and
/// how to take it back.
const ALL_SITES_DETAIL: &str = "Covers every public site. Sign-in and payment pages still ask.";

/// The card option for one granting choice.
pub(crate) fn browser_grant_option(
    choice: BrowserGrantChoice,
    hosts: &[String],
    severity: Severity,
) -> crate::consent_card::ConsentOption {
    let level = browser_grant_level_words(severity.tier);
    let (label, detail) = match choice {
        BrowserGrantChoice::SiteThirtyMinutes => (
            format!(
                "Allow on {} for 30 minutes",
                join_words(&hosts.iter().map(String::as_str).collect::<Vec<_>>(), "and")
            ),
            level.to_string(),
        ),
        BrowserGrantChoice::OriginAlways => (
            format!(
                "Always allow on {}",
                join_words(&hosts.iter().map(String::as_str).collect::<Vec<_>>(), "and")
            ),
            level.to_string(),
        ),
        BrowserGrantChoice::AllSitesThirtyMinutes => (
            "Allow on all sites for 30 minutes".to_string(),
            ALL_SITES_DETAIL.to_string(),
        ),
        BrowserGrantChoice::AllSitesAlways => (
            "Always allow on all sites".to_string(),
            ALL_SITES_DETAIL.to_string(),
        ),
    };
    let option =
        crate::consent_card::ConsentOption::grant(choice.option_id(), label).with_detail(detail);
    if matches!(
        choice,
        BrowserGrantChoice::AllSitesThirtyMinutes | BrowserGrantChoice::AllSitesAlways
    ) {
        option.danger()
    } else {
        option
    }
}

pub(crate) fn browser_grant_question(
    origins: &[String],
    hazards: &[String],
    severity: Severity,
    urgency: crate::consent_card::Urgency,
    choices: &[BrowserGrantChoice],
) -> Value {
    use crate::consent_card::*;
    let hosts: Vec<String> = origins
        .iter()
        .map(|origin| crate::login_import::origin_host(origin).unwrap_or_else(|| origin.clone()))
        .collect();
    let standing_scopes: Vec<String> = origins
        .iter()
        .map(|origin| {
            crate::browser_standing_grants::domain_scope(origin).map_or_else(
                || crate::login_import::origin_host(origin).unwrap_or_else(|| origin.clone()),
                |domain| format!("{domain} and its subdomains"),
            )
        })
        .collect();
    let mut facts = Vec::new();
    if choices.contains(&BrowserGrantChoice::OriginAlways) && standing_scopes != hosts {
        facts.push(Fact::new("Standing access", standing_scopes.join(", ")));
    }
    let message = browser_grant_message(&hosts, hazards, severity.tier);
    // Separate the capabilities from the headline without losing the ceiling's meaning.
    if let Some((_, capabilities)) = message.split_once("? ") {
        for sentence in capabilities.split(". ") {
            facts.push(Fact::new(
                if sentence.contains("can't") {
                    "Can't"
                } else {
                    "Can"
                },
                sentence.trim_end_matches('.'),
            ));
        }
    }
    if origins.iter().any(|o| !o.starts_with("https://"))
        || hosts
            .iter()
            .enumerate()
            .any(|(i, h)| hosts[..i].contains(h))
    {
        facts.push(Fact::new("Exact sites", origins.join(", ")));
    }
    ConsentCard {
        title: "Allow browser access".into(),
        prompt: format!("Let the agent use {} in its own browser?", hosts.join(", ")),
        target: Target {
            kind: TargetKind::Site,
            label: hosts.join(", "),
        },
        facts,
        grants: choices
            .iter()
            .map(|choice| {
                browser_grant_option(
                    *choice,
                    if *choice == BrowserGrantChoice::SiteThirtyMinutes {
                        &hosts
                    } else {
                        &standing_scopes
                    },
                    severity,
                )
            })
            .collect(),
        decline: ConsentOption::decline(BROWSER_GRANT_DECLINE, "Don't allow"),
        expires_in: PHONE_CONSENT_DEADLINE,
        material_damage: true,
        late_execution: LateExecution::Execute,
        urgency,
        scope: browser_grant_scope(origins, hazards, severity),
    }
    .render()
}

/// The values `settle_browser_grant` mints the grant from: its authorized
/// origins, its ceiling tier, and the hazards it discloses. The credential and
/// financial flags of the ceiling are not repeated because only those hazards
/// set them.
fn browser_grant_scope(
    origins: &[String],
    hazards: &[String],
    severity: Severity,
) -> crate::consent_card::Scope {
    let scope = crate::consent_card::Scope::new()
        .with("origins", origins)
        .with("tier", severity.tier);
    if hazards.is_empty() {
        scope
    } else {
        scope.with("hazards", hazards)
    }
}

pub(crate) fn profile_root_rebind_question(root_path: &str, preview: &RebindReport) -> Value {
    use crate::consent_card::*;
    ConsentCard {
        title: "Browser profiles moved".into(),
        prompt: "Let the agent use its browser profiles at their new location?".into(),
        target: Target {
            kind: TargetKind::Machine,
            label: "the agent's browser profiles".into(),
        },
        facts: vec![
            Fact::new("Location", root_path),
            Fact::new("Profiles affected", preview.record_count.to_string()),
            Fact::new(
                "Limit",
                "Only the agent's own browser profiles are affected.",
            ),
        ],
        grants: vec![ConsentOption::grant("allow", "Use them here")],
        decline: ConsentOption::decline("deny", "Don't allow"),
        expires_in: PHONE_CONSENT_DEADLINE,
        material_damage: true,
        late_execution: LateExecution::Execute,
        // Asked ahead: the management call replies consent_pending without
        // waiting for the answer, so no tool call is blocked on the person.
        urgency: Urgency::Normal,
        scope: profile_root_rebind_scope(preview),
    }
    .render()
}

/// The registry transition an allowing answer applies only if it still holds:
/// the stored identity, the identity recorded in its place, and the registry
/// generation. The root's path is left out of both identities; the rest of
/// each is what the registry compares, and the reply already discloses them.
fn profile_root_rebind_scope(preview: &RebindReport) -> crate::consent_card::Scope {
    let facts_without_path = |facts: &crate::profile::RootIdentityFacts| {
        json!({
            "formula": facts.formula,
            "inode": facts.inode,
            "birth_time": facts.birth_time,
        })
    };
    let old_identity = match &preview.old_identity {
        crate::profile::ManagedRootIdentity::HashOnly(digest) => json!({ "digest": digest }),
        crate::profile::ManagedRootIdentity::Facts(facts) => facts_without_path(facts),
    };
    crate::consent_card::Scope::new()
        .with("old_identity", old_identity)
        .with("new_identity", facts_without_path(&preview.new_identity))
        .with("generation", preview.generation_before)
}

/// Evidence is checked again before clearing; consent is not proof the browser exited.
pub(crate) fn launch_recovery_clear_question(preview: &ClearPreview) -> Value {
    use crate::consent_card::*;
    ConsentCard {
        title: "Fix the agent's browser".into(),
        prompt: "Clear the stuck record so the agent can open its browser again?".into(),
        target: Target {
            kind: TargetKind::Machine,
            label: "the agent's browser profile".into(),
        },
        facts: vec![
            Fact::new(
                "Browser launched",
                preview
                    .launched_at
                    .as_deref()
                    .unwrap_or("Time not recorded"),
            ),
            Fact::new("Checked", clearance_evidence_text(&preview.evidence)),
            Fact::new(
                "Why",
                "After a restart, CortexKit couldn't confirm the agent's last browser had closed.",
            ),
            Fact::new("Before clearing", "These checks run again."),
        ],
        grants: vec![ConsentOption::grant("clear", "Clear it")],
        decline: ConsentOption::decline("keep", "Keep it locked"),
        expires_in: PHONE_CONSENT_DEADLINE,
        material_damage: true,
        late_execution: LateExecution::Execute,
        // Asked ahead: the management call replies consent_pending without
        // waiting for the answer, so no tool call is blocked on the person.
        urgency: Urgency::Normal,
        // An allowing answer clears exactly the launch-journal record with
        // this sequence number: the one launch of this profile that startup
        // recovery kept active.
        scope: Scope::new()
            .with("profile_uuid", preview.profile_uuid.as_str())
            .with("sequence", preview.sequence),
    }
    .render()
}

fn clearance_evidence_text(evidence: &crate::launch_recovery::ProfileEvidence) -> String {
    let readings = evidence.as_json();
    let processes = readings["processes"]["reading"].as_str().unwrap_or("");
    let lock = readings["singleton_lock"]["reading"].as_str().unwrap_or("");
    format!(
        "{}; {}",
        clearance_process_text(processes),
        clearance_lock_text(lock)
    )
}

fn clearance_process_text(reading: &str) -> &'static str {
    match reading {
        "none_names_profile" => "No running program is using the agent's browser profile",
        "named_by" => "A running program is using the agent's browser profile",
        "unreadable" => "The running programs could not all be checked",
        _ => "The running programs could not be checked",
    }
}

fn clearance_lock_text(reading: &str) -> &'static str {
    match reading {
        "absent" => "The browser's lock file is gone",
        "pid_not_alive" => "The browser's lock points to a program that has closed",
        // The program is still running; it just isn't a browser, so the lock is stale.
        "pid_not_a_browser" => "The browser's lock points to a program that isn't a browser",
        "live_browser" => "The browser's lock points to a running browser",
        "other_host" => "The browser's lock was created on another computer",
        "unreadable" => "The browser's lock could not be read",
        _ => "The browser's lock could not be checked",
    }
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
            "remedy": "the operator must move or account for these directories before the root can be re-identified; rebind_profile_root will never adopt them",
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

/// A permission snapshot not yet filed under a consent-service card id.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PreparedConsent {
    Browser(PendingBrowserGrant),
    Rebind(PendingProfileRootRebind),
    Clear(PendingLaunchRecoveryClear),
}

/// A question to put to the user, and how long it stays one.
#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    pub(crate) prepared: PreparedConsent,
    pub ask_id: String,
    pub body: Value,
    pub deadline: Duration,
}

impl Question {
    pub(crate) fn subject(&self) -> String {
        use crate::cingulate_client::subject;
        match &self.prepared {
            PreparedConsent::Browser(pending) => subject::website_access_in_call(
                &pending.conversation_key,
                &pending.authorized_origins,
            ),
            PreparedConsent::Rebind(pending) => {
                subject::profile_reidentification(&pending.conversation_key)
            }
            PreparedConsent::Clear(pending) => subject::stuck_profile_clearance(
                &pending.preview.agent_project_id,
                pending.preview.sequence,
            ),
        }
    }
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

/// A local preflight/failure correlation token. The returned card id and the
/// module startup identifier are tracked separately when the question is filed.
fn new_launch_recovery_clear_ask_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "browser-launch-recovery-clear-{}",
        NEXT.fetch_add(1, Ordering::Relaxed) + 1
    )
}

/// Answer one browser item of an install-time check from `standing`, the
/// agent's durable site grants. A conversation grant never counts, because a
/// flow outlives the conversation that granted it.
///
/// The needed level defaults to the lowest, reading a page. A row that covers
/// the origin at a lower level than asked answers `level_above_grant`, so the
/// install card can say which grant to raise. An unreadable store answers
/// `browser_standing_grants_unavailable` rather than reading as no grant.
fn browser_standing_grant_answer(
    standing: &StandingBrowserGrants,
    signed_in: &crate::browser_signed_in::SignedInDomains,
    agent: &str,
    origin: &str,
    level: Option<u64>,
) -> (&'static str, &'static str) {
    let level = level
        .and_then(|level| u8::try_from(level).ok())
        .unwrap_or(crate::authorization::OBSERVE);
    // Install checks name a tier, not an action. At the typing tier, conservatively
    // require consent on signed-in domains; read-only flows remain unattended.
    if crate::authorization::public_web_baseline_covers(
        origin,
        crate::authorization::Severity::new(level, false, false),
        &BTreeSet::new(),
    ) && (level == crate::authorization::OBSERVE
        || !signed_in.is_signed_in(agent, "default", origin))
    {
        return ("yes", crate::authorization::PUBLIC_WEB_BASELINE);
    }
    if standing.store_error().is_some() {
        return ("would_ask", "browser_standing_grants_unavailable");
    }
    let now = standing.now_ms();
    let none = BTreeSet::new();
    if standing_browser_grant_covers(standing, agent, origin, level, &none, now) {
        ("yes", "standing_grant")
    } else if standing_browser_grant_covers(
        standing,
        agent,
        origin,
        crate::authorization::OBSERVE,
        &none,
        now,
    ) {
        ("would_ask", "level_above_grant")
    } else {
        ("would_ask", "no_standing_grant")
    }
}

fn browser_token_grant_answer(
    standing: &StandingBrowserGrants,
    signed_in: &crate::browser_signed_in::SignedInDomains,
    agent: &str,
    grant: &Value,
    origin: &str,
) -> (&'static str, &'static str) {
    if grant["subject"].get("domain").is_none() {
        return browser_standing_grant_answer(
            standing,
            signed_in,
            agent,
            origin,
            grant["level"].as_u64(),
        );
    }
    let baseline =
        browser_standing_grant_answer(standing, signed_in, agent, origin, grant["level"].as_u64());
    if baseline.1 == crate::authorization::PUBLIC_WEB_BASELINE {
        return baseline;
    }
    if standing.store_error().is_some() {
        return ("would_ask", "browser_standing_grants_unavailable");
    }
    // An origin row at the domain's apex does not cover its subdomains.
    let rows = standing.live_rows(agent);
    let ceilings: Vec<_> = rows
        .iter()
        .filter(|row| {
            row.subject.to_value() == grant["subject"]
                || matches!(
                    row.subject,
                    crate::browser_standing_grants::StandingSubject::AllSites
                )
        })
        .map(|row| u64::from(row.severity().tier))
        .collect();
    if ceilings
        .iter()
        .any(|ceiling| *ceiling >= grant["level"].as_u64().unwrap())
    {
        ("yes", "standing_grant")
    } else if !ceilings.is_empty() {
        ("would_ask", "level_above_grant")
    } else {
        ("would_ask", "no_standing_grant")
    }
}

pub(crate) struct WouldAskItem {
    tool: String,
    target: Value,
    level: Option<u64>,
    grant: Option<Result<Value, String>>,
}
pub(crate) struct WouldAskRequest {
    pub agent_id: String,
    pub flow_id: String,
    items: Vec<WouldAskItem>,
}
pub(crate) struct WouldAskRequestError {
    pub field: String,
    pub reason: &'static str,
}

pub(crate) fn parse_would_ask(
    params: &serde_json::Map<String, Value>,
) -> Result<WouldAskRequest, WouldAskRequestError> {
    let error = |field: &str, reason| WouldAskRequestError {
        field: field.to_string(),
        reason,
    };
    if let Some(field) = params
        .keys()
        .filter(|k| !matches!(k.as_str(), "agent_id" | "flow_id" | "items"))
        .min()
    {
        return Err(error(field, "unknown_field"));
    }
    let agent_id = params
        .get("agent_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error("agent_id", "missing_field"))?
        .to_string();
    let flow_id = params
        .get("flow_id")
        .and_then(Value::as_str)
        .filter(|s| (1..=256).contains(&s.len()) && s.bytes().all(|b| (33..=126).contains(&b)))
        .ok_or_else(|| error("flow_id", "invalid_value"))?
        .to_string();
    let items = params
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| error("items", "wrong_type"))?;
    if !(1..=64).contains(&items.len()) {
        return Err(error("items", "out_of_range"));
    }
    let mut parsed = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let prefix = format!("items[{index}]");
        let item = item
            .as_object()
            .ok_or_else(|| error(&prefix, "wrong_type"))?;
        if let Some(token) = item.get("grant") {
            if item.len() != 1 {
                return Err(error(&format!("{prefix}.grant"), "unknown_field"));
            }
            let decoded = token
                .as_str()
                .ok_or_else(|| error(&format!("{prefix}.grant"), "wrong_type"))?;
            parsed.push(WouldAskItem {
                tool: "browser_use".into(),
                target: json!(""),
                level: None,
                grant: Some(decode_grant(decoded)),
            });
            continue;
        }
        if let Some(field) = item
            .keys()
            .filter(|k| !matches!(k.as_str(), "tool" | "target" | "level"))
            .min()
        {
            return Err(error(&format!("{prefix}.{field}"), "unknown_field"));
        }
        let tool = item
            .get("tool")
            .and_then(Value::as_str)
            .filter(|t| matches!(*t, "browser_use" | "computer_use"))
            .ok_or_else(|| error(&format!("{prefix}.tool"), "invalid_value"))?;
        let target = item
            .get("target")
            .ok_or_else(|| error(&format!("{prefix}.target"), "missing_field"))?;
        if !target.is_string() && !(tool == "browser_use" && target.is_null()) {
            return Err(error(&format!("{prefix}.target"), "wrong_type"));
        }
        let level = match item.get("level") {
            None => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .filter(|v| (1..=4).contains(v))
                    .ok_or_else(|| error(&format!("{prefix}.level"), "out_of_range"))?,
            ),
        };
        parsed.push(WouldAskItem {
            tool: tool.to_string(),
            target: target.clone(),
            level,
            grant: None,
        });
    }
    Ok(WouldAskRequest {
        agent_id,
        flow_id,
        items: parsed,
    })
}

pub(crate) fn would_ask_result_schema() -> Value {
    json!({"type":"object","required":["items"],"additionalProperties":false,"properties":{
        "items":{"type":"array","items":{
            "type":"object","required":["tool","target","verdict","reason"],"additionalProperties":false,
            "properties":{
                "tool":{"type":"string","enum":["browser_use","computer_use","unknown"]},
                "target":{"type":"string"},
                "verdict":{"type":"string","enum":["yes","no","would_ask","invalid_grant"]},
                "reason":{"type":"string","enum":["public_web_baseline","standing_grant","no_standing_grant","level_above_grant","app_signer_not_eligible_for_always","browser_standing_grants_unavailable","invalid_target","invalid_grant"]},
                "field":{"type":"string"}
            }
        }}
    }})
}

/// A stateless description of a missing permission, not an authorization credential.
/// The checksum rejects damaged or edited descriptions; possession grants no access.
pub(crate) fn encode_grant(value: Value) -> String {
    let bytes = serde_json::to_vec(&value).expect("grant description serializes");
    use sha2::{Digest, Sha256};
    format!(
        "g1.{}.{:x}",
        cerebellum_core::serde_base64::encode(&bytes),
        Sha256::digest(&bytes)
    )
}

pub(crate) fn decode_grant(token: &str) -> Result<Value, String> {
    let encoded = token.strip_prefix("g1.").ok_or("version")?;
    let (encoded, checksum) = encoded.rsplit_once('.').ok_or("encoding")?;
    let bytes = cerebellum_core::serde_base64::decode(encoded).map_err(|_| "encoding")?;
    use sha2::{Digest, Sha256};
    if format!("{:x}", Sha256::digest(&bytes)) != checksum {
        return Err("checksum".into());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "encoding")?;
    let object = value.as_object().ok_or("grant")?;
    let tool = value["tool"].as_str().ok_or("tool")?;
    let fields: &[&str] = match tool {
        "browser_use" => &["tool", "subject", "level"],
        "computer_use" => &["tool", "target", "signer", "level"],
        _ => return Err("tool".into()),
    };
    for field in object.keys() {
        if !fields.contains(&field.as_str()) {
            return Err(field.clone());
        }
    }
    if !value["level"]
        .as_u64()
        .is_some_and(|v| (1..=4).contains(&v))
    {
        return Err("level".into());
    }
    if tool == "browser_use" {
        let subject: crate::browser_standing_grants::StandingSubject =
            serde_json::from_value(value["subject"].clone()).map_err(|_| "subject")?;
        if matches!(
            subject,
            crate::browser_standing_grants::StandingSubject::AllSites
        ) {
            return Err("subject".into());
        }
    } else {
        if value["level"] != 4 {
            return Err("level".into());
        }
        if !value["target"].as_str().is_some_and(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        }) {
            return Err("target".into());
        }
        if !value["signer"].as_str().is_some_and(|s| !s.is_empty()) {
            return Err("signer".into());
        }
    }
    if encode_grant(value.clone()) != token {
        return Err("encoding".into());
    }
    Ok(value)
}

pub(crate) fn browser_missing_grant(origin: &str, level: u64) -> Value {
    let subject = crate::browser_standing_grants::always_subject(origin.to_owned());
    let label = match &subject {
        crate::browser_standing_grants::StandingSubject::Domain(domain) => domain.as_str(),
        _ => origin,
    };
    json!({"reason":"unattended_flow", "grant":encode_grant(json!({"tool":"browser_use", "subject":subject.to_value(), "level":level})), "grant_label":format!("browser access to {label} {}", browser_grant_level_words(level as u8).trim_end_matches('.').to_lowercase())})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clearance_evidence_uses_plain_sentences_for_every_reading() {
        use crate::launch_recovery::{
            ProcessReading as P, ProfileEvidence, SingletonLockReading as L,
        };

        for (reading, expected) in [
            (
                P::NoneNamesDirectory { examined: 137 },
                "No running program is using the agent's browser profile",
            ),
            (
                P::NamedBy { pid: 12345 },
                "A running program is using the agent's browser profile",
            ),
            (
                P::Unreadable,
                "The running programs could not all be checked",
            ),
        ] {
            let evidence = ProfileEvidence {
                processes: reading,
                singleton_lock: L::Absent,
            };
            assert_eq!(
                clearance_evidence_text(&evidence),
                format!("{expected}; The browser's lock file is gone")
            );
        }
        for (reading, expected) in [
            (L::Absent, "The browser's lock file is gone"),
            (
                L::PidNotAlive { pid: 12345 },
                "The browser's lock points to a program that has closed",
            ),
            (
                L::PidNotABrowser { pid: 12345 },
                "The browser's lock points to a program that isn't a browser",
            ),
            (
                L::LiveBrowser { pid: 12345 },
                "The browser's lock points to a running browser",
            ),
            (
                L::OtherHost,
                "The browser's lock was created on another computer",
            ),
            (L::Unreadable, "The browser's lock could not be read"),
        ] {
            let evidence = ProfileEvidence {
                processes: P::NoneNamesDirectory { examined: 137 },
                singleton_lock: reading,
            };
            assert_eq!(
                clearance_evidence_text(&evidence),
                format!("No running program is using the agent's browser profile; {expected}")
            );
        }
        assert_eq!(
            clearance_process_text("future diagnostic 12345"),
            "The running programs could not be checked"
        );
        assert_eq!(
            clearance_lock_text("future diagnostic 12345"),
            "The browser's lock could not be checked"
        );
    }

    struct Fixed(TargetResolution);

    impl TargetResolver for Fixed {
        fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
            self.0.clone()
        }
    }

    fn plane(resolution: TargetResolution) -> ManagementPlane {
        ManagementPlane::new(Arc::new(Fixed(resolution)))
    }

    /// Agents call the flat `browser_use` tool: no agent tool is named
    /// `browser.<x>`. Every rebind refusal they can read must therefore name
    /// the operation in plain words instead of the granular capability id.
    #[test]
    fn every_rebind_refusal_remedy_names_no_granular_browser_id() {
        fn has_granular_id(remedy: &str) -> bool {
            let mut rest = remedy;
            while let Some(at) = rest.find("browser.") {
                rest = &rest[at + "browser.".len()..];
                if rest
                    .chars()
                    .next()
                    .is_some_and(|next| next.is_ascii_lowercase())
                {
                    return true;
                }
            }
            false
        }

        // One refusal per variant; the match in `rebind_refusal_reply` has no
        // catch-all, so a new variant does not compile until it is answered
        // there, and this list then refuses to pass until it is sampled here.
        let refusals = [
            RebindRefusal::RegistryMissing,
            RebindRefusal::MalformedRegistry,
            RebindRefusal::UnsupportedRegistrySchema,
            RebindRefusal::IntegrityMismatch,
            RebindRefusal::AlreadyBound,
            RebindRefusal::PossiblyManagedPath {
                unaccounted: vec!["profiles/alien".to_string()],
            },
            RebindRefusal::RootUnstable,
            RebindRefusal::BirthTimeUnavailable {
                root_path: std::path::PathBuf::from("/example/root"),
            },
            RebindRefusal::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "probe",
            )),
        ];
        let mut checked = 0;
        for refusal in refusals {
            let reply = rebind_refusal_reply(refusal);
            if let Some(remedy) = reply.get("remedy").and_then(Value::as_str) {
                assert!(
                    !has_granular_id(remedy),
                    "{reply}: the remedy names a granular browser id no agent tool provides"
                );
                checked += 1;
            }
        }
        assert!(checked > 5, "only {checked} remedies scanned");
    }

    /// The platform resolver reads a real application's signature: Finder is
    /// Apple-anchored with no Team ID, so it may be offered "always"; it
    /// satisfies its own designated requirement and not one naming another
    /// signer; and a grant whose process was replaced reads as unreadable
    /// rather than as the replacement's signature.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_platform_resolver_reads_and_checks_finders_signature() {
        let finder = cerebellum_macos::all_process_ids()
            .unwrap_or_default()
            .into_iter()
            .find(|pid| {
                cerebellum_macos::process_executable_path(*pid)
                    .ok()
                    .flatten()
                    .is_some_and(|path| {
                        path.to_string_lossy()
                            .ends_with("/Finder.app/Contents/MacOS/Finder")
                    })
            });
        let Some(pid) = finder else {
            // No desktop session in this environment; nothing to read.
            return;
        };
        let generation =
            cerebellum_macos::process_start_time_micros(pid).expect("Finder's start time reads");
        let grant = ProcessGrant {
            pid,
            bundle_identity: "com.apple.finder".to_string(),
            process_generation_evidence: generation.to_string(),
        };
        let code = PlatformResolver::new().app_code(&grant);
        let identity = code.identity().expect("Finder's signature reads");
        assert_eq!(identity.team_id, None);
        assert!(!identity.ad_hoc);
        assert!(identity.apple_anchored);
        assert!(identity.names_a_lasting_signer());
        assert_eq!(code.satisfies(&identity.designated_requirement), Ok(true));
        assert_eq!(
            code.satisfies(
                "identifier \"com.apple.finder\" and anchor apple generic and \
                 certificate leaf[subject.OU] = \"ABCDE12345\""
            ),
            Ok(false)
        );

        let replaced = ProcessGrant {
            process_generation_evidence: (generation + 1).to_string(),
            ..grant
        };
        assert!(matches!(
            PlatformResolver::new().app_code(&replaced).identity(),
            Err(AppIdentityUnreadable::Failed { .. })
        ));
    }

    #[test]
    fn site_card_discloses_ambiguous_origins() {
        for origins in [
            vec!["https://github.com", "http://localhost:3000"],
            vec!["https://github.com", "https://github.com:8443"],
        ] {
            let origins = origins.into_iter().map(str::to_string).collect::<Vec<_>>();
            let body = browser_grant_question(
                &origins,
                &[],
                Severity::new(2, false, false),
                crate::consent_card::Urgency::Normal,
                &[BrowserGrantChoice::SiteThirtyMinutes],
            );
            assert_eq!(body["params"]["scope"]["origins"], json!(origins));
            assert!(body["params"]["facts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["label"] == "Exact sites" && f["value"] == origins.join(", ")));
        }
        let body = browser_grant_question(
            &["https://github.com".into()],
            &[],
            Severity::new(2, false, false),
            crate::consent_card::Urgency::Normal,
            &[BrowserGrantChoice::SiteThirtyMinutes],
        );
        assert!(!body["params"]["facts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["label"] == "Exact sites"));
    }

    fn card_capabilities(body: &Value) -> String {
        body["params"]["facts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["label"] == "Can" || f["label"] == "Can't")
            .map(|f| format!("{}.", f["value"].as_str().unwrap()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[tokio::test]
    async fn browser_grant_question_renders_and_mints_the_exact_disclosed_scope() {
        let plane = plane(TargetResolution::NotRunning).with_agent_grants(Arc::new(
            crate::agent_grants::AgentGrants::in_memory(Some("machine-test".into())),
        ));
        let (reply, question) = plane
            .open_browser_grant_at_tier(
                "conversation",
                vec![
                    "https://docs.example.com".to_string(),
                    "https://example.net".to_string(),
                ],
                vec![
                    HazardClass::CredentialFormSubmit,
                    HazardClass::FinancialFormSubmit,
                ],
                None,
                true,
                Some("head"),
            )
            .await
            .unwrap();
        let question = question.unwrap();
        plane.record_prepared_consent(&question, &question.ask_id);
        crate::consent_card::assert_contract(
            &question.body,
            &["allow_30m", "allow_origin_always", "deny"],
            "deny",
        );
        assert_eq!(
            question.body["params"]["target"]["label"],
            "docs.example.com, example.net"
        );
        let prompt = question.body["params"]["prompt"].as_str().unwrap();
        assert!(prompt.contains("example.com") && prompt.contains("example.net"));
        assert_eq!(reply["outcome"], "consent_pending");
        assert_eq!(
            question.body["params"]["scope"]["origins"],
            reply["origins"]
        );
        assert_eq!(
            question.body["params"]["scope"]["hazards"],
            reply["hazards"]
        );
        assert_eq!(
            question.body["params"]["scope"]["tier"],
            reply["severity_ceiling"]["tier"]
        );
        // `open_browser_grant` replies consent_pending without waiting for the
        // answer, so the card is not an interrupting alert.
        assert_eq!(question.body["params"]["urgency"], "normal");
        // The prose is for the person; the structured fields above are the
        // scope. It must say what the grant allows AND what it still refuses.
        assert_eq!(
            card_capabilities(&question.body),
            "It can open and read pages there and click ordinary \
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
                .settle_browser_grant(&question.ask_id, Some(&json!({"decision": "allow_30m"})))
                .await
        );
        let rows = plane
            .agent_grants()
            .live_rows(None, plane.agent_grants().now_ms())
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter()
                .map(|row| row.subject.clone())
                .collect::<Vec<_>>(),
            vec![
                crate::agent_grants::GrantSubject::Origin("https://docs.example.com".into()),
                crate::agent_grants::GrantSubject::Origin("https://example.net".into())
            ]
        );
        for row in rows {
            assert_eq!(
                row.hazards,
                vec![
                    HazardClass::CredentialFormSubmit,
                    HazardClass::FinancialFormSubmit
                ]
            );
            assert_eq!(row.max_level, MUTATE_DURABLE);
            assert_eq!(row.expires_at_ms, Some(row.granted_at_ms + 1_800_000));
            for origin in [
                "https://example.com",
                "https://mail.example.com",
                "https://docs.example.com:8443",
                "http://docs.example.com",
            ] {
                assert!(
                    !crate::agent_grants::GrantDemand::Browser {
                        target: crate::agent_grants::BrowserTarget::AgentProfile,
                        origin: origin.into(),
                        severity: Severity::new(OBSERVE, false, false),
                        hazards: Default::default(),
                    }
                    .covers(&row),
                    "{origin}"
                );
            }
        }
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
            card_capabilities(&question.unwrap().body),
            "It can open and \
             read pages there and click ordinary buttons and links. It can't submit \
             sign-in forms, payment forms or forms whose purpose it couldn't check."
        );
    }

    /// A requested tier above the default must be spelled out for the person,
    /// must raise only the tier, and must never turn on the credential or
    /// financial flags, which only a disclosed hazard can grant.
    #[tokio::test]
    async fn a_requested_tier_is_told_to_the_person_and_raises_only_the_tier() {
        let plane = plane(TargetResolution::NotRunning).with_agent_grants(Arc::new(
            crate::agent_grants::AgentGrants::in_memory(Some("machine-test".into())),
        ));
        let (reply, question) = plane
            .open_browser_grant_at_tier(
                "conversation",
                vec!["https://example.com".to_string()],
                vec![],
                Some(MUTATE_DURABLE),
                true,
                Some("head"),
            )
            .await
            .unwrap();
        let question = question.unwrap();
        plane.record_prepared_consent(&question, &question.ask_id);
        assert_eq!(
            reply["severity_ceiling"],
            json!({"tier": 4, "name": "mutate_durable", "credential": false, "financial": false})
        );
        assert_eq!(
            question.body["params"]["scope"],
            json!({"origins": ["https://example.com"], "tier": 4})
        );
        assert_eq!(
            card_capabilities(&question.body),
            "It can open and \
             read pages there and click ordinary buttons and links. It can also follow \
             links that lead to other sites and submit other forms, which can make \
             lasting changes such as posting, saving or sending something. It can't \
             submit sign-in forms, payment forms or forms whose purpose it couldn't check."
        );
        assert!(
            plane
                .settle_browser_grant(&question.ask_id, Some(&json!({"decision": "allow_30m"})))
                .await
        );
        let rows = plane
            .agent_grants()
            .live_rows(None, plane.agent_grants().now_ms())
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].max_level, MUTATE_DURABLE);
        assert!(rows[0].hazards.is_empty());

        let (reply, question) = plane
            .open_browser_grant_at_tier(
                "conversation",
                vec!["https://example.com".to_string()],
                vec![],
                Some(MUTATE_REVERSIBLE),
                true,
                None,
            )
            .await
            .unwrap();
        assert_eq!(reply["severity_ceiling"]["name"], "mutate_reversible");
        assert_eq!(
            card_capabilities(&question.unwrap().body),
            "It can open and \
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
                None,
            )
            .await
            .unwrap();
        assert_eq!(reply["severity_ceiling"]["tier"], 2);
        assert_eq!(
            card_capabilities(&question.unwrap().body),
            "It can open and \
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
                        None,
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
    async fn browser_grant_refusal_and_no_agent_each_leave_the_store_empty() {
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
        let question = question.unwrap();
        plane.record_prepared_consent(&question, &question.ask_id);
        assert!(
            plane
                .settle_browser_grant(&question.ask_id, Some(&json!({"decision": "deny"})))
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

    /// A browser call held open on the answer blocks the agent, so its card is
    /// sent at high urgency; the same grant asked ahead is not.
    #[tokio::test]
    async fn only_a_browser_grant_held_in_call_is_sent_at_high_urgency() {
        let plane = plane(TargetResolution::NotRunning);
        let origins = vec!["https://example.com".to_string()];
        let (_, held) = plane
            .open_in_call_browser_grant(
                "conversation",
                origins.clone(),
                vec![],
                Some(OBSERVE),
                None,
            )
            .await
            .unwrap();
        let (_, ahead) = plane
            .open_browser_grant_at_tier("conversation", origins, vec![], Some(OBSERVE), true, None)
            .await
            .unwrap();
        assert_eq!(held.unwrap().body["params"]["urgency"], "high");
        assert_eq!(ahead.unwrap().body["params"]["urgency"], "normal");
    }
}

mod agent_enforcement;
pub(crate) mod retained_browser_ops;
#[cfg(test)]
mod retained_browser_ops_tests;
