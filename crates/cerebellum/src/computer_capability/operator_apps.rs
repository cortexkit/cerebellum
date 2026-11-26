//! The applications no agent may use: the ones that confirm the person's own
//! actions.
//!
//! A request sent from the operator's desktop app, or from the phone paired with
//! it, counts as the operator's own action. That holds only while no agent
//! can drive those apps, so every `computer_use` action aimed at one is
//! refused outright: before any grant is looked up, before any question is
//! put to the person, and before anything is read or posted. Reads are
//! refused too (`read_state`, its screenshot, `wait`), because an agent that
//! cannot read the app cannot aim at it either. `list_apps` leaves these apps
//! out instead of refusing the whole list.
//!
//! The set is compiled in. No config file, setting or grant can widen or
//! narrow it.
//!
//! # Development builds
//!
//! One exception is compiled in too. The agents in [`DEV_BUILD_DRIVERS`],
//! which develop the desktop app, may drive its development builds:
//! the identities marked [`Class::DevelopmentBuild`], running with a
//! signature that can be read and is not the released app's (Team ID
//! [`RELEASE_TEAM_ID`]). For those agents such a build is admitted as if an
//! "always" app grant were held for it: no card is shown and no grant is
//! stored, and every other check of the action still runs. Every other agent
//! is refused a development build as before. The released app and iPhone
//! Mirroring stay refused for every agent.
//!
//! The exemption keys on the caller's admitted head identity, the same
//! `agent_project_id` grants are held under, which the route's accepted bind
//! supplies. It reads no file, environment variable or setting: an agent's
//! shell can edit those, and an exemption it could edit would let any agent
//! grant itself the operator's apps.
//!
//! # How an application is recognised
//!
//! An application is refused when its bundle identity, or the file name of
//! the executable its process runs, is in [`OPERATOR_APPS`]. Both are read
//! from the same process identity the grant path reads: the [`ProcessGrant`]
//! that names a pid, its bundle identity and its start time. Bundle
//! identities are self-declared, which is acceptable here: any application
//! claiming one of these identities is refused, so a false claim can only
//! fail closed. A development build is admitted only when both its bundle
//! identity and its executable can be read, and its signature too.
//!
//! When the bundle identity or the executable cannot be read, the application
//! is refused only if one of its titles names Alfonso: the name the caller
//! gave, the name the application runs under, or the title of its focused
//! window. A title names Alfonso when "Alfonso" is one of its words, ignoring
//! case ("Alfonso", "Alfonso Desktop", "alfonso-desktop"; not "Alfonsoville").
//! Otherwise the call goes on as it would have without this check, and any
//! refusal the unreadable identity causes comes from the action itself. This
//! holds for the agents in [`DEV_BUILD_DRIVERS`] too, because an application
//! that cannot be identified could be the released app.

use std::sync::Arc;

use cerebellum_computer::app_state::source::{AppStateSource, InstalledApp, RunningApp};
use cerebellum_computer::platform::ProcessGrant;
use serde_json::{json, Value};

use cerebellum_computer::app_state::session::ElementResolution;
use cerebellum_computer::capture::CaptureBackend;
use cerebellum_computer::platform::PlatformDriver;
use cerebellum_core::clock::MonotonicClock;
use cerebellum_core::journal::{JournalStorage, Redactor, SeverityTaxonomy};

use super::{Servable, ServeContext, Served};
use crate::agent_grants::GrantHolder;
use crate::computer_grants::{ConsentContext, GrantAdmission, GrantCaller, GrantNeed};
use crate::management::{AppRefusal, ManagementPlane};
use crate::CancelHandle;

/// The `reason` an operator-app refusal carries, beside the outcome
/// `authorization_denied`.
pub(crate) const OPERATOR_APP_BLOCKED: &str = "operator_app_blocked";

/// The agents that may drive desktop development builds, identified by the
/// same agent identity used for grants. Only the app's development agent is
/// admitted.
pub(crate) const DEV_BUILD_DRIVERS: &[&str] = &["agent_16013c86"];

/// The Apple Developer Team ID that signs the released desktop app.
/// A process carrying it is never taken for a development build, which is
/// signed ad hoc.
pub(crate) const RELEASE_TEAM_ID: &str = "5R5846NBPW";

/// What part of an application's identity an entry names.
#[derive(Debug, Clone, Copy)]
enum Identity {
    /// A bundle identifier, which also covers every identifier under it
    /// (`dev.cortexkit.alfonso.helper` under `dev.cortexkit.alfonso`).
    BundleIdentity(&'static str),
    /// The file name of the executable a process runs.
    Executable(&'static str),
}

/// Who may use an application an entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// No agent: the released desktop app, and iPhone Mirroring.
    Always,
    /// A development build of the desktop app, which only the agents
    /// in [`DEV_BUILD_DRIVERS`] may use, and only while it is not signed as
    /// the released app.
    DevelopmentBuild,
}

/// One application identity the operator-app rules cover, and the platform
/// its identity comes from.
#[derive(Debug, Clone, Copy)]
struct OperatorApp {
    identity: Identity,
    class: Class,
    /// Where this identity is used. Documentation only: every entry is
    /// checked on every platform. On macOS a target names a bundle identity
    /// and on Windows an executable file name, and an identity that belongs
    /// to the desktop app on one platform names nothing else on another.
    /// Checking all identities on every platform can only refuse more.
    #[allow(dead_code)]
    platform: &'static str,
}

/// The applications every `computer_use` action refuses, apart from the
/// development builds [`DEV_BUILD_DRIVERS`] may use. All comparisons ignore
/// ASCII case: bundle identifiers are case-insensitive to macOS's
/// LaunchServices and file names are case-insensitive on Windows, and a
/// lower-case spelling of one of these names is still that app on Linux.
///
/// Keep these entries in sync with the identities of the released app and
/// its development builds.
const OPERATOR_APPS: &[OperatorApp] = &[
    // The current desktop development build.
    OperatorApp {
        identity: Identity::BundleIdentity("dev.cortexkit.alfonso"),
        class: Class::DevelopmentBuild,
        platform: "macos",
    },
    // The desktop app's release identifier.
    OperatorApp {
        identity: Identity::BundleIdentity("io.cortexkit.alfonso.desktop"),
        class: Class::Always,
        platform: "macos",
    },
    // iPhone Mirroring would let an agent drive the operator's phone app.
    OperatorApp {
        identity: Identity::BundleIdentity("com.apple.ScreenContinuity"),
        class: Class::Always,
        platform: "macos",
    },
    // The development build's executable, inside the desktop app bundle.
    OperatorApp {
        identity: Identity::Executable("alfonso-desktop"),
        class: Class::DevelopmentBuild,
        platform: "macos",
    },
    // The recommended release executable.
    OperatorApp {
        identity: Identity::Executable("Alfonso"),
        class: Class::Always,
        platform: "macos",
    },
    OperatorApp {
        identity: Identity::Executable("Alfonso.exe"),
        class: Class::Always,
        platform: "windows",
    },
    OperatorApp {
        identity: Identity::Executable("alfonso"),
        class: Class::Always,
        platform: "linux",
    },
];

/// Which class of [`OPERATOR_APPS`] `identity`, a bundle identity or an
/// executable name or path, belongs to, or `None` when it is none of them.
/// An identity that matches entries of both classes is [`Class::Always`].
/// Both kinds are matched against every identity string, since a target on
/// Windows names an executable where a target on macOS names a bundle
/// identity.
fn identity_class(identity: &str) -> Option<Class> {
    let identity = identity.trim();
    let file_name = identity.rsplit(['/', '\\']).next().unwrap_or(identity);
    let mut matched = OPERATOR_APPS.iter().filter(|app| match app.identity {
        Identity::BundleIdentity(blocked) => {
            identity.eq_ignore_ascii_case(blocked)
                || (identity
                    .get(..blocked.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(blocked))
                    && identity.as_bytes().get(blocked.len()) == Some(&b'.'))
        }
        Identity::Executable(blocked) => file_name.eq_ignore_ascii_case(blocked),
    });
    let first = matched.next()?.class;
    Some(if matched.any(|app| app.class == Class::Always) {
        Class::Always
    } else {
        first
    })
}

/// Whether `identity`, a bundle identity or an executable name or path, is
/// one of [`OPERATOR_APPS`], development builds included.
pub(crate) fn identity_blocked(identity: &str) -> bool {
    identity_class(identity).is_some()
}

/// Whether a title names Alfonso: "Alfonso" is one of its words, ignoring
/// case, where words are separated by anything that is not a letter or digit.
pub(crate) fn title_names_operator_app(title: &str) -> bool {
    title
        .split(|character: char| !character.is_alphanumeric())
        .any(|word| word.eq_ignore_ascii_case("alfonso"))
}

/// Whether `caller` is one of [`DEV_BUILD_DRIVERS`].
///
/// Only an admitted head counts: the route's accepted bind named the agent,
/// the daemon attested it, and the grant holder resolved from it is that
/// agent's head. A codemode run its head admitted counts as that head, since
/// it acts as the head. A worker does not: its holder is a worker even when
/// it works for a driver, and attribution to an agent is not that agent's
/// authority.
pub(crate) fn drives_development_builds(caller: &GrantCaller) -> bool {
    caller.durable_identity_attested
        && matches!(
            &caller.holder,
            Some(GrantHolder::Head { agent_id })
                if *agent_id == caller.agent_project_id
                    && DEV_BUILD_DRIVERS.contains(&agent_id.as_str())
        )
}

/// Whether a resolved process carries a signature that can be read and is
/// not the released app's, read through the same code-signing reader the
/// grant path checks app grants against.
///
/// Any sign of the release team refuses: the Team ID the signature claims,
/// the team its designated requirement names, or satisfying the release
/// signing requirement. An unsigned process, or one whose signature cannot
/// be read, is refused too, since it might be the released app.
fn signed_as_development_build(management: &ManagementPlane, grant: &ProcessGrant) -> bool {
    development_signature_check(management, grant).is_ok()
}

fn failed_check(condition: &str) -> Value {
    json!({ "condition": condition })
}

fn signature_error(error: crate::computer_grants::AppIdentityUnreadable) -> Value {
    use crate::computer_grants::AppIdentityUnreadable;
    let (kind, message) = match error {
        AppIdentityUnreadable::NoReader => ("NoReader", "no code-signing reader".to_string()),
        AppIdentityUnreadable::Unsigned => (
            "Unsigned",
            "no signature or designated requirement".to_string(),
        ),
        AppIdentityUnreadable::Failed { detail } => ("Failed", detail),
    };
    json!({
        "condition": "signature_unreadable",
        "error_kind": kind,
        "error": short_error(&message),
    })
}

fn short_error(error: &str) -> String {
    error.chars().take(240).collect()
}

fn development_signature_check(
    management: &ManagementPlane,
    grant: &ProcessGrant,
) -> Result<(), Value> {
    let GrantNeed::App { code, .. } =
        management.app_need(&grant.bundle_identity, grant, String::new())
    else {
        return Err(signature_error(
            crate::computer_grants::AppIdentityUnreadable::NoReader,
        ));
    };
    let identity = code.identity().map_err(signature_error)?;
    let release = RELEASE_TEAM_ID.to_ascii_lowercase();
    if identity
        .team_id
        .as_deref()
        .is_some_and(|team| team.trim().eq_ignore_ascii_case(RELEASE_TEAM_ID))
        || identity
            .designated_requirement
            .to_ascii_lowercase()
            .contains(&release)
    {
        return Err(failed_check("release_signed"));
    }
    let release_requirement =
        format!("anchor apple generic and certificate leaf[subject.OU] = \"{RELEASE_TEAM_ID}\"");
    match code.satisfies(&release_requirement) {
        Ok(false) => Ok(()),
        Ok(true) => Err(failed_check("release_signed")),
        Err(error) => Err(signature_error(error)),
    }
}

/// Read the development-build checks without admitting an action or storing a grant.
///
/// This diagnostic deliberately reads both signature results, even if identity
/// reading fails, so a host probe can distinguish the failing checks. It does not
/// attest a caller or establish that the caller may drive development builds.
#[doc(hidden)]
pub fn development_build_snapshot(management: &ManagementPlane, grant: &ProcessGrant) -> Value {
    use crate::computer_grants::AppIdentityUnreadable;

    fn error(error: AppIdentityUnreadable) -> Value {
        let detail = match &error {
            AppIdentityUnreadable::Failed { detail } => Some(detail.as_str()),
            _ => None,
        };
        json!({ "error": format!("{error:?}"), "detail": detail })
    }

    let executable = native_executable(grant).ok();
    let sighting = Sighting {
        bundle_identity: readable(&grant.bundle_identity),
        executable: executable.clone(),
        titles: Vec::new(),
    };
    let release_requirement =
        format!("anchor apple generic and certificate leaf[subject.OU] = \"{RELEASE_TEAM_ID}\"");
    let mut snapshot = json!({
        "pid": grant.pid,
        "process_generation_evidence": grant.process_generation_evidence,
        "bundle_identity": grant.bundle_identity,
        "executable": executable,
        "sighting_verdict": format!("{:?}", sighting.verdict()),
        "release_requirement": release_requirement,
    });
    let GrantNeed::App { code, .. } =
        management.app_need(&grant.bundle_identity, grant, String::new())
    else {
        snapshot["app_need_is_app"] = json!(false);
        return snapshot;
    };
    snapshot["app_need_is_app"] = json!(true);
    snapshot["identity"] = match code.identity() {
        Ok(identity) => json!({ "ok": {
            "team_id": identity.team_id,
            "designated_requirement": identity.designated_requirement,
            "ad_hoc": identity.ad_hoc,
            "apple_anchored": identity.apple_anchored,
        }}),
        Err(unreadable) => error(unreadable),
    };
    snapshot["satisfies_release_requirement"] = match code.satisfies(&release_requirement) {
        Ok(satisfies) => json!({ "ok": satisfies }),
        Err(unreadable) => error(unreadable),
    };
    snapshot
}

/// What [`OPERATOR_APPS`] says about one sighted application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// None of them: the call goes on.
    Ordinary,
    /// Refused for every agent.
    Blocked,
    /// A development build, fully identified; whether it is refused depends
    /// on the caller and on the process's signature.
    DevelopmentBuild,
}

/// What a lookup learned about one application: its bundle identity and
/// executable, each `None` when it could not be read, and the titles it is
/// known by.
struct Sighting {
    bundle_identity: Option<String>,
    executable: Option<String>,
    titles: Vec<String>,
}

impl Sighting {
    fn failed_development_check(&self) -> Value {
        let bundle_class = self.bundle_identity.as_deref().and_then(identity_class);
        let executable_class = self.executable.as_deref().and_then(identity_class);
        let classes = [bundle_class, executable_class];
        if !classes.contains(&Some(Class::Always))
            && classes.contains(&Some(Class::DevelopmentBuild))
        {
            if self.bundle_identity.is_none() {
                return failed_check("identity_unreadable");
            }
            if self.executable.is_none() {
                return failed_check("executable_unreadable");
            }
        }
        let class_name = |class: Option<Class>| match class {
            Some(Class::Always) => "always",
            Some(Class::DevelopmentBuild) => "development_build",
            None => "unmatched",
        };
        json!({
            "condition": if classes.iter().all(Option::is_none) && self.blocked() {
                "title_fallback"
            } else {
                "not_a_development_build"
            },
            "bundle_identity_present": self.bundle_identity.is_some(),
            "executable_present": self.executable.is_some(),
            "classes": {
                "bundle_identity": class_name(bundle_class),
                "executable": class_name(executable_class),
            },
        })
    }

    fn verdict(&self) -> Verdict {
        let classes: Vec<Class> = [&self.bundle_identity, &self.executable]
            .into_iter()
            .flatten()
            .filter_map(|identity| identity_class(identity))
            .collect();
        if classes.contains(&Class::Always) {
            return Verdict::Blocked;
        }
        let partly_unreadable = self.bundle_identity.is_none() || self.executable.is_none();
        if partly_unreadable
            && self
                .titles
                .iter()
                .any(|title| title_names_operator_app(title))
        {
            return Verdict::Blocked;
        }
        if classes.contains(&Class::DevelopmentBuild) {
            // A development build counts only when nothing about it is
            // unknown: part of it unread could be the released app.
            return if partly_unreadable {
                Verdict::Blocked
            } else {
                Verdict::DevelopmentBuild
            };
        }
        Verdict::Ordinary
    }

    /// Whether the application is refused to an agent that may not drive
    /// development builds.
    fn blocked(&self) -> bool {
        self.verdict() != Verdict::Ordinary
    }
}

fn readable(identity: &str) -> Option<String> {
    Some(identity.trim().to_string()).filter(|identity| !identity.is_empty())
}

/// Whether `caller` may use the resolved process as a development build:
/// the caller is one of [`DEV_BUILD_DRIVERS`], the process's bundle identity
/// and executable are both read and name a development build and nothing
/// refused to every agent, and its signature is not the released app's.
///
/// The grant path asks this of the process it is about to admit, so the
/// process acted on is the one checked, whatever was checked when the call
/// arrived.
pub(super) fn admits_development_build(
    management: &ManagementPlane,
    caller: &GrantCaller,
    executable: &ExecutableReader,
    grant: &ProcessGrant,
) -> bool {
    drives_development_builds(caller)
        && Sighting {
            bundle_identity: readable(&grant.bundle_identity),
            executable: executable(grant).ok(),
            titles: Vec::new(),
        }
        .verdict()
            == Verdict::DevelopmentBuild
        && signed_as_development_build(management, grant)
}

const OPERATOR_APP_REMEDY: &str =
    "The agent may not use this app, because it confirms the person's own \
    actions; nothing was read or done in it, and nobody was asked. No agent may \
    use it, so ask the person to act in the app themselves.";

/// The refusal every action answers for an operator app.
pub(crate) fn refusal() -> Value {
    json!({
        "outcome": "authorization_denied",
        "reason": OPERATOR_APP_BLOCKED,
        "remedy": OPERATOR_APP_REMEDY,
    })
}

fn development_remedy(
    check: &Value,
    running_app: bool,
    failed_read: Option<&str>,
) -> Option<String> {
    let remedy = match check["condition"].as_str()? {
        "process_unresolved" => "Cerebellum couldn't identify this app's running process to confirm it's a development build. Make sure the development build is running, then retry.",
        "identity_unreadable" => "Cerebellum couldn't read this app's identity to confirm it's a development build, so it treats the app as the released one. Restart the development build, then retry.",
        "executable_unreadable" if running_app => {
            let location = check["path"].as_str().map_or_else(String::new, |path| {
                format!(" at {}", cerebellum_computer::app_state::render::one_line(path))
            });
            let (read, recovery) = failed_read.map_or(
                (
                    "read the running app's program location",
                    "Run the development build from a location Cerebellum can read (an internal disk), then retry.",
                ),
                |read| (read, "Restart the development build, then retry."),
            );
            return Some(format!("Cerebellum couldn't {read}{location} to confirm it's a development build, so it treats the app as the released one. {recovery}"));
        }
        "executable_unreadable" => "Cerebellum can't confirm this is a development build from the installed app entry, so it won't open the app. Target the running development build, or start it yourself first if it isn't running.",
        "signature_unreadable" => "Cerebellum couldn't verify this app's signature to confirm it's a development build, so it treats the app as the released one. Run a signed development build, then retry.",
        "title_fallback" => "Cerebellum couldn't read this app's full identity, and its name suggests it may be the released app. Make sure the intended development build is running, then retry with its app identifier.",
        // A release identity or signature still gets the permanent refusal.
        _ => return None,
    };
    Some(remedy.to_string())
}

fn refusal_with_development_check(
    check: Value,
    running_app: bool,
    failed_read: Option<&str>,
) -> Value {
    let mut reply = refusal();
    if let Some(remedy) = development_remedy(&check, running_app, failed_read) {
        reply["remedy"] = json!(remedy);
    }
    reply["detail"] = json!({ "development_build_check": check });
    reply
}

fn name_checked_app(reply: &mut Value, source: &str, name: &str) {
    let check = &reply["detail"]["development_build_check"];
    if matches!(check["condition"].as_str(), Some(condition) if !matches!(condition, "caller" | "not_a_development_build" | "release_signed"))
    {
        let name = cerebellum_computer::app_state::render::one_line(name);
        let app = if name.is_empty() {
            source.to_owned()
        } else {
            format!("{source} ({name})")
        };
        if let Some(remedy) = reply["remedy"].as_str() {
            reply["remedy"] = json!(format!("{remedy} Cerebellum checked {app}."));
        }
    }
}

/// Whether `reply` is the operator-app refusal.
pub(crate) fn is_refusal(reply: &Value) -> bool {
    reply["outcome"] == "authorization_denied" && reply["reason"] == OPERATOR_APP_BLOCKED
}

/// Why a running process's program name could not be established. A path
/// is only kept if it is known to belong to the process that was checked.
#[derive(Default)]
pub struct ProgramLocationUnreadable {
    pub(super) path: Option<std::path::PathBuf>,
    pub(super) error: Option<std::io::ErrorKind>,
    pub(super) failed_read: Option<&'static str>,
}

impl ProgramLocationUnreadable {
    fn add_detail(&self, check: &mut Value) {
        if let Some(path) = self.path.as_deref().and_then(std::path::Path::to_str) {
            check["path"] = json!(path);
        }
        if let Some(error) = self.error {
            check["error"] = json!(error.to_string());
        }
    }
}

/// Reads the file name of the executable a resolved process runs.
pub type ExecutableReader =
    Arc<dyn Fn(&ProcessGrant) -> Result<String, ProgramLocationUnreadable> + Send + Sync>;

/// The platform's reading of a process's executable file name.
///
/// On macOS the path is read by pid, and the process's start time is then
/// compared with the grant's, so a pid handed to another process meanwhile
/// reads as unreadable rather than as that other process. A grant without
/// start-time evidence, as `list_apps` builds one from a running-app entry,
/// skips that comparison. On Windows the identity a grant carries already is
/// the executable's file name. Elsewhere nothing can be read.
pub(crate) fn native_executable(grant: &ProcessGrant) -> Result<String, ProgramLocationUnreadable> {
    #[cfg(target_os = "macos")]
    {
        let path = cerebellum_macos::process_executable_path(grant.pid)
            .map_err(|errno| ProgramLocationUnreadable {
                path: None,
                error: (errno != 0).then(|| std::io::Error::from_raw_os_error(errno).kind()),
                failed_read: None,
            })?
            .ok_or(ProgramLocationUnreadable {
                path: None,
                error: Some(std::io::ErrorKind::NotFound),
                failed_read: Some("find the running process to read its program location"),
            })?;
        if !grant.process_generation_evidence.is_empty()
            && !cerebellum_macos::process_start_time_micros(grant.pid)
                .is_some_and(|started| started.to_string() == grant.process_generation_evidence)
        {
            return Err(ProgramLocationUnreadable {
                failed_read: Some(
                    "confirm the program location still belonged to the same running process",
                ),
                ..ProgramLocationUnreadable::default()
            });
        }
        path.file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .ok_or(ProgramLocationUnreadable {
                path: Some(path),
                error: None,
                failed_read: Some("read the program name from the running app's location"),
            })
    }
    #[cfg(target_os = "windows")]
    {
        readable(&grant.bundle_identity).ok_or_else(ProgramLocationUnreadable::default)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = grant;
        Err(ProgramLocationUnreadable::default())
    }
}

/// Everything a lookup needs, owned so it can run on a blocking worker.
#[derive(Clone)]
pub(super) struct Lookup {
    pub(super) management: Arc<ManagementPlane>,
    pub(super) source: Arc<dyn AppStateSource>,
    pub(super) executable: ExecutableReader,
    /// Whether the caller is one of [`DEV_BUILD_DRIVERS`].
    pub(super) drives_development_builds: bool,
}

fn unresolved_process_facts(pid: u32) -> Value {
    #[cfg(all(target_os = "macos", not(test)))]
    {
        use cerebellum_macos::{process_owner, process_window_counts, ProcessOwner};
        let alive = match process_owner(pid) {
            ProcessOwner::Running { zombie, .. } => Some(u8::from(!zombie)),
            ProcessOwner::NoSuchProcess => Some(0),
            ProcessOwner::NotPermitted | ProcessOwner::Unreadable(_) => None,
        };
        let windows = process_window_counts(pid);
        let mut facts = json!({"pid": pid});
        for (name, count) in [
            ("pid_alive", alive.map(usize::from)),
            ("total_windows", windows.total_windows),
            ("on_screen_windows", windows.on_screen_windows),
            (
                "windows_on_active_display",
                windows.windows_on_active_display,
            ),
            ("windows_on_awake_display", windows.windows_on_awake_display),
        ] {
            if let Some(count) = count {
                facts[name] = json!(count);
            }
        }
        facts
    }
    // Unit-test PIDs are fixtures, not processes on the operator's machine.
    #[cfg(any(not(target_os = "macos"), test))]
    json!({ "pid": pid })
}

impl Lookup {
    fn refusal(&self, check: Value) -> Value {
        if self.drives_development_builds {
            refusal_with_development_check(check, true, None)
        } else {
            refusal()
        }
    }

    fn unresolved(&self, bundle_identity: &str, pid: Option<u32>, error: &str) -> Value {
        let mut check = json!({
            "condition": "process_unresolved",
            "error": short_error(error),
        });
        if self.drives_development_builds {
            let pids = match pid {
                Some(pid) => Some(vec![pid]),
                None => self.source.running_apps().ok().map(|apps| {
                    let mut pids = apps
                        .into_iter()
                        .filter(|app| app.bundle_identity.eq_ignore_ascii_case(bundle_identity))
                        .map(|app| app.pid)
                        .collect::<Vec<_>>();
                    pids.sort_unstable();
                    pids.dedup();
                    pids
                }),
            };
            if let Some(pids) = pids {
                check["processes"] = json!(pids
                    .into_iter()
                    .map(unresolved_process_facts)
                    .collect::<Vec<_>>());
            }
        }
        self.refusal(check)
    }

    /// Whether an identity the request named is refused before it is
    /// resolved: anything in [`OPERATOR_APPS`], except that a development
    /// build named by a driver is resolved and checked as a process.
    fn identity_refused(&self, identity: &str) -> bool {
        match identity_class(identity) {
            Some(Class::Always) => true,
            Some(Class::DevelopmentBuild) => !self.drives_development_builds,
            None => false,
        }
    }

    /// The refusal for a resolved operator app. `titles` are names the
    /// caller already knows it by; the application's running name and its
    /// focused window's title are added only when its identity is partly
    /// unreadable, the one case titles decide.
    /// Read new evidence regardless of where the process grant came from:
    /// an element or image can outlive the evidence that allowed its read.
    pub(super) fn process_refusal(
        &self,
        grant: &ProcessGrant,
        mut titles: Vec<String>,
    ) -> Option<Value> {
        let (executable, unreadable) = match (self.executable)(grant) {
            Ok(name) => (Some(name), None),
            Err(error) => (None, Some(error)),
        };
        let mut sighting = Sighting {
            bundle_identity: readable(&grant.bundle_identity),
            executable,
            titles: Vec::new(),
        };
        if sighting.bundle_identity.is_none() || sighting.executable.is_none() {
            titles.push(self.management.application_name(grant));
            if let Ok(Some(window)) = self.source.focused_window(grant) {
                titles.extend(window.title);
            }
            sighting.titles = titles;
        }
        match sighting.verdict() {
            Verdict::Ordinary => None,
            Verdict::Blocked => {
                let mut check = sighting.failed_development_check();
                if self.drives_development_builds && check["condition"] == "executable_unreadable" {
                    if let Some(unreadable) = unreadable {
                        unreadable.add_detail(&mut check);
                        return Some(refusal_with_development_check(
                            check,
                            true,
                            unreadable.failed_read,
                        ));
                    }
                }
                Some(self.refusal(check))
            }
            Verdict::DevelopmentBuild => {
                if !self.drives_development_builds {
                    return Some(self.refusal(failed_check("caller")));
                }
                development_signature_check(&self.management, grant)
                    .err()
                    .map(|check| self.refusal(check))
            }
        }
    }

    pub(super) fn process_blocked(&self, grant: &ProcessGrant, titles: Vec<String>) -> bool {
        self.process_refusal(grant, titles).is_some()
    }

    pub(super) fn pointer_refusal(&self, grant: &ProcessGrant, source: &str) -> Option<Value> {
        let mut reply = self.process_refusal(grant, Vec::new())?;
        if reply["remedy"] != OPERATOR_APP_REMEDY {
            name_checked_app(&mut reply, source, &grant.bundle_identity);
            return Some(reply);
        }
        let name = self
            .source
            .running_apps()
            .ok()
            .and_then(|apps| {
                apps.into_iter().find(|app| {
                    app.pid == grant.pid
                        && !app.name.trim().is_empty()
                        && !app.name.eq_ignore_ascii_case(&grant.bundle_identity)
                })
            })
            .map(|app| app.name.trim().to_string())
            .unwrap_or_else(|| self.management.application_name(grant));
        let name = cerebellum_computer::app_state::render::one_line(&name);
        reply["remedy"] = json!(format!(
            "The pointer is over {name}, which agents may not use because it confirms the person's own actions. Nothing was read or done in it, and nobody was asked. Move the pointer to the intended application's window, then retry; to use {name}, ask the person to act in the app themselves."
        ));
        Some(reply)
    }

    fn pointer_location_refusal(&self) -> Option<Value> {
        let point = self.source.cursor_position()?;
        let (_, Some(pid)) = self
            .source
            .element_at(
                cerebellum_computer::app_state::source::HitScope::SystemWide,
                point,
            )
            .ok()
            .flatten()?
        else {
            return None;
        };
        let grant = self.management.process_for_pid(pid)?;
        self.pointer_refusal(&grant, "the app under the pointer")
    }

    /// The refusal for a target given by name or app identity, if it is an operator app.
    ///
    /// The target as given is checked first, so naming an operator app is
    /// refused even while it is not running. A name is then matched against
    /// the running applications the way the action itself matches it, and
    /// the bundle identity it leads to is resolved to its process, whose
    /// executable is read. A target that resolves to no process, or to
    /// several, is left to the action, which refuses it as not running or
    /// ambiguous.
    fn named_refusal(&self, target: &str) -> Option<Value> {
        if self.identity_refused(target) {
            return Some(
                self.refusal(
                    Sighting {
                        bundle_identity: readable(target),
                        executable: None,
                        titles: Vec::new(),
                    }
                    .failed_development_check(),
                ),
            );
        }
        let mut titles = vec![target.to_string()];
        let bundle_identity = if super::looks_like_bundle_identity(target) {
            target.trim().to_string()
        } else {
            let apps = match self.source.running_apps() {
                Ok(apps) => apps,
                Err(error) => {
                    // The running applications could not be listed, so the name
                    // leads to no identity at all.
                    return title_names_operator_app(target).then(|| {
                        self.refusal(json!({
                            "condition": "title_fallback",
                        "bundle_identity_present": false,
                        "executable_present": false,
                            "error": short_error(&format!("{error:?}")),
                        }))
                    });
                }
            };
            let Ok(matched) = super::match_target_name(target, &apps) else {
                return None;
            };
            titles.extend(
                apps.iter()
                    .filter(|app| app.bundle_identity == matched.bundle_identity)
                    .map(|app| app.name.clone()),
            );
            matched.bundle_identity
        };
        if self.identity_refused(&bundle_identity) {
            return Some(
                self.refusal(
                    Sighting {
                        bundle_identity: readable(&bundle_identity),
                        executable: None,
                        titles: Vec::new(),
                    }
                    .failed_development_check(),
                ),
            );
        }
        match self.management.resolve_process(&bundle_identity) {
            Ok(grant) => self.process_refusal(&grant, titles),
            // The process could not be identified, so its executable cannot
            // be read.
            Err(reply) if reply["outcome"] == "targets_unreadable" => titles
                .iter()
                .any(|title| title_names_operator_app(title))
                .then(|| self.unresolved(&bundle_identity, None, &reply.to_string())),
            Err(_) => None,
        }
    }

    /// The refusal for the frontmost operator app. A frontmost
    /// application that cannot be read at all is not refused.
    fn frontmost_refusal(&self) -> Option<Value> {
        let pid = self.source.frontmost_pid()?;
        if let Some(grant) = self.management.process_for_pid(pid) {
            let mut reply = self.process_refusal(&grant, Vec::new())?;
            name_checked_app(&mut reply, "the frontmost app", &grant.bundle_identity);
            return Some(reply);
        }
        // The process could not be identified by its start time; what the
        // running-application list says about that pid is all there is.
        let app = self.source.running_apps().ok()?.into_iter().find(|app| {
            app.pid == pid
                && (identity_blocked(&app.bundle_identity) || title_names_operator_app(&app.name))
        })?;
        let mut reply = self.unresolved("", Some(pid), "process_for_pid returned None");
        name_checked_app(&mut reply, "the frontmost app", &app.bundle_identity);
        Some(reply)
    }
}

impl<B, R, T, S, D> super::ComputerPlane<B, R, T, S, D>
where
    B: CaptureBackend + Send + 'static,
    R: Redactor + Send + 'static,
    T: SeverityTaxonomy + Send + 'static,
    S: JournalStorage + Send + 'static,
    D: PlatformDriver + 'static,
{
    pub(super) fn operator_lookup(
        &self,
        management: &Arc<ManagementPlane>,
        caller: &GrantCaller,
    ) -> Lookup {
        Lookup {
            management: Arc::clone(management),
            source: Arc::clone(&self.app_state_source),
            executable: Arc::clone(&self.process_executable),
            drives_development_builds: drives_development_builds(caller),
        }
    }

    /// Resolve an application and hold its app grant, as
    /// [`ManagementPlane::admit_app`] does, except that a development build
    /// the caller may drive is admitted at once: as if an "always" app grant
    /// were held, so nobody is asked and nothing is stored.
    pub(super) async fn admit_app(
        &self,
        management: &ManagementPlane,
        bundle_identity: &str,
        consent: &ConsentContext,
        cancel: &CancelHandle,
    ) -> Result<(ProcessGrant, GrantAdmission), AppRefusal> {
        if drives_development_builds(&consent.caller) {
            if let Ok(grant) = management.resolve_process(bundle_identity) {
                if admits_development_build(
                    management,
                    &consent.caller,
                    &self.process_executable,
                    &grant,
                ) {
                    return Ok((grant, GrantAdmission::default()));
                }
            }
        }
        Box::pin(management.admit_app(bundle_identity, consent, cancel)).await
    }

    /// The refusal for a call aimed at an operator app, or `None` when the
    /// call may go on. Run once for every action, before the action looks
    /// up a grant, asks anyone or touches the application.
    ///
    /// Every application the request names is checked: a target given by
    /// name or app identity, the application an element id or image id was
    /// read from, and, for the pointer takeover actions, the frontmost
    /// application, which receives the real pointer. The application under
    /// a takeover point, which only the placement's hit test finds, is
    /// checked there, and the installed application `open_app` resolves is
    /// checked where it is resolved; both before any grant is consulted.
    pub(super) async fn operator_app_refusal<C: MonotonicClock>(
        &self,
        capability: Servable,
        arguments: &Value,
        context: &ServeContext<'_, C>,
    ) -> Option<Value> {
        let conversation = &context.identity.conversation_key;
        let sessions = context.management.app_state_sessions();
        let text = |field: &str| {
            arguments
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let mut named: Vec<String> = Vec::new();
        let mut processes: Vec<(String, ProcessGrant)> = Vec::new();
        let mut frontmost = false;
        match capability.0 {
            Served::ListApps => return None,
            Served::ReadState | Served::Type | Served::Keys | Served::OpenApp => {
                named.extend(text("target"));
            }
            Served::TakeoverScroll => {
                named.extend(text("target"));
                frontmost = true;
            }
            Served::Wait => named.extend(text("app")),
            Served::PressElement | Served::WriteText => {
                named.extend(text("target"));
                let listed = arguments
                    .get("element_ids")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned);
                for id in text("element_id").into_iter().chain(listed) {
                    if let ElementResolution::Live {
                        bundle_identity,
                        pid,
                        process_generation,
                        ..
                    } = sessions.resolve(conversation, &id)
                    {
                        processes.push((
                            id,
                            ProcessGrant {
                                pid,
                                bundle_identity,
                                process_generation_evidence: process_generation,
                            },
                        ));
                    }
                }
            }
            Served::PressPoint
            | Served::TakeoverMove
            | Served::TakeoverClick
            | Served::TakeoverDrag => {
                named.extend(text("target"));
                if let Some(id) = text("image_id") {
                    if let Some(image) = sessions.resolve_image(conversation, &id) {
                        processes.push((
                            id,
                            ProcessGrant {
                                pid: image.pid,
                                bundle_identity: image.bundle_identity,
                                process_generation_evidence: image.process_generation,
                            },
                        ));
                    }
                }
                frontmost = !matches!(capability.0, Served::PressPoint);
            }
        }
        // The frontmost application matters only to a pointer takeover that
        // would post. A malformed one is refused by the action itself, and
        // must say what is wrong with it whatever happens to be in front.
        if frontmost {
            frontmost = super::takeover::parse_request(capability.capability(), arguments).is_ok();
        }
        let process_source = if matches!(capability.0, Served::PressElement | Served::WriteText) {
            "the element's app"
        } else {
            "the image's app"
        };
        let lookup = self.operator_lookup(context.management, &context.consent.caller);
        let (claimed, reply) = tokio::task::spawn_blocking(move || {
            if let Some(refused) = named.iter().find_map(|target| {
                let mut reply = lookup.named_refusal(target)?;
                name_checked_app(&mut reply, "the named app", target);
                Some((target.clone(), reply))
            }) {
                return Some(refused);
            }
            if let Some(refused) = processes.iter().find_map(|(id, grant)| {
                let mut reply = lookup.process_refusal(grant, Vec::new())?;
                name_checked_app(&mut reply, process_source, &grant.bundle_identity);
                Some((id.clone(), reply))
            }) {
                return Some(refused);
            }
            frontmost
                .then(|| {
                    lookup
                        .pointer_location_refusal()
                        .or_else(|| lookup.frontmost_refusal())
                })
                .flatten()
                .map(|reply| ("frontmost application".to_string(), reply))
        })
        .await
        .unwrap_or_else(|error| std::panic::resume_unwind(error.into_panic()))?;
        self.operator_app_refused(context.grantee, &claimed).await;
        Some(reply)
    }

    /// Record an operator-app refusal in the refusal ring under `caller`,
    /// addressed as the request named it, and return the refusal.
    pub(super) async fn operator_app_refused(&self, caller: &str, claimed: &str) -> Value {
        let _ = self.refusal_ring.lock().await.record_refusal(
            caller,
            claimed,
            super::ComputerRefusalReason {
                chord: String::new(),
                reason: OPERATOR_APP_BLOCKED.to_string(),
            },
        );
        refusal()
    }
}

impl Lookup {
    /// Whether `list_apps` leaves a running application out. Its executable
    /// is read by pid; the entry carries no start time to compare.
    ///
    /// A development build is listed only to a caller that may drive it, and
    /// only once its process is identified by its start time and passes the
    /// same check an action on it would.
    pub(super) fn running_app_hidden(&self, app: &RunningApp) -> bool {
        let entry = ProcessGrant {
            pid: app.pid,
            bundle_identity: app.bundle_identity.clone(),
            process_generation_evidence: String::new(),
        };
        let verdict = Sighting {
            bundle_identity: readable(&app.bundle_identity),
            executable: (self.executable)(&entry).ok(),
            titles: vec![app.name.clone()],
        }
        .verdict();
        match verdict {
            Verdict::Ordinary => false,
            Verdict::Blocked => true,
            Verdict::DevelopmentBuild => {
                !(self.drives_development_builds
                    && self
                        .management
                        .process_for_pid(app.pid)
                        .filter(|process| process.bundle_identity == app.bundle_identity)
                        .is_some_and(|process| {
                            !self.process_blocked(&process, vec![app.name.clone()])
                        }))
            }
        }
    }
}

/// Whether an installed application is an operator app. No executable is
/// read from an installed bundle, so its name decides when its bundle
/// identity is not one of [`OPERATOR_APPS`].
pub(super) fn installed_app_blocked(app: &InstalledApp) -> bool {
    Sighting {
        bundle_identity: readable(&app.bundle_identity),
        executable: None,
        titles: vec![app.name.clone()],
    }
    .blocked()
}

pub(super) fn installed_app_refusal(app: &InstalledApp, caller: &GrantCaller) -> Value {
    if drives_development_builds(caller) {
        let sighting = Sighting {
            bundle_identity: readable(&app.bundle_identity),
            executable: None,
            titles: vec![app.name.clone()],
        };
        let mut reply =
            refusal_with_development_check(sighting.failed_development_check(), false, None);
        name_checked_app(&mut reply, "the installed app", &app.bundle_identity);
        reply
    } else {
        refusal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_check_error_strings_are_bounded_without_splitting_unicode() {
        assert_eq!(short_error(&"é".repeat(241)), "é".repeat(240));
    }

    #[test]
    fn development_check_distinguishes_unreadable_identity_from_executable() {
        for (bundle_identity, executable, condition) in [
            (None, Some("alfonso-desktop"), "identity_unreadable"),
            (
                Some("dev.cortexkit.alfonso.review"),
                None,
                "executable_unreadable",
            ),
        ] {
            let sighting = Sighting {
                bundle_identity: bundle_identity.map(str::to_string),
                executable: executable.map(str::to_string),
                titles: vec!["Alfonso".into()],
            };
            assert_eq!(
                sighting.failed_development_check(),
                json!({"condition":condition})
            );
        }
    }

    #[test]
    fn a_release_class_wins_over_an_unreadable_identity_in_the_diagnostic_too() {
        let sighting = Sighting {
            bundle_identity: None,
            executable: Some("Alfonso".into()),
            titles: vec![],
        };
        let check = sighting.failed_development_check();
        assert_eq!(check["condition"], "not_a_development_build");
        assert_eq!(
            check["classes"],
            json!({"bundle_identity":"unmatched","executable":"always"})
        );
    }

    #[test]
    fn every_compiled_identity_and_its_children_are_blocked_in_any_case() {
        for identity in [
            "dev.cortexkit.alfonso",
            "dev.cortexkit.alfonso.helper",
            "DEV.CortexKit.Alfonso",
            "io.cortexkit.alfonso.desktop",
            "io.cortexkit.alfonso.desktop.widget",
            "com.apple.ScreenContinuity",
            "com.apple.screencontinuity",
            "alfonso-desktop",
            "/Applications/Alfonso.app/Contents/MacOS/alfonso-desktop",
            "Alfonso",
            "Alfonso.exe",
            "ALFONSO.EXE",
            r"C:\Program Files\Alfonso\Alfonso.exe",
            "alfonso",
        ] {
            assert!(identity_blocked(identity), "{identity}");
        }
    }

    #[test]
    fn neighbouring_identities_are_not_blocked() {
        for identity in [
            "dev.cortexkit.alfonsox",
            "dev.cortexkit",
            "io.cortexkit.alfonso",
            "com.apple.ScreenContinuityX",
            "com.apple.Safari",
            "alfonso-desktop-helper",
            "notepad.exe",
            "",
        ] {
            assert!(!identity_blocked(identity), "{identity}");
        }
    }

    #[test]
    fn a_title_names_alfonso_only_as_a_whole_word() {
        for title in [
            "Alfonso",
            "alfonso desktop",
            "Alfonso — Approvals",
            "alfonso-desktop",
        ] {
            assert!(title_names_operator_app(title), "{title}");
        }
        for title in ["Alfonsoville", "Safari", ""] {
            assert!(!title_names_operator_app(title), "{title}");
        }
    }

    #[test]
    fn titles_decide_only_when_part_of_the_identity_is_unreadable() {
        let titled = |bundle: Option<&str>, executable: Option<&str>| Sighting {
            bundle_identity: bundle.map(str::to_owned),
            executable: executable.map(str::to_owned),
            titles: vec!["Alfonso".into()],
        };
        assert!(!titled(Some("com.example.Editor"), Some("Editor")).blocked());
        assert!(titled(Some("com.example.Editor"), None).blocked());
        assert!(titled(None, Some("Editor")).blocked());
        assert!(titled(Some("com.example.Editor"), Some("alfonso-desktop")).blocked());
    }

    #[test]
    fn the_refusal_is_recognised_as_itself() {
        assert!(is_refusal(&refusal()));
        assert!(!is_refusal(&json!({"outcome": "authorization_denied"})));
    }
}
