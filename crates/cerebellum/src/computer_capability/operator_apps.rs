//! The applications no agent may use: the ones that confirm the person's own
//! actions.
//!
//! A request sent from the Alfonso desktop app, or from the phone paired with
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
//! # How an application is recognised
//!
//! An application is refused when its bundle identity, or the file name of
//! the executable its process runs, is in [`OPERATOR_APPS`]. Both are read
//! from the same process identity the grant path reads: the [`ProcessGrant`]
//! that names a pid, its bundle identity and its start time. Bundle
//! identities are self-declared, which is acceptable here: any application
//! claiming one of these identities is refused, so a false claim can only
//! fail closed.
//!
//! When the bundle identity or the executable cannot be read, the application
//! is refused only if one of its titles names Alfonso: the name the caller
//! gave, the name the application runs under, or the title of its focused
//! window. A title names Alfonso when "Alfonso" is one of its words, ignoring
//! case ("Alfonso", "Alfonso Desktop", "alfonso-desktop"; not "Alfonsoville").
//! Otherwise the call goes on as it would have without this check, and is
//! answered by whatever refusal the unreadable identity leads to there.

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
use crate::management::ManagementPlane;

/// The `reason` an operator-app refusal carries, beside the outcome
/// `authorization_denied`.
pub(crate) const OPERATOR_APP_BLOCKED: &str = "operator_app_blocked";

/// What part of an application's identity an entry names.
#[derive(Debug, Clone, Copy)]
enum Identity {
    /// A bundle identifier, which also covers every identifier under it
    /// (`dev.cortexkit.alfonso.helper` under `dev.cortexkit.alfonso`).
    BundleIdentity(&'static str),
    /// The file name of the executable a process runs.
    Executable(&'static str),
}

/// One application no agent may use, and the platform its identity comes
/// from.
#[derive(Debug, Clone, Copy)]
struct OperatorApp {
    identity: Identity,
    /// Where this identity is used. Documentation only: every entry is
    /// checked on every platform. On macOS a target names a bundle identity
    /// and on Windows an executable file name, and an identity that belongs
    /// to Alfonso on one platform names nothing else on another, so matching
    /// all of them everywhere can only refuse more.
    #[allow(dead_code)]
    platform: &'static str,
}

/// The applications every `computer_use` action refuses. All comparisons
/// ignore ASCII case: bundle identifiers are case-insensitive to macOS's
/// LaunchServices and file names are case-insensitive on Windows, and a
/// lower-case spelling of one of these names is still that app on Linux.
///
/// These are interim values from CKDESK, the team that ships the Alfonso
/// desktop app; CKDESK confirms the final release values, and this table is
/// updated when it does.
const OPERATOR_APPS: &[OperatorApp] = &[
    // The Alfonso desktop app: today's development build.
    OperatorApp {
        identity: Identity::BundleIdentity("dev.cortexkit.alfonso"),
        platform: "macos",
    },
    // The Alfonso desktop app: the recommended release identifier.
    OperatorApp {
        identity: Identity::BundleIdentity("io.cortexkit.alfonso.desktop"),
        platform: "macos",
    },
    // iPhone Mirroring. Through it an agent could press the buttons of the
    // Alfonso app on the person's phone.
    OperatorApp {
        identity: Identity::BundleIdentity("com.apple.ScreenContinuity"),
        platform: "macos",
    },
    // Today's executable, inside Alfonso.app.
    OperatorApp {
        identity: Identity::Executable("alfonso-desktop"),
        platform: "macos",
    },
    // The recommended release executable.
    OperatorApp {
        identity: Identity::Executable("Alfonso"),
        platform: "macos",
    },
    OperatorApp {
        identity: Identity::Executable("Alfonso.exe"),
        platform: "windows",
    },
    OperatorApp {
        identity: Identity::Executable("alfonso"),
        platform: "linux",
    },
];

/// Web origins the person's browser and the agent's own browser would refuse
/// for the same reason. Empty: the Alfonso app serves no web interface. An
/// origin added here must also be checked by both browser planes, which do
/// not consult this list while it is empty.
#[allow(dead_code)]
pub(crate) const OPERATOR_WEB_ORIGINS: &[&str] = &[];

/// Whether `identity`, a bundle identity or an executable name or path, is
/// one of [`OPERATOR_APPS`]. Both kinds are matched against every identity
/// string, since a target on Windows names an executable where a target on
/// macOS names a bundle identity.
pub(crate) fn identity_blocked(identity: &str) -> bool {
    let identity = identity.trim();
    let file_name = identity.rsplit(['/', '\\']).next().unwrap_or(identity);
    OPERATOR_APPS.iter().any(|app| match app.identity {
        Identity::BundleIdentity(blocked) => {
            identity.eq_ignore_ascii_case(blocked)
                || (identity
                    .get(..blocked.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(blocked))
                    && identity.as_bytes().get(blocked.len()) == Some(&b'.'))
        }
        Identity::Executable(blocked) => file_name.eq_ignore_ascii_case(blocked),
    })
}

/// Whether a title names Alfonso: "Alfonso" is one of its words, ignoring
/// case, where words are separated by anything that is not a letter or digit.
pub(crate) fn title_names_operator_app(title: &str) -> bool {
    title
        .split(|character: char| !character.is_alphanumeric())
        .any(|word| word.eq_ignore_ascii_case("alfonso"))
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
    fn blocked(&self) -> bool {
        if self
            .bundle_identity
            .as_deref()
            .is_some_and(identity_blocked)
            || self.executable.as_deref().is_some_and(identity_blocked)
        {
            return true;
        }
        (self.bundle_identity.is_none() || self.executable.is_none())
            && self
                .titles
                .iter()
                .any(|title| title_names_operator_app(title))
    }
}

fn readable(identity: &str) -> Option<String> {
    Some(identity.trim().to_string()).filter(|identity| !identity.is_empty())
}

/// The refusal every action answers for an operator app.
pub(crate) fn refusal() -> Value {
    json!({
        "outcome": "authorization_denied",
        "reason": OPERATOR_APP_BLOCKED,
        "remedy": "The agent may not use this app, because it confirms the person's own \
                   actions; nothing was read or done in it, and nobody was asked. No agent may \
                   use it, so ask the person to act in the app themselves.",
    })
}

/// Whether `reply` is the operator-app refusal.
pub(crate) fn is_refusal(reply: &Value) -> bool {
    reply["outcome"] == "authorization_denied" && reply["reason"] == OPERATOR_APP_BLOCKED
}

/// Reads the file name of the executable a resolved process runs, or `None`
/// when it cannot be read.
pub type ExecutableReader = Arc<dyn Fn(&ProcessGrant) -> Option<String> + Send + Sync>;

/// The platform's reading of a process's executable file name.
///
/// On macOS the path is read by pid, and the process's start time is then
/// compared with the grant's, so a pid handed to another process meanwhile
/// reads as unreadable rather than as that other process. A grant without
/// start-time evidence, as `list_apps` builds one from a running-app entry,
/// skips that comparison. On Windows the identity a grant carries already is
/// the executable's file name. Elsewhere nothing can be read.
pub(crate) fn native_executable(grant: &ProcessGrant) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let path = cerebellum_macos::process_executable_path(grant.pid).ok()??;
        if !grant.process_generation_evidence.is_empty()
            && cerebellum_macos::process_start_time_micros(grant.pid)?.to_string()
                != grant.process_generation_evidence
        {
            return None;
        }
        path.file_name()?.to_str().map(str::to_owned)
    }
    #[cfg(target_os = "windows")]
    {
        readable(&grant.bundle_identity)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = grant;
        None
    }
}

/// Everything a lookup needs, owned so it can run on a blocking worker.
#[derive(Clone)]
pub(super) struct Lookup {
    pub(super) management: Arc<ManagementPlane>,
    pub(super) source: Arc<dyn AppStateSource>,
    pub(super) executable: ExecutableReader,
}

impl Lookup {
    /// Whether a resolved process is an operator app. `titles` are names the
    /// caller already knows it by; the application's running name and its
    /// focused window's title are added only when its identity is partly
    /// unreadable, the one case titles decide.
    pub(super) fn process_blocked(&self, grant: &ProcessGrant, mut titles: Vec<String>) -> bool {
        let mut sighting = Sighting {
            bundle_identity: readable(&grant.bundle_identity),
            executable: (self.executable)(grant),
            titles: Vec::new(),
        };
        if sighting.bundle_identity.is_some() && sighting.executable.is_some() {
            return sighting.blocked();
        }
        titles.push(self.management.application_name(grant));
        if let Ok(Some(window)) = self.source.focused_window(grant) {
            titles.extend(window.title);
        }
        sighting.titles = titles;
        sighting.blocked()
    }

    /// Whether a target given by name or app identity is an operator app.
    ///
    /// The target as given is checked first, so naming an operator app is
    /// refused even while it is not running. A name is then matched against
    /// the running applications the way the action itself matches it, and
    /// the bundle identity it leads to is resolved to its process, whose
    /// executable is read. A target that resolves to no process, or to
    /// several, is left to the action, which refuses it as not running or
    /// ambiguous.
    pub(super) fn named_blocked(&self, target: &str) -> bool {
        if identity_blocked(target) {
            return true;
        }
        let mut titles = vec![target.to_string()];
        let bundle_identity = if super::looks_like_bundle_identity(target) {
            target.trim().to_string()
        } else {
            let Ok(apps) = self.source.running_apps() else {
                // The running applications could not be listed, so the name
                // leads to no identity at all.
                return title_names_operator_app(target);
            };
            let Ok(matched) = super::match_target_name(target, &apps) else {
                return false;
            };
            titles.extend(
                apps.iter()
                    .filter(|app| app.bundle_identity == matched.bundle_identity)
                    .map(|app| app.name.clone()),
            );
            matched.bundle_identity
        };
        if identity_blocked(&bundle_identity) {
            return true;
        }
        match self.management.resolve_process(&bundle_identity) {
            Ok(grant) => self.process_blocked(&grant, titles),
            // The process could not be identified, so its executable cannot
            // be read.
            Err(reply) if reply["outcome"] == "targets_unreadable" => {
                titles.iter().any(|title| title_names_operator_app(title))
            }
            Err(_) => false,
        }
    }

    /// Whether the frontmost application is an operator app. A frontmost
    /// application that cannot be read at all is not refused.
    pub(super) fn frontmost_blocked(&self) -> bool {
        let Some(pid) = self.source.frontmost_pid() else {
            return false;
        };
        if let Some(grant) = self.management.process_for_pid(pid) {
            return self.process_blocked(&grant, Vec::new());
        }
        // The process could not be identified by its start time; what the
        // running-application list says about that pid is all there is.
        self.source.running_apps().is_ok_and(|apps| {
            apps.iter().filter(|app| app.pid == pid).any(|app| {
                identity_blocked(&app.bundle_identity) || title_names_operator_app(&app.name)
            })
        })
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
    pub(super) fn operator_lookup(&self, management: &Arc<ManagementPlane>) -> Lookup {
        Lookup {
            management: Arc::clone(management),
            source: Arc::clone(&self.app_state_source),
            executable: Arc::clone(&self.process_executable),
        }
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
            Served::PressPoint | Served::TakeoverMove | Served::TakeoverDrag => {
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
        let lookup = self.operator_lookup(context.management);
        let claimed = tokio::task::spawn_blocking(move || {
            if let Some(target) = named.iter().find(|target| lookup.named_blocked(target)) {
                return Some(target.clone());
            }
            if let Some((id, _)) = processes
                .iter()
                .find(|(_, grant)| lookup.process_blocked(grant, Vec::new()))
            {
                return Some(id.clone());
            }
            (frontmost && lookup.frontmost_blocked()).then(|| "frontmost application".to_string())
        })
        .await
        .unwrap_or_else(|error| std::panic::resume_unwind(error.into_panic()))?;
        Some(self.operator_app_refused(context.grantee, &claimed).await)
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

/// Whether `list_apps` leaves a running application out. Its executable is
/// read by pid; the entry carries no start time to compare.
pub(super) fn running_app_blocked(app: &RunningApp, executable: &ExecutableReader) -> bool {
    let grant = ProcessGrant {
        pid: app.pid,
        bundle_identity: app.bundle_identity.clone(),
        process_generation_evidence: String::new(),
    };
    Sighting {
        bundle_identity: readable(&app.bundle_identity),
        executable: executable(&grant),
        titles: vec![app.name.clone()],
    }
    .blocked()
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn the_web_origin_list_is_empty() {
        assert!(OPERATOR_WEB_ORIGINS.is_empty());
    }

    #[test]
    fn the_refusal_is_recognised_as_itself() {
        assert!(is_refusal(&refusal()));
        assert!(!is_refusal(&json!({"outcome": "authorization_denied"})));
    }
}
