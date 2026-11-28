//! Launch admission binds the same per-app consent to the selected bundle's
//! signer before the platform receives the launch request. No process must
//! already exist.

use super::*;
use crate::computer_grants::{AppCode, AppIdentity, AppIdentityUnreadable, GrantNeed};
use crate::open_app_history::{AppKey, Observation, Outcome};
use cerebellum_computer::app_state::source::OpenAppError;
use cerebellum_computer::app_state::source::{InstalledApp, InstalledApps};
use cerebellum_computer::platform::ProcessGrant;
use cerebellum_core::config::AppUse;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(windows)]
mod windows;

struct BundleCode {
    source: Arc<dyn AppStateSource>,
    app: InstalledApp,
}

impl AppCode for BundleCode {
    fn identity(&self) -> Result<AppIdentity, AppIdentityUnreadable> {
        let signature =
            self.source
                .bundle_signature(&self.app)
                .map_err(|_| AppIdentityUnreadable::Failed {
                    detail: "bundle signature unavailable".into(),
                })?;
        // Launching an untrusted build is itself acting in it. An ad-hoc seal
        // identifies bytes but no signer, so it cannot authorize this launch.
        if !signature.signed || signature.ad_hoc {
            return Err(AppIdentityUnreadable::Unsigned);
        }
        Ok(AppIdentity {
            team_id: signature.team_id,
            designated_requirement: signature
                .designated_requirement
                .filter(|s| !s.is_empty())
                .ok_or(AppIdentityUnreadable::Unsigned)?,
            ad_hoc: false,
            apple_anchored: signature.apple_anchored,
        })
    }

    fn satisfies(&self, requirement: &str) -> Result<bool, AppIdentityUnreadable> {
        self.identity()?;
        Ok(self.source.bundle_satisfies(&self.app, requirement))
    }
}

impl<B, R, T, S, D> ComputerPlane<B, R, T, S, D>
where
    B: CaptureBackend + Send + 'static,
    R: Redactor + Send + 'static,
    T: SeverityTaxonomy + Send + 'static,
    S: JournalStorage + Send + 'static,
    D: PlatformDriver + 'static,
{
    pub(super) async fn serve_open_app<C: MonotonicClock>(
        &self,
        arguments: &Value,
        context: ServeContext<'_, C>,
    ) -> Value {
        let request = match parse_request(arguments) {
            Ok(target) => target,
            Err(reply) => return reply,
        };
        let source = self.app_state_source.clone();
        let listed =
            tokio::task::spawn_blocking(move || source.installed_apps(Duration::from_secs(2)))
                .await
                .unwrap_or_default();
        let source = self.app_state_source.clone();
        let apps = listed.apps.clone();
        let target = request.target.clone();
        let resolved = tokio::task::spawn_blocking(move || resolve_installed(&target, &apps, &*source))
            .await
            .unwrap_or_else(|_| Err(json!({"outcome":"launch_failed", "remedy":"Application inventory could not be checked; retry list_apps before opening the app"})));
        let mut reply = self
            .serve_installed_open_app(&request, &listed, resolved, context)
            .await;
        // Unreadable bundles elsewhere do not invalidate a found target: its
        // bytes still need a signer-bound grant naming that application. Disclose
        // the inventory limit on both launches and inventory-backed refusals.
        reply["installed_list"] = json!(if listed.complete {
            "complete"
        } else {
            "partial"
        });
        reply
    }

    async fn serve_installed_open_app<C: MonotonicClock>(
        &self,
        request: &OpenRequest,
        listed: &InstalledApps,
        resolved: Result<ResolvedInstalled, Value>,
        context: ServeContext<'_, C>,
    ) -> Value {
        let ResolvedInstalled { app, running } = match resolved {
            Ok(resolved) => resolved,
            Err(mut reply) => {
                if !listed.complete && reply["outcome"] == "no_installed_app_named" {
                    #[cfg(target_os = "windows")]
                    let remedy = "the installed inventory is incomplete; retry list_apps, or use the exact name or app identity of an app it shows";
                    #[cfg(not(target_os = "windows"))]
                    let remedy = "the application may be in the unreadable part of the installed inventory; restore access and retry, or use the exact name or app identity (a bundle id on macOS) of an app shown by list_apps";
                    reply["remedy"] = json!(remedy);
                }
                return reply;
            }
        };
        // The installed application a name leads to is known only now; an
        // application no agent may use is refused before its signature is
        // read or its grant looked up.
        if super::operator_apps::installed_app_blocked(&app) {
            self.operator_app_refused(context.grantee, &request.target)
                .await;
            return super::operator_apps::installed_app_refusal(&app, &context.consent.caller);
        }
        if let Some(url) = request.url.as_deref() {
            let source = self.app_state_source.clone();
            let bundle = app.clone();
            let registered =
                tokio::task::spawn_blocking(move || source.bundle_url_schemes(&bundle))
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default();
            if let Err(reply) = admit_url(url, &registered, &app.bundle_identity) {
                return reply;
            }
        }
        let code = Arc::new(BundleCode {
            source: self.app_state_source.clone(),
            app: app.clone(),
        });
        // Validate even when a conversation already holds a grant. The grant's
        // requirement is then checked against these on-disk bytes by require.
        let read_code = code.clone();
        let identity = tokio::task::spawn_blocking(move || read_code.identity())
            .await
            .ok()
            .and_then(Result::ok);
        let Some(identity) = identity else {
            #[cfg(target_os = "windows")]
            let remedy = "On Windows, open_app requires an installed app with a verified publisher and program identity or a verified package identity";
            #[cfg(not(target_os = "windows"))]
            let remedy = "On macOS, the installed application must carry a valid, non-ad-hoc signature before it can be launched";
            return json!({"outcome":"consent_unavailable", "detail":{"reason":"app_identity_unreadable","grant":"app","grant_label":app.name}, "remedy":remedy});
        };
        let history_key = AppKey::verified(&app.bundle_identity, &identity);
        let need = GrantNeed::App {
            bundle_identity: app.bundle_identity.clone(),
            display_name: {
                #[cfg(windows)]
                {
                    windows::consent_name(&app)
                }
                #[cfg(not(windows))]
                {
                    app.name.clone()
                }
            },
            code: code.clone(),
        };
        let admission = match context
            .management
            .computer_grants()
            .require(&need, &context.consent, &context.cancel)
            .await
        {
            Ok(admission) => admission,
            Err(refusal) => return AppRefusal::Consent(refusal).reply(&app.bundle_identity),
        };
        if let Some(locked) = self.locked_after_wait(admission.waited, &admission) {
            return locked;
        }
        // Consent can take minutes; never launch replaced bytes under its answer.
        if !context
            .management
            .computer_grants()
            .holds(&context.consent.caller, &need)
        {
            return json!({"outcome":"consent_unavailable", "remedy":"the application changed after approval; retry to approve its current signer"});
        }
        if context.cancel.is_cancelled() {
            return json!({"outcome":"cancelled"});
        }
        let work = super::quarantine::CallWork::current();
        let conversation_key = context.identity.conversation_key.clone();
        let token = {
            use cerebellum_computer::audit::{
                ComputerPlaneDescriptor, ObservationState, TypedCaptureDispatch,
            };
            use cerebellum_computer::grounding::ContainmentRung;
            // A short lock for the journal steps only; it is released before
            // the launch below.
            let mut audit = cerebellum_computer::audit::lock_audit(&self.audit);
            let capability = ComputerCapability::OpenApp;
            // A new process has no pid yet; do not claim pid containment for
            // the LaunchServices request that creates it.
            let rung = ContainmentRung::GlobalNone;
            let descriptor =
                ComputerPlaneDescriptor::new(capability, rung, ObservationState::HumanUnobserved);
            let reservation = match audit.reserve(context.identity, descriptor) {
                Ok(reservation) => reservation,
                Err(_) => return read_audit_unavailable_reply(),
            };
            // The computer gate point for a launch: once the call has been
            // answered, no application is opened.
            if !work.begin_mutation() {
                let _ = audit
                    .finalize_rejected(reservation, br#"{"outcome":"dispatch_stopped"}"#.to_vec());
                return super::quarantine::stopped_before_dispatch_reply();
            }
            let dispatch =
                TypedCaptureDispatch::new(capability, rung, ObservationState::HumanUnobserved)
                    .dispatch_material(capability.capability_id().as_bytes().to_vec());
            match audit.commit_dispatched(reservation, &dispatch, b"app_grant".to_vec(), None) {
                Ok(token) => token,
                Err(_) => return read_audit_unavailable_reply(),
            }
        };
        let source = self.app_state_source.clone();
        let launching = app.clone();
        let url = request.url.clone();
        let bounds = history_key
            .as_ref()
            .map(|key| self.launch_history.advice(key).bounds)
            .unwrap_or_default();
        let attempted = Arc::new(AtomicBool::new(false));
        let launch_started = attempted.clone();
        let launch_work = work.clone();
        #[cfg(windows)]
        let background =
            self.fronting_admission(&context.consent, false).mode == AppUse::Background;
        #[cfg(windows)]
        let restore_admitted = self.windows_background_restore_admitted;
        let opened = tokio::task::spawn_blocking(move || {
            let _ax = launch_work.bound_ax();
            #[cfg(windows)]
            let foreground =
                (background && launching.windows_entry.is_some()).then(windows::sample);
            let launch = || {
                if let Some(url) = url.as_deref() {
                    // Consent can outlive a bundle update. Re-read the declarations
                    // immediately before dispatch, just as the signer is rechecked.
                    let schemes = source.bundle_url_schemes(&launching).unwrap_or_default();
                    if admit_url(url, &schemes, &launching.bundle_identity).is_err() {
                        return Err(OpenAppError::Failed);
                    }
                }
                if let Some(process) = running {
                    // A URL is still an instruction when the app is running. Bind
                    // delivery to the selected path and generation, and disclose
                    // any replacement instead of claiming it was already running.
                    return if let Some(url) = url {
                        source.open_running_app_url(&launching, &process, &url, bounds)
                    } else {
                        source.opened_running_app(&launching, &process)
                    };
                }
                // URL revalidation can refuse before any launch call. Keep that
                // out of history, while still counting a worker failure after the
                // platform was asked to open the app as a real launch attempt.
                launch_started.store(true, Ordering::Release);
                if let Some(url) = url {
                    source.open_app_url(&launching, &url, bounds)
                } else {
                    source.open_app(&launching, bounds)
                }
            };
            let opened = launch();
            #[cfg(windows)]
            let changed = foreground.and_then(|before| {
                windows::foreground_change(
                    before,
                    restore_admitted,
                    opened.as_ref().ok().map(|app| app.pid),
                    &launching.bundle_identity,
                    launch_work.deadline(),
                )
            });
            #[cfg(not(windows))]
            let changed: Option<super::fronting::Fronting> = None;
            (opened, changed)
        })
        .await
        .unwrap_or((Err(OpenAppError::Failed), None));
        let (opened, foreground_change) = opened;
        let mut observation = Observation::default();
        match &opened {
            Ok(opened) => {
                observation.process_started_ms = Some(opened.process_started_ms);
                observation.first_window_ms = opened
                    .has_window
                    .then_some(opened.first_window_ms)
                    .flatten();
                if !opened.has_window {
                    // The default budget totals 40 seconds: 30 for a process,
                    // then 10 for a window. Doubling only the short window
                    // stage gives 20 seconds, below that minimum total, so it
                    // would repeat the same wait. Use the full configured
                    // budget as a conservative timeout sample instead.
                    observation.timeout_floor_ms = Some(bounds.ready_timeout.as_millis() as u64);
                }
            }
            Err(OpenAppError::TimedOut) => {
                observation.timeout_floor_ms = Some(bounds.ready_timeout.as_millis() as u64);
            }
            Err(
                OpenAppError::Failed
                | OpenAppError::RunningChanged
                | OpenAppError::ElevationRequired
                | OpenAppError::IdentityMismatch,
            ) => {}
        }
        let mut reply = match opened {
            Ok(opened) => json!({
                "outcome": if opened.already_running { "already_running" } else if opened.has_window { "launched" } else { "launched_no_window" },
                "pid": opened.pid, "has_window": opened.has_window, "frontmost": opened.frontmost,
            }),
            Err(OpenAppError::TimedOut) => {
                let wait_ms = bounds.process_timeout.as_millis();
                #[cfg(target_os = "windows")]
                let remedy = format!("The launcher did not return a process within its {wait_ms} ms process wait; use list_apps before retrying because the application may still start");
                #[cfg(not(target_os = "windows"))]
                let remedy = format!("On macOS, LaunchServices did not return a process within its {wait_ms} ms process wait; list_apps before retrying because the application may still start");
                json!({"outcome":"launch_failed", "remedy":remedy})
            }
            Err(OpenAppError::Failed) => {
                #[cfg(target_os = "windows")]
                let remedy = "The application could not be opened; use list_apps before retrying because the application may still start";
                #[cfg(not(target_os = "windows"))]
                let remedy = "On macOS, LaunchServices could not open the application; list_apps before retrying because the application may still start";
                json!({"outcome":"launch_failed", "remedy":remedy})
            }
            Err(OpenAppError::RunningChanged) => {
                let mut remedy = "The running application changed or an additional process appeared while delivering the URL. The URL may have been delivered and another copy may have started; use list_apps and read_state before retrying.";
                if native_windows_app(&app) {
                    remedy = "The running application changed; use list_apps before retrying.";
                }
                json!({"outcome":"launch_failed", "remedy":remedy})
            }
            Err(OpenAppError::ElevationRequired) => json!({
                "outcome":"launch_failed", "detail":{"reason":"target_elevated"},
                "remedy":"The application requires elevation. Nothing was started."
            }),
            Err(OpenAppError::IdentityMismatch) => json!({
                "outcome":"launch_failed", "detail":{"reason":"identity_indeterminate"},
                "remedy":"The launched application identity could not be confirmed. A process may have started; use list_apps before retrying."
            }),
        };
        // Foreground mode brings the opened application to the front through
        // the same one-way front and guards every action uses: once a running
        // application is found, or a launch reports its first window. The
        // launch itself never activates. A front that stops leaves the launch
        // result standing and says why.
        if native_windows_app(&app) {
            // Do not resolve a bare launch pid into an action grant. Windows
            // never admits the app-use foreground path, even for a proven window.
            let admission = self.fronting_admission(&context.consent, false);
            if let (AppUse::Foreground, Err(stop)) = (admission.mode, admission.may_front()) {
                super::fronting::Fronting::stopped(
                    AppUse::Foreground,
                    super::fronting::Purpose::ForegroundMode,
                    stop,
                )
                .apply(&mut reply);
            }
        } else if let Ok(opened) = &opened {
            if opened.already_running || opened.has_window {
                if let Some(grant) = context.management.process_for_pid(opened.pid) {
                    let front = self
                        .front_for_foreground(super::fronting::FrontCall {
                            grant: &grant,
                            consent: &context.consent,
                            cancel: &context.cancel,
                            management: context.management,
                            conversation_key: &conversation_key,
                            input_follows: false,
                        })
                        .await;
                    // The launch's own row, reserved before the launch and
                    // finalized below, records the outcome after this front.
                    super::fronting::action_row_started();
                    if let Some(front) = front {
                        if let (true, Some(change)) = (opened.already_running, front.change) {
                            // Nothing was launched; the action was the front,
                            // refused because the person changed the target.
                            reply = super::element_actions::state_changed_by_person_reply(
                                &app.name, change,
                            );
                        }
                        front.fronting.apply(&mut reply);
                    }
                }
            }
        }
        if let Some(change) = foreground_change {
            change.apply(&mut reply);
        }
        if let (true, Some(key), Some(outcome)) = (
            attempted.load(Ordering::Acquire),
            history_key,
            Outcome::from_reply(reply["outcome"].as_str().unwrap_or("")),
        ) {
            let advice = self.launch_history.advice(&key);
            let elapsed = observation.first_window_ms;
            if self.launch_history.record(key, observation, outcome) {
                if let Some(usual) = advice.usual_ready_ms {
                    reply["usual_ready_ms"] = json!(usual);
                    if let Some(elapsed) = elapsed.filter(|elapsed| *elapsed > usual) {
                        reply["launch_note"] = json!(format!("This launch is slower than usual ({elapsed} ms elapsed; usual readiness {usual} ms)."));
                    }
                }
            }
        }
        // Only app and outcome go into the journal: no path, window content,
        // request text, pid or frontmost state is copied there.
        let summary = json!({"app":{"name":app.name,"bundle_identity":app.bundle_identity},"outcome":reply["outcome"]});
        if cerebellum_computer::audit::lock_audit(&self.audit)
            .finalize_dispatched(
                token,
                serde_json::to_vec(&summary).expect("JSON summary"),
                Vec::new(),
            )
            .is_err()
        {
            reply = json!({"outcome":"audit_unavailable", "remedy":"the application may have launched, but its outcome could not be journaled; list_apps before retrying"});
        }
        admission.decorate(&mut reply);
        reply
    }
}

fn native_windows_app(_app: &InstalledApp) -> bool {
    #[cfg(windows)]
    {
        _app.windows_entry.is_some()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub(super) struct OpenRequest {
    pub target: String,
    pub url: Option<String>,
}

pub(super) fn parse_request(arguments: &Value) -> Result<OpenRequest, Value> {
    let object = arguments
        .as_object()
        .ok_or_else(|| invalid_read_state_request("arguments", "expected an object"))?;
    if let Some(field) = object
        .keys()
        .find(|key| !["target", "url"].contains(&key.as_str()))
    {
        return Err(invalid_read_state_request(field, "unknown_field"));
    }
    let url = optional_text(object, "url")?;
    if let Some(url) = &url {
        if url.chars().any(|ch| ch.is_control() || ch.is_whitespace()) || url_scheme(url).is_none()
        {
            return Err(invalid_read_state_request("url", "invalid_url"));
        }
    }
    Ok(OpenRequest {
        target: required_text(object, "target")?,
        url,
    })
}

fn url_scheme(url: &str) -> Option<&str> {
    let (scheme, _) = url.split_once(':')?;
    (scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && scheme
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'+' | b'-' | b'.')))
    .then_some(scheme)
}

fn admit_url(url: &str, registered: &[String], bundle: &str) -> Result<(), Value> {
    let scheme = url_scheme(url).unwrap_or("");
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "file" | "http" | "https"
    ) && registered
        .iter()
        .any(|claimed| claimed.eq_ignore_ascii_case(scheme))
    {
        return Ok(());
    }
    Err(
        json!({"outcome":"url_scheme_refused", "scheme":scheme, "target":bundle, "remedy":format!("On macOS, scheme {scheme:?} is forbidden or not declared by {bundle}'s CFBundleURLTypes; use a registered app page address")}),
    )
}

pub(super) struct ResolvedInstalled {
    pub app: InstalledApp,
    pub running: Option<ProcessGrant>,
}

pub(super) fn resolve_installed(
    target: &str,
    apps: &[InstalledApp],
    source: &dyn AppStateSource,
) -> Result<ResolvedInstalled, Value> {
    #[cfg(windows)]
    if apps.iter().any(|app| app.windows_entry.is_some()) {
        return windows::resolve(target, apps, source);
    }
    let wanted = target.trim();
    let by_id: Vec<_> = apps
        .iter()
        .filter(|app| app.bundle_identity.eq_ignore_ascii_case(wanted))
        .collect();
    let matches: Vec<_> = if by_id.is_empty() {
        apps.iter()
            .filter(|app| app.name.trim().eq_ignore_ascii_case(wanted))
            .collect()
    } else {
        by_id
    };
    match matches.as_slice() {
        [app] => Ok(ResolvedInstalled {
            app: (*app).clone(),
            running: None,
        }),
        [] => Err(
            json!({"outcome":"no_installed_app_named", "target":wanted, "remedy":"list_apps shows installed applications; use an exact name or app identity (a bundle id on macOS)"}),
        ),
        _ => {
            let same_bundle = matches.iter().all(|app| {
                app.bundle_identity
                    .eq_ignore_ascii_case(&matches[0].bundle_identity)
            });
            if same_bundle {
                if let Ok(running) = source.running_app_instances(&matches[0].bundle_identity) {
                    match running.as_slice() {
                        [instance] => {
                            let copies: Vec<_> = matches
                                .iter()
                                .filter(|app| {
                                    let path = app
                                        .path
                                        .canonicalize()
                                        .unwrap_or_else(|_| app.path.clone());
                                    instance.executable_path.starts_with(&path)
                                        && instance.executable_path != path
                                })
                                .collect();
                            if let [app] = copies.as_slice() {
                                return Ok(ResolvedInstalled {
                                    app: (***app).clone(),
                                    running: Some(instance.process.clone()),
                                });
                            }
                        }
                        [] => {
                            let versions: Option<Vec<_>> =
                                matches.iter().map(|app| app_version(app)).collect();
                            if let Some(versions) = versions {
                                let best = versions.iter().max().expect("nonempty candidates");
                                let newest: Vec<_> = matches
                                    .iter()
                                    .zip(&versions)
                                    .filter(|(_, version)| *version == best)
                                    .collect();
                                if let [(app, _)] = newest.as_slice() {
                                    return Ok(ResolvedInstalled {
                                        app: (**app).clone(),
                                        running: None,
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            let copies = matches
                .iter()
                .map(|app| {
                    format!(
                        "{} (version {}; build {})",
                        app.path.display(),
                        app.version.as_deref().unwrap_or("unknown"),
                        app.build_version.as_deref().unwrap_or("unknown")
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            let remedy = if same_bundle {
                format!("Multiple copies of this app are installed ({copies}). Ask the person to close extra running copies or remove the copy they don't use, then retry.")
            } else {
                format!("Several installed applications share this name ({copies}). Use a unique app identity (a bundle id on macOS), or ask the person which app they mean.")
            };
            Err(
                json!({"outcome":"ambiguous_app", "target":wanted, "candidates":matches.iter().map(|app| json!({"name":app.name,"bundle_identity":app.bundle_identity})).collect::<Vec<_>>(), "remedy":remedy}),
            )
        }
    }
}

fn app_version(app: &InstalledApp) -> Option<Vec<u64>> {
    fn parse(version: &str) -> Option<Vec<u64>> {
        let mut parts: Vec<_> = version
            .split('.')
            .map(|part| {
                if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                    None
                } else {
                    part.parse().ok()
                }
            })
            .collect::<Option<_>>()?;
        // Missing trailing parts have value zero: 1, 1.0 and 1.0.0 tie.
        while parts.last() == Some(&0) {
            parts.pop();
        }
        Some(parts)
    }
    app.version
        .as_deref()
        .and_then(parse)
        .or_else(|| app.build_version.as_deref().and_then(parse))
}
