//! Launch admission binds the same per-app consent to the selected bundle's
//! signer before LaunchServices receives its URL. No process must already exist.

use super::*;
use crate::computer_grants::{AppCode, AppIdentity, AppIdentityUnreadable, GrantNeed};
use crate::open_app_history::{AppKey, Observation, Outcome};
use cerebellum_computer::app_state::source::OpenAppError;
use cerebellum_computer::app_state::source::{InstalledApp, InstalledApps};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
        let mut reply = self
            .serve_installed_open_app(&request, &listed, context)
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
        context: ServeContext<'_, C>,
    ) -> Value {
        let app = match resolve_installed(&request.target, &listed.apps) {
            Ok(app) => app,
            Err(mut reply) => {
                if !listed.complete && reply["outcome"] == "no_installed_app_named" {
                    reply["remedy"] = json!("the application may be in the unreadable part of the installed inventory; restore access and retry, or use the exact name or bundle identity of an app shown by list_apps");
                }
                return reply;
            }
        };
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
            return json!({"outcome":"consent_unavailable", "detail":{"reason":"app_identity_unreadable","grant":"app","grant_label":app.name}, "remedy":"the installed application must carry a valid, non-ad-hoc signature before it can be launched"});
        };
        let history_key = AppKey::verified(&app.bundle_identity, &identity);
        let need = GrantNeed::App {
            bundle_identity: app.bundle_identity.clone(),
            display_name: app.name.clone(),
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
            return json!({"outcome":"consent_unavailable", "remedy":"the bundle changed after approval; retry to approve its current signer"});
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
        let opened = tokio::task::spawn_blocking(move || {
            let _ax = launch_work.bound_ax();
            if let Some(url) = url.as_deref() {
                // Consent can outlive a bundle update. Re-read the declarations
                // immediately before dispatch, just as the signer is rechecked.
                let schemes = source.bundle_url_schemes(&launching).unwrap_or_default();
                if admit_url(url, &schemes, &launching.bundle_identity).is_err() {
                    return Err(OpenAppError::Failed);
                }
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
        })
        .await
        .unwrap_or(Err(OpenAppError::Failed));
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
            Err(OpenAppError::Failed) => {}
        }
        let mut reply = match opened {
            Ok(opened) => json!({
                "outcome": if opened.already_running { "already_running" } else if opened.has_window { "launched" } else { "launched_no_window" },
                "pid": opened.pid, "has_window": opened.has_window, "frontmost": opened.frontmost,
            }),
            Err(OpenAppError::TimedOut) => {
                json!({"outcome":"launch_failed", "remedy":format!("LaunchServices did not return a process within its {} ms process wait; list_apps before retrying because the application may still start", bounds.process_timeout.as_millis())})
            }
            Err(OpenAppError::Failed) => {
                json!({"outcome":"launch_failed", "remedy":"LaunchServices could not open the application; list_apps before retrying because the application may still start"})
            }
        };
        // Foreground mode brings the opened application to the front through
        // the same one-way front and guards every action uses: once a running
        // application is found, or a launch reports its first window. The
        // launch itself never activates. A front that stops leaves the launch
        // result standing and says why.
        if let Ok(opened) = &opened {
            if opened.already_running || opened.has_window {
                if let Some(grant) = context.management.process_for_pid(opened.pid) {
                    let front = self
                        .front_for_foreground(super::fronting::FrontCall {
                            grant: &grant,
                            consent: &context.consent,
                            cancel: &context.cancel,
                            management: context.management,
                            conversation_key: &conversation_key,
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
        json!({"outcome":"url_scheme_refused", "scheme":scheme, "target":bundle, "remedy":format!("scheme {scheme:?} is forbidden or not declared by {bundle}'s CFBundleURLTypes; use a registered app page address")}),
    )
}

pub(super) fn resolve_installed(
    target: &str,
    apps: &[InstalledApp],
) -> Result<InstalledApp, Value> {
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
        [app] => Ok((*app).clone()),
        [] => Err(
            json!({"outcome":"no_installed_app_named", "target":wanted, "remedy":"list_apps shows installed applications; use an exact name or bundle identity"}),
        ),
        _ => Err(
            json!({"outcome":"ambiguous_app", "target":wanted, "candidates":matches.iter().map(|app| json!({"name":app.name,"bundle_identity":app.bundle_identity})).collect::<Vec<_>>(), "remedy":"several installed bundles match; use a unique bundle identity (duplicate installations must be removed or renamed)"}),
        ),
    }
}
