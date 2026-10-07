//! Launch admission binds the same per-app consent to the selected bundle's
//! signer before LaunchServices receives its URL. No process must already exist.

use super::*;
use crate::computer_grants::{AppCode, AppIdentity, AppIdentityUnreadable, GrantNeed};
use cerebellum_computer::app_state::source::{InstalledApp, OpenAppBounds};
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
        let target = match parse_request(arguments) {
            Ok(target) => target,
            Err(reply) => return reply,
        };
        let source = self.app_state_source.clone();
        let listed =
            tokio::task::spawn_blocking(move || source.installed_apps(Duration::from_secs(2)))
                .await
                .unwrap_or_default();
        if !listed.complete {
            return json!({"outcome":"installed_list_partial", "installed_list":"partial", "remedy":"the installed inventory is incomplete, so a unique target cannot be established; retry after the unreadable directory or metadata is available"});
        }
        let app = match resolve_installed(&target, &listed.apps) {
            Ok(app) => app,
            Err(mut reply) => {
                reply["installed_list"] = json!(if listed.complete {
                    "complete"
                } else {
                    "partial"
                });
                return reply;
            }
        };
        let code = Arc::new(BundleCode {
            source: self.app_state_source.clone(),
            app: app.clone(),
        });
        // Validate even when a conversation already holds a grant. The grant's
        // requirement is then checked against these on-disk bytes by require.
        let read_code = code.clone();
        if tokio::task::spawn_blocking(move || read_code.identity())
            .await
            .ok()
            .and_then(Result::ok)
            .is_none()
        {
            return json!({"outcome":"consent_unavailable", "detail":{"reason":"app_identity_unreadable","grant":"app","grant_label":app.name}, "remedy":"the installed application must carry a valid, non-ad-hoc signature before it can be launched"});
        }
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
        let token = {
            use cerebellum_computer::audit::{
                ComputerPlaneDescriptor, ObservationState, TypedCaptureDispatch,
            };
            use cerebellum_computer::grounding::ContainmentRung;
            let mut audit = self.audit.lock().await;
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
        let opened = tokio::task::spawn_blocking(move || {
            source.open_app(&launching, OpenAppBounds::default())
        })
        .await
        .unwrap_or(Err(AppStateReadError::Unreadable));
        let mut reply = match opened {
            Ok(opened) => json!({
                "outcome": if opened.already_running { "already_running" } else if opened.has_window { "launched" } else { "launched_no_window" },
                "pid": opened.pid, "has_window": opened.has_window, "frontmost": opened.frontmost,
            }),
            Err(_) => {
                json!({"outcome":"launch_failed", "remedy":"LaunchServices did not return a process within 30 seconds; list_apps before retrying because the application may still start"})
            }
        };
        // Only app and outcome go into the journal: no path, window content,
        // request text, pid or frontmost state is copied there.
        let summary = json!({"app":{"name":app.name,"bundle_identity":app.bundle_identity},"outcome":reply["outcome"]});
        if self
            .audit
            .lock()
            .await
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

pub(super) fn parse_request(arguments: &Value) -> Result<String, Value> {
    let object = arguments
        .as_object()
        .ok_or_else(|| invalid_read_state_request("arguments", "expected an object"))?;
    if let Some(field) = object.keys().find(|key| key.as_str() != "target") {
        return Err(invalid_read_state_request(field, "unknown_field"));
    }
    required_text(object, "target")
}

fn resolve_installed(target: &str, apps: &[InstalledApp]) -> Result<InstalledApp, Value> {
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
