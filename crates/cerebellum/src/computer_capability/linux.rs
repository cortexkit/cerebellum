//! Linux release bindings and call-time desktop admission.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;

use cerebellum_computer::app_state::source::{AppStateSource, ElementActionError, ElementHandle};
use cerebellum_computer::audit::ComputerCapability;
use cerebellum_computer::capture::*;
use cerebellum_computer::platform::linux::{self as semantic, Source};
use cerebellum_computer::platform::*;
use cerebellum_linux::atspi;
use cerebellum_linux::desktop_entry::{self, LaunchRefusal};
use cerebellum_linux::identity::{IdentityReader, Refusal as IdentityRefusal, VerifiedApp};
use cerebellum_linux::session::{self, AccessibilityBus, DesktopSession, Environment, SessionKind};
use cerebellum_linux::{place_desktop_scope, DesktopExit, ProcessGeneration};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio::time::{timeout_at, Instant};

use super::open_app::OpenRequest;
use super::{
    computer_audit, permissions, ComputerPlane, ComputerPlaneUnavailable, ResultSchemaEnforcement,
    RunningComputerPlane,
};
use super::{JournalStorage, MonotonicClock, Redactor, ServeContext, SeverityTaxonomy};
use crate::computer_grants::{
    AppCode, AppIdentity, AppIdentityUnreadable, ConsentContext, GrantAdmission, GrantNeed,
};
use crate::management::{AppRefusal, ManagementPlane};
use crate::{CancelHandle, ComputerReleaseInputs, JournalPersistence};

pub(crate) const IDENTITY_REVIEW: Option<&str> =
    option_env!("CEREBELLUM_LINUX_APP_IDENTITY_REVIEW_REVISION");

pub(crate) fn compiled_reviews() -> LinuxReleaseInputs {
    LinuxReleaseInputs {
        app_identity: IDENTITY_REVIEW.map(str::to_owned),
        semantic: option_env!("CEREBELLUM_LINUX_SEMANTIC_REVIEW_REVISION").map(str::to_owned),
        launch: option_env!("CEREBELLUM_LINUX_LAUNCH_REVIEW_REVISION").map(str::to_owned),
        x11_capture: option_env!("CEREBELLUM_LINUX_X11_CAPTURE_REVIEW_REVISION").map(str::to_owned),
        x11_fronting: option_env!("CEREBELLUM_LINUX_X11_FRONTING_REVIEW_REVISION")
            .map(str::to_owned),
        x11_takeover: option_env!("CEREBELLUM_LINUX_X11_TAKEOVER_REVIEW_REVISION")
            .map(str::to_owned),
    }
}

#[allow(clippy::result_large_err)]
pub(crate) fn plane(
    inputs: &ComputerReleaseInputs,
    admitted: Arc<BTreeSet<String>>,
    journal: JournalPersistence,
) -> Result<Arc<RunningComputerPlane>, ComputerPlaneUnavailable> {
    let reviews = &inputs.linux;
    if !LinuxReleaseInputs::GATES
        .iter()
        .any(|gate| reviews.bound(gate))
    {
        return Err(ComputerPlaneUnavailable::NoLinuxReviews);
    }
    let mut session = LinuxSession::new(reviews.bound(LinuxReleaseInputs::SEMANTIC), admitted);
    if reviews.bound(LinuxReleaseInputs::IDENTITY) {
        session.identity = Some(Arc::default());
    }
    let session = Arc::new(session);
    let audit = computer_audit(journal)?;
    let driver_session = Arc::clone(&session);
    let app_use_fronting = [
        LinuxReleaseInputs::IDENTITY,
        LinuxReleaseInputs::SEMANTIC,
        LinuxReleaseInputs::FRONTING,
    ]
    .iter()
    .all(|gate| reviews.bound(gate));
    let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        audit,
        ResultSchemaEnforcement::Withhold,
        move || LinuxDriver {
            session: Arc::clone(&driver_session),
            resolved: None,
        },
    )
    .with_app_state_source(Arc::new(Source(session.clone())))
    .with_fronting_bracket_admitted(app_use_fronting)
    .with_app_use_fronting_admitted(app_use_fronting)
    .with_takeover_pointer_fronting_admitted(
        app_use_fronting && reviews.bound(LinuxReleaseInputs::TAKEOVER),
    );
    Ok(Arc::new(ComputerPlane {
        linux_session: Some(session),
        ..plane
    }))
}

// Arrival runs on the frame reader. Bound both contention for the latch and
// all endpoint discovery, so a stalled local service cannot strand that loop.
const SESSION_READ_LIMIT: Duration = Duration::from_millis(250);

type ReadResult = Result<SessionReading, session::NoSupportedSession>;
type SessionReader = dyn Fn() -> Pin<Box<dyn Future<Output = ReadResult> + Send>> + Send + Sync;
#[cfg(test)]
type ScopePlacer = dyn Fn(ProcessGeneration) -> Pin<Box<dyn Future<Output = Result<(), &'static str>> + Send>>
    + Send
    + Sync;

struct SessionReading {
    desktop: DesktopSession,
    // A connection generation, not a DISPLAY string: a replacement X server
    // can use the same endpoint. Wayland never uses this component.
    x11_connection: Option<u64>,
    permissions: PermissionLivenessReport,
}

#[derive(PartialEq, Eq)]
struct EpochKey {
    session: String,
    kind: SessionKind,
    x11_connection: Option<u64>,
    accessibility: Option<AccessibilityBus>,
}

struct Epoch {
    serial: u64,
    key: EpochKey,
    permissions: PermissionLivenessReport,
    bus: Option<atspi::Bus>,
}

static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);

pub(super) struct LinuxSession {
    read: Box<SessionReader>,
    epoch: Mutex<Option<(Arc<Epoch>, bool)>>,
    admitted: Arc<BTreeSet<String>>,
    identity: Option<Arc<IdentityReader>>,
    #[cfg(test)]
    proof_for_test: Option<fn(u32) -> Result<VerifiedApp, IdentityRefusal>>,
    #[cfg(test)]
    scope_for_test: Option<Arc<ScopePlacer>>,
}

impl LinuxSession {
    pub(super) async fn select(
        self: &Arc<Self>,
        target: &str,
    ) -> Result<(ProcessGrant, String), Value> {
        let source = Source(self.clone());
        let target = target.trim().to_owned();
        let (epoch, _) = self
            .refresh()
            .await
            .map_err(|failure| failure.reply(ComputerCapability::ReadState))?;
        tokio::task::spawn_blocking(move || {
            let apps = source.inventory().map_err(semantic_read_refusal)?;
            let qualified = cerebellum_linux::identity::is_subject(&target);
            let mut matches: Vec<_> = apps.iter().filter(|app| {
                if qualified {
                    app.grant.as_ref().is_some_and(|grant| grant.bundle_identity == target)
                } else {
                    app.name.eq_ignore_ascii_case(&target)
                }
            }).collect();
            if matches.is_empty() && !qualified {
                matches.extend(apps.iter().filter(|app| super::target_resolution::names_in_part(&app.name, &target)));
            }
            if matches.iter().any(|app| app.proof == Err(IdentityRefusal::OperatorAppBlocked)) {
                return Err(semantic_read_refusal("operator_app_blocked"));
            }
            let verified: Vec<_> = matches.iter().filter_map(|app| app.grant.as_ref().map(|grant| (*app, grant))).collect();
            if verified.iter().any(|(_, first)| verified.iter().any(|(_, other)| first.pid != other.pid)) {
                return Err(json!({"outcome": "ambiguous", "reason": "ambiguous_app", "bundle_identity": target,
                    "remedy": "quit all but one matching instance, then retry"}));
            }
            if let [(app, grant)] = verified.as_slice() {
                source.verify(grant).map_err(semantic_read_refusal)?;
                let proof = app.proof.as_ref().expect("a semantic grant has a proof");
                return Ok(((*grant).clone(), proof.display_name(Some(&app.name))));
            }
            if let Some(reason) = matches.iter().find_map(|app| app.proof.as_ref().err()) {
                return Err(semantic_read_refusal(reason.reason()));
            }
            if !verified.is_empty() { return Err(semantic_read_refusal("accessibility_tree_unavailable")); }
            if epoch.key.kind == SessionKind::X11 {
                // Without the X Resource extension's client PID, a missing
                // peer might be a running app with no accessibility tree.
                return Err(semantic_read_refusal("backend_unavailable"));
            }
            Err(json!({"outcome": "not_running", "bundle_identity": target,
                "remedy": "start the application, then retry"}))
        }).await.unwrap_or_else(|_| Err(semantic_read_refusal("backend_unavailable")))
    }

    pub(super) async fn admit_named(
        self: &Arc<Self>,
        management: &ManagementPlane,
        target: &str,
        consent: &ConsentContext,
        cancel: &CancelHandle,
    ) -> Result<(ProcessGrant, GrantAdmission), AppRefusal> {
        let (grant, display_name) = self.select(target).await.map_err(AppRefusal::Resolution)?;
        self.admit_bound(management, grant, Some(display_name), consent, cancel)
            .await
    }

    pub(super) async fn admit_bound(
        self: &Arc<Self>,
        management: &ManagementPlane,
        grant: ProcessGrant,
        display_name: Option<String>,
        consent: &ConsentContext,
        cancel: &CancelHandle,
    ) -> Result<(ProcessGrant, GrantAdmission), AppRefusal> {
        let display_name = match display_name {
            Some(name) => {
                self.verify_bound(&grant)
                    .await
                    .map_err(|reason| AppRefusal::Resolution(semantic_read_refusal(reason)))?;
                name
            }
            None => {
                let source = Source(self.clone());
                let selected = grant.clone();
                tokio::task::spawn_blocking(move || source.bound_display_name(&selected))
                    .await
                    .unwrap_or(Err("backend_unavailable"))
                    .map_err(|reason| AppRefusal::Resolution(semantic_read_refusal(reason)))?
            }
        };
        let driver = LinuxDriver {
            session: self.clone(),
            resolved: None,
        };
        let need = GrantNeed::App {
            bundle_identity: grant.bundle_identity.clone(),
            display_name,
            code: driver.app_code(&grant),
        };
        let admission = management
            .computer_grants()
            .require(&need, consent, cancel)
            .await
            .map_err(AppRefusal::Consent)?;
        self.verify_bound(&grant)
            .await
            .map_err(|reason| AppRefusal::Resolution(semantic_read_refusal(reason)))?;
        Ok((grant, admission))
    }

    pub(super) async fn verify_bound(
        self: &Arc<Self>,
        grant: &ProcessGrant,
    ) -> Result<(), &'static str> {
        let grant = grant.clone();
        let source = Source(self.clone());
        tokio::task::spawn_blocking(move || source.verify(&grant))
            .await
            .unwrap_or(Err("backend_unavailable"))
    }

    pub(super) fn driver(self: &Arc<Self>) -> LinuxDriver {
        LinuxDriver {
            session: self.clone(),
            resolved: None,
        }
    }

    fn new(require_accessibility: bool, admitted: Arc<BTreeSet<String>>) -> Self {
        Self {
            read: Box::new(move || {
                Box::pin(async move {
                    let desktop = session::resolve(require_accessibility).await?;
                    // Session discovery has asked the bus daemon for its ID.
                    // DISPLAY alone proves none of the X11 facilities.
                    let permissions = PermissionLivenessReport::from_results(
                        desktop.accessibility.iter().map(|_| PermissionProbeResult {
                            service: PermissionService::Accessibility,
                            liveness: PermissionLiveness::Live,
                            responsible_process: "ck-cerebellum".into(),
                            off_main: true,
                        }),
                    );
                    Ok(SessionReading {
                        desktop,
                        x11_connection: None,
                        permissions,
                    })
                })
            }),
            epoch: Mutex::new(None),
            admitted,
            identity: None,
            #[cfg(test)]
            proof_for_test: None,
            #[cfg(test)]
            scope_for_test: None,
        }
    }

    async fn refresh(&self) -> Result<(Arc<Epoch>, bool), LinuxRefusal> {
        self.refresh_with_environment()
            .await
            .map(|(epoch, locked, _)| (epoch, locked))
    }

    async fn refresh_with_environment(
        &self,
    ) -> Result<(Arc<Epoch>, bool, Environment), LinuxRefusal> {
        let deadline = Instant::now() + SESSION_READ_LIMIT;
        let mut latch = timeout_at(deadline, self.epoch.lock())
            .await
            .map_err(|_| LinuxRefusal::NoSupportedSession)?;
        let reading = match timeout_at(deadline, (self.read)()).await {
            Ok(Ok(reading)) => reading,
            Ok(Err(_)) | Err(_) => {
                *latch = None;
                return Err(LinuxRefusal::NoSupportedSession);
            }
        };
        let key = EpochKey {
            session: reading.desktop.id,
            kind: reading.desktop.kind,
            x11_connection: if reading.desktop.kind == SessionKind::X11 {
                reading.x11_connection
            } else {
                None
            },
            accessibility: reading.desktop.accessibility,
        };
        let previous = latch
            .as_ref()
            .filter(|(epoch, _)| epoch.key == key)
            .map(|(epoch, _)| epoch.clone());
        let bus = match (
            &key.accessibility,
            previous.as_ref().and_then(|epoch| epoch.bus.as_ref()),
        ) {
            (Some(accessibility), Some(bus)) => {
                if !matches!(
                    timeout_at(deadline, bus.check_id(&accessibility.id)).await,
                    Ok(Ok(()))
                ) {
                    *latch = None;
                    return Err(LinuxRefusal::NoSupportedSession);
                }
                Some(bus.clone())
            }
            (Some(accessibility), None) => timeout_at(deadline, atspi::Bus::connect(accessibility))
                .await
                .ok()
                .and_then(Result::ok),
            (None, _) => None,
        };
        let epoch = previous
            .filter(|epoch| epoch.bus.is_some() == bus.is_some())
            .unwrap_or_else(|| {
                Arc::new(Epoch {
                    serial: NEXT_EPOCH.fetch_add(1, AtomicOrdering::Relaxed),
                    key,
                    permissions: reading.permissions,
                    bus,
                })
            });
        *latch = Some((epoch.clone(), reading.desktop.locked));
        Ok((epoch, reading.desktop.locked, reading.desktop.environment))
    }

    async fn check_launch_session(&self, serial: u64) -> Result<(), &'static str> {
        let (epoch, locked) = self.refresh().await.map_err(|_| "no_supported_session")?;
        if locked {
            return Err("screen_locked");
        }
        if epoch.serial != serial {
            return Err("stale_reference");
        }
        Ok(())
    }

    async fn place_scope(&self, generation: ProcessGeneration) -> Result<(), &'static str> {
        #[cfg(test)]
        if let Some(place) = &self.scope_for_test {
            return place(generation).await;
        }
        place_desktop_scope(generation)
            .await
            .map_err(|_| "launch_scope_unavailable")
    }

    pub(super) async fn refusal(&self, capability: ComputerCapability) -> Option<Value> {
        use ComputerCapability::*;
        let (epoch, locked) = match self.refresh().await {
            Ok(state) => state,
            Err(reason) => return Some(reason.reply(capability)),
        };
        if locked {
            return Some(super::screen_locked_reply());
        }
        let reason =
            if capability != PressPoint && !self.admitted.contains(capability.capability_id()) {
                LinuxRefusal::RouteNotReviewed
            } else if capability == PressPoint {
                LinuxRefusal::PointHitTestUnsupported
            } else if epoch.key.kind == SessionKind::Wayland
                && matches!(
                    capability,
                    Type | Keys | TakeoverMove | TakeoverClick | TakeoverDrag | TakeoverScroll
                )
            {
                LinuxRefusal::WaylandSeatInputUnverifiable
            } else if capability == OpenApp
                || (matches!(
                    capability,
                    ListApps | Wait | ReadState | PressElement | WriteText
                ) && epoch.bus.is_some())
            {
                return None;
            } else if epoch.key.kind == SessionKind::X11 && epoch.key.x11_connection.is_none() {
                LinuxRefusal::BackendUnavailable
            } else if let Some(reply) = permissions::refusal(capability, &epoch.permissions) {
                return Some(reply);
            } else {
                // Do not fall through to handlers for an unavailable Linux backend.
                LinuxRefusal::BackendUnavailable
            };
        Some(reason.reply(capability))
    }
}

// The launch resolver proved this program before deriving the grant need. No
// synthetic pid or desktop-file package is used in the grant store. The same
// snapshot is checked again before spawn and before letting the child run.
struct LaunchPackageCode(String);

impl AppCode for LaunchPackageCode {
    fn identity(&self) -> Result<AppIdentity, AppIdentityUnreadable> {
        Ok(AppIdentity {
            team_id: None,
            designated_requirement: self.0.clone(),
            ad_hoc: false,
            apple_anchored: false,
        })
    }

    fn satisfies(&self, requirement: &str) -> Result<bool, AppIdentityUnreadable> {
        Ok(self.0 == requirement)
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
    pub(super) async fn serve_linux_open_app<C: MonotonicClock>(
        &self,
        session: &Arc<LinuxSession>,
        request: OpenRequest,
        context: ServeContext<'_, C>,
    ) -> Value {
        use cerebellum_computer::audit::{
            ComputerPlaneDescriptor, ObservationState, TypedCaptureDispatch,
        };
        use cerebellum_computer::grounding::ContainmentRung;
        use cerebellum_computer::platform::linux::launch;

        let (epoch, environment) = match session.refresh_with_environment().await {
            Ok((_, true, _)) => return super::screen_locked_reply(),
            Ok((epoch, false, environment)) => (epoch.serial, environment),
            Err(_) => return launch_failure("no_supported_session"),
        };
        let Some(identity) = session.identity.clone() else {
            return launch_failure("route_not_reviewed");
        };
        let target = request.target.clone();
        let resolve_identity = identity.clone();
        let resolve_environment = environment.clone();
        let snapshot = match tokio::task::spawn_blocking(move || {
            desktop_entry::resolve(&resolve_identity, &resolve_environment, &target)
        })
        .await
        {
            Ok(Ok(snapshot)) => snapshot,
            Ok(Err(LaunchRefusal::NotInstalled)) => {
                return json!({"outcome":"no_installed_app_named", "target":request.target, "remedy":"use an exact desktop file ID, display name, or verified package identity"})
            }
            Ok(Err(LaunchRefusal::Ambiguous)) => {
                return json!({"outcome":"ambiguous_app", "target":request.target, "remedy":"use a unique desktop file ID"})
            }
            Ok(Err(LaunchRefusal::Identity(IdentityRefusal::OperatorAppBlocked))) => {
                return self
                    .operator_app_refused(context.grantee, &request.target)
                    .await
            }
            Ok(Err(reason)) => return launch_failure(reason.reason()),
            Err(_) => return launch_failure("backend_unavailable"),
        };
        let name = snapshot.name().to_owned();
        let subject = snapshot.subject().to_owned();
        if super::operator_apps::title_names_operator_app(&name)
            || super::operator_apps::identity_blocked(&subject)
        {
            return self
                .operator_app_refused(context.grantee, &request.target)
                .await;
        }
        if request.url.is_some() {
            return launch_failure("launch_entry_unsupported");
        }
        if let Err(reason) = session.check_launch_session(epoch).await {
            return launch_failure(reason);
        }
        let need = GrantNeed::App {
            bundle_identity: subject.clone(),
            display_name: name.clone(),
            code: Arc::new(LaunchPackageCode(subject.clone())),
        };
        let grants = context.management.computer_grants();
        let admission = match grants
            .require(&need, &context.consent, &context.cancel)
            .await
        {
            Ok(admission) => admission,
            Err(refusal) => return AppRefusal::Consent(refusal).reply(&subject),
        };
        if !grants.holds(&context.consent.caller, &need) {
            return json!({"outcome":"consent_unavailable", "remedy":"the application grant is no longer held; retry to request approval"});
        }
        if context.cancel.is_cancelled() {
            return launch_failure("cancelled");
        }
        let work = super::quarantine::CallWork::current();
        let token = {
            let mut audit = cerebellum_computer::audit::lock_audit(&self.audit);
            let capability = ComputerCapability::OpenApp;
            let rung = ContainmentRung::GlobalNone;
            let observation = ObservationState::HumanUnobserved;
            let descriptor = ComputerPlaneDescriptor::new(capability, rung, observation);
            let reservation = match audit.reserve(context.identity, descriptor) {
                Ok(reservation) => reservation,
                Err(_) => return super::read_audit_unavailable_reply(),
            };
            if !work.begin_mutation() {
                let _ = audit
                    .finalize_rejected(reservation, br#"{"outcome":"dispatch_stopped"}"#.to_vec());
                return super::quarantine::stopped_before_dispatch_reply();
            }
            let dispatch = TypedCaptureDispatch::new(capability, rung, observation)
                .dispatch_material(capability.capability_id().as_bytes().to_vec());
            match audit.commit_dispatched(reservation, &dispatch, b"app_grant".to_vec(), None) {
                Ok(token) => token,
                Err(_) => return super::read_audit_unavailable_reply(),
            }
        };
        let session = session.clone();
        let cancel = context.cancel.clone();
        let opened = tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Handle::current();
            launch::release(&snapshot, &identity, &environment,
                || runtime.block_on(session.check_launch_session(epoch)), || {
                if cancel.is_cancelled() || work.stopped() { return Err("cancelled"); }
                Ok(())
            }, |generation| runtime.block_on(async {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => Err("cancelled"),
                    result = tokio::time::timeout(Duration::from_secs(3), session.place_scope(generation)) =>
                        result.unwrap_or(Err("launch_scope_unavailable")),
                }
            }))
        }).await.unwrap_or(Err("backend_unavailable"));
        let mut reply = match opened {
            Ok(child) => launch_settle_reply(child.settle().await),
            Err(reason) => launch_failure(reason),
        };
        let summary =
            json!({"app":{"name":name,"bundle_identity":subject},"outcome":reply["outcome"]});
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

fn launch_failure(reason: &'static str) -> Value {
    match reason {
        "screen_locked" => super::screen_locked_reply(),
        "cancelled" => json!({"outcome":"cancelled"}),
        "no_supported_session" => {
            LinuxRefusal::NoSupportedSession.reply(ComputerCapability::OpenApp)
        }
        _ => json!({"outcome":"launch_failed", "reason":reason}),
    }
}

fn launch_settle_reply(settle: semantic::launch::Settle) -> Value {
    use semantic::launch::Settle;
    match settle {
        Settle::Running(pid) => {
            json!({"outcome":"launched_no_window", "pid":pid, "has_window":false, "frontmost":false})
        }
        Settle::Exited(exit) => {
            let detail = match exit {
                DesktopExit::Code(status) => json!({"exit_status":status}),
                DesktopExit::Signal(signal) => json!({"signal":signal}),
            };
            json!({"outcome":"launch_failed", "reason":"launch_child_exited", "detail":detail,
                "remedy":"the launched process exited; its activation effect is unknown. Check list_apps before retrying."})
        }
        Settle::Unknown => json!({"outcome":"launch_failed", "reason":"launch_status_unknown",
            "remedy":"the launched process could not be observed; check list_apps before retrying"}),
    }
}

pub(super) fn semantic_read_refusal(reason: &'static str) -> Value {
    match reason {
        "screen_locked" => super::screen_locked_reply(),
        "operator_app_blocked" => json!({"outcome": "authorization_denied", "reason": reason,
            "remedy": "choose a different application"}),
        _ => json!({"outcome": "targets_unreadable", "reason": reason,
            "remedy": "read the application again after the desktop and accessibility tree are available"}),
    }
}

pub(super) fn semantic_element_refusal(reason: &'static str) -> Value {
    match reason {
        "screen_locked" | "operator_app_blocked" => semantic_read_refusal(reason),
        "secure_field_focused" | "focus_unreadable" => json!({
            "outcome": "secure_field_refused", "reason": reason,
            "remedy": "use a readable non-sensitive element or ask the person to act directly"}),
        "web_content_needs_type" => json!({"outcome": "web_content_needs_type", "reason": reason,
            "remedy": "edit this web field directly; this semantic action does not send keystrokes"}),
        _ => json!({"outcome": "stale_element", "reason": reason,
            "remedy": "read the application's state again before retrying"}),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn poll_wait<R, T, S>(
    session: Arc<LinuxSession>,
    audit: super::SharedAudit<R, T, S>,
    work: super::quarantine::CallWork,
    identity: cerebellum_core::journal::JournalIdentity,
    grant: ProcessGrant,
    predicate: cerebellum_computer::dispatch::post_condition::PostCondition,
    timeout_ms: u64,
    cancel: CancelHandle,
    admission: GrantAdmission,
) -> Value
where
    R: cerebellum_core::journal::Redactor + Send + 'static,
    T: cerebellum_core::journal::SeverityTaxonomy + Send + 'static,
    S: cerebellum_core::journal::JournalStorage + Send + 'static,
{
    use cerebellum_computer::dispatch::{wait_until_predicate, PlatformPredicatePoller};
    let mut token = super::AuditToken::new(audit, work.gate());
    match tokio::task::spawn_blocking(move || {
        let _ax = work.bound_ax();
        let _scope = cerebellum_computer::audit::AccessibilityReadScope::new(grant.pid, None);
        token.record_accessibility_read(identity, ComputerCapability::Wait, &grant, || {
            let mut poller = PlatformPredicatePoller::new(session.driver(), grant.clone());
            wait_until_predicate(&mut poller, predicate, timeout_ms, &|| {
                cancel.is_cancelled()
            })
        })
    })
    .await
    {
        Ok(Ok(result)) => {
            let terminal_reason = match &result.evidence {
                cerebellum_computer::dispatch::WaitEvidence::Indeterminate { reason, .. }
                    if matches!(
                        reason.as_str(),
                        "stale_reference" | "no_supported_session" | "screen_locked"
                    ) =>
                {
                    Some(reason.clone())
                }
                _ => None,
            };
            let mut reply = super::wait_wire_reply(result);
            if let Some(reason) = terminal_reason {
                reply["reason"] = json!(reason);
            }
            admission.decorate(&mut reply);
            reply
        }
        _ => super::wait_indeterminate_reply(None, json!({"reason": "polling_task_unavailable"})),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxRefusal {
    NoSupportedSession,
    RouteNotReviewed,
    PointHitTestUnsupported,
    WaylandSeatInputUnverifiable,
    BackendUnavailable,
}

impl semantic::Session for LinuxSession {
    fn current(&self) -> Result<semantic::Live, &'static str> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| "no_supported_session")?;
        let (epoch, locked) = runtime
            .block_on(self.refresh())
            .map_err(|_| "no_supported_session")?;
        if locked {
            return Err("screen_locked");
        }
        let bus = epoch.bus.clone().ok_or("accessibility_tree_unavailable")?;
        Ok(semantic::Live {
            epoch: epoch.serial,
            bus,
        })
    }

    fn prove(&self, pid: u32) -> Result<VerifiedApp, IdentityRefusal> {
        #[cfg(test)]
        if let Some(prove) = self.proof_for_test {
            return prove(pid);
        }
        self.identity
            .as_ref()
            .ok_or(IdentityRefusal::AppIdentityUnproven)?
            .prove(pid)
    }

    fn reprove(
        &self,
        pid: u32,
        generation: &str,
        subject: &str,
    ) -> Result<VerifiedApp, IdentityRefusal> {
        #[cfg(test)]
        if let Some(prove) = self.proof_for_test {
            let app = prove(pid)?;
            return if app.generation_evidence() == generation && app.subject == subject {
                Ok(app)
            } else {
                Err(IdentityRefusal::StaleReference)
            };
        }
        self.identity
            .as_ref()
            .ok_or(IdentityRefusal::AppIdentityUnproven)?
            .reprove(pid, generation, subject)
    }
}

impl LinuxRefusal {
    fn reply(self, capability: ComputerCapability) -> Value {
        use ComputerCapability::*;
        let (reason, remedy) = match self {
            Self::NoSupportedSession => (
                "no_supported_session",
                "use an active, verifiable Linux desktop session",
            ),
            Self::RouteNotReviewed => (
                "route_not_reviewed",
                "use a build that carries the reviews for this operation",
            ),
            Self::PointHitTestUnsupported => (
                "point_hit_test_unsupported",
                "use press_element with an accessibility element id",
            ),
            Self::WaylandSeatInputUnverifiable => (
                "wayland_seat_input_unverifiable",
                "use an accessibility action instead of seat input on Wayland",
            ),
            Self::BackendUnavailable => (
                "backend_unavailable",
                "the Linux backend for this operation is unavailable",
            ),
        };
        let outcome = match capability {
            ListApps | ReadState | Wait => "targets_unreadable",
            OpenApp => "launch_failed",
            Type | Keys => "not_servable",
            _ => "authorization_denied",
        };
        json!({"outcome": outcome, "reason": reason, "remedy": remedy})
    }
}

pub struct LinuxDriver {
    session: Arc<LinuxSession>,
    resolved: Option<(ElementResolutionResult, ElementHandle)>,
}

impl LinuxDriver {
    /// Only authenticated desktop peer PIDs may be submitted by a backend.
    pub fn prove_app(&self, pid: u32) -> Result<VerifiedApp, IdentityRefusal> {
        self.session
            .identity
            .as_ref()
            .ok_or(IdentityRefusal::AppIdentityUnproven)?
            .prove(pid)
    }

    pub fn app_code(&self, grant: &ProcessGrant) -> Arc<dyn crate::computer_grants::AppCode> {
        #[cfg(test)]
        if self.session.proof_for_test.is_some() {
            return Arc::new(crate::computer_grants::SignedByFixtureTeam);
        }
        let mut grant = grant.clone();
        grant.process_generation_evidence =
            semantic::kernel_generation(&grant.process_generation_evidence);
        match &self.session.identity {
            Some(reader) => Arc::new(crate::management::LinuxAppCode {
                grant,
                reader: Arc::clone(reader),
            }),
            None => Arc::new(crate::computer_grants::NoIdentityReader),
        }
    }

    pub fn verify_target(&self, grant: &ProcessGrant) -> Result<VerifiedApp, IdentityRefusal> {
        self.session
            .identity
            .as_ref()
            .ok_or(IdentityRefusal::AppIdentityUnproven)?
            .reprove(
                grant.pid,
                &semantic::kernel_generation(&grant.process_generation_evidence),
                &grant.bundle_identity,
            )
    }

    fn source(&self) -> Source {
        Source(self.session.clone())
    }
}

macro_rules! unsupported {
    ($error:expr; $(fn $name:ident($($parameter:ident: $input:ty),*) -> $output:ty;)*) => {
        $(fn $name(&mut self, $($parameter: $input),*) -> $output { Err($error) })*
    };
}

impl PlatformDriver for LinuxDriver {
    fn capability_declarations(
        &self,
        context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        capability_declarations(context, true)
    }

    fn session_locked(&self) -> Option<bool> {
        let epoch = self.session.epoch.try_lock().ok()?;
        epoch.as_ref().map(|(_, locked)| *locked)
    }

    fn input_observer_liveness(&self) -> InputObserverLiveness {
        InputObserverLiveness {
            session_tap_live: false,
            raw_hid_live: false,
            self_echo_filter_live: false,
        }
    }

    fn verify_attendance(
        &mut self,
        request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        self.verify_target(&request.target)
            .map_err(|reason| DriverError::StartupRefused(reason.reason()))?;
        // A verified app and unlocked desktop are not enough to post input.
        // An observer must also attest that the person is not using the seat.
        Err(DriverError::StartupRefused(match self.session_locked() {
            Some(true) => "screen_locked",
            None => "no_supported_session",
            Some(false) => "backend_unavailable",
        }))
    }

    fn read_accessibility_tree(
        &mut self,
        request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError> {
        self.source().accessibility_tree(request)
    }

    fn read_accessibility_element(
        &mut self,
        request: AccessibilityElementReadRequest,
    ) -> Result<AccessibilityElementReadResult, DriverError> {
        self.source().scoped_read(request)
    }

    fn resolve_element(
        &mut self,
        request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError> {
        self.resolved = None;
        let (resolution, handle) = self.source().resolve(request)?;
        self.resolved = Some((resolution.clone(), handle));
        Ok(resolution)
    }

    fn dispatch_semantic(
        &mut self,
        request: SemanticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        let (resolved, handle) = self
            .resolved
            .take()
            .filter(|(resolved, _)| *resolved == request.element)
            .ok_or(DriverError::StartupRefused("stale_reference"))?;
        if request.action != SEMANTIC_PRESS_ACTION
            || !resolved.semantic_actions.contains(&request.action)
        {
            return Err(DriverError::Unsupported("AT-SPI action"));
        }
        self.source().press(&handle).map_err(|error| match error {
            ElementActionError::PlatformRefused(reason) => DriverError::StartupRefused(reason),
            _ => DriverError::Semantic(SemanticDriverError::PathUnavailable),
        })?;
        Ok(DispatchResult {
            accepted_by_platform: true,
            effect_status: EffectStatus::EffectIndeterminate,
            unreadable_subtrees: 0,
            delivery_posts_returned: 1,
            delivery_generation_verifications: 1,
        })
    }

    fn observe_effect(
        &mut self,
        request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        Ok(self.source().effect(request))
    }

    fn query_focus(&mut self, request: FocusQueryRequest) -> Result<FocusQueryResult, DriverError> {
        // AT-SPI focus is reported by the app. Never use it as evidence that
        // seat input would reach a particular process or surface.
        let _ = self.source().focused_element(&request.target);
        Err(DriverError::StartupRefused("focus_unreadable"))
    }

    unsupported!(DriverError::Unsupported("Linux desktop backend");
        fn dispatch_per_pid(_request: SyntheticDispatchRequest, _cancelled: &dyn Fn() -> bool) -> Result<DispatchResult, DriverError>;
        fn dispatch_global(_request: GlobalDispatchRequest, _cancelled: &dyn Fn() -> bool) -> Result<DispatchResult, DriverError>;
        fn fronting_snapshot(_target: &ProcessGrant) -> Result<FrontingSnapshot, DriverError>;
        fn observe_input(_request: InputObservationRequest) -> Result<InputObservationResult, DriverError>;
    );
}

pub struct LinuxCaptureBackend;

impl CaptureBackend for LinuxCaptureBackend {
    fn platform_support(&self) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn screen_recording_liveness(&self) -> PermissionLiveness {
        PermissionLiveness::Unresolved
    }

    unsupported!(BackendError::UnsupportedOnPlatform;
        fn enumerate_windows(_target: &ProcessGrant) -> Result<Vec<EnumeratedWindow>, BackendError>;
        fn poll_window_change(_target: &ProcessGrant) -> Result<Option<WindowChange>, BackendError>;
        fn capture_window(_request: &WindowCaptureRequest) -> Result<WindowCaptureFrame, BackendError>;
        fn capture_display(_request: &BroadDisplayCaptureRequest) -> Result<CaptureArtifact, BackendError>;
        fn begin_teardown() -> Result<BackendTeardownProgress, BackendError>;
        fn poll_teardown(_elapsed_ms: u64) -> Result<BackendTeardownProgress, BackendError>;
    );
}

#[cfg(test)]
#[path = "linux_semantic_tests.rs"]
mod semantic_tests;

#[cfg(test)]
#[path = "linux_launch_tests.rs"]
mod launch_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use cerebellum_computer::platform::vocabulary::validate_capability_result;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use subc_protocol::{Frame, FrameType};

    #[test]
    fn linux_identity_reader_binds_exactly_with_k1() {
        let bound = compiled_reviews().bound(LinuxReleaseInputs::IDENTITY);
        assert_eq!(
            crate::management::PlatformResolver::HAS_APP_IDENTITY_READER,
            bound
        );
        let driver = LinuxDriver {
            session: Arc::new(LinuxSession::new(false, Arc::default())),
            resolved: None,
        };
        let placeholder = ProcessGrant {
            pid: 0,
            bundle_identity: "dpkg:fixture".into(),
            process_generation_evidence: "fixture".into(),
        };
        assert_eq!(
            driver.prove_app(placeholder.pid),
            Err(IdentityRefusal::AppIdentityUnproven)
        );
        assert_eq!(
            driver.app_code(&placeholder).identity().unwrap_err(),
            crate::computer_grants::AppIdentityUnreadable::NoReader
        );
    }

    fn read_with(
        kind: SessionKind,
        id: &str,
        a11y_id: &str,
        permissions: PermissionLivenessReport,
    ) -> SessionReading {
        SessionReading {
            desktop: DesktopSession {
                id: id.into(),
                kind,
                locked: false,
                environment: Default::default(),
                accessibility: Some(AccessibilityBus {
                    address: "fixture-bus".into(),
                    id: a11y_id.into(),
                }),
            },
            x11_connection: Some(1),
            permissions,
        }
    }

    #[tokio::test]
    async fn latch_remembers_only_the_current_epoch_and_rereads_the_lock() {
        use std::collections::VecDeque;
        let kind = SessionKind::Wayland;
        let unresolved = PermissionLivenessReport::default();
        let live = permissions::live_for_test();
        let first = read_with(kind, "1", "bus-one", unresolved.clone());
        let mut same = read_with(kind, "1", "bus-one", live.clone());
        same.desktop.locked = true;
        same.x11_connection = Some(31); // Xwayland has no X11 epoch component.
        let replaced_bus = read_with(kind, "1", "bus-two", live.clone());
        let replaced_session = read_with(SessionKind::X11, "2", "bus-two", unresolved);
        let mut reconnected_x11 = read_with(SessionKind::X11, "2", "bus-two", live);
        reconnected_x11.x11_connection = Some(2);
        let readings = std::sync::Mutex::new(VecDeque::from([
            Err(session::NoSupportedSession),
            Ok(first),
            Ok(same),
            Ok(replaced_bus),
            Ok(replaced_session),
            Ok(reconnected_x11),
            Err(session::NoSupportedSession),
        ]));
        let mut session = LinuxSession::new(true, Arc::default());
        session.read = Box::new(move || {
            Box::pin(std::future::ready(
                readings.lock().unwrap().pop_front().unwrap(),
            ))
        });
        assert!(matches!(
            session.refresh().await,
            Err(LinuxRefusal::NoSupportedSession)
        ));
        let (first, unlocked) = session.refresh().await.unwrap();
        assert!(!unlocked);
        let (same, locked) = session.refresh().await.unwrap();
        assert!(locked);
        assert!(Arc::ptr_eq(&first, &same));
        assert_eq!(
            same.permissions.state(PermissionService::Accessibility),
            PermissionLiveness::Unresolved
        );
        let (replaced_bus, _) = session.refresh().await.unwrap();
        assert!(!Arc::ptr_eq(&first, &replaced_bus));
        assert_eq!(
            replaced_bus
                .permissions
                .state(PermissionService::Accessibility),
            PermissionLiveness::Live
        );
        let (replaced_session, _) = session.refresh().await.unwrap();
        assert!(!Arc::ptr_eq(&replaced_bus, &replaced_session));
        let (reconnected, _) = session.refresh().await.unwrap();
        assert!(!Arc::ptr_eq(&replaced_session, &reconnected));
        assert!(matches!(
            session.refresh().await,
            Err(LinuxRefusal::NoSupportedSession)
        ));
        assert!(session.epoch.lock().await.is_none());
    }

    pub(super) fn bind_fixture(planes: &crate::Planes) {
        planes.routes.insert(7, 1, crate::AcceptedBindFacts::from_bind(
            &subc_protocol::BindIdentity::new("test", "session".to_string()),
            crate::session_caller_principal_for_test(),
            Some(&json!({"agentProjectId":"test-project", "sessionKind":"primary", "effectiveCapabilityScope":["*"]})),
            Some(&["elicitation".to_string()]),
            &subc_protocol::RouteTarget::ToolProvider { module_id: "cerebellum".into() },
        ));
    }

    pub(super) fn request(corr: u64, name: &str, arguments: Value) -> Frame {
        Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, true),
            7,
            1,
            corr,
            serde_json::to_vec(&json!({"name":name, "arguments":arguments})).unwrap(),
        )
        .unwrap()
    }

    fn planes_with(session: LinuxSession) -> crate::Planes {
        let mut planes = crate::Planes::with_browser_config_journaling(
            Arc::default(),
            None,
            JournalPersistence::Isolated,
        );
        planes.computer_admitted = Arc::clone(&session.admitted);
        let audit = computer_audit(JournalPersistence::Isolated).unwrap();
        let refusing_plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
            audit,
            ResultSchemaEnforcement::Withhold,
            || panic!("early refusal reached the dispatch driver"),
        );
        planes.computer = Ok(Arc::new(ComputerPlane {
            linux_session: Some(Arc::new(session)),
            ..refusing_plane
        }));
        bind_fixture(&planes);
        planes
    }

    #[tokio::test]
    async fn arrival_and_serve_apply_linux_refusal_order_before_permissions() {
        for (admitted, kind, capability, missing, reason) in [
            (
                true,
                SessionKind::Wayland,
                "type",
                true,
                "no_supported_session",
            ),
            (
                false,
                SessionKind::Wayland,
                "type",
                false,
                "route_not_reviewed",
            ),
            (
                true,
                SessionKind::Wayland,
                "type",
                false,
                "wayland_seat_input_unverifiable",
            ),
            (
                false,
                SessionKind::X11,
                "press_point",
                true,
                "no_supported_session",
            ),
            (
                false,
                SessionKind::X11,
                "press_point",
                false,
                "point_hit_test_unsupported",
            ),
            (true, SessionKind::X11, "type", false, "permission_missing"),
        ] {
            let name = format!("computer.{capability}");
            let names = if admitted {
                BTreeSet::from([name.clone()])
            } else {
                BTreeSet::new()
            };
            let mut session = LinuxSession::new(true, Arc::new(names));
            let queries = Arc::new(AtomicUsize::new(0));
            let probe_count = Arc::clone(&queries);
            session.read = Box::new(move || {
                probe_count.fetch_add(1, Ordering::Relaxed);
                Box::pin(std::future::ready(if missing {
                    Err(session::NoSupportedSession)
                } else {
                    Ok(read_with(
                        kind,
                        "fixture",
                        "bus",
                        PermissionLivenessReport::default(),
                    ))
                }))
            });
            let planes = planes_with(session);
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            let arguments = if capability == "type" {
                json!({"target":"fixture","text":"x"})
            } else {
                json!({"image_id":"previous-image","x":1,"y":1})
            };
            crate::handle_frame(request(42, &name, arguments), &tx, &planes)
                .await
                .unwrap();
            let response = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
                .await
                .unwrap()
                .unwrap();
            let reply: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(response.header.ty, FrameType::Response, "{reply}");
            if reason == "permission_missing" {
                assert_eq!(reply["outcome"], reason);
                assert!(reply["remedy"]
                    .as_str()
                    .unwrap()
                    .contains("Linux desktop session"));
            } else {
                assert_eq!(reply["reason"], reason, "{reply}");
            }
            validate_capability_result(&name, &reply).unwrap();
            assert_eq!(
                queries.load(Ordering::Relaxed),
                2,
                "arrival and serve each check, without constructing a dispatch driver"
            );
        }
    }

    #[tokio::test]
    async fn a_stalled_arrival_cannot_wedge_the_frame_reader() {
        let mut session =
            LinuxSession::new(true, Arc::new(BTreeSet::from(["computer.type".into()])));
        let queries = Arc::new(AtomicUsize::new(0));
        let probe_count = Arc::clone(&queries);
        session.read = Box::new(move || {
            probe_count.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::pending())
        });
        let planes = planes_with(session);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let next_frame = async {
            crate::handle_frame(
                request(42, "computer.type", json!({"target":"fixture","text":"x"})),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            crate::handle_frame(
                request(43, "browser_use", json!({"action":"status"})),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            let other = rx.recv().await.unwrap();
            assert_eq!(
                other.header.corr, 43,
                "browser route need not wait for serve's session timeout"
            );
        };
        tokio::time::timeout(crate::test_support::HANG_GUARD, next_frame)
            .await
            .unwrap();
        let refusal = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
            .await
            .unwrap()
            .unwrap();
        let reply: Value = serde_json::from_slice(&refusal.body).unwrap();
        assert_eq!(refusal.header.corr, 42);
        assert_eq!(reply["reason"], "no_supported_session");
        assert_eq!(queries.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn unbound_linux_build_refuses_direct_rows_and_empty_sets_disable_flat_tool() {
        let mut inputs = ComputerReleaseInputs {
            app_state_review_revision: Some("non-linux-review".into()),
            element_addressed_review_revision: Some("non-linux-review".into()),
            takeover_dispatch_review_revision: Some("non-linux-review".into()),
            ..Default::default()
        };
        let mut planes = crate::Planes::with_browser_config_journaling(
            Arc::default(),
            None,
            JournalPersistence::Isolated,
        );
        bind_fixture(&planes);
        planes.computer_admitted = Arc::default();
        planes.computer = plane(
            &inputs,
            Arc::clone(&planes.computer_admitted),
            JournalPersistence::Isolated,
        );
        assert!(matches!(
            planes.computer,
            Err(ComputerPlaneUnavailable::NoLinuxReviews)
        ));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        for (index, row) in ComputerCapability::ALL.into_iter().enumerate() {
            let frame = request(
                100 + index as u64,
                row.capability_id(),
                json!({
                    "target": "fixture", "element_id": "old1", "image_id": "old-image"
                }),
            );
            crate::handle_frame(frame, &tx, &planes).await.unwrap();
            let refusal = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(refusal.header.ty, FrameType::Error);
            let body = String::from_utf8_lossy(&refusal.body);
            assert!(
                body.contains("capability_not_admitted"),
                "{}: {body}",
                row.capability_id()
            );
        }

        inputs.linux.app_identity = Some("identity-review".into());
        for (index, capture) in [None, Some("capture-review".into())]
            .into_iter()
            .enumerate()
        {
            inputs.linux.x11_capture = capture;
            planes.computer = plane(
                &inputs,
                Arc::clone(&planes.computer_admitted),
                JournalPersistence::Isolated,
            );
            assert!(
                planes.computer.is_ok(),
                "a bound review builds the plane, not a tool"
            );
            crate::handle_frame(
                request(
                    200 + index as u64,
                    "computer_use",
                    json!({"action":"list_apps"}),
                ),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            let refusal = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(refusal.header.ty, FrameType::Error);
            let body = String::from_utf8_lossy(&refusal.body);
            assert!(body.contains("tool_disabled"), "{body}");
        }
    }
}
