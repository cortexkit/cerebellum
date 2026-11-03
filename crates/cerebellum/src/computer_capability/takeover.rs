//! The takeover actions: clicking, moving, dragging and scrolling with the one real
//! pointer the person at the machine also uses.
//!
//! Every one of them needs the conversation's takeover grant, because the
//! pointer is shared by every application on the screen and by the person. The
//! grant is asked for through the same blocking question as any other grant.
//!
//! The application an action is contained to, its containment target, is
//! decided here and nowhere else:
//!
//! * a move acts in the application under its destination point;
//! * a drag acts in the application under its starting point, and is refused
//!   before anything is posted when its end lies in a different application;
//! * a scroll carries no point at all. The wheel event goes wherever the
//!   pointer already is, so it is contained to the application its request
//!   names and needs no app grant: it is the one takeover action that does
//!   not.
//!
//! A move, click or drag also needs the app grant of the application under the
//! pointer. That grant is checked, never asked for: the question belongs to a
//! call that names the application, and `read_state` on it asks.
//!
//! The admitted pointer-fronting path (admitted only when its release review key
//! is bound) temporarily fronts the target application. For image actions, the
//! request's image_id identifies a window image returned by read_state, and the
//! target is that window's owning app. Exact-window containment is checked before
//! every image-addressed post; scroll uses its named target. Builds
//! without that review retain frontmost-only move, drag and scroll, with no
//! click action. Both paths check generation and focus at each post.

use std::sync::Arc;

use cerebellum_computer::app_state::session::RegisteredImage;
use cerebellum_computer::app_state::source::{AppStateSource, HitScope};
use cerebellum_computer::audit::ComputerCapability;
use cerebellum_computer::dispatch::post_condition::PostCondition;
use cerebellum_computer::dispatch::{
    AttendanceContext, DispatchError, DispatchRequest, Dispatcher, ExpectedPostCondition,
    FrozenDispatchRow, IdleGateRefusal,
};
use cerebellum_computer::platform::{
    AccessibilityElementName, DispatchMode, HeldStateDisposition, PlatformDriver, ProcessGrant,
    SyntheticAction, SyntheticPoint, SyntheticScrollAxis, SyntheticScrollUnit,
};
use cerebellum_core::clock::MonotonicClock;
use cerebellum_core::consent::OnceDispatchToken;
use cerebellum_core::journal::{JournalIdentity, JournalStorage, Redactor, SeverityTaxonomy};
use serde_json::{json, Value};

use crate::computer_grants::{ConsentRefusal, GrantCaller};
use crate::management::ManagementPlane;
use crate::CancelHandle;

/// Every field `computer.takeover_move` accepts; all are required.
pub(crate) const MOVE_FIELDS: [&str; 2] = ["image_id", "to"];
pub(crate) const CLICK_FIELDS: [&str; 3] = ["image_id", "x", "y"];
/// Every field `computer.takeover_drag` accepts; all are required.
pub(crate) const DRAG_FIELDS: [&str; 3] = ["image_id", "from", "to"];
/// Every field `computer.takeover_scroll` accepts; all are required.
pub(crate) const SCROLL_FIELDS: [&str; 3] = ["target", "axis", "amount_lines"];

/// The most lines one scroll may turn, either way, as the request schema
/// bounds it.
const MAX_SCROLL_LINES: i64 = 100;

pub(crate) fn request_fields(capability: ComputerCapability) -> Option<&'static [&'static str]> {
    match capability {
        ComputerCapability::TakeoverMove => Some(&MOVE_FIELDS),
        ComputerCapability::TakeoverClick => Some(&CLICK_FIELDS),
        ComputerCapability::TakeoverDrag => Some(&DRAG_FIELDS),
        ComputerCapability::TakeoverScroll => Some(&SCROLL_FIELDS),
        _ => None,
    }
}

/// A takeover request as parsed, before anything is resolved.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TakeoverRequest {
    Click {
        image_id: String,
        point: (u64, u64),
    },
    Move {
        image_id: String,
        to: (u64, u64),
    },
    Drag {
        image_id: String,
        from: (u64, u64),
        to: (u64, u64),
    },
    Scroll {
        target: String,
        axis: SyntheticScrollAxis,
        lines: i32,
    },
}

fn invalid(field: &str, reason: &str) -> Value {
    json!({"outcome": "invalid_request", "field": field, "reason": reason})
}

fn required_string(object: &serde_json::Map<String, Value>, field: &str) -> Result<String, Value> {
    match object.get(field) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(Value::String(_)) => Err(invalid(field, "empty_value")),
        Some(_) => Err(invalid(field, "wrong_type")),
        None => Err(invalid(field, "missing_field")),
    }
}

/// A point in an image's pixel space: exactly `x` and `y`, both whole and
/// not negative.
fn required_point(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(u64, u64), Value> {
    let point = match object.get(field) {
        Some(Value::Object(point)) => point,
        Some(_) => return Err(invalid(field, "wrong_type")),
        None => return Err(invalid(field, "missing_field")),
    };
    if point.keys().any(|key| key != "x" && key != "y") {
        return Err(invalid(field, "unknown_field"));
    }
    match (
        point.get("x").and_then(Value::as_u64),
        point.get("y").and_then(Value::as_u64),
    ) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(invalid(field, "wrong_type")),
    }
}

pub(crate) fn parse_request(
    capability: ComputerCapability,
    arguments: &Value,
) -> Result<TakeoverRequest, Value> {
    let Some(fields) = request_fields(capability) else {
        return Err(json!({"outcome": "invalid_request"}));
    };
    let Some(object) = arguments.as_object() else {
        return Err(invalid("$", "wrong_type"));
    };
    if let Some(field) = object
        .keys()
        .filter(|field| !fields.contains(&field.as_str()))
        .min()
    {
        return Err(invalid(field, "unknown_field"));
    }
    match capability {
        ComputerCapability::TakeoverClick => {
            let coordinate = |field: &str| {
                object
                    .get(field)
                    .ok_or_else(|| invalid(field, "missing_field"))?
                    .as_u64()
                    .ok_or_else(|| invalid(field, "wrong_type"))
            };
            Ok(TakeoverRequest::Click {
                image_id: required_string(object, "image_id")?,
                point: (coordinate("x")?, coordinate("y")?),
            })
        }
        ComputerCapability::TakeoverMove => Ok(TakeoverRequest::Move {
            image_id: required_string(object, "image_id")?,
            to: required_point(object, "to")?,
        }),
        ComputerCapability::TakeoverDrag => Ok(TakeoverRequest::Drag {
            image_id: required_string(object, "image_id")?,
            from: required_point(object, "from")?,
            to: required_point(object, "to")?,
        }),
        _ => {
            let target = required_string(object, "target")?;
            let axis = match object.get("axis") {
                Some(Value::String(axis)) if axis == "vertical" => SyntheticScrollAxis::Vertical,
                Some(Value::String(axis)) if axis == "horizontal" => {
                    SyntheticScrollAxis::Horizontal
                }
                Some(Value::String(_)) => return Err(invalid("axis", "unknown_value")),
                Some(_) => return Err(invalid("axis", "wrong_type")),
                None => return Err(invalid("axis", "missing_field")),
            };
            let lines = match object.get("amount_lines") {
                Some(value) => value
                    .as_i64()
                    .ok_or_else(|| invalid("amount_lines", "wrong_type"))?,
                None => return Err(invalid("amount_lines", "missing_field")),
            };
            if !(-MAX_SCROLL_LINES..=MAX_SCROLL_LINES).contains(&lines) {
                return Err(invalid("amount_lines", "out_of_range"));
            }
            // A scroll of nothing posts an event that moves nothing, and
            // answering `completed` for it would report an action that never
            // happened.
            if lines == 0 {
                return Err(invalid("amount_lines", "empty_value"));
            }
            Ok(TakeoverRequest::Scroll {
                target,
                axis,
                lines: lines as i32,
            })
        }
    }
}

fn image_unknown() -> Value {
    json!({
        "outcome": "image_reference_unknown",
        "remedy": "this image_id names no image this conversation holds for a running \
                   application; call read_state with include_image and use that image",
    })
}

/// Why a takeover action does not act in an application that is not in
/// front. Shared by the refusal decided here and the one the dispatch path
/// returns when the front changes between posts.
const NOT_FRONTMOST_REMEDY: &str =
    "the application the pointer would act in is not frontmost, and a takeover action never \
     brings one forward, so nothing more was posted; ask the person to bring it to the front, \
     or use press_point, which needs no pointer";

fn nothing_identifiable_at_point() -> Value {
    json!({
        "outcome": "target_not_frontmost",
        "reason": "no_application_at_point",
        "remedy": "no application could be identified under that point, so nothing was \
                   posted; read the state again and choose a point inside a window",
    })
}

fn out_of_bounds(image: &RegisteredImage) -> Value {
    json!({
        "outcome": "point_out_of_bounds",
        "remedy": format!(
            "every point must lie inside the image, which is {} by {} pixels",
            image.width_px, image.height_px
        ),
    })
}

fn inside(image: &RegisteredImage, (x, y): (u64, u64)) -> bool {
    x < u64::from(image.width_px) && y < u64::from(image.height_px)
}

fn desktop(image: &RegisteredImage, (x, y): (u64, u64)) -> SyntheticPoint {
    let (x, y) = image.mapping.pixel_to_desktop(x as f64, y as f64);
    SyntheticPoint { x, y }
}

fn image_grant(image: &RegisteredImage) -> ProcessGrant {
    ProcessGrant {
        pid: image.pid,
        bundle_identity: image.bundle_identity.clone(),
        process_generation_evidence: image.process_generation.clone(),
    }
}

/// The application under a desktop point, identified by its process.
///
/// Asked of the image's own application first: an element of it at the
/// point settles the question without reading anything else. Otherwise the
/// system-wide hit test names whichever process owns what is on top there,
/// and that process is identified by its start time so a later process given
/// the same pid is not mistaken for it.
fn application_under(
    source: &dyn AppStateSource,
    management: &ManagementPlane,
    image: &RegisteredImage,
    point: SyntheticPoint,
) -> Result<ProcessGrant, Value> {
    let at = (point.x, point.y);
    if let Ok(Some((_, owner))) = source.element_at(HitScope::Application { pid: image.pid }, at) {
        if owner.is_none_or(|owner| owner == image.pid) {
            return Ok(image_grant(image));
        }
    }
    let owner = match source.element_at(HitScope::SystemWide, at) {
        Ok(Some((_, Some(owner)))) => owner,
        _ => return Err(nothing_identifiable_at_point()),
    };
    if owner == image.pid {
        return Ok(image_grant(image));
    }
    management
        .process_for_pid(owner)
        .ok_or_else(nothing_identifiable_at_point)
}

/// Refuse, without asking anyone, when the application the pointer would
/// act in holds no app grant in this conversation.
///
/// Not asked here because this call never named that application: it named
/// an image and a point. The question is raised by `read_state` on the
/// application, which the remedy names.
fn require_app_grant(
    management: &ManagementPlane,
    executable: &super::ExecutableReader,
    caller: &GrantCaller,
    grant: &ProcessGrant,
) -> Result<(), Value> {
    // A development build its driver may use counts as holding an "always"
    // app grant; the takeover grant is still required separately.
    if super::operator_apps::admits_development_build(management, caller, executable, grant) {
        return Ok(());
    }
    let need = management.app_need(&grant.bundle_identity, grant, grant.bundle_identity.clone());
    if management.computer_grants().holds(caller, &need) {
        return Ok(());
    }
    Err(json!({
        "outcome": "app_grant_required",
        "bundle_identity": grant.bundle_identity,
        "remedy": format!(
            "the pointer would act in {bundle}, which this conversation holds no app grant \
             for, so nothing was posted and nobody was asked. Call read_state with target \
             {bundle}, which asks the person, then retry",
            bundle = grant.bundle_identity
        ),
    }))
}

/// A dispatch refusal in the reply vocabulary the takeover rows declare.
///
/// The rows name the refusals a caller acts on differently: the person is
/// using the machine, the person took the pointer back, the target is not in
/// front, the call was cancelled. Every other dispatch error is the module
/// failing to carry out a correct request, and answers `dispatch_failed` with
/// the error's own code in `reason`, never `invalid_request`, which would send
/// the caller to change a request that was right.
fn refusal_reply(refusal: &DispatchError) -> Value {
    match refusal {
        DispatchError::Cancelled { .. } | DispatchError::DispatchStopped => {
            super::synthetic_dispatch_refusal(refusal)
        }
        DispatchError::IdleGateRefused(IdleGateRefusal::BelowThreshold {
            threshold_ms,
            user_idle_ms,
            ..
        }) => json!({
            "outcome": "not_idle",
            "remedy": format!(
                "the person used the mouse or keyboard {user_idle_ms} ms ago, and the pointer \
                 is taken only after {threshold_ms} ms without input, so nothing was posted; \
                 retry once they have stepped away"
            ),
        }),
        DispatchError::IdleGateRefused(IdleGateRefusal::Unreadable(_)) => json!({
            "outcome": "idle_unreadable",
            "remedy": "how long the machine has been idle could not be read, so whether the \
                       person is using it is unknown and nothing was posted",
        }),
        // Not an idle reading: the error means the watch for the person's own
        // input was not shown to be live (its heartbeat was missed), or the
        // row's posts could not be paced inside the seize bound. Either way
        // the module could not carry the action out safely.
        DispatchError::ObserverUnavailable => json!({
            "outcome": "dispatch_failed",
            "reason": "observer_unavailable",
            "remedy": "the watch for the person's own input could not be shown to be live, so \
                       the pointer was not taken and nothing more was posted; the request was \
                       not at fault, so retry it unchanged, and report it if it persists",
        }),
        DispatchError::UserSeizedControl { .. } => json!({
            "outcome": "user_seized_control",
            "remedy": "the person used the mouse or keyboard, so the action stopped at once \
                       and any button it held was let go; ask them before trying again",
        }),
        DispatchError::SeizeLatencyBoundExceeded => json!({
            "outcome": "seize_latency_bound_exceeded",
            "remedy": "the posts could not be paced so that the person's own input would stop \
                       them in time, so nothing more was posted",
        }),
        DispatchError::TargetFocusMismatch => json!({
            "outcome": "target_not_frontmost",
            "reason": "target_focus_mismatch",
            "remedy": NOT_FRONTMOST_REMEDY,
        }),
        DispatchError::AuditUnavailable => json!({
            "outcome": "audit_unavailable",
            "remedy": "the action's journal record could not be written; read the state to \
                       see whether anything happened before acting again",
        }),
        other => json!({
            "outcome": "dispatch_failed",
            "reason": other.reason_code(),
            "remedy": "the module could not carry out the pointer action; the request was not \
                       at fault, so do not change it. Read the state to see whether anything \
                       happened before retrying, and report it if it persists",
        }),
    }
}

fn cancelled_before_posting() -> Value {
    super::synthetic_dispatch_refusal(&DispatchError::Cancelled {
        posts_returned: 0,
        held_state: HeldStateDisposition::NoneHeld,
    })
}

impl<B, R, T, S, D> super::ComputerPlane<B, R, T, S, D>
where
    B: cerebellum_computer::capture::CaptureBackend + Send + 'static,
    R: Redactor + Send + 'static,
    T: SeverityTaxonomy + Send + 'static,
    S: JournalStorage + Send + 'static,
    D: PlatformDriver + 'static,
{
    /// Serve one takeover action: find its containment target, hold the
    /// takeover grant, and post under the observed-mode gates.
    pub(super) async fn serve_takeover<C: MonotonicClock>(
        &self,
        capability: ComputerCapability,
        arguments: &Value,
        context: super::ServeContext<'_, C>,
    ) -> Value {
        if self.takeover_pointer_fronting_admitted
            && matches!(
                capability,
                ComputerCapability::TakeoverClick | ComputerCapability::TakeoverDrag
            )
            && !cerebellum_computer::platform::DOWN_GESTURE_RECOVERY_MEASURED
            && !{
                #[cfg(test)]
                {
                    self.down_gesture_recovery_measured
                }
                #[cfg(not(test))]
                {
                    false
                }
            }
        {
            return invalid("action", "unknown_value");
        }
        if capability == ComputerCapability::TakeoverClick
            && !self.takeover_pointer_fronting_admitted
        {
            return invalid("action", "unknown_value");
        }
        let mut request = match parse_request(capability, arguments) {
            Ok(request) => request,
            Err(refusal) => return refusal,
        };
        // A scroll's target may be the application's name; it is resolved
        // to a bundle identity once, before anything is placed or asked.
        if let TakeoverRequest::Scroll { target, .. } = &mut request {
            *target = match self.resolve_target_name(target).await {
                Ok(bundle_identity) => bundle_identity,
                Err(refusal) => return refusal,
            };
        }
        let super::ServeContext {
            cancel,
            grantee,
            identity,
            management,
            consent,
            clock,
            now_ms: _,
        } = context;

        let (mut target, mut action, mut scroll_window) = match self
            .place(
                management,
                &identity.conversation_key,
                &consent.caller,
                &request,
            )
            .await
        {
            Ok(placed) => placed,
            Err(refusal) => return self.placement_refused(grantee, &request, refusal).await,
        };
        let takeover = match management
            .computer_grants()
            .require_takeover_dispatch(&consent, &cancel)
            .await
        {
            Ok(takeover) => takeover,
            Err(ConsentRefusal::Cancelled) => return cancelled_before_posting(),
            Err(refusal) => return refusal.reply(None),
        };
        // Before placing again: a hit test on a locked screen finds nothing,
        // which would be reported as nothing at the point.
        if let Some(locked) =
            self.locked_after_wait(takeover.admission().waited, takeover.admission())
        {
            return locked;
        }
        if takeover.admission().waited {
            // The person may have taken a while to answer, and windows,
            // processes and grants may have moved meanwhile: find the target
            // again rather than acting on what was true before the question.
            match self
                .place(
                    management,
                    &identity.conversation_key,
                    &consent.caller,
                    &request,
                )
                .await
            {
                Ok((placed_target, placed_action, placed_window)) => {
                    target = placed_target;
                    action = placed_action;
                    scroll_window = placed_window;
                }
                Err(refusal) => return self.placement_refused(grantee, &request, refusal).await,
            }
        }
        let admission = takeover.admission().clone();
        let work = super::quarantine::CallWork::current();
        if let Some(mut busy) = work.bind(&self.serializer.quarantine, &target) {
            admission.decorate(&mut busy);
            return busy;
        }
        if let Err(mut unconfirmed) = self
            .confirm_held_input_released(capability.capability_id(), management, &work)
            .await
        {
            admission.decorate(&mut unconfirmed);
            return unconfirmed;
        }
        let mut reply = self
            .dispatch_takeover(
                capability,
                action,
                target,
                takeover.into_token(),
                identity,
                grantee,
                cancel,
                clock,
                management,
                &request,
                scroll_window,
            )
            .await;
        admission.decorate(&mut reply);
        reply
    }

    /// A placement's refusal, recorded in the refusal ring when it refused
    /// an application no agent may use, addressed as the request named it.
    async fn placement_refused(
        &self,
        grantee: &str,
        request: &TakeoverRequest,
        refusal: Value,
    ) -> Value {
        if !super::operator_apps::is_refusal(&refusal) {
            return refusal;
        }
        let claimed = match request {
            TakeoverRequest::Move { image_id, .. }
            | TakeoverRequest::Click { image_id, .. }
            | TakeoverRequest::Drag { image_id, .. } => image_id,
            TakeoverRequest::Scroll { target, .. } => target,
        };
        self.operator_app_refused(grantee, claimed).await;
        refusal
    }

    fn pointer_guard(
        &self,
        management: &Arc<ManagementPlane>,
        conversation_key: &str,
        request: &TakeoverRequest,
        target: &ProcessGrant,
        scroll_window: Option<u32>,
    ) -> cerebellum_computer::platform::GlobalPointerGuard {
        let (image_id, points) = match request {
            TakeoverRequest::Move { image_id, to } => (image_id.clone(), vec![*to]),
            TakeoverRequest::Click { image_id, point } => (image_id.clone(), vec![*point]),
            TakeoverRequest::Drag { image_id, from, to } => (image_id.clone(), vec![*from, *to]),
            TakeoverRequest::Scroll { .. } => {
                let source = Arc::clone(&self.app_state_source);
                let target = target.clone();
                return cerebellum_computer::platform::GlobalPointerGuard(Arc::new(
                    move |deadline| {
                        let window = scroll_window.ok_or("scroll target window unavailable")?;
                        let point = source
                            .cursor_position()
                            .ok_or("scroll real cursor location unavailable")?;
                        cerebellum_computer::app_state::pointer_sensitivity::pointer_target_check_until(
                        source.as_ref(),
                        &target,
                        point,
                        window,
                        deadline,
                    )
                    },
                ));
            }
        };
        let management = Arc::clone(management);
        let source = Arc::clone(&self.app_state_source);
        let conversation_key = conversation_key.to_owned();
        cerebellum_computer::platform::GlobalPointerGuard(Arc::new(move |deadline| {
            let Some(image) = management
                .app_state_sessions()
                .resolve_image(&conversation_key, &image_id)
            else {
                return Err("pointer image unavailable");
            };
            let Some(window) = management
                .app_state_sessions()
                .image_window(&conversation_key, &image_id)
            else {
                return Err("pointer image window unavailable");
            };
            points.iter().try_for_each(|point| {
                let point = desktop(&image, *point);
                cerebellum_computer::app_state::pointer_sensitivity::pointer_target_check_until(
                    source.as_ref(),
                    &image_grant(&image),
                    (point.x, point.y),
                    window,
                    deadline,
                )?;
                if application_under(source.as_ref(), &management, &image, point).is_ok_and(
                    |owner| {
                        owner.pid == image.pid
                            && owner.process_generation_evidence == image.process_generation
                    },
                ) {
                    Ok(())
                } else {
                    Err("pointer target application changed")
                }
            })
        }))
    }

    /// The containment target of a request and the pointer action to post.
    async fn place(
        &self,
        management: &Arc<ManagementPlane>,
        conversation_key: &str,
        caller: &GrantCaller,
        request: &TakeoverRequest,
    ) -> Result<(ProcessGrant, SyntheticAction, Option<u32>), Value> {
        let (image_id, points) = match request {
            TakeoverRequest::Click { image_id, point } => (image_id, vec![*point]),
            TakeoverRequest::Scroll {
                target,
                axis,
                lines,
            } => {
                let grant = management.resolve_process(target)?;
                let mut scroll_window = None;
                if self.takeover_pointer_fronting_admitted {
                    let source = Arc::clone(&self.app_state_source);
                    let target = grant.clone();
                    scroll_window = Some(tokio::task::spawn_blocking(move || {
                        let focused = source.focused_window(&target).ok().flatten().ok_or("scroll target window unavailable")?;
                        let window = source.element_window_number(&focused.handle).ok_or("scroll target window number unavailable")?;
                        let point = source.cursor_position().ok_or("scroll real cursor location unavailable")?;
                        cerebellum_computer::app_state::pointer_sensitivity::pointer_target_check(source.as_ref(), &target, point, window)?;
                        Ok::<_, &'static str>(window)
                    }).await.unwrap_or(Err("scroll cursor placement worker failed")).map_err(|step| {
                        let mut refusal = nothing_identifiable_at_point();
                        refusal["remedy"] = json!(format!("{step}; nothing was posted"));
                        refusal
                    })?);
                }
                return Ok((
                    grant,
                    SyntheticAction::scroll_along(*axis, SyntheticScrollUnit::Line, *lines),
                    scroll_window,
                ));
            }
            TakeoverRequest::Move { image_id, to } => (image_id, vec![*to]),
            TakeoverRequest::Drag { image_id, from, to } => (image_id, vec![*from, *to]),
        };

        let image = management
            .app_state_sessions()
            .resolve_image(conversation_key, image_id)
            .ok_or_else(image_unknown)?;
        if points.iter().any(|point| !inside(&image, *point)) {
            return Err(out_of_bounds(&image));
        }
        // An image of a process that has since exited or restarted maps its
        // pixels onto windows that are gone.
        match management.resolve_process(&image.bundle_identity) {
            Ok(current)
                if current.pid == image.pid
                    && current.process_generation_evidence == image.process_generation => {}
            _ => return Err(image_unknown()),
        }

        let window_number = management
            .app_state_sessions()
            .image_window(conversation_key, image_id);
        let desktop_points: Vec<SyntheticPoint> =
            points.iter().map(|point| desktop(&image, *point)).collect();
        if self.takeover_pointer_fronting_admitted {
            // A covered image is admitted by its own process identity, not
            // by the covering window. Exact containment is checked after the
            // front and before every post, including the paired release.
            let grant = image_grant(&image);
            if let Some(refusal) = self
                .operator_lookup(management, caller)
                .process_refusal(&grant, Vec::new())
            {
                return Err(refusal);
            }
            require_app_grant(management, &self.process_executable, caller, &grant)?;
            if window_number.is_none() {
                return Err(nothing_identifiable_at_point());
            }
            let source = Arc::clone(&self.app_state_source);
            let check_grant = grant.clone();
            let check_points = desktop_points.clone();
            let window = window_number.unwrap();
            if !tokio::task::spawn_blocking(move || {
                check_points.iter().all(|point| {
                    cerebellum_computer::app_state::pointer_sensitivity::pointer_target_safe(
                        source.as_ref(),
                        &check_grant,
                        (point.x, point.y),
                        window,
                    )
                })
            })
            .await
            .unwrap_or(false)
            {
                return Err(nothing_identifiable_at_point());
            }
            let action = match request {
                TakeoverRequest::Click { .. } => SyntheticAction::ClickPointer {
                    point: desktop_points[0],
                },
                TakeoverRequest::Drag { .. } => {
                    SyntheticAction::drag_pointer(desktop_points[0], desktop_points[1])
                }
                _ => SyntheticAction::move_pointer(desktop_points[0]),
            };
            return Ok((grant, action, None));
        }
        let source = self.app_state_source.clone();
        let hit_management = Arc::clone(management);
        let hit_image = image.clone();
        let hit_points = desktop_points.clone();
        let lookup = self.operator_lookup(management, caller);
        let placed = tokio::task::spawn_blocking(move || {
            // The real pointer reaches whichever window is on top at a point,
            // which may be another window than the image shows, of this
            // application or another. Every point must land on the imaged
            // window itself, positively identified; otherwise nothing is
            // posted, whatever is there and whatever grant it holds.
            let on_imaged_window = window_number.is_some()
                && hit_points
                    .iter()
                    .all(|point| source.topmost_window_at((point.x, point.y)) == window_number);
            on_imaged_window.then(|| {
                hit_points
                    .iter()
                    .map(|point| {
                        // The pointer lands in whichever application is
                        // under the point, so that application is refused
                        // here if no agent may use it, before its grant is
                        // looked up.
                        application_under(source.as_ref(), &hit_management, &hit_image, *point)
                            .and_then(|owner| {
                                if let Some(refusal) = lookup.process_refusal(&owner, Vec::new()) {
                                    Err(refusal)
                                } else {
                                    Ok(owner)
                                }
                            })
                    })
                    .collect::<Vec<_>>()
            })
        })
        .await;
        let owners = match placed {
            Ok(Some(owners)) => owners,
            Ok(None) => {
                return Err(super::element_actions::point_in_another_window_reply(
                    &management.application_name(&image_grant(&image)),
                    "nothing was posted",
                ))
            }
            Err(_) => vec![Err(nothing_identifiable_at_point())],
        };
        let mut owners = owners.into_iter();
        let target = owners
            .next()
            .unwrap_or_else(|| Err(nothing_identifiable_at_point()))?;
        require_app_grant(management, &self.process_executable, caller, &target)?;

        match request {
            TakeoverRequest::Drag { .. } => {
                let end = owners
                    .next()
                    .unwrap_or_else(|| Err(nothing_identifiable_at_point()))?;
                // One drag is one application's gesture. Across two, the
                // second would receive a button release it never saw pressed,
                // under a frontmost check made for the first; it is refused
                // before anything is posted.
                if end.pid != target.pid {
                    return Err(json!({
                        "outcome": "target_not_frontmost",
                        "reason": "drag_crosses_applications",
                        "remedy": format!(
                            "the drag starts in {} and ends in {}; a drag must start and end in \
                             one application, so nothing was posted",
                            target.bundle_identity, end.bundle_identity
                        ),
                    }));
                }
                Ok((
                    target,
                    SyntheticAction::drag_pointer(desktop_points[0], desktop_points[1]),
                    None,
                ))
            }
            _ => Ok((
                target,
                SyntheticAction::move_pointer(desktop_points[0]),
                None,
            )),
        }
    }

    /// Post one takeover action through the observed global dispatch, which
    /// applies the idle gate, watches for the person's input, and checks the
    /// target's generation and front before every post.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_takeover<C: MonotonicClock>(
        &self,
        capability: ComputerCapability,
        action: SyntheticAction,
        target: ProcessGrant,
        token: OnceDispatchToken,
        identity: JournalIdentity,
        grantee: &str,
        cancel: CancelHandle,
        clock: &C,
        management: &Arc<ManagementPlane>,
        takeover_request: &TakeoverRequest,
        scroll_window: Option<u32>,
    ) -> Value {
        let Some(row) = FrozenDispatchRow::for_capability(capability.capability_id()) else {
            return json!({
                "outcome": "dispatch_failed",
                "reason": "no_dispatch_row",
                "remedy": "this build has no dispatch row for the action; report it",
            });
        };
        let at_ms = clock.now().as_nanos() / 1_000_000;
        let attendance = AttendanceContext::observed(
            identity.conversation_key.clone(),
            target.clone(),
            grantee,
            at_ms,
            at_ms,
            true,
        );
        // No takeover request declares a post-condition: a pointer post may
        // change anything, and the caller reads the state afterwards. The
        // placeholder only labels the predicate the dispatcher serializes.
        let expected = ExpectedPostCondition::new(
            "computer-takeover-no-effect-claim-v1",
            PostCondition::ElementPresent {
                element: AccessibilityElementName::Identifier(target.bundle_identity.clone()),
            },
        );
        let held_press = if self.takeover_pointer_fronting_admitted {
            Some(super::held_input::HeldPress::global_send(&target, &action))
        } else {
            super::held_input::HeldPress::global(&target, &action)
        };
        let target_name = management.application_name(&target);
        let request = DispatchRequest::new(
            row,
            DispatchMode::Observed,
            target.clone(),
            expected,
            attendance,
            at_ms,
        )
        .with_synthetic(action)
        .with_once_dispatch_token(token);

        // Reserved here under a short lock; the worker commits and finalizes
        // through the token, so no audit lock is held across the posts.
        let work = super::quarantine::CallWork::current();
        let mut audit =
            cerebellum_computer::audit::AuditToken::new(self.audit.clone(), work.gate());
        if cerebellum_computer::dispatch::reserve_actuation_ahead(
            &mut audit,
            identity.clone(),
            &request,
        )
        .is_err()
        {
            return refusal_reply(&DispatchError::AuditUnavailable);
        }
        let mode =
            super::app_use::call_mode().unwrap_or(cerebellum_core::config::AppUse::Background);
        let pointer_failure = Arc::new(std::sync::Mutex::new(None));
        let (hooks, exclusion, pointer_guard) = if self.takeover_pointer_fronting_admitted {
            let mut stopped = |stop| {
                let reason = match stop {
                    cerebellum_computer::dispatch::FrontingStop::Cancelled => {
                        DispatchError::DispatchStopped
                    }
                    cerebellum_computer::dispatch::FrontingStop::FrontingLockTimedOut => {
                        DispatchError::FrontingBoundExceeded
                    }
                    cerebellum_computer::dispatch::FrontingStop::HeldInputUnconfirmed => {
                        DispatchError::DispatchStopped
                    }
                    _ => DispatchError::SyntheticUnavailable,
                };
                if audit.release_unused(&reason).is_err() {
                    return refusal_reply(&DispatchError::AuditUnavailable);
                }
                super::fronting::not_fronted_reply(super::fronting::Fronting::stopped(
                    mode,
                    super::fronting::Purpose::NeedsFront,
                    stop,
                ))
            };
            let Some(terminal) = work.terminal.clone() else {
                return stopped(cerebellum_computer::dispatch::FrontingStop::FrontingNotAdmitted);
            };
            let lock = match self.fronting_lock.take(&cancel).await {
                Ok(lock) => Arc::new(lock),
                Err(stop) => return stopped(stop),
            };
            if !super::fronting::held_input_confirmed(&self.held_input) {
                return stopped(cerebellum_computer::dispatch::FrontingStop::HeldInputUnconfirmed);
            }
            let hooks = super::fronting::CellHooks::new(super::fronting::ObligationParts {
                terminal,
                lock: Some(Box::new(Arc::clone(&lock))),
                target_name,
                mode: match mode {
                    cerebellum_core::config::AppUse::Background => {
                        crate::terminal_arbiter::FrontingMode::Background
                    }
                    cerebellum_core::config::AppUse::Foreground => {
                        crate::terminal_arbiter::FrontingMode::Foreground
                    }
                },
                purpose: crate::terminal_arbiter::FrontingPurpose::NeedsFront,
            });
            (
                Some(hooks),
                Some(lock),
                Some({
                    let guard = self.pointer_guard(
                        management,
                        &identity.conversation_key,
                        takeover_request,
                        &target,
                        scroll_window,
                    );
                    let failure = Arc::clone(&pointer_failure);
                    cerebellum_computer::platform::GlobalPointerGuard(Arc::new(move |deadline| {
                        let result = (guard.0)(deadline);
                        if let Err(step) = result {
                            *failure
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(step);
                        }
                        result
                    }))
                }),
            )
        } else {
            (None, None, None)
        };
        let ticket = if let Some(press) = held_press {
            let ticket = if let Some(exclusion) = exclusion {
                self.held_input.begin_global_send_under_lock(
                    press,
                    work.terminal.clone(),
                    exclusion,
                )
            } else {
                match self
                    .held_input
                    .begin_global_send(press, work.terminal.clone(), &self.fronting_lock, &cancel)
                    .await
                {
                    Ok(ticket) => ticket,
                    Err(_) => {
                        if audit
                            .release_unused(&DispatchError::DispatchStopped)
                            .is_err()
                        {
                            return refusal_reply(&DispatchError::AuditUnavailable);
                        }
                        return super::held_input::held_input_unconfirmed_reply("takeover");
                    }
                }
            };
            if let Some(terminal) = &work.terminal {
                let outcome = ticket.outcome();
                let permit = work.permits().and_then(|permits| permits.take_release());
                terminal.set_release(async move {
                    let _permit = permit;
                    outcome.await
                });
            }
            Some(ticket)
        } else {
            None
        };

        // Posting blocks for as long as the sequence takes. Run it off the
        // runtime so a cancel frame can still be read and set the signal.
        let make_driver = self.make_synthetic_driver.clone();
        // The pointer events posted here reach the platform's input count
        // like the person's do; noting them keeps a later element or
        // keystroke action from taking them for the person's use.
        let own_input = self.own_input.clone();
        let input_source = self.app_state_source.clone();
        let worker_hooks = hooks.clone();
        let record_hooks = hooks.clone();
        let dispatched = tokio::task::spawn_blocking(move || {
            let _ax = work.bound_ax();
            let _fronting_record = record_hooks.map(|hooks| {
                cerebellum_computer::audit::FrontingRecordScope::new(move || {
                    super::fronting::keystroke_row_fronting(mode, &hooks.peek()).row_record()
                })
            });
            let cancelled = || cancel.is_cancelled();
            let mut driver = make_driver();
            if let (Some(guard), Some(hooks)) = (pointer_guard, &worker_hooks) {
                if !driver.accept_pointer_fronting(guard)
                    || !driver.accept_fronted_dispatch_hooks(super::fronting::boxed_hooks(hooks))
                {
                    super::settle_held_input(
                        ticket,
                        &Err::<(), _>(DispatchError::SyntheticUnavailable),
                        make_driver.as_ref(),
                    );
                    return if audit
                        .release_unused(&DispatchError::SyntheticUnavailable)
                        .is_err()
                    {
                        Err(DispatchError::AuditUnavailable)
                    } else {
                        Err(DispatchError::SyntheticUnavailable)
                    };
                }
            }
            let mut dispatcher = Dispatcher::new(driver, &cancelled);
            let posting = own_input.begin_posting(
                cerebellum_computer::app_state::person::last_input_instant(input_source.as_ref()),
            );
            work.publish_posting(&own_input, &posting);
            let dispatched = dispatcher.dispatch(&mut audit, identity, request);
            own_input.end_posting(posting);
            let held = super::settle_held_input(ticket, &dispatched, make_driver.as_ref());
            if let Some(hooks) = &worker_hooks {
                super::fronting::finish_after_release(hooks, held, None);
            }
            dispatched
        })
        .await
        .unwrap_or(Err(DispatchError::Platform));
        let mut reply = match dispatched {
            Ok(_) => json!({"outcome": "completed"}),
            Err(refusal) => refusal_reply(&refusal),
        };
        if let Some(hooks) = &hooks {
            if reply["reason"] == "target_focus_mismatch" {
                reply["remedy"] = json!("pointer containment could not be confirmed at the AppKit mouse-down window hit-test, exact imaged-window, accessibility sensitivity or target-focus check; no further action posts were made. Read state again before retrying");
            }
            let end = hooks.end();
            let mut fronting = super::fronting::chord_fronting(mode, &end);
            if let Some(report) = &end.report {
                if report.posts_returned == 0
                    && matches!(
                        report.stop,
                        Some(
                            cerebellum_computer::dispatch::BracketStop::FrontFailed
                                | cerebellum_computer::dispatch::BracketStop::PreviousUnknown
                                | cerebellum_computer::dispatch::BracketStop::ObserverUnavailable
                                | cerebellum_computer::dispatch::BracketStop::BoundExceeded
                        )
                    )
                {
                    let stop = cerebellum_computer::dispatch::FrontingStop::from_bracket_stop(
                        report.stop.as_ref().unwrap(),
                    )
                    .unwrap();
                    let mut stopped = super::fronting::Fronting::stopped(
                        mode,
                        super::fronting::Purpose::NeedsFront,
                        stop,
                    );
                    stopped.restore = fronting.restore;
                    reply = super::fronting::not_fronted_reply(stopped);
                    fronting = stopped;
                }
            }
            fronting.apply(&mut reply);
            if let Some(report) = &end.report {
                if report.longest_fronted_interval_ms > 300
                    || matches!(
                        report.stop,
                        Some(cerebellum_computer::dispatch::BracketStop::BoundExceeded)
                    )
                {
                    reply["fronting_bound_exceeded"] = json!(true);
                }
            }
            if matches!(fronting.restore, super::fronting::Restore::Failed) {
                reply["outcome"] = json!("restore_failed");
                reply["remedy"] = json!("the previous application could not be restored; application restoration does not select its previous window. Read state before continuing");
            }
        }
        // Dispatch's existing reason vocabulary is intentionally coarse. Keep
        // the private query step in the existing remedy, not a new stored error.
        if let Some(step) = *pointer_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            let remedy = reply["remedy"]
                .as_str()
                .unwrap_or("Read state before retrying");
            reply["remedy"] = json!(format!("{step}; {remedy}"));
        }
        reply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scroll(axis: Value, lines: Value) -> Result<TakeoverRequest, Value> {
        parse_request(
            ComputerCapability::TakeoverScroll,
            &json!({"target": "com.example.Editor", "axis": axis, "amount_lines": lines}),
        )
    }

    #[test]
    fn a_scroll_is_held_to_its_declared_axis_and_bounds() {
        assert_eq!(
            scroll(json!("horizontal"), json!(-100)).unwrap(),
            TakeoverRequest::Scroll {
                target: "com.example.Editor".into(),
                axis: SyntheticScrollAxis::Horizontal,
                lines: -100,
            }
        );
        assert_eq!(
            scroll(json!("diagonal"), json!(1)).unwrap_err()["reason"],
            "unknown_value"
        );
        assert_eq!(
            scroll(json!("vertical"), json!(101)).unwrap_err()["reason"],
            "out_of_range"
        );
        assert_eq!(
            scroll(json!("vertical"), json!(0)).unwrap_err()["reason"],
            "empty_value"
        );
        assert_eq!(
            scroll(json!("vertical"), json!(1.5)).unwrap_err()["reason"],
            "wrong_type"
        );
    }

    /// Every dispatch error answers an outcome the takeover rows declare, and
    /// none answers `invalid_request`: a dispatch error is never the request's
    /// fault. Listed by hand so a new error variant has to be placed here.
    #[test]
    fn every_dispatch_error_reaches_a_declared_outcome_and_none_blames_the_request() {
        use cerebellum_computer::platform::vocabulary::validate_capability_result;
        use cerebellum_computer::platform::IdleUnreadable;
        let errors = [
            DispatchError::InvalidRequest,
            DispatchError::SyntheticUnavailable,
            DispatchError::Cancelled {
                posts_returned: 1,
                held_state: HeldStateDisposition::Released { posts_returned: 1 },
            },
            DispatchError::EnvelopeUnrecognized,
            DispatchError::UnsupportedMode,
            DispatchError::ObserverUnavailable,
            DispatchError::SeizeLatencyBoundExceeded,
            DispatchError::IdleGateRefused(IdleGateRefusal::BelowThreshold {
                threshold_ms: 1_000,
                hid_idle_ms: 10,
                user_idle_ms: 10,
            }),
            DispatchError::IdleGateRefused(IdleGateRefusal::Unreadable(
                IdleUnreadable::TableUnavailable,
            )),
            DispatchError::UserSeizedControl {
                sourced_input_kind: None,
            },
            DispatchError::AttendanceUnavailable,
            DispatchError::TargetFocusMismatch,
            DispatchError::GroundingUntrusted,
            DispatchError::GrantIdentityMismatch,
            DispatchError::IdentityVerificationUnavailable,
            DispatchError::EffectObservationUnavailable,
            DispatchError::Platform,
            DispatchError::AuditUnavailable,
        ];
        for error in &errors {
            let reply = refusal_reply(error);
            assert_ne!(reply["outcome"], "invalid_request", "{error:?}: {reply}");
            for row in [
                "computer.takeover_move",
                "computer.takeover_click",
                "computer.takeover_drag",
                "computer.takeover_scroll",
            ] {
                validate_capability_result(row, &reply)
                    .unwrap_or_else(|violation| panic!("{error:?} on {row}: {violation:?}"));
            }
        }
        let observer = refusal_reply(&DispatchError::ObserverUnavailable);
        assert_eq!(observer["outcome"], "dispatch_failed");
        assert_eq!(observer["reason"], "observer_unavailable");
        let platform = refusal_reply(&DispatchError::Platform);
        assert_eq!(platform["outcome"], "dispatch_failed");
        assert_eq!(platform["reason"], "platform_error");
    }

    #[test]
    fn a_point_is_exactly_two_whole_coordinates() {
        let moved = |to: Value| {
            parse_request(
                ComputerCapability::TakeoverMove,
                &json!({"image_id": "image-1", "to": to}),
            )
        };
        assert!(moved(json!({"x": 0, "y": 7})).is_ok());
        assert_eq!(
            moved(json!({"x": -1, "y": 7})).unwrap_err()["reason"],
            "wrong_type"
        );
        assert_eq!(
            moved(json!({"x": 1, "y": 7, "z": 0})).unwrap_err()["reason"],
            "unknown_field"
        );
        assert_eq!(moved(json!("1,7")).unwrap_err()["field"], "to");
    }

    #[test]
    fn a_click_requires_only_an_image_and_two_whole_pixel_coordinates() {
        let capability = ComputerCapability::TakeoverClick;
        assert_eq!(
            parse_request(capability, &json!({"image_id":"image","x":10,"y":20})).unwrap(),
            TakeoverRequest::Click {
                image_id: "image".into(),
                point: (10, 20)
            }
        );
        for request in [
            json!({"image_id":"image","x":10}),
            json!({"image_id":"image","x":-1,"y":20}),
            json!({"image_id":"image","x":1.5,"y":20}),
            json!({"image_id":"image","x":10,"y":20,"to":{"x":10,"y":20}}),
        ] {
            assert_eq!(
                parse_request(capability, &request).unwrap_err()["outcome"],
                "invalid_request"
            );
        }
    }
}
