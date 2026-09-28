//! The takeover actions: moving, dragging and scrolling with the one real
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
//! A move or drag also needs the app grant of the application under the
//! pointer. That grant is checked, never asked for: the question belongs to a
//! call that names the application, and `read_state` on it asks.
//!
//! Nothing here brings an application forward. The containment target must
//! already be frontmost, and the dispatch path checks its process generation
//! and that it is still frontmost before every single post, stopping the
//! sequence the moment either fails.

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
        ComputerCapability::TakeoverDrag => Some(&DRAG_FIELDS),
        ComputerCapability::TakeoverScroll => Some(&SCROLL_FIELDS),
        _ => None,
    }
}

/// A takeover request as parsed, before anything is resolved.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TakeoverRequest {
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
    caller: &GrantCaller,
    grant: &ProcessGrant,
) -> Result<(), Value> {
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
        DispatchError::Cancelled { .. } => super::synthetic_dispatch_refusal(refusal),
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
        let request = match parse_request(capability, arguments) {
            Ok(request) => request,
            Err(refusal) => return refusal,
        };
        let super::ServeContext {
            cancel,
            grantee,
            identity,
            management,
            consent,
            clock,
            now_ms: _,
        } = context;

        let (mut target, mut action) = match self
            .place(
                management,
                &identity.conversation_key,
                &consent.caller,
                &request,
            )
            .await
        {
            Ok(placed) => placed,
            Err(refusal) => return refusal,
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
                Ok((placed_target, placed_action)) => {
                    target = placed_target;
                    action = placed_action;
                }
                Err(refusal) => return refusal,
            }
        }
        let admission = takeover.admission().clone();
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
            )
            .await;
        admission.decorate(&mut reply);
        reply
    }

    /// The containment target of a request and the pointer action to post.
    async fn place(
        &self,
        management: &Arc<ManagementPlane>,
        conversation_key: &str,
        caller: &GrantCaller,
        request: &TakeoverRequest,
    ) -> Result<(ProcessGrant, SyntheticAction), Value> {
        let (image_id, points) = match request {
            TakeoverRequest::Scroll {
                target,
                axis,
                lines,
            } => {
                let grant = management.resolve_process(target)?;
                return Ok((
                    grant,
                    SyntheticAction::scroll_along(*axis, SyntheticScrollUnit::Line, *lines),
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

        let desktop_points: Vec<SyntheticPoint> =
            points.iter().map(|point| desktop(&image, *point)).collect();
        let source = self.app_state_source.clone();
        let hit_management = Arc::clone(management);
        let hit_image = image.clone();
        let hit_points = desktop_points.clone();
        let owners = tokio::task::spawn_blocking(move || {
            hit_points
                .iter()
                .map(|point| {
                    application_under(source.as_ref(), &hit_management, &hit_image, *point)
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_else(|_| vec![Err(nothing_identifiable_at_point())]);
        let mut owners = owners.into_iter();
        let target = owners
            .next()
            .unwrap_or_else(|| Err(nothing_identifiable_at_point()))?;
        require_app_grant(management, caller, &target)?;

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
                ))
            }
            _ => Ok((target, SyntheticAction::move_pointer(desktop_points[0]))),
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
        let request = DispatchRequest::new(
            row,
            DispatchMode::Observed,
            target,
            expected,
            attendance,
            at_ms,
        )
        .with_synthetic(action)
        .with_once_dispatch_token(token);

        // Posting blocks for as long as the sequence takes. Run it off the
        // runtime so a cancel frame can still be read and set the signal.
        let audit = self.audit.clone();
        let make_driver = self.make_synthetic_driver.clone();
        let dispatched = tokio::task::spawn_blocking(move || {
            let mut audit = audit.blocking_lock();
            let cancelled = || cancel.is_cancelled();
            let mut dispatcher = Dispatcher::new(make_driver(), &cancelled);
            dispatcher.dispatch(&mut audit, identity, request)
        })
        .await
        .unwrap_or(Err(DispatchError::Platform));
        match dispatched {
            Ok(_) => json!({"outcome": "completed"}),
            Err(refusal) => refusal_reply(&refusal),
        }
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
}
