//! Serving computer capabilities through the plane: which names are served at
//! all, how a wait finds the application it is about, and how an unreadable
//! target is reported.

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use cerebellum::computer_capability::{
    servable, ComputerPlane, ComputerPlaneUnavailable, ResultSchemaEnforcement, ServeContext,
};
use cerebellum::management::ManagementPlane;
use cerebellum_computer::audit::ComputerCapability;
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::platform::{TargetResolution, UnreadableReason};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::journal::{IoDiagnostic, StorageError};
use serde_json::{json, Value};
use support::computer::{
    audit, granted_management, identity, management, no_relay, relayed, Fixed, ScriptedCarrier,
};

#[test]
fn journal_boot_failure_message_names_its_path_and_typed_cause() {
    let path = PathBuf::from("/unwritable/cortexkit/cerebellum/journal/computer.json");
    let reason = ComputerPlaneUnavailable::JournalStorage {
        path: path.clone(),
        error: StorageError::CreateDirectory {
            path: path.parent().expect("journal directory").to_path_buf(),
            source: IoDiagnostic {
                kind: std::io::ErrorKind::PermissionDenied,
                message: "permission denied".to_string(),
            },
        },
    };

    let message = reason.to_string();

    assert!(message.contains(path.to_str().expect("UTF-8 fixture path")));
    assert!(message.contains("CreateDirectory"));
    assert!(message.contains("PermissionDenied"));
}

/// Exactly the capabilities with a wire handler are servable.
///
/// Listed by name rather than matched by a wildcard, so a capability cannot
/// become servable by default: the match in `servable` stops compiling until a
/// new capability is admitted or refused by name, and this list forces the
/// same decision in the test. A retired capability id is not servable.
#[test]
fn only_the_capabilities_with_a_wire_handler_are_servable() {
    for (name, capability) in [
        ("computer.read_state", ComputerCapability::ReadState),
        ("computer.press_element", ComputerCapability::PressElement),
        ("computer.press_point", ComputerCapability::PressPoint),
        ("computer.write_text", ComputerCapability::WriteText),
        ("computer.type", ComputerCapability::Type),
        ("computer.keys", ComputerCapability::Keys),
        ("computer.takeover_move", ComputerCapability::TakeoverMove),
        ("computer.takeover_drag", ComputerCapability::TakeoverDrag),
        (
            "computer.takeover_scroll",
            ComputerCapability::TakeoverScroll,
        ),
        ("computer.wait", ComputerCapability::Wait),
    ] {
        assert_eq!(
            servable(name).map(|s| s.capability()),
            Some(capability),
            "{name} has a reviewed wire path and must be servable"
        );
    }
    for name in [
        "computer.click",
        "computer.screenshot",
        "computer.move",
        "computer.drag",
        "computer.scroll",
        "computer.not-a-capability",
    ] {
        assert!(servable(name).is_none(), "{name} must not be servable");
    }
}

fn predicate() -> Value {
    json!({
        "kind": "element_present",
        "element": {"Identifier": "ready"},
    })
}

async fn serve_wait(
    management: &Arc<ManagementPlane>,
    clock: &FakeClock,
    arguments: Value,
) -> Value {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> =
        ComputerPlane::with_result_schema_enforcement(audit(), ResultSchemaEnforcement::Withhold);
    plane
        .serve(
            servable("computer.wait").expect("wait is servable"),
            &arguments,
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: "pj-example",
                identity: identity(),
                management,
                consent: no_relay(),
                clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("every wait reply conforms to its row")
}

/// With no app grant for the application a wait names, and no way to ask a
/// person, the wait says nobody could be asked rather than pretending to poll.
#[tokio::test]
async fn a_wait_without_its_app_grant_and_nobody_to_ask_is_consent_unavailable() {
    let clock = FakeClock::new();
    let reply = serve_wait(
        &management(),
        &clock,
        json!({"app": "com.apple.Safari", "predicate": predicate(), "timeout_ms": 250}),
    )
    .await;

    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    assert_eq!(reply["reason"], "cannot_relay", "{reply}");
}

/// A wait is admitted by the app grant for the application it NAMES, never by
/// one some earlier call obtained.
///
/// The conversation holds Safari's app grant. A wait naming another
/// application must not borrow it: resolving the predicate there would read an
/// application the request did not name. A wait naming Safari gets past
/// admission.
#[tokio::test]
async fn a_wait_is_admitted_only_by_the_app_grant_for_the_app_it_names() {
    let clock = FakeClock::new();
    let management = granted_management().await;

    let elsewhere = serve_wait(
        &management,
        &clock,
        json!({"app": "com.example.Other", "predicate": predicate(), "timeout_ms": 0}),
    )
    .await;
    assert_eq!(
        elsewhere["outcome"], "consent_unavailable",
        "a wait naming another application was admitted by Safari's grant: {elsewhere}"
    );

    let named = serve_wait(
        &management,
        &clock,
        json!({"app": "com.apple.Safari", "predicate": predicate(), "timeout_ms": 0}),
    )
    .await;
    assert!(
        !named["outcome"]
            .as_str()
            .unwrap_or_default()
            .starts_with("consent_"),
        "the app grant for the named application did not admit the wait: {named}"
    );
}

/// A wait that names no application is refused by name at the wire.
#[tokio::test]
async fn a_wait_without_app_is_refused_before_any_grant_is_consulted() {
    let clock = FakeClock::new();
    let reply = serve_wait(
        &granted_management().await,
        &clock,
        json!({"predicate": predicate(), "timeout_ms": 250}),
    )
    .await;
    assert_eq!(reply["outcome"], "invalid_request");
    assert_eq!(reply["field"], "app");
    assert_eq!(reply["reason"], "missing_field");
}

/// An unreadable window list is never reported as the application being absent.
///
/// The two answers send a person in opposite directions: `not_running` says to
/// start the application, while an unreadable list says nothing about whether it
/// is running at all.
///
/// Not hypothetical. Under concurrent load on a real machine the permission
/// query reported capture as permitted while enumeration failed in the same
/// instant with a declined-permission error, so a transient window-server
/// failure arrives wearing a denial's clothes. Reporting that as "not running"
/// tells someone to start a second copy of an application already in front of
/// them, and the second copy then makes the target ambiguous.
#[tokio::test]
async fn an_unreadable_window_list_is_not_reported_as_the_application_being_absent() {
    let plane = Arc::new(ManagementPlane::new(Arc::new(Fixed(
        TargetResolution::Unreadable(UnreadableReason::WindowListUnavailable),
    ))));
    let carrier = ScriptedCarrier::default();

    let body = plane
        .open_target(
            "com.example.App",
            &relayed(&carrier),
            &cerebellum::CancelHandle::pending(),
        )
        .await;

    assert_eq!(
        body["outcome"], "targets_unreadable",
        "an unreadable window list produced: {body}"
    );
    assert!(
        carrier.questions().is_empty(),
        "a person was asked to approve a target nothing could see: {body}"
    );
}

/// The REASON a target was unreadable reaches the wire, and the remedy is
/// that reason's remedy.
///
/// One word used to carry every cause, and the remedy attached to it named a
/// macOS screen-recording grant -- so a Windows caller running in a service
/// session was told to check a permission on the wrong operating system for
/// a problem that was the session it ran in. Asserted at the reply, because
/// the reason travelled correctly inside the resolver for a day while the
/// wire kept saying the same thing.
#[tokio::test]
async fn an_unreadable_reason_reaches_the_wire_with_its_own_remedy() {
    let mut seen = std::collections::BTreeSet::new();

    for (reason, remedy_names) in [
        (
            UnreadableReason::SessionNotInteractive {
                session_id: 0,
                console_session_id: 1,
            },
            "console session",
        ),
        (
            UnreadableReason::NoConsoleSession { session_id: 0 },
            "log a user in",
        ),
        (
            UnreadableReason::PartialWindowList {
                unreadable_owners: 2,
            },
            "could not be attributed",
        ),
        (
            UnreadableReason::GenerationUnreadable { pid: 4242 },
            "do NOT start another instance",
        ),
        (
            UnreadableReason::WindowListUnavailable,
            "window-reading permission",
        ),
    ] {
        let plane = Arc::new(ManagementPlane::new(Arc::new(Fixed(
            TargetResolution::Unreadable(reason.clone()),
        ))));
        let body = plane
            .open_target(
                "com.example.App",
                &no_relay(),
                &cerebellum::CancelHandle::pending(),
            )
            .await;

        assert_eq!(body["outcome"], "targets_unreadable", "{body}");
        // The reason itself, serialized, not merely a prose hint about it.
        assert_eq!(
            body["unreadable"],
            serde_json::to_value(&reason).expect("reason serializes"),
            "the wire did not carry the reason: {body}"
        );
        let remedy = body["remedy"].as_str().expect("a remedy string");
        assert!(
            remedy.contains(remedy_names),
            "the remedy for {reason:?} does not name its own fix: {remedy}"
        );
        // Five reasons, five distinct remedies. A shared remedy would mean a
        // reason with nothing to say for itself, which is the collapse again.
        assert!(
            seen.insert(remedy.to_string()),
            "two reasons share one remedy: {remedy}"
        );
    }
}
