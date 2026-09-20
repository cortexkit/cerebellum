//! Exact inventory of computer replies against the frozen v8 result schemas.
//!
//! Every reply recorded here is returned by `ComputerPlane::serve`. The shared
//! fixture from `computer_screenshot` supplies fake clocks, leases, audit storage,
//! capture backends, and a resolver whose answer can change after consent.
//!
//! The inventory reaches these refusal states: invalid screenshot region and
//! scope, missing broad grant, ambiguous target, unavailable audit, failed and
//! oversized capture, no capturable window, invalid click request, ambiguous
//! click target, five invalid synthetic requests, and a wait target that becomes
//! unreadable after consent.
//!
//! The following states cannot be reached deterministically through `serve` yet:
//! semantic click-driver refusals (the production macOS driver is constructed
//! inside `serve`), successful and timed-out waits (the predicate poller is also
//! constructed there), and `not_servable` (the `servable` gate rejects that
//! capability before the serving boundary). They are intentionally absent rather
//! than represented by literals that could drift away from production replies.
//!
//! Both divergence-owner sets must stay empty. The code declares no fields the
//! artifact omits, and the artifact declares every deliberate served reply field.

mod support;

use std::collections::BTreeSet;
use std::sync::Arc;

use cerebellum::computer_capability::{servable, ComputerPlane, ServeContext};
use cerebellum_computer::capture::{EnumeratedWindow, InMemoryCaptureBackend, WindowFrame};
use cerebellum_computer::platform::vocabulary::{
    validate_capability_result, CapabilityResultValidationError, CapabilityResultViolation,
};
use cerebellum_computer::platform::{TargetCandidate, TargetResolution, UnreadableReason};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::consent::ActionKind;
use serde_json::{json, Value};
use support::computer::{
    audit, failing_audit, grant, grant_lease, identity, leased_management,
    management as unleased_management, management_with, request, CapturingBackend,
    MutableTargetResolver, RefusingBackend, GRANTEE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum OwedBy {
    Artifact,
    Reply,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum DivergenceKind {
    UndeclaredProperty,
    UnlistedEnumValue,
    WrongType,
    MissingRequiredProperty,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DivergenceFact {
    capability_id: &'static str,
    path: String,
    kind: DivergenceKind,
    owed_by: OwedBy,
}

fn fact(
    capability_id: &'static str,
    path: impl Into<String>,
    kind: DivergenceKind,
    owed_by: OwedBy,
) -> DivergenceFact {
    DivergenceFact {
        capability_id,
        path: path.into(),
        kind,
        owed_by,
    }
}

fn undeclared_field_owner(capability_id: &str, path: &str) -> OwedBy {
    let useful = match capability_id {
        "computer.click" => matches!(
            path,
            "$.field" | "$.reason" | "$.bundle_identity" | "$.instances" | "$.remedy"
        ),
        "computer.screenshot" => matches!(
            path,
            "$.field"
                | "$.reason"
                | "$.remedy"
                | "$.bundle_identity"
                | "$.instances"
                | "$.bytes"
                | "$.bound_bytes"
        ),
        _ => false,
    };
    if useful {
        OwedBy::Artifact
    } else {
        OwedBy::Reply
    }
}

fn observed_facts(
    capability_id: &'static str,
    replies: impl IntoIterator<Item = Value>,
) -> BTreeSet<DivergenceFact> {
    let mut facts = BTreeSet::new();
    for reply in replies {
        let Err(error) = validate_capability_result(capability_id, &reply) else {
            continue;
        };
        let CapabilityResultValidationError::ReplyViolations { violations, .. } = error else {
            panic!("the frozen result schema itself could not be checked: {error}");
        };
        for violation in violations {
            let fact = match violation {
                CapabilityResultViolation::ExpectedType { path, .. } => fact(
                    capability_id,
                    path,
                    DivergenceKind::WrongType,
                    OwedBy::Reply,
                ),
                CapabilityResultViolation::MissingRequiredProperty { path, property } => fact(
                    capability_id,
                    format!("{path}.{property}"),
                    DivergenceKind::MissingRequiredProperty,
                    OwedBy::Reply,
                ),
                CapabilityResultViolation::UndeclaredProperty { path } => fact(
                    capability_id,
                    path.clone(),
                    DivergenceKind::UndeclaredProperty,
                    undeclared_field_owner(capability_id, &path),
                ),
                CapabilityResultViolation::EnumMismatch { path } => fact(
                    capability_id,
                    path,
                    DivergenceKind::UnlistedEnumValue,
                    OwedBy::Reply,
                ),
            };
            facts.insert(fact);
        }
    }
    facts
}

fn named_reply(reply: Value, expected_outcome: &str) -> Value {
    assert_eq!(
        reply["outcome"], expected_outcome,
        "fixture did not reach {expected_outcome}: {reply}"
    );
    reply
}

async fn served_screenshot_replies() -> Vec<Value> {
    let mut replies = Vec::new();

    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());
    let management = leased_management(&clock).await;
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({
                "scope": "target_windows",
                "include_cursor": false,
                "region": null,
            }),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| CapturingBackend {
                windows: Vec::new(),
                png: Vec::new(),
            },
        )
        .await
        .expect("detect-only validation preserves the invalid-region reply");
    replies.push(named_reply(reply, "invalid_request"));

    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());
    let management = unleased_management();
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "display", "include_cursor": false }),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the broad-grant reply");
    replies.push(named_reply(reply, "broad_grant_required"));

    let clock = FakeClock::new();
    let plane = ComputerPlane::new(audit());
    let management = unleased_management();
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "all_windows", "include_cursor": false }),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the unknown-scope reply");
    replies.push(named_reply(reply, "invalid_request"));

    let clock = FakeClock::new();
    let resolver = MutableTargetResolver::new(TargetResolution::Resolved(grant()));
    let management = management_with(Arc::new(resolver.clone()));
    grant_lease(&management, ActionKind::Observe, &clock).await;
    resolver.replace(TargetResolution::Ambiguous(vec![
        TargetCandidate {
            pid: 4242,
            window_count: 1,
        },
        TargetCandidate {
            pid: 4343,
            window_count: 2,
        },
    ]));
    let plane = ComputerPlane::new(audit());
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": false }),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the ambiguous-target reply");
    replies.push(named_reply(reply, "ambiguous"));

    let clock = FakeClock::new();
    let management = leased_management(&clock).await;
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(failing_audit());
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": false }),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the audit-unavailable reply");
    replies.push(named_reply(reply, "audit_unavailable"));

    let clock = FakeClock::new();
    let management = leased_management(&clock).await;
    let plane = ComputerPlane::new(audit());
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &request(),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| RefusingBackend {
                windows: vec![fixture_window(1, 1)],
            },
        )
        .await
        .expect("detect-only validation preserves the capture-failed reply");
    replies.push(named_reply(reply, "capture_failed"));

    let clock = FakeClock::new();
    let management = leased_management(&clock).await;
    let plane = ComputerPlane::new(audit());
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": false }),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| CapturingBackend {
                windows: vec![fixture_window(1, 1)],
                png: vec![0; 16 * 1024 * 1024 + 1],
            },
        )
        .await
        .expect("detect-only validation preserves the image-too-large reply");
    replies.push(named_reply(reply, "image_too_large"));

    let clock = FakeClock::new();
    let management = leased_management(&clock).await;
    let plane = ComputerPlane::new(audit());
    let reply = plane
        .serve(
            servable("computer.screenshot").expect("screenshot is servable"),
            &json!({ "scope": "target_windows", "include_cursor": false }),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| CapturingBackend {
                windows: Vec::new(),
                png: Vec::new(),
            },
        )
        .await
        .expect("detect-only validation preserves the no-window reply");
    replies.push(named_reply(reply, "no_window_captured"));

    replies
}

async fn served_synthetic_replies() -> Vec<(&'static str, Value)> {
    let cases = [
        ("computer.type", json!({})),
        (
            "computer.keys",
            json!({"keys": ["a", "b"], "target": "editor"}),
        ),
        (
            "computer.scroll",
            json!({"target": "editor", "axis": "vertical", "amount_lines": "bad"}),
        ),
        ("computer.move", json!({})),
        ("computer.drag", json!({})),
    ];
    let mut replies = Vec::with_capacity(cases.len());
    for (capability_id, arguments) in cases {
        let clock = FakeClock::new();
        let plane = ComputerPlane::new(audit());
        let management = unleased_management();
        let reply = plane
            .serve(
                servable(capability_id).expect("synthetic capability is servable"),
                &arguments,
                ServeContext {
                    cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                    grantee: GRANTEE,
                    identity: identity(),
                    management: &management,
                    clock: &clock,
                    now_ms: 10,
                },
                |_| InMemoryCaptureBackend::default(),
            )
            .await
            .expect("detect-only validation preserves the synthetic refusal");
        replies.push((capability_id, named_reply(reply, "invalid_request")));
    }
    replies
}

async fn served_wait_replies() -> Vec<Value> {
    let clock = FakeClock::new();
    let resolver = MutableTargetResolver::new(TargetResolution::Resolved(grant()));
    let management = management_with(Arc::new(resolver.clone()));
    grant_lease(&management, ActionKind::Observe, &clock).await;
    resolver.replace(TargetResolution::Unreadable(
        UnreadableReason::WindowListUnavailable,
    ));
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let reply = plane
        .serve(
            servable("computer.wait").expect("wait is servable"),
            &json!({
                "predicate": {
                    "kind": "element_present",
                    "element": { "Identifier": "ready" },
                },
                "timeout_ms": 250,
            }),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("the target-unreadable wait reply conforms");

    vec![named_reply(reply, "indeterminate")]
}

#[cfg(target_os = "macos")]
async fn served_click_replies() -> Vec<Value> {
    let mut replies = Vec::new();

    let clock = FakeClock::new();
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let management = unleased_management();
    let reply = plane
        .serve(
            servable("computer.click").expect("click is servable"),
            &json!({}),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the invalid-click reply");
    replies.push(named_reply(reply, "invalid_request"));

    let clock = FakeClock::new();
    let resolver = MutableTargetResolver::new(TargetResolution::Resolved(grant()));
    let management = management_with(Arc::new(resolver.clone()));
    grant_lease(&management, ActionKind::Compose, &clock).await;
    resolver.replace(TargetResolution::Ambiguous(vec![
        TargetCandidate {
            pid: 4242,
            window_count: 1,
        },
        TargetCandidate {
            pid: 4343,
            window_count: 2,
        },
    ]));
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let reply = plane
        .serve(
            servable("computer.click").expect("click is servable"),
            &json!({
                "target": { "by": "identifier", "identifier": "confirm" },
                "button": "left",
                "click_count": 1,
                "modifiers": [],
            }),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the ambiguous-click reply");
    replies.push(named_reply(reply, "ambiguous"));

    replies
}

#[cfg(not(target_os = "macos"))]
async fn served_click_replies() -> Vec<Value> {
    Vec::new()
}

fn fixture_window(width: u32, height: u32) -> EnumeratedWindow {
    EnumeratedWindow {
        window_id: "window-1".to_string(),
        owner_identity: grant(),
        owner_identity_verified: true,
        frame: WindowFrame {
            x: 0,
            y: 0,
            width,
            height,
        },
        accessibility_root: None,
    }
}

#[tokio::test]
async fn served_reply_divergence_inventory_is_empty() {
    let screenshot = observed_facts("computer.screenshot", served_screenshot_replies().await);
    let wait = observed_facts("computer.wait", served_wait_replies().await);
    let click = observed_facts("computer.click", served_click_replies().await);
    let synthetic: BTreeSet<_> = served_synthetic_replies()
        .await
        .into_iter()
        .flat_map(|(capability_id, reply)| observed_facts(capability_id, [reply]))
        .collect();

    let actual: BTreeSet<_> = screenshot
        .into_iter()
        .chain(click)
        .chain(wait)
        .chain(synthetic)
        .collect();
    let code_owned: BTreeSet<_> = actual
        .iter()
        .filter(|fact| fact.owed_by == OwedBy::Reply)
        .cloned()
        .collect();
    assert_eq!(
        code_owned,
        BTreeSet::new(),
        "every code-owned result divergence must be removed"
    );

    let artifact_owned: BTreeSet<_> = actual
        .iter()
        .filter(|fact| fact.owed_by == OwedBy::Artifact)
        .cloned()
        .collect();
    assert_eq!(
        artifact_owned,
        BTreeSet::new(),
        "every artifact-owned result divergence must be removed"
    );
}

/// An undeclared property inside a `windows` element is a violation.
///
/// Until v12 it was not, and the reason is worth stating where the fence is:
/// `computer.screenshot.windows` was declared `{"type": "array"}` with no
/// `items`, and BOTH layers treated that as nothing to check. Artifact
/// validation accepted the array as closed, and enforcement walked elements
/// only when it had a schema for them, so every element of the one array a
/// caller reads after asking for `target_windows` passed unchecked -- in
/// Withhold mode, on a row that reads as closed.
///
/// Two assertions rather than one: the element must reject what it does not
/// declare AND accept what it does, because a schema that refuses everything
/// would pass the first on its own.
#[test]
fn an_undeclared_property_inside_a_window_element_is_withheld() {
    let element = json!({
        "window_id": "window-1",
        "width_px": 30,
        "height_px": 16,
        "image_png_b64": "AAAA",
    });
    let mut reply = json!({
        "outcome": "captured",
        "windows": [element.clone()],
        "windows_enumeration": "complete",
    });

    validate_capability_result("computer.screenshot", &reply)
        .expect("the declared element shape is accepted");

    reply["windows"][0]
        .as_object_mut()
        .expect("a window element is an object")
        .insert(
            "screen_text".into(),
            json!("whatever the window was showing"),
        );
    let error = validate_capability_result("computer.screenshot", &reply)
        .expect_err("an undeclared element property is withheld");
    assert!(
        matches!(
            error,
            CapabilityResultValidationError::ReplyViolations { ref violations, .. }
                if violations == &[CapabilityResultViolation::UndeclaredProperty {
                    path: "$.windows[0].screen_text".into()
                }]
        ),
        "expected one undeclared-property violation naming the element path, got {error:?}"
    );
}
