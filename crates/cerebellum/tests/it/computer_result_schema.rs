//! Exact inventory of computer replies against the frozen result schemas.
//!
//! Every reply recorded here is returned by `ComputerPlane::serve`. The shared
//! fixture supplies fake clocks, leases, audit storage and a resolver whose
//! answer can change after consent.
//!
//! The inventory reaches these refusal states: an invalid request for each
//! keystroke row, a wait naming no application, and a wait whose target
//! becomes unreadable after consent.
//!
//! The following states cannot be reached deterministically through `serve` yet:
//! successful and timed-out waits (the predicate poller is constructed inside
//! `serve`). They are intentionally absent rather than represented by
//! literals that could drift away from production replies.
//!
//! Both divergence-owner sets must stay empty. The code declares no fields the
//! artifact omits, and the artifact declares every deliberate served reply field.

use super::support;

use std::collections::BTreeSet;
use std::sync::Arc;

use cerebellum::computer_capability::{servable, ComputerPlane, ServeContext};
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::platform::vocabulary::{
    validate_capability_result, CapabilityResultValidationError, CapabilityResultViolation,
};
use cerebellum_computer::platform::{TargetResolution, UnreadableReason};
use cerebellum_core::clock::FakeClock;
use serde_json::{json, Value};
use support::computer::{
    audit, grant, grant_app, identity, management as unleased_management, management_with,
    no_relay, MutableTargetResolver, GRANTEE, TARGET_BUNDLE_ID,
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

/// Who owes the fix for a reply field its row does not declare. No served
/// row has a field the artifact should declare and does not, so every such
/// field is the reply's to remove.
fn undeclared_field_owner(_capability_id: &str, _path: &str) -> OwedBy {
    OwedBy::Reply
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

async fn served_synthetic_replies() -> Vec<(&'static str, Value)> {
    let cases = [
        ("computer.type", json!({})),
        (
            "computer.keys",
            json!({"keys": ["a", "b"], "target": "editor"}),
        ),
    ];
    let mut replies = Vec::with_capacity(cases.len());
    for (capability_id, arguments) in cases {
        let clock = FakeClock::new();
        let plane = ComputerPlane::new(audit())
            .with_permission_liveness(super::support::computer::live_permissions());
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
                    consent: no_relay(),
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
    let mut replies = Vec::new();

    let clock = FakeClock::new();
    let management = unleased_management();
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let reply = plane
        .serve(
            servable("computer.wait").expect("wait is servable"),
            &json!({"predicate": {"kind": "element_present", "element": {"Identifier": "ready"}}, "timeout_ms": 250}),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                consent: no_relay(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("the missing-app wait reply conforms");
    replies.push(named_reply(reply, "invalid_request"));

    let clock = FakeClock::new();
    let resolver = MutableTargetResolver::new(TargetResolution::Resolved(grant()));
    let management = management_with(Arc::new(resolver.clone()));
    grant_app(&management).await;
    resolver.replace(TargetResolution::Unreadable(
        UnreadableReason::WindowListUnavailable,
    ));
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> = ComputerPlane::new(audit());
    let reply = plane
        .serve(
            servable("computer.wait").expect("wait is servable"),
            &json!({
                "app": TARGET_BUNDLE_ID,
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
                consent: no_relay(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("the target-unreadable wait reply conforms");

    replies.push(named_reply(reply, "targets_unreadable"));
    replies
}

#[tokio::test]
async fn served_reply_divergence_inventory_is_empty() {
    let wait = observed_facts("computer.wait", served_wait_replies().await);
    let synthetic: BTreeSet<_> = served_synthetic_replies()
        .await
        .into_iter()
        .flat_map(|(capability_id, reply)| observed_facts(capability_id, [reply]))
        .collect();

    let actual: BTreeSet<_> = wait.into_iter().chain(synthetic).collect();
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

/// An undeclared property inside an array element is a violation.
///
/// Enforcement walks the elements of a declared array only when it has an
/// element schema, and an array declared without one lets every element
/// through unchecked -- in Withhold mode, on a row that reads as closed. The
/// ambiguity refusal's `instances` array is where a keystroke reply carries
/// one, so it is checked there.
///
/// Two assertions rather than one: the element must reject what it does not
/// declare AND accept what it does, because a schema that refuses everything
/// would pass the first on its own.
#[test]
fn an_undeclared_property_inside_an_array_element_is_withheld() {
    let mut reply = json!({
        "outcome": "ambiguous",
        "containment_rung": "global_none",
        "effect_status": "effect_indeterminate",
        "target_fronted": false,
        "bundle_identity": TARGET_BUNDLE_ID,
        "instances": [{"pid": 4242, "window_count": 1}],
    });

    validate_capability_result("computer.type", &reply)
        .expect("the declared element shape is accepted");

    reply["instances"][0]
        .as_object_mut()
        .expect("an instance element is an object")
        .insert(
            "screen_text".into(),
            json!("whatever the window was showing"),
        );
    let error = validate_capability_result("computer.type", &reply)
        .expect_err("an undeclared element property is withheld");
    assert!(
        matches!(
            error,
            CapabilityResultValidationError::ReplyViolations { ref violations, .. }
                if violations == &[CapabilityResultViolation::UndeclaredProperty {
                    path: "$.instances[0].screen_text".into()
                }]
        ),
        "expected one undeclared-property violation naming the element path, got {error:?}"
    );
}
