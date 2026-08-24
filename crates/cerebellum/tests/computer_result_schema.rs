//! Exact inventory of computer replies against the frozen v4 result schemas.
//!
//! Code-owned divergence must stay empty. The remaining entries are fields the
//! reply deliberately preserves because they tell callers how to repair a
//! refusal, but which the digest-pinned artifact does not yet declare. They are
//! recorded as artifact-owned debt rather than mislabelled as reply defects.
//! Every sample still passes through the serving-boundary validator, and both
//! inventories are asserted exactly, so adding or removing one field reddens the
//! test by capability and JSON path.
//!
//! The wait request still differs between the handler and the declared request
//! schema: the handler accepts `predicate` as the typed `PostCondition` object
//! while the artifact declares a string. That request-contract mismatch is not a
//! result-schema divergence and is tracked separately from this file.

use std::collections::BTreeSet;

use cerebellum_computer::platform::vocabulary::{
    validate_capability_result, CapabilityResultValidationError, CapabilityResultViolation,
};
use serde_json::{json, Value};

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
            "$.field"
                | "$.reason"
                | "$.bundle_identity"
                | "$.instances"
                | "$.remedy"
                | "$.key_form"
                | "$.match_count"
                | "$.action"
                | "$.advertised"
                | "$.disposition"
                | "$.deadline_ms"
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

fn click_refusal(mut refusal: Value, unreadable_subtrees: u64) -> Value {
    let object = refusal.as_object_mut().expect("fixture is an object");
    object
        .entry("outcome")
        .or_insert_with(|| Value::String("refused".to_string()));
    object.insert("containment_rung".into(), json!("global_none"));
    object.insert("effect_status".into(), json!("effect_indeterminate"));
    object.insert("unreadable_subtrees".into(), json!(unreadable_subtrees));
    refusal
}

fn screenshot_refusal(mut refusal: Value) -> Value {
    refusal
        .as_object_mut()
        .expect("fixture is an object")
        .insert("windows".into(), json!([]));
    refusal
}

#[test]
fn served_reply_code_divergence_inventory_is_empty_and_artifact_debt_is_exact() {
    let screenshot = observed_facts(
        "computer.screenshot",
        [
            screenshot_refusal(json!({
                "outcome": "invalid_request",
                "field": "region",
                "reason": "wrong_type",
            })),
            screenshot_refusal(json!({
                "outcome": "broad_grant_required",
                "remedy": "obtain a broad grant",
            })),
            screenshot_refusal(json!({
                "outcome": "invalid_request",
                "field": "scope",
                "reason": "unknown_value",
            })),
            screenshot_refusal(json!({
                "outcome": "ambiguous",
                "bundle_identity": "com.example.app",
                "instances": [],
                "remedy": "choose one target",
            })),
            screenshot_refusal(json!({
                "outcome": "audit_unavailable",
                "remedy": "retry after repair",
            })),
            screenshot_refusal(json!({"outcome": "capture_failed"})),
            screenshot_refusal(json!({
                "outcome": "image_too_large",
                "bytes": 20_000_000,
                "bound_bytes": 16_777_216,
                "remedy": "capture fewer windows",
            })),
            screenshot_refusal(json!({
                "outcome": "no_window_captured",
                "remedy": "open a window",
            })),
        ],
    );
    let click = observed_facts(
        "computer.click",
        [
            click_refusal(
                json!({
                    "outcome": "invalid_request",
                    "field": "target",
                    "reason": "missing_field",
                }),
                0,
            ),
            click_refusal(
                json!({
                    "outcome": "ambiguous",
                    "bundle_identity": "com.example.app",
                    "instances": [],
                    "remedy": "choose one target",
                }),
                0,
            ),
            click_refusal(
                json!({
                    "reason": "element_name_ambiguous",
                    "key_form": "identifier",
                    "match_count": 2,
                }),
                0,
            ),
            click_refusal(
                json!({
                    "reason": "action_not_advertised",
                    "action": "AXPress",
                    "advertised": ["AXCancel"],
                }),
                0,
            ),
            click_refusal(json!({"reason": "application_refused"}), 0),
            click_refusal(
                json!({
                    "reason": "target_no_longer_current",
                    "disposition": "gone",
                }),
                0,
            ),
            click_refusal(
                json!({
                    "reason": "semantic_dispatch_transient",
                    "deadline_ms": 3000,
                }),
                0,
            ),
            click_refusal(
                json!({
                    "outcome": "not_servable",
                    "remedy": "report the missing implementation",
                }),
                0,
            ),
        ],
    );
    let wait = observed_facts(
        "computer.wait",
        [
            json!({
                "outcome": "predicate_satisfied",
                "evidence": r#"{"status":"settled","predicate":{"kind":"element_present","element":{"Identifier":"ready"}},"readback":{"present":true,"focused":null,"enabled":null,"value":null}}"#,
                "settle_path": "poll_with_deadline",
            }),
            json!({
                "outcome": "timeout",
                "evidence": r#"{"status":"timed_out","predicate":{"kind":"element_present","element":{"Identifier":"ready"}},"readback":{"present":false,"focused":null,"enabled":null,"value":null}}"#,
                "settle_path": "poll_with_deadline",
            }),
            json!({
                "outcome": "indeterminate",
                "evidence": r#"{"status":"indeterminate","predicate":{"kind":"element_present","element":{"Identifier":"ready"}},"readback":null,"reason":"target_not_inspectable"}"#,
                "settle_path": "poll_with_deadline",
            }),
        ],
    );

    let actual: BTreeSet<_> = screenshot.into_iter().chain(click).chain(wait).collect();
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

    let expected_artifact_debt = BTreeSet::from([
        fact(
            "computer.screenshot",
            "$.field",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.screenshot",
            "$.reason",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.screenshot",
            "$.remedy",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.screenshot",
            "$.bundle_identity",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.screenshot",
            "$.instances",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.screenshot",
            "$.bytes",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.screenshot",
            "$.bound_bytes",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.click",
            "$.field",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.click",
            "$.reason",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.click",
            "$.bundle_identity",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.click",
            "$.instances",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.click",
            "$.remedy",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.click",
            "$.key_form",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.click",
            "$.match_count",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.click",
            "$.action",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.click",
            "$.advertised",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.click",
            "$.disposition",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
        fact(
            "computer.click",
            "$.deadline_ms",
            DivergenceKind::UndeclaredProperty,
            OwedBy::Artifact,
        ),
    ]);
    assert_eq!(actual, expected_artifact_debt);
}

#[test]
fn all_three_v4_wait_terminal_values_conform_with_the_current_settle_path() {
    let replies = [
        json!({
            "outcome": "predicate_satisfied",
            "evidence": r#"{"status":"settled","predicate":{"kind":"element_present","element":{"Identifier":"ready"}},"readback":{"present":true,"focused":null,"enabled":null,"value":null}}"#,
            "settle_path": "poll_with_deadline",
        }),
        json!({
            "outcome": "timeout",
            "evidence": r#"{"status":"timed_out","predicate":{"kind":"element_present","element":{"Identifier":"ready"}},"readback":{"present":false,"focused":null,"enabled":null,"value":null}}"#,
            "settle_path": "poll_with_deadline",
        }),
        json!({
            "outcome": "indeterminate",
            "evidence": r#"{"status":"indeterminate","predicate":{"kind":"element_present","element":{"Identifier":"ready"}},"readback":null,"reason":"target_not_inspectable"}"#,
            "settle_path": "poll_with_deadline",
        }),
    ];

    for reply in replies {
        assert_eq!(validate_capability_result("computer.wait", &reply), Ok(()));
    }
}

#[test]
fn current_click_success_and_unreadable_post_action_state_conform() {
    let current = json!({
        "outcome": "completed",
        "containment_rung": "semantic_element",
        "effect_status": "effect_indeterminate",
        "unreadable_subtrees": 1,
    });
    let queried_but_unreadable = json!({
        "outcome": "completed",
        "containment_rung": "semantic_element",
        "effect_status": "effect_indeterminate",
        "unreadable_subtrees": 1,
        "post_action_state": {
            "status": "tree_unreadable",
            "elements": [],
            "read_after_action_ms": 42,
            "unreadable_subtrees": 1,
        },
    });

    assert_eq!(
        validate_capability_result("computer.click", &current),
        Ok(())
    );
    assert_eq!(
        validate_capability_result("computer.click", &queried_but_unreadable),
        Ok(())
    );
}

#[test]
fn a_current_screenshot_success_conforms_instead_of_every_reply_being_rejected() {
    let reply = json!({
        "outcome": "captured",
        "windows": [{
            "window_id": "window-1",
            "width_px": 800,
            "height_px": 600,
            "image_png_b64": "iVBORw==",
        }],
    });

    assert_eq!(
        validate_capability_result("computer.screenshot", &reply),
        Ok(())
    );
}
