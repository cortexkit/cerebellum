//! Exact inventory of replies that disagree with the frozen computer result schemas.
//!
//! This is asserted content, not an exemption list: every sample is passed
//! through the same validator as the serving boundary, and the test fails when
//! either side changes. Entries can be removed as the frozen schemas and serving
//! behavior are reconciled, until the inventory reaches zero.
//!
//! The artifact has no uniform refusal contract. `computer.wait.outcome` is an
//! enum containing only `predicate_satisfied` and `timeout`, so its refusal is
//! outside the schema by value. Click and screenshot accept any outcome string,
//! but still require success-only fields (`containment_rung`/`effect_status` or
//! `windows`), so their current refusals are outside those schemas by shape.
//!
//! The wait request is independently divergent: the artifact requires
//! `predicate` and `timeout_ms`, while the handler reads `duration_ms`. That is
//! request-contract debt rather than a result-validator exemption. Type, keys,
//! scroll, move, and drag have no current wire serving path, so they produce no
//! reply shapes to inventory here.

use std::collections::BTreeSet;

use cerebellum_computer::platform::vocabulary::{
    validate_capability_result, CapabilityResultValidationError, CapabilityResultViolation,
};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum WrongSide {
    ReplyCarriesUndeclaredField,
    ReplyUsesUnlistedEnumValue,
    ReplyUsesWrongType,
    SchemaRequiresFieldReplyLacks,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DivergenceFact {
    capability_id: &'static str,
    path: String,
    wrong_side: WrongSide,
}

fn fact(
    capability_id: &'static str,
    path: impl Into<String>,
    wrong_side: WrongSide,
) -> DivergenceFact {
    DivergenceFact {
        capability_id,
        path: path.into(),
        wrong_side,
    }
}

fn observed_facts(
    capability_id: &'static str,
    replies: impl IntoIterator<Item = Value>,
) -> BTreeSet<DivergenceFact> {
    replies
        .into_iter()
        .flat_map(|reply| {
            let error = validate_capability_result(capability_id, &reply)
                .expect_err("every inventoried reply shape is currently divergent");
            let CapabilityResultValidationError::ReplyViolations { violations, .. } = error else {
                panic!("the frozen result schema itself could not be checked: {error}");
            };
            violations
                .into_iter()
                .map(move |violation| match violation {
                    CapabilityResultViolation::ExpectedType { path, .. } => {
                        fact(capability_id, path, WrongSide::ReplyUsesWrongType)
                    }
                    CapabilityResultViolation::MissingRequiredProperty { path, property } => fact(
                        capability_id,
                        format!("{path}.{property}"),
                        WrongSide::SchemaRequiresFieldReplyLacks,
                    ),
                    CapabilityResultViolation::UndeclaredProperty { path } => {
                        fact(capability_id, path, WrongSide::ReplyCarriesUndeclaredField)
                    }
                    CapabilityResultViolation::EnumMismatch { path } => {
                        fact(capability_id, path, WrongSide::ReplyUsesUnlistedEnumValue)
                    }
                })
        })
        .collect()
}

#[test]
fn current_served_reply_schema_divergences_are_exactly_this_inventory() {
    let wait = observed_facts(
        "computer.wait",
        [
            json!({
                "outcome": "invalid_request",
                "field": "duration_ms",
                "reason": "missing_field",
            }),
            json!({"outcome": "completed", "waited_ms": 25}),
        ],
    );
    let screenshot = observed_facts(
        "computer.screenshot",
        [
            json!({
                "outcome": "invalid_request",
                "field": "region",
                "reason": "region_unsupported_for_window_capture",
            }),
            json!({"outcome": "broad_grant_required", "remedy": "obtain a broad grant"}),
            json!({
                "outcome": "invalid_request",
                "field": "scope",
                "reason": "unknown_value",
                "value": "other",
            }),
            json!({
                "outcome": "ambiguous",
                "bundle_identity": "com.example.app",
                "instances": [],
                "remedy": "choose one target",
            }),
            json!({
                "outcome": "audit_unavailable",
                "detail": "storage unavailable",
                "remedy": "retry after repair",
            }),
            json!({"outcome": "capture_failed", "detail": "backend failed"}),
            json!({
                "outcome": "image_too_large",
                "bytes": 20_000_000,
                "bound_bytes": 16_777_216,
                "remedy": "capture fewer windows",
            }),
            json!({"outcome": "no_window_captured", "remedy": "open a window"}),
        ],
    );
    let click = observed_facts(
        "computer.click",
        [
            json!({
                "outcome": "completed",
                "containment_rung": "semantic_element",
                "effect_status": "effect_indeterminate",
                "unreadable_subtrees": 1,
            }),
            json!({
                "outcome": "invalid_request",
                "field": "target",
                "reason": "missing_field",
            }),
            json!({
                "outcome": "ambiguous",
                "bundle_identity": "com.example.app",
                "instances": [],
                "remedy": "choose one target",
            }),
            json!({
                "reason": "element_name_ambiguous",
                "key_form": "identifier",
                "match_count": 2,
            }),
            json!({
                "reason": "action_not_advertised",
                "action": "AXPress",
                "advertised": ["AXCancel"],
            }),
            json!({"reason": "application_refused", "ax_error": -25205}),
            json!({"reason": "target_no_longer_current", "disposition": "gone"}),
            json!({"reason": "semantic_dispatch_transient", "deadline_ms": 3000}),
            json!({
                "outcome": "not_servable",
                "capability": "computer.click",
                "remedy": "report the missing implementation",
            }),
        ],
    );

    let actual: BTreeSet<_> = wait.into_iter().chain(screenshot).chain(click).collect();
    let expected = BTreeSet::from([
        fact(
            "computer.wait",
            "$.evidence",
            WrongSide::SchemaRequiresFieldReplyLacks,
        ),
        fact(
            "computer.wait",
            "$.outcome",
            WrongSide::ReplyUsesUnlistedEnumValue,
        ),
        fact(
            "computer.wait",
            "$.field",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.wait",
            "$.reason",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.wait",
            "$.waited_ms",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.screenshot",
            "$.windows",
            WrongSide::SchemaRequiresFieldReplyLacks,
        ),
        fact(
            "computer.screenshot",
            "$.field",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.screenshot",
            "$.reason",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.screenshot",
            "$.remedy",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.screenshot",
            "$.value",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.screenshot",
            "$.bundle_identity",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.screenshot",
            "$.instances",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.screenshot",
            "$.detail",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.screenshot",
            "$.bytes",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.screenshot",
            "$.bound_bytes",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.outcome",
            WrongSide::SchemaRequiresFieldReplyLacks,
        ),
        fact(
            "computer.click",
            "$.containment_rung",
            WrongSide::SchemaRequiresFieldReplyLacks,
        ),
        fact(
            "computer.click",
            "$.effect_status",
            WrongSide::SchemaRequiresFieldReplyLacks,
        ),
        fact(
            "computer.click",
            "$.unreadable_subtrees",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.field",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.reason",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.bundle_identity",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.instances",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.remedy",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.key_form",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.match_count",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.action",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.advertised",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.ax_error",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.disposition",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.deadline_ms",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
        fact(
            "computer.click",
            "$.capability",
            WrongSide::ReplyCarriesUndeclaredField,
        ),
    ]);

    assert_eq!(actual, expected);
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
