#[allow(dead_code)]
#[path = "../src/authorization.rs"]
mod authorization;
#[allow(dead_code)]
#[path = "../src/classification.rs"]
mod classification;

use authorization::{
    effective_severity, Action, ActionGrant, AuthorizationDeniedDetail, AuthorizationRequest,
    GrantStore, Severity, COMPOSE, MUTATE_DURABLE, OBSERVE,
};
use classification::{
    classify_click, AssociatedFormControlInput, ElementClassificationInput, NodeIdentityInput,
    NonTypeClassificationInput, TargetKind,
};

fn identity(number: u64) -> NodeIdentityInput {
    NodeIdentityInput::new("target", "frame", number)
}

fn grant(id: &str, origins: &[&str]) -> ActionGrant {
    ActionGrant::new(
        id,
        1,
        "conversation",
        Severity::new(MUTATE_DURABLE, true, true),
        origins.iter().copied(),
    )
}

#[test]
fn exact_financial_vocabulary_is_applied_to_submit_form_owner() {
    let submit = ElementClassificationInput::new(identity(1), TargetKind::Button)
        .form_owner(identity(10))
        .associated_control(
            AssociatedFormControlInput::new(identity(2)).with_tokens(["cc-number"]),
        );
    let record = classify_click(&NonTypeClassificationInput::new(
        4,
        submit,
        "https://shop.test",
    ))
    .unwrap();
    assert!(record.financial);
    assert!(!record.credential);
    assert_eq!(record.required_tier, MUTATE_DURABLE);

    let unknown = ElementClassificationInput::new(identity(3), TargetKind::Input)
        .input_type("text")
        .autocomplete(["cc-future-token"]);
    let record = classify_click(&NonTypeClassificationInput::new(
        4,
        unknown,
        "https://shop.test",
    ))
    .unwrap();
    assert!(!record.financial);

    for token in [
        "cc-name",
        "cc-given-name",
        "cc-additional-name",
        "cc-family-name",
        "cc-number",
        "cc-exp",
        "cc-exp-month",
        "cc-exp-year",
        "cc-csc",
        "cc-type",
    ] {
        let target = ElementClassificationInput::new(identity(40), TargetKind::Input)
            .input_type("text")
            .autocomplete([token]);
        assert!(
            classify_click(&NonTypeClassificationInput::new(
                4,
                target,
                "https://shop.test",
            ))
            .unwrap()
            .financial
        );
    }
    for token in ["current-password", "new-password", "one-time-code"] {
        let target = ElementClassificationInput::new(identity(41), TargetKind::Input)
            .input_type("text")
            .autocomplete([token]);
        assert!(
            classify_click(&NonTypeClassificationInput::new(
                4,
                target,
                "https://shop.test",
            ))
            .unwrap()
            .credential
        );
    }
}

#[test]
fn activation_target_derivation_covers_composed_descendants_labels_and_disabled_controls() {
    let submit =
        ElementClassificationInput::new(identity(10), TargetKind::Button).form_owner(identity(11));
    let descendant = ElementClassificationInput::new(identity(12), TargetKind::Other);
    let record = classify_click(
        &NonTypeClassificationInput::new(1, descendant, "https://example.test")
            .with_composed_ancestor(submit),
    )
    .unwrap();
    assert_ne!(record.node_identity, record.activation_target_identity);
    assert!(record.activation_invokes_form_submit);

    let disabled = ElementClassificationInput::new(identity(20), TargetKind::Button)
        .disabled(true)
        .form_owner(identity(21));
    let label =
        ElementClassificationInput::new(identity(22), TargetKind::Other).label_for(disabled);
    let record = classify_click(&NonTypeClassificationInput::new(
        1,
        label,
        "https://example.test",
    ))
    .unwrap();
    assert!(!record.activation_invokes_form_submit);
    assert_eq!(record.required_tier, COMPOSE);

    let label = ElementClassificationInput::new(identity(23), TargetKind::Other);
    let descendant = ElementClassificationInput::new(identity(24), TargetKind::Other);
    let record = classify_click(
        &NonTypeClassificationInput::new(1, descendant, "https://example.test")
            .with_composed_ancestor(label),
    )
    .unwrap();
    assert_eq!(record.node_identity, record.activation_target_identity);
}

#[test]
fn cross_origin_elevation_and_origin_scope_use_immutable_decision() {
    let anchor = ElementClassificationInput::new(identity(30), TargetKind::Anchor)
        .destination("https://pay.test/submit");
    let record = classify_click(&NonTypeClassificationInput::new(
        1,
        anchor,
        "https://shop.test",
    ))
    .unwrap();
    assert_eq!(record.required_tier, MUTATE_DURABLE);

    let mut grants = GrantStore::new([
        grant("z", &["https://shop.test"]),
        grant("a", &["https://pay.test"]),
    ]);
    let decision = grants
        .authorize(AuthorizationRequest::click(
            "conversation",
            Severity::new(COMPOSE, false, false),
            "invocation",
            "bind",
            &record,
        ))
        .unwrap();
    assert_eq!(decision.grant_id(), "a");
    let commitment = grants.commit(&decision).unwrap();
    grants.revoke("a").unwrap();
    assert!(commitment.evaluate_origin_scope("https://pay.test").is_ok());
    assert_eq!(
        commitment.evaluate_origin_scope("https://shop.test"),
        Err(AuthorizationDeniedDetail::OriginScope {
            attempted_origin: "https://shop.test".to_string(),
            granted_origins: vec!["https://pay.test".to_string()],
        })
    );
}

#[test]
fn replacement_before_commit_is_rejected_by_the_commit_guard() {
    let mut store = GrantStore::new([grant("grant-a", &["https://allowed.test"])]);
    let decision = store
        .authorize(AuthorizationRequest::navigate(
            "conversation",
            Severity::new(OBSERVE, false, false),
            "invocation",
            "bind",
        ))
        .unwrap();
    store
        .replace(ActionGrant::new(
            "grant-a",
            2,
            "conversation",
            Severity::new(MUTATE_DURABLE, true, true),
            ["https://replacement.test"],
        ))
        .unwrap();
    assert_eq!(
        store.commit(&decision),
        Err(authorization::AuthorizationCommitError::GrantReplaced)
    );
}

#[test]
fn missing_grant_is_opaque_and_navigation_has_observe_floor() {
    let store = GrantStore::new([]);
    let error = store
        .authorize(AuthorizationRequest::navigate(
            "conversation",
            Severity::new(OBSERVE, false, false),
            "invocation",
            "bind",
        ))
        .unwrap_err();
    assert_eq!(error, authorization::AuthorizationError::NoGrant);
    assert_eq!(
        Action::Navigate.floor(),
        Severity::new(OBSERVE, false, false)
    );

    let _ = effective_severity;
}
