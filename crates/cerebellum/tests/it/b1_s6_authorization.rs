use cerebellum::authorization::{
    effective_severity, target_hazards, Action, ActionGrant, AuthorizationError,
    AuthorizationRequest, GrantStore, HazardClass, Severity, COMPOSE, MUTATE_DURABLE, OBSERVE,
};
use cerebellum::classification::{
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
    // The exact target, not merely a different one. A derivation that picked the
    // wrong ancestor -- the form owner rather than the composed submit control --
    // satisfies assert_ne and is wrong, and this classifier decides whether a
    // click counts as submitting a form, so WHICH control it resolves to is the
    // whole question.
    //
    // The expectation comes from classifying a click on the submit control
    // itself rather than from recomputing the fingerprint here: a test that
    // derives its expected value with the code under test agrees with that code
    // by construction, including when both are wrong.
    let direct = classify_click(&NonTypeClassificationInput::new(
        2,
        ElementClassificationInput::new(identity(10), TargetKind::Button).form_owner(identity(11)),
        "https://example.test",
    ))
    .unwrap();
    assert_eq!(
        record.activation_target_identity, direct.node_identity,
        "a click on a descendant must resolve to the same control a direct click addresses"
    );
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
fn cross_origin_elevation_keeps_immutable_grant_decision() {
    let anchor = ElementClassificationInput::new(identity(30), TargetKind::Anchor)
        .destination("http://10.0.0.5/submit");
    let record = classify_click(&NonTypeClassificationInput::new(
        1,
        anchor,
        "https://shop.test",
    ))
    .unwrap();
    assert_eq!(record.required_tier, MUTATE_DURABLE);

    let mut grants = GrantStore::new([
        grant("z", &["https://shop.test"]),
        grant("a", &["http://10.0.0.5"]),
    ]);
    let decision = grants
        .authorize(
            AuthorizationRequest::click(
                "conversation",
                Severity::new(COMPOSE, false, false),
                "invocation",
                "bind",
                &record,
            ),
            "http://10.0.0.5",
        )
        .unwrap();
    assert_eq!(decision.grant_id(), "a");
    let commitment = grants.commit(&decision).unwrap();
    grants.revoke("a").unwrap();
    assert_eq!(commitment.decision(), &decision);
}

#[test]
fn an_action_on_the_second_granted_origin_selects_its_grant() {
    let store = GrantStore::new([
        grant("grant-a", &["https://a.test"]),
        grant("grant-b", &["https://b.test"]),
    ]);

    let decision = store
        .authorize(
            AuthorizationRequest::navigate(
                "conversation",
                Severity::new(OBSERVE, false, false),
                "invocation",
                "bind",
            ),
            "https://b.test",
        )
        .expect("the grant scoped to B authorizes an action on B");

    assert_eq!(decision.grant_id(), "grant-b");
}

#[test]
fn origin_scope_refusal_lists_every_severity_covering_grant_origin() {
    let store = GrantStore::new([
        grant("grant-a", &["https://a.test"]),
        grant("grant-b", &["https://b.test"]),
    ]);

    let error = store
        .authorize(
            AuthorizationRequest::navigate(
                "conversation",
                Severity::new(OBSERVE, false, false),
                "invocation",
                "bind",
            ),
            "https://c.test",
        )
        .expect_err("neither grant covers C");

    assert_eq!(
        error,
        AuthorizationError::OriginScope {
            attempted_origin: "https://c.test".to_string(),
            granted_origins: vec!["https://a.test".to_string(), "https://b.test".to_string()],
            required: Severity::new(OBSERVE, false, false),
            required_hazards: Default::default(),
        }
    );
}

#[test]
fn replacement_before_commit_is_rejected_by_the_commit_guard() {
    let mut store = GrantStore::new([grant("grant-a", &["https://allowed.test"])]);
    let decision = store
        .authorize(
            AuthorizationRequest::navigate(
                "conversation",
                Severity::new(OBSERVE, false, false),
                "invocation",
                "bind",
            ),
            "https://allowed.test",
        )
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
        Err(cerebellum::authorization::AuthorizationCommitError::GrantReplaced)
    );
}

#[test]
fn missing_grant_is_opaque_and_observations_have_an_empty_hazard_floor() {
    let store = GrantStore::new([]);
    let error = store
        .authorize(
            AuthorizationRequest::navigate(
                "conversation",
                Severity::new(OBSERVE, false, false),
                "invocation",
                "bind",
            ),
            "https://missing.test",
        )
        .unwrap_err();
    // Still opaque about other grants: the refusal names only the caller's own
    // attempted origin and the severity its own action requires, which is
    // what a caller needs to open the grant that covers it.
    assert_eq!(
        error,
        cerebellum::authorization::AuthorizationError::NoGrantForAction {
            attempted_origin: "https://missing.test".to_string(),
            required: Severity::new(OBSERVE, false, false),
        }
    );
    for action in [Action::Navigate, Action::Snapshot] {
        assert_eq!(action.floor(), Severity::new(OBSERVE, false, false));
    }
    assert!(target_hazards(Action::Snapshot, None).unwrap().is_empty());

    let _ = effective_severity;
}

/// The production mint path must bind the exact disclosure scope to the grant.
///
/// This scan does not try to prove authorization semantics; the behavioral tests
/// do that. It keeps the production constructor and insertion path visible while
/// asserting that neither can mint an origin-only grant that loses the human's
/// hazard disclosure.
#[test]
fn production_action_grant_mint_carries_disclosure_scope() {
    let management = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/management.rs"),
    )
    .expect("read the production browser grant mint");
    for required in [
        "ActionGrant::new",
        ".with_disclosed_hazards(pending.disclosed_hazards)",
        "settle_browser_grant",
        "browser_grant_question",
    ] {
        assert!(
            management.contains(required),
            "production mint lost required disclosure binding `{required}`"
        );
    }
}

#[test]
fn disclosure_coverage_is_subset_semantics_and_unknown_is_distinct() {
    let credential_submit = ElementClassificationInput::new(identity(50), TargetKind::Button)
        .form_owner(identity(51))
        .associated_control(
            AssociatedFormControlInput::new(identity(52)).with_tokens(["current-password"]),
        );
    let record = classify_click(&NonTypeClassificationInput::new(
        1,
        credential_submit,
        "https://login.test",
    ))
    .unwrap();

    let credential_only = grant("credential", &["https://login.test"])
        .with_disclosed_hazards([HazardClass::CredentialFormSubmit]);
    let store = GrantStore::new([credential_only]);
    assert!(store
        .authorize(
            AuthorizationRequest::click(
                "conversation",
                Severity::new(MUTATE_DURABLE, true, false),
                "invocation",
                "bind",
                &record,
            ),
            "https://login.test",
        )
        .is_ok());

    let unknown = store
        .authorize(
            AuthorizationRequest::click_unverified(
                "conversation",
                Severity::new(COMPOSE, false, false),
                "invocation",
                "bind",
            ),
            "https://login.test",
        )
        .unwrap_err();
    assert_eq!(
        unknown,
        AuthorizationError::HazardNotDisclosed {
            missing: HazardClass::UnverifiedFormContents,
            attempted_origin: "https://login.test".to_string(),
            required: Severity::new(MUTATE_DURABLE, true, true),
            required_hazards: [HazardClass::UnverifiedFormContents].into(),
        }
    );

    let unknown_grant = grant("unknown", &["https://login.test"])
        .with_disclosed_hazards([HazardClass::UnverifiedFormContents]);
    assert!(GrantStore::new([unknown_grant])
        .authorize(
            AuthorizationRequest::click_unverified(
                "conversation",
                Severity::new(COMPOSE, false, false),
                "invocation",
                "bind",
            ),
            "https://login.test",
        )
        .is_ok());
}
