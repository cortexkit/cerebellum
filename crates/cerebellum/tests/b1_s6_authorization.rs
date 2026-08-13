use cerebellum::authorization::{
    effective_severity, Action, ActionGrant, AuthorizationDeniedDetail, AuthorizationRequest,
    GrantStore, Severity, COMPOSE, MUTATE_DURABLE, OBSERVE,
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
        Err(cerebellum::authorization::AuthorizationCommitError::GrantReplaced)
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
    assert_eq!(
        error,
        cerebellum::authorization::AuthorizationError::NoGrant
    );
    assert_eq!(
        Action::Navigate.floor(),
        Severity::new(OBSERVE, false, false)
    );

    let _ = effective_severity;
}

/// Nothing in production mints an `ActionGrant`, so every authorized browser
/// action is refused for want of a covering grant.  That is fail-closed and
/// deliberate: consent for an act-on-world capability must be attributable to a
/// human decision at a point in time, and no such path exists yet.
///
/// This test exists to redden on the day someone builds one, because the grant
/// that path mints carries a requirement that is invisible from the mint site.
/// The failure message is the delivery mechanism for it.
///
/// The scan skips exactly the brace-balanced extent of each `#[cfg(test)]`
/// module rather than everything following the marker, because top-level code
/// placed after a test module is production code and a marker-offset scan reads
/// it as test code -- a blind spot measured with a mutation, not assumed.
#[test]
fn no_production_path_mints_an_action_grant() {
    let mut wired: Vec<String> = Vec::new();

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            let mut in_test_module = false;
            let mut depth: i32 = 0;
            for (index, line) in text.lines().enumerate() {
                if !in_test_module && line.trim_start().starts_with("#[cfg(test)]") {
                    in_test_module = true;
                    depth = 0;
                    continue;
                }
                if in_test_module {
                    depth += line.matches('{').count() as i32;
                    depth -= line.matches('}').count() as i32;
                    if depth <= 0 && line.contains('}') {
                        in_test_module = false;
                    }
                    continue;
                }
                for ctor in ["ActionGrant::new", "GrantStore::new"] {
                    if line.contains(ctor) {
                        wired.push(format!(
                            "{}:{} calls {ctor}",
                            path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                                .unwrap_or(&path)
                                .display(),
                            index + 1
                        ));
                    }
                }
            }
        }
    }

    assert!(
        wired.is_empty(),
        "A production path now mints browser action grants:\n  {}\n\n\
         Before this ships, the minting path must carry the disclosure scope \
         ruled on 2026-08-13, because the hazard is a property of the TARGET \
         while the grant is issued AHEAD of the action:\n\
         \x20 1. The grant carries a SET of disclosed hazard classes, not a \
         boolean.  `unverified_form_contents` is its own member: a grant \
         covering `credential_form_submit` must NOT cover a form whose \
         classification could not be determined.  Unknown is a distinct thing \
         to consent to.\n\
         \x20 2. Coverage is subset semantics — the target's classified hazards \
         must be a subset of the grant's disclosed hazards, evaluated at \
         dispatch against the pinned snapshot's classification so the existing \
         TOCTOU revalidation fences it.\n\
         \x20 3. A dispatch refusal must NAME the missing hazard class.  The \
         refusal is what triggers re-elicitation, and an error carrying the \
         fact needed to act keeps that loop one round instead of a guess.\n\
         \x20 4. Mint-time text renders the hazard set verbatim to the human, so \
         the wire and the words cannot drift.\n\n\
         Grants are minted through the same elicitation machinery the computer \
         plane uses (elicit.rs + AskRegistry), never carried on config or bind: \
         consent must be attributable to a human decision at a point in time.\n\n\
         If you are wiring this deliberately and have satisfied the above, \
         update this test to assert the disclosure scope instead of deleting it.",
        wired.join("\n  ")
    );
}
