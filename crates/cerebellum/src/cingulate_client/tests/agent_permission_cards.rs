//! Exact request parameters exported for the phone UI and consent validator.

use super::*;
use crate::agent_grants::GrantHolder;
use crate::authorization::Severity;
use crate::consent_card::Urgency;
use crate::management::BrowserGrantChoice;

fn holder(head: bool) -> GrantHolder {
    if head {
        GrantHolder::Head {
            agent_id: "agent-golden".into(),
        }
    } else {
        GrantHolder::Worker {
            agent_id: "agent-golden".into(),
            scope_ref: "worker-golden".into(),
        }
    }
}

fn exported() -> Vec<(String, CardRequest)> {
    let mut result = Vec::new();
    for head in [true, false] {
        let prefix = if head { "head" } else { "worker" };
        for (kind, name, body, deadline) in cards_with_standing(head) {
            result.push((
                format!("{prefix}-{name}"),
                request_for(kind, &body, deadline),
            ));
        }
        let origins = vec!["https://example.com".into()];
        let choices = crate::permission_cards::browser_choices(
            &origins,
            &Default::default(),
            Severity::new(3, false, false),
            Some(&holder(head)),
            true,
        );
        for (kind, name, urgency) in [
            (
                CardKind::WebsiteAccessInCall,
                "website-public-in-call",
                Urgency::High,
            ),
            (
                CardKind::WebsiteAccessInAdvance,
                "website-public-in-advance",
                Urgency::Normal,
            ),
        ] {
            let body = crate::management::browser_grant_question(
                &origins,
                &[],
                Severity::new(3, false, false),
                urgency,
                &choices,
            );
            result.push((
                format!("{prefix}-{name}.json"),
                request_for(kind, &body, crate::management::PHONE_CONSENT_DEADLINE),
            ));
        }
        for (tier, name) in [(1, "user-browser-ordinary"), (3, "user-browser-public")] {
            let body = crate::user_browser::site_question_with_choices(
                &origins[0],
                tier,
                &Default::default(),
                &crate::permission_cards::user_browser_choices(
                    &origins,
                    &Default::default(),
                    Severity::new(tier, false, false),
                    Some(&holder(head)),
                    true,
                ),
            );
            result.push((
                format!("{prefix}-{name}.json"),
                request_for(CardKind::UserBrowserSite, &body, USER_BROWSER_SITE_DEADLINE),
            ));
        }
    }
    for head in [true, false] {
        let prefix = if head { "head" } else { "worker" };
        for (kind, name, body, deadline) in cards_with_standing(head) {
            if matches!(kind, CardKind::LoginCapture | CardKind::LoginImport) {
                let card = request_for(kind, &body, deadline).for_features(
                    crate::cingulate_client::features::CingulateFeatures {
                        option_group: true,
                        single_use: true,
                        no_expiry: false,
                    },
                );
                result.push((
                    format!(
                        "{prefix}-{}-single-use.json",
                        name.trim_end_matches(".json")
                    ),
                    card,
                ));
            }
        }
    }
    result
}

#[test]
fn exported_permission_cards_match_goldens_and_fail_closed() {
    use sha2::{Digest, Sha256};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/agent-permission-cards");
    let write = std::env::var_os("CEREBELLUM_WRITE_AGENT_PERMISSION_CARDS").is_some();
    let mut sums = String::new();
    let cards = exported();
    assert_eq!(cards.len(), 30);
    for (name, card) in cards {
        assert_eq!(
            card.params.get("single_use") == Some(&serde_json::Value::Bool(true)),
            name.ends_with("-single-use.json"),
            "{name}"
        );
        assert_eq!(card.params["default"], card.decline_id, "{name}");
        assert_eq!(card.params["on_expiry"], "deny", "{name}");
        crate::consent_card::core_verdict(&card.params)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        let options = card.params["options"].as_array().unwrap();
        let safe = options
            .iter()
            .filter(|o| o["effect"] == "grant" && o["group"] != "danger")
            .count();
        assert!(safe > 0, "{name}");
        for option in options {
            let id = option["id"].as_str().unwrap();
            if id.starts_with("computer_") || id.starts_with("allow_all_sites_") {
                assert_eq!(option["group"], "danger", "{name}: {id}");
            }
            if option["group"] == "danger" {
                assert!(
                    option["detail"]
                        .as_str()
                        .is_some_and(|detail| !detail.trim().is_empty()),
                    "{name}: {id} needs a danger explanation"
                );
                assert_eq!(
                    option["detail"],
                    if id.starts_with("computer_") {
                        "Covers every app, including taking over your mouse and keyboard."
                    } else {
                        "Covers every public site. Sign-in and payment pages still ask."
                    }
                );
            }
            if name.starts_with("worker-") {
                assert!(!id.contains("always"), "{name}: {id}");
            }
        }
        let bytes = format!("{}\n", serde_json::to_string_pretty(&card.params).unwrap());
        if write {
            std::fs::write(dir.join(&name), &bytes).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(dir.join(&name)).unwrap(),
            bytes,
            "{name}"
        );
        sums.push_str(&format!("{:x}  {name}\n", Sha256::digest(bytes.as_bytes())));
    }
    if write {
        std::fs::write(dir.join("SHA256SUMS"), &sums).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap(),
        sums
    );
}

#[test]
fn cingulate_single_use_vectors_pin_the_login_export_shape() {
    use sha2::{Digest, Sha256};

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/consent-outcomes-refs-v1");
    let expected_pins = [
        (
            "single-use-non-boolean-refusal.json",
            "dbe1bb1c9f68e29419981ebcdeb75fe2f2cb3d3f4837c3cf9fb42afa9700a00f",
        ),
        (
            "single-use-non-consent-refusal.json",
            "dabe84da799654860a7bbdf11767f636fe1b51a870bb9ccfdc1e630bc5cc5ba0",
        ),
        (
            "single-use-outcomes-reply.json",
            "ddae72b743dd126ea4c795929185a5109d9313c91082ca1c3c1476035996945b",
        ),
        (
            "single-use-reply.json",
            "94c32b237b1a464812b81872e515537703e4140418158866cec6db06a78a0c74",
        ),
        (
            "single-use-request.json",
            "c439d04e5b2cbf1bd103b6b386c0d8a4040d3c76a742ad34a3fd4dbdbaba4c6c",
        ),
    ];
    let mut sums = String::new();
    for (name, expected) in expected_pins {
        let bytes = std::fs::read(dir.join(name)).unwrap();
        let actual = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(actual, expected, "{name}");
        sums.push_str(&format!("{actual}  {name}\n"));
    }
    assert_eq!(
        std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap(),
        sums
    );

    let request: Value =
        serde_json::from_slice(&std::fs::read(dir.join("single-use-request.json")).unwrap())
            .unwrap();
    let params = &request["params"];
    assert_eq!(params["kind"], "consent");
    assert_eq!(params["single_use"], true);
    assert_eq!(params["requester_ref"], "call-single-use");
    assert_single_use_position(params, "Cingulate request vector");

    let reply: Value =
        serde_json::from_slice(&std::fs::read(dir.join("single-use-reply.json")).unwrap()).unwrap();
    assert_eq!(reply["result"]["elicitation_id"], "el_1");
    let outcomes: Value =
        serde_json::from_slice(&std::fs::read(dir.join("single-use-outcomes-reply.json")).unwrap())
            .unwrap();
    let outcome = &outcomes["result"]["records"][0];
    assert_eq!(outcome["kind"], "consent");
    assert_eq!(outcome["single_use"], true);
    assert_eq!(outcome["requester_ref"], params["requester_ref"]);
    assert!(outcome.get("late").is_none());

    let login_exports: Vec<_> = exported()
        .into_iter()
        .filter(|(name, _)| name.ends_with("-single-use.json"))
        .collect();
    assert_eq!(login_exports.len(), 4);
    for (name, card) in login_exports {
        assert_eq!(card.params["kind"], params["kind"], "{name}");
        assert!(card.params["requester_ref"].is_string(), "{name}");
        assert_eq!(card.params["single_use"], params["single_use"], "{name}");
        assert_single_use_position(&card.params, &name);
    }
}

fn assert_single_use_position(params: &Value, context: &str) {
    let keys: Vec<_> = params
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let position = keys
        .iter()
        .position(|key| *key == "single_use")
        .unwrap_or_else(|| panic!("{context}: single_use is not a top-level request field"));
    assert_eq!(
        keys.get(position.wrapping_sub(1)),
        Some(&"scope"),
        "{context}"
    );
    assert_eq!(keys.get(position + 1), Some(&"target"), "{context}");
}

#[test]
fn cingulate_single_use_refusal_vectors_match_the_closed_request_checker() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/consent-outcomes-refs-v1");
    let request: Value =
        serde_json::from_slice(&std::fs::read(dir.join("single-use-request.json")).unwrap())
            .unwrap();
    let non_consent: Value = serde_json::from_slice(
        &std::fs::read(dir.join("single-use-non-consent-refusal.json")).unwrap(),
    )
    .unwrap();
    let mut params = request["params"].clone();
    params["kind"] = json!("package");
    let refusal = crate::consent_card::core_verdict(&params).unwrap_err();
    assert_eq!(refusal.code, non_consent["code"]);
    assert_eq!(refusal.message, non_consent["message"]);

    let non_boolean: Value = serde_json::from_slice(
        &std::fs::read(dir.join("single-use-non-boolean-refusal.json")).unwrap(),
    )
    .unwrap();
    params = request["params"].clone();
    params["single_use"] = json!("yes");
    let refusal = crate::consent_card::core_verdict(&params).unwrap_err();
    assert_eq!(refusal.code, non_boolean["code"]);
    assert_eq!(refusal.message, non_boolean["message"]);
}

#[test]
fn danger_vectors_exercise_the_production_mapper_and_local_verdict() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/danger-option-group-v1");
    for name in [
        "file-card",
        "refuse-danger-default",
        "refuse-only-danger-grants",
        "refuse-unknown-group",
    ] {
        let vector: Value =
            serde_json::from_slice(&std::fs::read(dir.join(format!("{name}.json"))).unwrap())
                .unwrap();
        let params = &vector["request"];
        let mapped = consent_request(
            CardKind::AppControl,
            &json!({"params":params}),
            Duration::from_secs(60),
            None,
            None,
            None,
        );
        let verdict = crate::consent_card::core_verdict(params);
        if name == "file-card" {
            assert!(mapped.is_ok(), "{name}: {mapped:?}");
            assert!(verdict.is_ok(), "{name}: {verdict:?}");
        } else {
            assert!(mapped.is_err(), "{name}: mapper admitted forbidden card");
            assert_eq!(verdict.unwrap_err().code, vector["error"]["code"], "{name}");
        }
    }
}

#[test]
fn mapper_refuses_a_grant_default_or_expiry_allow() {
    let (_, _, body, deadline) = todays_cards().remove(0);
    let mut grant_default = body.clone();
    grant_default["params"]["default"] = json!("allow_30m");
    assert!(consent_request(
        CardKind::WebsiteAccessInCall,
        &grant_default,
        deadline,
        None,
        None,
        None
    )
    .is_err());
    let mut expiry_allow = body;
    expiry_allow["params"]["on_expiry"] = json!("allow");
    assert!(consent_request(
        CardKind::WebsiteAccessInCall,
        &expiry_allow,
        deadline,
        None,
        None,
        None
    )
    .is_err());
}

#[test]
fn site_choices_limit_worker_lifetimes_and_withhold_all_sites_for_hazards_private_or_tier_four() {
    let worker = holder(false);
    let head = holder(true);
    let ordinary = Severity::new(3, false, false);
    let choices = |origin: &str, severity, hazards, holder| {
        crate::permission_cards::browser_choices(&[origin.into()], &hazards, severity, holder, true)
    };
    assert_eq!(
        choices(
            "https://example.com",
            ordinary,
            Default::default(),
            Some(&worker)
        ),
        vec![
            BrowserGrantChoice::SiteThirtyMinutes,
            BrowserGrantChoice::AllSitesThirtyMinutes
        ]
    );
    for (origin, severity, hazards) in [
        (
            "https://example.com",
            Severity::new(4, false, false),
            Default::default(),
        ),
        (
            "https://example.com",
            Severity::new(3, true, false),
            Default::default(),
        ),
        (
            "https://example.com",
            Severity::new(3, false, true),
            Default::default(),
        ),
        (
            "https://example.com",
            ordinary,
            std::collections::BTreeSet::from([
                crate::authorization::HazardClass::UnverifiedFormContents,
            ]),
        ),
        ("http://localhost", ordinary, Default::default()),
        ("http://10.0.0.5", ordinary, Default::default()),
        ("http://[::1]", ordinary, Default::default()),
    ] {
        assert_eq!(
            choices(origin, severity, hazards, Some(&head)),
            vec![
                BrowserGrantChoice::SiteThirtyMinutes,
                BrowserGrantChoice::OriginAlways
            ],
            "{origin}: {severity:?}"
        );
    }
    assert!(choices("https://example.com", ordinary, Default::default(), None).is_empty());
    assert!(crate::permission_cards::browser_choices(
        &["https://example.com".into()],
        &Default::default(),
        ordinary,
        Some(&head),
        false
    )
    .is_empty());
}

#[test]
fn user_browser_cards_never_offer_all_sites_or_danger() {
    for head in [true, false] {
        let origins = vec!["https://example.com".into()];
        let identity = holder(head);
        let choices = crate::permission_cards::user_browser_choices(
            &origins,
            &Default::default(),
            Severity::new(3, false, false),
            Some(&identity),
            true,
        );
        assert_eq!(
            choices,
            if head {
                vec![
                    BrowserGrantChoice::SiteThirtyMinutes,
                    BrowserGrantChoice::OriginAlways,
                ]
            } else {
                vec![BrowserGrantChoice::SiteThirtyMinutes]
            }
        );
        let broad = crate::management::offered_browser_grant_choices(
            &origins,
            &Default::default(),
            Severity::new(3, false, false),
            true,
        );
        let body = crate::user_browser::site_question_with_choices(
            &origins[0],
            3,
            &Default::default(),
            &broad,
        );
        assert!(body["params"]["options"]
            .as_array()
            .unwrap()
            .iter()
            .all(|option| option["group"].is_null()
                && !option["id"].as_str().unwrap().contains("all_sites")));
    }
    for (name, card) in exported()
        .into_iter()
        .filter(|(_, card)| card.kind == CardKind::UserBrowserSite)
    {
        assert!(
            card.params["options"]
                .as_array()
                .unwrap()
                .iter()
                .all(|option| option["group"].is_null()
                    && !option["id"].as_str().unwrap().contains("all_sites")),
            "{name}"
        );
    }
}

#[tokio::test]
async fn profile_site_answers_keep_the_row_id_and_bind_worker_choices_before_filing() {
    let store = Arc::new(crate::agent_grants::AgentGrants::in_memory(Some(
        "machine-test".into(),
    )));
    let plane = crate::management::ManagementPlane::new(Arc::new(
        crate::management::PlatformResolver::new(),
    ))
    .with_agent_grants(store.clone());
    for (head, temporary, permanent) in [
        (true, "allow_30m", Some("allow_origin_always")),
        (true, "allow_all_sites_30m", Some("allow_all_sites_always")),
        (false, "allow_30m", None),
        (false, "allow_all_sites_30m", None),
    ] {
        let identity = holder(head);
        let choices: Vec<&str> = std::iter::once(temporary).chain(permanent).collect();
        let mut id = None;
        let before = store.live_rows(None, store.now_ms()).unwrap().len();
        for (round, choice) in choices.iter().enumerate() {
            let (_, mut question) = plane
                .open_browser_grant_at_tier(
                    "conversation",
                    vec!["https://example.com".into()],
                    vec![],
                    Some(3),
                    true,
                    None,
                )
                .await
                .unwrap();
            let question = question.as_mut().unwrap();
            question.bind_holder(Some(identity.clone())).unwrap();
            let offered = question.body["params"]["options"].as_array().unwrap();
            assert!(offered.iter().any(|option| option["id"] == *choice));
            if !head {
                assert!(!offered
                    .iter()
                    .any(|option| option["id"].as_str().unwrap().contains("always")));
            }
            plane.record_prepared_consent(question, &question.ask_id);
            let result = plane
                .settle_browser_grant_outcome(
                    &question.ask_id,
                    Some(&Ending::Granted {
                        choice_id: (*choice).into(),
                    }),
                )
                .await;
            assert!(
                matches!(
                    result,
                    crate::management::BrowserGrantSettlement::Granted(_)
                ),
                "{result:?}"
            );
            let rows = store.live_rows(None, store.now_ms()).unwrap();
            assert_eq!(rows.len(), before + 1);
            let row = rows
                .iter()
                .find(|row| {
                    row.holder == identity
                        && (row.subject == crate::agent_grants::GrantSubject::AllSites)
                            == temporary.contains("all_sites")
                })
                .unwrap();
            if let Some(id) = &id {
                assert_eq!(&row.id, id);
            } else {
                id = Some(row.id.clone());
            }
            assert_eq!(row.expires_at_ms.is_none(), round == 1);
            if round == 0 {
                assert_eq!(row.expires_at_ms, Some(row.granted_at_ms + 1_800_000));
            }
        }
    }
}

#[tokio::test]
async fn stripped_profile_danger_answers_never_mint_a_row() {
    let store = Arc::new(crate::agent_grants::AgentGrants::in_memory(Some(
        "machine-test".into(),
    )));
    let plane = crate::management::ManagementPlane::new(Arc::new(
        crate::management::PlatformResolver::new(),
    ))
    .with_agent_grants(store.clone());
    let (_, mut question) = plane
        .open_browser_grant_at_tier(
            "conversation",
            vec!["https://example.com".into()],
            vec![],
            Some(3),
            true,
            Some("head"),
        )
        .await
        .unwrap();
    let question = question.as_mut().unwrap();
    question.bind_holder(Some(holder(true))).unwrap();
    plane.record_prepared_consent(question, &question.ask_id);
    assert_eq!(
        plane
            .settle_browser_grant_outcome(
                &question.ask_id,
                Some(&Ending::Declined {
                    choice_id: "allow_all_sites_30m".into()
                })
            )
            .await,
        crate::management::BrowserGrantSettlement::UnrecognizedAnswer
    );
    assert!(store.live_rows(None, store.now_ms()).unwrap().is_empty());
}
