use super::*;
use crate::cingulate_client::desk::{Ending, SecretUseRefusal};
use crate::cingulate_client::features::CingulateFeatures;

fn request() -> CardRequest {
    let params: Value = serde_json::from_slice(include_bytes!(
        "../../../tests/vectors/secret-use-v1/consent.request.secret_use.json"
    ))
    .unwrap();
    consent_request(
        CardKind::SecretUse,
        &json!({"params": params}),
        Duration::from_secs(123),
        Some("not-sent"),
        Some("not-sent"),
        Some("not-sent"),
    )
    .unwrap()
}

fn answer(decision: &str) -> Value {
    let mut answer = json!({"decision": decision, "items": [{"request_id": "01HF7YAT000000000000000001", "decision": decision}]});
    if decision == "allow" {
        answer["duration"] = json!("hour");
        answer["envelope_sha256"] =
            json!("7bcd68a3ec5698ad9c9d11e0efa1d67ef7e7aa6ee18c56d963d5f6b18014f180");
    }
    answer
}

#[test]
fn dedicated_filing_stays_closed_for_every_generic_feature_combination() {
    let expected =
        include_bytes!("../../../tests/vectors/secret-use-v1/consent.request.secret_use.json");
    for option_group in [false, true] {
        for single_use in [false, true] {
            for no_expiry in [false, true] {
                let card = request().for_features(CingulateFeatures {
                    option_group,
                    single_use,
                    no_expiry,
                    secret_use_approval: true,
                });
                assert_eq!(serde_json::to_vec(&card.params).unwrap(), expected);
            }
        }
    }
    for extra in [
        "title",
        "prompt",
        "facts",
        "options",
        "expires_in_ms",
        "late_execution",
        "requester_ref",
    ] {
        let mut params = request().params;
        params[extra] = json!("forbidden");
        assert!(consent_request(
            CardKind::SecretUse,
            &json!({"params": params}),
            Duration::ZERO,
            None,
            None,
            None
        )
        .is_err());
    }
    let mut params = request().params;
    params["kind"] = json!("consent");
    assert!(consent_request(
        CardKind::SecretUse,
        &json!({"params": params}),
        Duration::ZERO,
        None,
        None,
        None
    )
    .is_err());
}

#[tokio::test]
async fn missing_capability_and_filing_refusals_never_fall_back_to_generic_consent() {
    for (features, code, ending) in [
        (
            None,
            None,
            Ending::NoCard(NoCard::SecretUseRefused(
                SecretUseRefusal::MissingCapability,
            )),
        ),
        (
            Some(CingulateFeatures::default()),
            None,
            Ending::NoCard(NoCard::SecretUseRefused(
                SecretUseRefusal::MissingCapability,
            )),
        ),
        (
            Some(CingulateFeatures {
                secret_use_approval: true,
                ..Default::default()
            }),
            Some("elicitation_request_conflict"),
            Ending::NoCard(NoCard::SecretUseRefused(SecretUseRefusal::RequestConflict)),
        ),
        (
            Some(CingulateFeatures {
                secret_use_approval: true,
                ..Default::default()
            }),
            Some("elicitation_requester_refused"),
            Ending::NoCard(NoCard::SecretUseRefused(SecretUseRefusal::RequesterRefused)),
        ),
        (
            Some(CingulateFeatures {
                secret_use_approval: true,
                ..Default::default()
            }),
            Some("elicitation_expired"),
            Ending::NoAnswer,
        ),
    ] {
        let peer = ScriptedCingulate::new();
        peer.report_features(features);
        if let Some(code) = code {
            peer.then(wire::CONSENT_REQUEST, Reply::Refused(code));
        }
        let desk = ConsentDesk::new(Arc::new(peer.clone()));
        let (live, _) = live_call("sc_head_alf");
        let mut session = desk.session(&live).await.unwrap();
        assert_eq!(session.raise(request(), "subject").await, Err(ending));
        assert_eq!(peer.calls().len(), usize::from(code.is_some()));
        for (_, params) in peer.calls() {
            assert_eq!(params["kind"], "secret_use");
        }
    }
}

#[tokio::test]
async fn dedicated_answers_require_the_matching_single_item_and_binding() {
    let peer = ScriptedCingulate::new();
    peer.then(wire::CONSENT_REQUEST, created());
    let desk = ConsentDesk::new(Arc::new(peer));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    session
        .raise(
            request(),
            &subject::secret_use("conversation", "01HF7YAT000000000000000001"),
        )
        .await
        .unwrap();
    let card = desk.raised("el_1").unwrap();
    for (answer, expected) in [
        (
            answer("allow"),
            Ending::Granted {
                choice_id: "allow".into(),
            },
        ),
        (
            answer("decline"),
            Ending::Declined {
                choice_id: "decline".into(),
            },
        ),
    ] {
        let record = Record::parse(
            json!({"elicitation_id": "el_1", "state": "answered", "secret_use_answer": answer}),
        )
        .unwrap();
        assert_eq!(Ending::of_record(&record, &card), Some(expected));
    }
    let mut malformed = Vec::new();
    let mut omitted = answer("allow");
    omitted["items"] = json!([]);
    malformed.push(omitted);
    let mut wrong = answer("allow");
    wrong["items"][0]["request_id"] = json!("another");
    malformed.push(wrong);
    let mut no_hash = answer("allow");
    no_hash.as_object_mut().unwrap().remove("envelope_sha256");
    malformed.push(no_hash);
    let mut no_duration = answer("allow");
    no_duration.as_object_mut().unwrap().remove("duration");
    malformed.push(no_duration);
    for answer in malformed {
        let record = Record::parse(json!({"elicitation_id": "el_1", "state": "answered", "answered_choice_id": "allow", "secret_use_answer": answer})).unwrap();
        assert_eq!(Ending::of_record(&record, &card), Some(Ending::NoAnswer));
    }
    let generic = Record::parse(
        json!({"elicitation_id": "el_1", "state": "answered", "answered_choice_id": "allow"}),
    )
    .unwrap();
    assert_eq!(Ending::of_record(&generic, &card), Some(Ending::NoAnswer));
}

#[tokio::test]
async fn refiling_identical_items_accepts_the_same_card_id() {
    let peer = ScriptedCingulate::new();
    peer.then(wire::CONSENT_REQUEST, created())
        .then(wire::CONSENT_REQUEST, created());
    let desk = ConsentDesk::new(Arc::new(peer.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let first = session.raise(request(), "same").await.unwrap();
    let second = session.raise(request(), "same").await.unwrap();
    assert_eq!(first, second);
    assert_eq!(peer.calls()[0].1, peer.calls()[1].1);
    assert!(desk.raised(&first).is_some());
}

#[tokio::test(start_paused = true)]
async fn a_dedicated_approval_detaches_at_the_call_limit_without_an_expiry_override() {
    for hangs in [false, true] {
        let peer = ScriptedCingulate::new();
        peer.then(wire::CONSENT_REQUEST, created())
            .then(
                wire::CONSENT_AWAIT,
                if hangs {
                    Reply::Hang
                } else {
                    Reply::Result(pending())
                },
            )
            .then(
                wire::CONSENT_DETACH,
                Reply::Result(
                    json!({"elicitation_id": "el_1", "state": "pending", "detached": true}),
                ),
            );
        let desk = ConsentDesk::new(Arc::new(peer.clone()));
        let (live, _) = live_call("sc_head_alf");
        let mut session = desk.session(&live).await.unwrap();
        let id = session
            .raise(
                request(),
                &subject::secret_use("conversation", "01HF7YAT000000000000000001"),
            )
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        assert_eq!(
            session
                .park(&id, Duration::from_secs(120), std::future::pending())
                .await,
            InCall::Pending { ask_id: id }
        );
        assert!(started.elapsed() <= Duration::from_secs(120));
        assert_eq!(peer.calls()[0].1.as_object().unwrap().len(), 2);
        assert!(peer.calls()[0].1.get("expires_in_ms").is_none());
    }
}
