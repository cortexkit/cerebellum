use super::*;
use crate::cingulate_client::desk::{Ending, SecretUseRefusal};
use crate::cingulate_client::features::CingulateFeatures;

const FILER_VECTORS: &[(&str, &[u8], &str)] = &[
    (
        "filer-request.json",
        include_bytes!("../../../tests/vectors/secret-use-v1/filer-request.json"),
        "be75724519b10547d1baacdee20095f753130251b1519c10342ab19ed42364c9",
    ),
    (
        "filer-request-repeat.json",
        include_bytes!("../../../tests/vectors/secret-use-v1/filer-request-repeat.json"),
        "be75724519b10547d1baacdee20095f753130251b1519c10342ab19ed42364c9",
    ),
    (
        "filer-await-pending.json",
        include_bytes!("../../../tests/vectors/secret-use-v1/filer-await-pending.json"),
        "db39e1458276124efd66694d39f64e0ce34f0811c860b3ac4af2be6e6afbd0e6",
    ),
    (
        "filer-await-allowed.json",
        include_bytes!("../../../tests/vectors/secret-use-v1/filer-await-allowed.json"),
        "e5e665b918c4cb19750a8217457497c068eb4fb098df694da5f6dbd18511b286",
    ),
    (
        "filer-await-partial.json",
        include_bytes!("../../../tests/vectors/secret-use-v1/filer-await-partial.json"),
        "8ebc4ce81712071e97c1a53b471722c1ac83020ed468723b83fcb674785a6b99",
    ),
    (
        "filer-await-declined.json",
        include_bytes!("../../../tests/vectors/secret-use-v1/filer-await-declined.json"),
        "f49061b64579f5601883bd466aea4d0951915fc4e121c3e1390830003acc0c84",
    ),
    (
        "filer-await-expired.json",
        include_bytes!("../../../tests/vectors/secret-use-v1/filer-await-expired.json"),
        "95eb5015d42f4e3d059729696f12ac0bfc2447a6f74b24c450bef36a39b0a6c4",
    ),
    (
        "filer-refusals.json",
        include_bytes!("../../../tests/vectors/secret-use-v1/filer-refusals.json"),
        "66740bda26d96c0abd25e22244965209fcdee04e120bcd4d7214644e0580fa65",
    ),
];

fn filer(name: &str) -> Value {
    let (_, bytes, _) = FILER_VECTORS
        .iter()
        .find(|(file, ..)| *file == name)
        .unwrap();
    serde_json::from_slice(bytes).unwrap()
}

fn filer_result(name: &str) -> Value {
    wire::result_of(&serde_json::to_vec(&filer(name)["reply"]).unwrap()).unwrap()
}

#[test]
fn published_filer_replies_are_byte_pinned() {
    use sha2::{Digest, Sha256};
    for (name, bytes, hash) in FILER_VECTORS {
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), *hash, "{name}");
    }
}

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
async fn dedicated_answers_require_matching_items_and_valid_allow_metadata() {
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

#[tokio::test]
async fn published_filer_records_decode_pending_allow_decline_expiry_and_partial_items() {
    let peer = ScriptedCingulate::new();
    for name in ["filer-request.json", "filer-request-repeat.json"] {
        let sample = filer(name);
        assert_eq!(sample["method"], wire::CONSENT_REQUEST);
        assert_eq!(
            serde_json::to_vec(&sample["params"]).unwrap(),
            include_bytes!("../../../tests/vectors/secret-use-v1/consent.request.secret_use.json")
        );
        peer.then(
            wire::CONSENT_REQUEST,
            Reply::Result(sample["reply"]["result"].clone()),
        );
    }
    let desk = ConsentDesk::new(Arc::new(peer.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let subject = subject::secret_use("conversation", "01HF7YAT000000000000000001");
    let first = session.raise(request(), &subject).await.unwrap();
    assert_eq!(session.raise(request(), &subject).await.unwrap(), first);
    assert_eq!(first, "el_1");
    let mut card = desk.raised(&first).unwrap();
    for (name, expected) in [
        ("filer-await-pending.json", None),
        (
            "filer-await-allowed.json",
            Some(Ending::Granted {
                choice_id: "allow".into(),
            }),
        ),
        (
            "filer-await-declined.json",
            Some(Ending::Declined {
                choice_id: "decline".into(),
            }),
        ),
        ("filer-await-expired.json", Some(Ending::NoAnswer)),
    ] {
        let sample = filer(name);
        assert_eq!(sample["method"], wire::CONSENT_AWAIT);
        let record = Record::parse(filer_result(name)).unwrap();
        assert_eq!(record.elicitation_id, first);
        assert_eq!(Ending::of_record(&record, &card), expected, "{name}");
        if name == "filer-await-declined.json" {
            assert_eq!(record.state, wire::CardState::Answered);
            assert_eq!(record.answered_choice_id.as_deref(), Some("decline"));
        }
        if name == "filer-await-expired.json" {
            assert_eq!(record.state, wire::CardState::Expired);
        }
    }
    let partial = Record::parse(filer_result("filer-await-partial.json")).unwrap();
    assert_eq!(
        Ending::of_record(&partial, &card),
        Some(Ending::Granted {
            choice_id: "allow".into()
        })
    );
    card.subject = subject::secret_use("conversation", "01HF7YAT000000000000000002");
    assert_eq!(
        Ending::of_record(&partial, &card),
        Some(Ending::Declined {
            choice_id: "decline".into()
        })
    );
    assert_eq!(peer.calls()[0].1, peer.calls()[1].1);
}

#[tokio::test]
async fn every_published_filer_refusal_is_typed() {
    let samples = filer("filer-refusals.json");
    let cases = samples["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        let expected = match case["name"].as_str().unwrap() {
            "agent-mismatch" | "non-canonical" => SecretUseRefusal::InvalidRequest,
            "request-conflict" => SecretUseRefusal::RequestConflict,
            "broca-refused" => SecretUseRefusal::RequesterRefused,
            other => panic!("unrecognized refusal fixture {other}"),
        };
        let body = serde_json::to_vec(&case["reply"]["error"]).unwrap();
        let decoded = wire::Refusal::from_error_body(&body).unwrap();
        assert_eq!(
            decoded.message,
            case["reply"]["error"]["message"].as_str().unwrap()
        );
        let peer = ScriptedCingulate::new();
        peer.then(wire::CONSENT_REQUEST, Reply::ErrorBody(body));
        let desk = ConsentDesk::new(Arc::new(peer));
        let (live, _) = live_call("sc_head_alf");
        let mut session = desk.session(&live).await.unwrap();
        assert_eq!(
            session.raise(request(), "subject").await,
            Err(Ending::NoCard(NoCard::SecretUseRefused(expected)))
        );
    }
}
