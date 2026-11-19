use cortexkit_role_tool_provider::vectors::late_result_ready::FILES;

use super::*;

fn sample(case: &str, file: &str) -> &'static str {
    FILES
        .iter()
        .find(|(path, _)| *path == format!("{case}/{file}"))
        .unwrap()
        .1
}

#[tokio::test]
async fn late_result_ready_matches_packaged_samples() {
    let (publisher, fake) = publisher();
    for (case, call_key, event_id, outcome) in [
        ("ok", "call:ok", "settlement:1", "ok"),
        ("error", "call:error", "settlement:2", "tool_denied"),
        ("unknown", "call:unknown", "settlement:3", "unknown"),
    ] {
        publisher.late_result("reserved:reader", call_key, event_id, outcome);
        settle().await;
        let writes = fake.writes.lock().unwrap();
        let actual = writes.last().unwrap();
        // The samples use a generic provider and omit the account namespace.
        let subject = format!(
            "ck.test.{}",
            sample(case, "subject.txt")
                .strip_suffix('\n')
                .unwrap()
                .replacen("event.provider.", "event.cerebellum.", 1)
        );
        assert_eq!(
            actual.kind.subject("test").unwrap().as_bytes(),
            subject.as_bytes(),
            "{case}"
        );
        assert_eq!(
            actual.bytes,
            sample(case, "payload.json").as_bytes(),
            "{case}"
        );
        assert_eq!(
            actual.id.as_bytes(),
            sample(case, "nats-msg-id.txt")
                .strip_suffix('\n')
                .unwrap()
                .as_bytes(),
            "{case}"
        );
    }
    assert_eq!(fake.writes.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn invalid_custodians_never_publish_a_broadcast_hint() {
    let (publisher, fake) = publisher();
    for principal in [
        "direct",
        "reserved:",
        "reserved:reader.*",
        "reserved:reader.>",
    ] {
        publisher.late_result(principal, "call:ok", "settlement:1", "ok");
    }
    settle().await;
    assert!(fake.writes.lock().unwrap().is_empty());
    assert_eq!(publisher.gauges.failed.load(Relaxed), 4);
    assert_eq!(publisher.gauges.published.load(Relaxed), 0);
    assert_eq!(
        publisher.gauges.last_failure.load(Relaxed),
        Failure::Unavailable as u8
    );
}

#[tokio::test]
async fn resumed_notices_use_settled_codes_and_the_pulled_event_id() {
    use crate::journal::call_records::{
        Begin, CallRecords, HandoffEnding, InMemoryCallRecordStorage, ScopeIdentity,
    };
    use cortexkit_role_tool_provider::late_results::LateResultsRequest;
    use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};

    for (frame_type, body, outcome) in [
        (
            FrameType::Response,
            json!({"isError":false,"content":[]}),
            "ok",
        ),
        (
            FrameType::Response,
            json!({"outcome":"login_observed"}),
            "ok",
        ),
        (
            FrameType::Response,
            json!({"isError":false,"structuredContent":{"outcome":"completed"}}),
            "ok",
        ),
        (
            FrameType::Response,
            json!({"isError":true,"errorCode":"tool_denied","structuredContent":{"outcome":"refused"}}),
            "tool_denied",
        ),
        (
            FrameType::Error,
            json!({"code":"protocol_denied"}),
            "protocol_denied",
        ),
        (
            FrameType::Response,
            json!({"outcome":"outcome_unknown"}),
            "unknown",
        ),
        (FrameType::Response, json!({"isError":true}), "unknown"),
        (FrameType::Response, json!({}), "unknown"),
    ] {
        let calls = CallRecords::open(Box::new(InMemoryCallRecordStorage::new()), 100);
        let fake = Arc::new(Fake::default());
        calls.events.connect(Arc::new(fake.clone()));
        let owner = "reserved:prefrontal";
        assert!(matches!(
            calls.begin(owner, "call:resume", "scope", 100),
            Begin::Execute(_)
        ));
        calls
            .hold_handoff(
                owner,
                "call:resume",
                "handoff",
                ScopeIdentity {
                    owner: owner.into(),
                    reference: "scope".into(),
                    scope_epoch: 1,
                },
                "https://login.example",
                100,
            )
            .unwrap();
        calls
            .finish_handoff(owner, "call:resume", HandoffEnding::Unknown, 101)
            .unwrap();
        let initial = calls
            .late_results(owner, &LateResultsRequest::new(), 101)
            .unwrap();
        settle().await;
        fake.writes.lock().unwrap().clear();
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            frame_type,
            Flags::new(false, Priority::Interactive, false),
            1,
            1,
            7,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        calls
            .finish_browser_request(owner, "call:resume", frame, false, 102)
            .unwrap();
        settle().await;
        let writes = fake.writes.lock().unwrap();
        assert_eq!(writes.len(), 1, "{body}");
        assert_eq!(
            writes[0].id,
            format!("{}:prefrontal", initial.entries[0].event_id)
        );
        assert_eq!(
            writes[0].bytes,
            format!(r#"{{"call_key":"call:resume","outcome":"{outcome}"}}"#).as_bytes(),
            "{body}"
        );
    }
}
