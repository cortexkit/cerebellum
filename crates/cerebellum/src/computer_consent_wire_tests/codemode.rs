use super::*;
use cerebellum_computer::app_state::source::{
    AppStateReadError, AppStateSource, ElementActionError, ElementHandle, RawAppState, ReadBounds,
};

struct NoFocusedField;
impl AppStateSource for NoFocusedField {
    fn read_app_state(
        &self,
        _: &ProcessGrant,
        _: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        Ok(RawAppState {
            roots: Vec::new(),
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        })
    }
    fn focused_element(
        &self,
        _: &ProcessGrant,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        Ok(None)
    }
}

fn run_request(corr: u64, body: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        control_flags(),
        9,
        3,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

async fn interrupted_keys(goodbye: bool) {
    let mut planes = crate::call_mode_tests::bound_run().await;
    planes.management = Arc::new(ManagementPlane::new(Arc::new(Running)).with_agent_grants(
        Arc::new(agent_grants::AgentGrants::in_memory(Some(
            "test-machine".into(),
        ))),
    ));
    crate::call_mode_tests::seed_app(&planes, APP);
    Arc::make_mut(&mut planes.computer_admitted).insert("computer.keys".into());
    let sequence = Arc::new(computer_capability::turn_stop_driver::Sequence::default());
    let script = sequence.clone();
    planes.computer_for_test = Some(Arc::new(
        computer_capability::ComputerPlane::with_synthetic_driver(
            computer_capability::computer_audit(JournalPersistence::Isolated).unwrap(),
            move || computer_capability::turn_stop_driver::Driver::scripted(script.clone()),
        )
        .with_permission_liveness(computer_capability::live_for_test())
        .with_session_lock_for_test(Some(false))
        .with_app_state_source(Arc::new(NoFocusedField)),
    ));
    let (tx, mut rx) = mpsc::channel(8);
    handle_frame_for_test(
        run_request(
            50,
            json!({"name":"computer_use","call_key":"active-keys","arguments":{
        "action":"keys","target":APP,"keys":["shift","a"]}}),
        ),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    tokio::select! {
        _ = sequence.posted.notified() => {},
        early = rx.recv() => panic!("keys must reach the fake platform: {}", String::from_utf8_lossy(&early.unwrap().body)),
        _ = tokio::time::sleep(HANG_GUARD) => panic!("keys never reached their second press"),
    }
    if goodbye {
        let close = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Goodbye,
            control_flags(),
            9,
            3,
            0,
            vec![],
        )
        .unwrap();
        handle_frame_for_test(close, &tx, &planes).await.unwrap();
        settle_to(&planes, (0, 0)).await;
        let terminal: Value = serde_json::from_slice(
            &rx.try_recv()
                .expect("started input has an honest terminal outcome")
                .body,
        )
        .unwrap();
        assert_eq!(
            terminal["outcome"], "dispatch_outcome_unknown",
            "{terminal}"
        );
        assert_eq!(terminal["detail"]["held_state"], "released", "{terminal}");
        assert!(
            planes.routes.get(8, 3).is_some(),
            "the head survives run teardown"
        );
    } else {
        handle_frame_for_test(
            run_request(
                51,
                json!({"name":"tool.withdraw","arguments":{"call_key":"active-keys"}}),
            ),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let mut replies = Vec::new();
        for _ in 0..2 {
            replies.push(
                tokio::time::timeout(HANG_GUARD, rx.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        let withdrawal: Value = serde_json::from_slice(
            &replies
                .iter()
                .find(|reply| reply.header.corr == 51)
                .unwrap()
                .body,
        )
        .unwrap();
        assert_eq!(withdrawal["answer"], "already_started", "{withdrawal}");
        let result: Value = serde_json::from_slice(
            &replies
                .iter()
                .find(|reply| reply.header.corr == 50)
                .unwrap()
                .body,
        )
        .unwrap();
        assert_eq!(result["outcome"], "dispatch_outcome_unknown", "{result}");
        assert_eq!(result["detail"]["held_state"], "released", "{result}");
        settle_to(&planes, (0, 0)).await;
    }
    assert_eq!(
        *sequence.events.lock().unwrap(),
        [(0, false), (1, false), (3, true), (2, true)]
    );
}

#[tokio::test]
async fn run_withdraw_releases_active_keys_and_never_claims_withdrawn() {
    interrupted_keys(false).await;
}

#[tokio::test]
async fn run_goodbye_releases_active_keys_without_ending_head() {
    interrupted_keys(true).await;
}
