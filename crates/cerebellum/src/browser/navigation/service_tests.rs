use super::tests::FakePipe;
use super::*;
use serde_json::json;

fn driver(frames: impl IntoIterator<Item = Value>) -> CdpNavigationDriver<FakePipe> {
    let mut driver = CdpNavigationDriver::new(
        FakePipe::with_frames(frames),
        CdpTransport::new(),
        CdpFrameDecoder::default(),
    );
    driver.enable_connection_service();
    driver.attachment = Some(AttachedTarget {
        target_id: "main".into(),
        session_id: "session".into(),
        context_key: "context".into(),
    });
    driver
        .identities
        .attach(Attachment {
            target_id: "main".into(),
            session_id: "session".into(),
            context_key: "context".into(),
            frame_ids: vec![],
        })
        .unwrap();
    driver
}

fn event(method: &str, params: Value) -> Value {
    json!({"method":method,"sessionId":"session","params":params})
}
fn commit(frame: &str, loader: &str) -> Value {
    event(
        "Page.frameNavigated",
        json!({"frame":{"id":frame,"loaderId":loader,"url":format!("https://example.test/{loader}")}}),
    )
}

#[test]
fn idle_events_update_current_frames_and_dialogs_without_dispatching_commands() {
    let mut driver = driver([
        commit("main", "old"),
        event(
            "Page.frameNavigated",
            json!({"frame":{"id":"child","parentId":"main","loaderId":"child-old","url":"https://example.test/child"}}),
        ),
        event(
            "Target.attachedToTarget",
            json!({"sessionId":"child-session","targetInfo":{"type":"iframe","targetId":"child"}}),
        ),
        event("Page.javascriptDialogOpening", json!({"type":"confirm"})),
        event(
            "Target.detachedFromTarget",
            json!({"sessionId":"child-session"}),
        ),
        commit("main", "new"),
        event("Page.loadEventFired", json!({})),
    ]);
    while driver.service_connection().unwrap() {}
    assert_eq!(driver.frame_documents.len(), 1);
    assert_eq!(driver.frame_documents[0].loader_id, "new");
    assert!(!driver.frame_revisions.contains_key("child"));
    assert!(driver.frame_sessions.is_empty());
    assert_eq!(driver.pending_javascript_dialogs.len(), 1);
    assert_eq!(driver.pending_javascript_dialogs[0].dialog_type, "confirm");
    assert!(
        driver.pipe.writes.is_empty(),
        "observing an idle dialog must not dismiss it"
    );
    assert!(driver.transport.pending_len() == 0);
    driver.pipe = FakePipe::with_frames([event(
        "Page.javascriptDialogClosed",
        json!({"result":false}),
    )]);
    assert!(driver.service_connection().unwrap());
    assert!(driver.pending_javascript_dialogs.is_empty());
}

#[test]
fn stale_idle_load_cannot_complete_a_new_loader_or_frame_generation() {
    let mut driver = driver([
        commit("main", "old"),
        event("Page.loadEventFired", json!({})),
        event(
            "Page.lifecycleEvent",
            json!({"frameId":"main","loaderId":"old","name":"load"}),
        ),
    ]);
    while driver.service_connection().unwrap() {}
    let mut tracker = Tracker::default();
    tracker.begin_loader_fence(driver.frame_generation);
    tracker.expect_loader("new".into());
    driver.pipe = FakePipe::with_frames([
        event("Page.loadEventFired", json!({})),
        event(
            "Page.lifecycleEvent",
            json!({"frameId":"main","loaderId":"old","name":"load"}),
        ),
        commit("main", "old"),
        commit("main", "new"),
        event("Page.loadEventFired", json!({})),
        event(
            "Page.lifecycleEvent",
            json!({"frameId":"main","loaderId":"old","name":"load"}),
        ),
        event(
            "Page.lifecycleEvent",
            json!({"frameId":"child","loaderId":"new","name":"load"}),
        ),
        event(
            "Page.lifecycleEvent",
            json!({"frameId":"main","loaderId":"new","name":"load"}),
        ),
    ]);
    let now = Instant::now();
    for _ in 0..7 {
        driver
            .read_turn(None, Some(("context", &mut tracker)), now)
            .unwrap();
        assert!(
            !tracker.load_observed,
            "only the matching loader's main-frame load may count"
        );
        assert!(!tracker.poll_settlement(now + Duration::from_secs(1)));
    }
    assert_eq!(
        tracker.url_final.as_deref(),
        Some("https://example.test/new")
    );
    driver
        .read_turn(None, Some(("context", &mut tracker)), now)
        .unwrap();
    assert!(tracker.load_observed);
    assert!(tracker.poll_settlement(now + Duration::from_secs(1)));

    tracker.begin_loader_fence(driver.frame_generation);
    tracker.load_observed = false;
    driver.pipe = FakePipe::with_frames([event(
        "Page.lifecycleEvent",
        json!({"frameId":"main","loaderId":"new","name":"load"}),
    )]);
    driver
        .read_turn(None, Some(("context", &mut tracker)), now)
        .unwrap();
    assert!(
        !tracker.load_observed,
        "the same loader must also belong to this navigation's frame generation"
    );
}

#[test]
fn a_commit_before_the_navigate_reply_must_match_the_reply_loader() {
    let mut driver = driver([
        commit("main", "old"),
        event(
            "Page.lifecycleEvent",
            json!({"frameId":"main","loaderId":"old","name":"load"}),
        ),
    ]);
    let mut tracker = Tracker::default();
    tracker.begin_loader_fence(0);
    let now = Instant::now();
    for _ in 0..2 {
        driver
            .read_turn(None, Some(("context", &mut tracker)), now)
            .unwrap();
    }
    assert!(tracker.load_observed);
    tracker.expect_loader("new".into());
    assert!(!tracker.load_observed);
    assert!(tracker.url_final.is_none());
    assert!(!tracker.poll_settlement(now + Duration::from_secs(1)));
}

#[test]
fn idle_cancelled_replies_are_correlated_without_retaining_payloads() {
    let mut driver = driver([
        json!({"id":1,"sessionId":"session","result":{"ignored":"late payload"}}),
        json!({"id":2,"sessionId":"session","result":{"expected":true}}),
    ]);
    let now = Instant::now();
    driver
        .transport
        .issue_command("Page.getFrameTree", None, Some("session".into()), now)
        .unwrap();
    driver.transport.abandon_command(1);
    driver
        .transport
        .issue_command("Page.getFrameTree", None, Some("session".into()), now)
        .unwrap();
    assert!(driver.service_connection().unwrap());
    assert!(driver.pending_responses.is_empty());
    assert!(driver.service_connection().unwrap());
    assert_eq!(driver.pending_responses.len(), 1);
    let reply = driver.read_turn(Some(2), None, now).unwrap();
    // read_turn's saved-reply fast path is exercised by command_response,
    // while idle servicing must leave that known reply available to it.
    assert!(matches!(reply, ReadTurn::WouldBlock));
    assert_eq!(
        driver.pending_responses.remove(&2).unwrap().result.unwrap()["expected"],
        true
    );
}

#[test]
fn detached_frame_history_does_not_accumulate() {
    let frames = (0..1000).flat_map(|i| [
        event("Page.frameNavigated", json!({"frame":{"id":format!("child-{i}"),"parentId":"main","loaderId":format!("loader-{i}"),"url":"https://example.test/child"}})),
        event("Page.frameDetached", json!({"frameId":format!("child-{i}"),"reason":"remove"})),
    ]);
    let mut driver = driver(frames);
    while driver.service_connection().unwrap() {}
    assert!(driver.frame_revisions.is_empty());
    assert!(driver.frame_documents.is_empty());
    assert_eq!(driver.connection_metadata().live_records, 2);
    assert!(driver.connection_metadata().retained_bytes < 16 * 1024);
}

#[test]
fn metadata_overload_is_a_connector_reset_not_a_partial_frame_tree() {
    let frames = (0..257).map(|i| event("Page.frameNavigated", json!({"frame":{"id":format!("child-{i}"),"parentId":"main","loaderId":format!("loader-{i}"),"url":"https://example.test/child"}})));
    let mut driver = driver(frames);
    for _ in 0..255 {
        assert!(driver.service_connection().unwrap());
    }
    assert_eq!(
        driver.service_connection().unwrap_err(),
        NavigationDriveError::ConnectorFailure
    );
    assert_eq!(
        driver.frame_documents.len(),
        256,
        "no frame may be silently dropped to claim a complete tree"
    );
}

#[test]
fn metadata_byte_dialog_reply_and_tombstone_caps_fail_closed() {
    let mut bytes = driver([event(
        "Page.javascriptDialogOpening",
        json!({"type":"x".repeat(4 * 1024 * 1024)}),
    )]);
    while matches!(bytes.service_connection(), Ok(true)) {}
    assert!(bytes.connection_metadata().retained_bytes > 4 * 1024 * 1024);
    assert_eq!(
        bytes.service_connection().unwrap_err(),
        NavigationDriveError::ConnectorFailure
    );

    let mut dialogs =
        driver((0..65).map(|_| event("Page.javascriptDialogOpening", json!({"type":"confirm"}))));
    for _ in 0..64 {
        dialogs.service_connection().unwrap();
    }
    assert_eq!(
        dialogs.service_connection().unwrap_err(),
        NavigationDriveError::ConnectorFailure
    );

    let mut tombstones = driver([]);
    for _ in 0..1025 {
        let command = tombstones
            .transport
            .issue_command(
                "Page.getFrameTree",
                None,
                Some("session".into()),
                Instant::now(),
            )
            .unwrap();
        tombstones.transport.abandon_command(command.id);
    }
    assert_eq!(
        tombstones.service_connection().unwrap_err(),
        NavigationDriveError::ConnectorFailure
    );
    assert_eq!(tombstones.transport.retained_metadata().1, 1025);

    let mut replies = driver([]);
    for _ in 0..17 {
        replies
            .transport
            .issue_command("Page.getFrameTree", None, None, Instant::now())
            .unwrap();
    }
    assert_eq!(
        replies.service_connection().unwrap_err(),
        NavigationDriveError::ConnectorFailure
    );
}

#[test]
fn a_same_document_history_update_does_not_hide_the_active_loaders_load() {
    let mut driver = driver([
        commit("main", "new"),
        event(
            "Page.navigatedWithinDocument",
            json!({"frameId":"main","url":"https://example.test/new#ready","navigationType":"historyApi"}),
        ),
        event(
            "Page.lifecycleEvent",
            json!({"frameId":"main","loaderId":"new","name":"load"}),
        ),
    ]);
    let mut tracker = Tracker::default();
    tracker.begin_loader_fence(0);
    tracker.expect_loader("new".into());
    let now = Instant::now();
    driver
        .read_turn(None, Some(("context", &mut tracker)), now)
        .unwrap();
    let document_generation = driver.frame_document_generations["main"];
    driver
        .read_turn(None, Some(("context", &mut tracker)), now)
        .unwrap();
    assert!(
        driver.frame_revisions["main"] > document_generation,
        "history updates must still invalidate retained refs"
    );
    assert_eq!(
        driver.frame_document_generations["main"],
        document_generation
    );
    driver
        .read_turn(None, Some(("context", &mut tracker)), now)
        .unwrap();
    assert!(
        tracker.load_observed,
        "the document did not change when its history entry changed"
    );
    assert!(tracker.poll_settlement(now + Duration::from_secs(1)));
}

#[test]
fn transient_navigation_request_overload_uses_its_own_reset_bound() {
    let mut driver = driver([]);
    let mut tracker = Tracker::default();
    let now = Instant::now();
    for index in 0..2048 {
        tracker.network_request_started(&format!("request-{index}"), "Fetch", now);
    }
    assert!(driver.enforce_metadata_bounds(Some(&tracker)).is_ok());
    assert_eq!(driver.connection_metadata().active_requests, 2048);
    assert_eq!(driver.connection_metadata().live_records, 1);
    tracker.network_request_started("one-request-over-the-bound", "Fetch", now);
    assert_eq!(
        driver.enforce_metadata_bounds(Some(&tracker)).unwrap_err(),
        NavigationDriveError::ConnectorFailure
    );
    assert!(
        driver.connection_metadata().retained_bytes < 4 * 1024 * 1024,
        "the independent count bound must reset before aggregate bytes reach their own bound"
    );
    drop(tracker);
    assert_eq!(
        driver.service_connection().unwrap_err(),
        NavigationDriveError::ConnectorFailure,
        "dropping an overflowing foreground tracker must not hide the reset from its owner"
    );
}
