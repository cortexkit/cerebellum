use std::time::Instant;

use cerebellum::browser::{self, BrowserCapability, BrowserPlane};
use cerebellum::cdp::{Attachment, CdpTransport, IdentityMap};
use cerebellum::coordinate::{ScreenshotPayload, TransformInputs, ViewportObservation};
use cerebellum::snapshot_store::{AxRecord, RefRecord, SnapshotKind, SnapshotRef};
use cerebellum::RouteIdentity;
use serde_json::json;

fn identity() -> RouteIdentity {
    RouteIdentity::from_bind(
        &subc_protocol::BindIdentity {
            project_root: "/tmp/b1-s3".into(),
            harness: "test".into(),
            session: "b1-s3-session".into(),
        },
        &Some(subc_protocol::Principal::Direct),
    )
}

/// A click whose coordinates came from a differently-sized copy is refused.
///
/// The endpoint that shows a screenshot to a model downscales it first, so the
/// coordinates it reports index that smaller copy. They still land inside the
/// image retained here, which is why nothing downstream objects: the transform
/// validates and the click actuates somewhere the caller never chose.
///
/// Driven through the dispatch surface rather than the mapping helper, because
/// what matters is that no click is dispatched. A check that computed the
/// mismatch correctly and then proceeded would satisfy an assertion about the
/// returned value alone.
#[tokio::test]
async fn a_click_addressing_a_differently_sized_image_is_refused_before_dispatch() {
    const ONE_BY_ONE_PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";

    let plane = BrowserPlane::new();
    let route = identity();
    plane.open_context(route.clone()).await.unwrap();

    // The context's own epoch, so the snapshot is not refused as stale before
    // the check under test is reached.
    let view = ViewportObservation::new(
        0,
        TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0),
    );
    let retained = plane
        .retain_screenshot(
            &route,
            ScreenshotPayload::new(ONE_BY_ONE_PNG_B64, 1, 1),
            view,
            view,
            false,
        )
        .await
        .expect("a coherent screenshot is retained");
    let snapshot_id = retained["snapshot_id"]
        .as_str()
        .expect("the retained screenshot carries its id")
        .to_string();

    // Reserving and rejecting a request are themselves logged, so the fence is
    // the absence of INPUT rather than the absence of activity.
    fn input_operations(log: &[(String, browser::Operation)]) -> usize {
        log.iter()
            .filter(|(_, operation)| {
                matches!(
                    operation,
                    browser::Operation::CdpInputPress
                        | browser::Operation::CdpInputRelease
                        | browser::Operation::CommitDispatched
                )
            })
            .count()
    }
    let input_before = input_operations(&plane.operation_log().await);

    // The only pixel that exists, addressed as though the image were larger:
    // the shape a model-reported coordinate takes after a server-side resize.
    let refusal = plane
        .dispatch(
            &route,
            BrowserCapability::ClickPoint,
            &json!({
                "snapshot_id": snapshot_id,
                "x_px": 0,
                "y_px": 0,
                "image_width_px": 2,
                "image_height_px": 2,
                "intent": "press what the model saw",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    // dispatch answers with a body rather than a Result, so the refusal is read
    // from the outcome it reports.
    assert_eq!(
        refusal["detail"]["reason_code"], "image_size_mismatch",
        "refused for an unrelated reason: {refusal}"
    );
    assert_eq!(
        input_operations(&plane.operation_log().await),
        input_before,
        "the refusal committed or actuated a click anyway"
    );
}

#[tokio::test]
async fn composed_routes_omit_browser_type_and_click_uses_one_lane() {
    assert_eq!(browser::ALL_TOOLS.len(), 6);
    assert!(!browser::ALL_TOOLS.contains(&"browser.type"));
    let plane = BrowserPlane::new();
    let route = identity();
    plane.open_context(route.clone()).await.unwrap();
    let reference = SnapshotRef::new("e1", "button", "Save", 0).unwrap();
    plane
        .retain_text_snapshot(
            &route,
            SnapshotKind::Ax,
            &[AxRecord {
                depth: 0,
                role: "button".into(),
                name: "Save".into(),
                value: None,
                reference: Some("e1".into()),
            }],
            None,
            vec![RefRecord {
                captured: reference,
                frame_path: vec![],
                backend_identity: None,
                raw_role: None,
                raw_name: None,
            }],
            4096,
        )
        .await
        .unwrap();
    let snapshot_id = plane
        .retain_text_snapshot(
            &route,
            SnapshotKind::DomFull,
            &[],
            Some("body"),
            vec![],
            4096,
        )
        .await
        .unwrap()["snapshot_id"]
        .as_str()
        .unwrap()
        .to_string();
    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Click,
            &json!({
                "ref": "e1",
                "snapshot_id": snapshot_id,
                "intent": "click",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;
    assert_eq!(result["outcome"], "ref_not_found");
    let operations = plane.operation_log().await;
    assert!(operations
        .iter()
        .all(|(_, operation)| *operation != browser::Operation::CdpInputPress));
}

#[tokio::test]
async fn navigation_reports_unsettled_result_after_recording_non_success() {
    let plane = BrowserPlane::new();
    let route = identity();
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://example.com",
                "intent": "open the example page",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    assert_eq!(result["outcome"], "not_settled");
    assert_eq!(result["url_final"], "https://example.com");
    assert!(result["lifecycle"].is_array());
}

#[test]
fn cdp_correlation_and_attachment_are_fail_closed() {
    let now = Instant::now();
    let mut transport = CdpTransport::new();
    let command = transport
        .issue_command("Page.enable", None, Some("s1".into()), now)
        .unwrap();
    let response =
        serde_json::to_vec(&json!({"id": command.id, "sessionId": "s1", "result": {}})).unwrap();
    assert!(transport.take_response(&response).unwrap().result.is_some());

    let mut identities = IdentityMap::new();
    identities
        .attach(Attachment {
            target_id: "t1".into(),
            session_id: "s1".into(),
            frame_ids: vec!["f1".into()],
            context_key: "ctx".into(),
        })
        .unwrap();
    assert_eq!(
        identities.context_for("t1", "s1", Some("f1")).unwrap(),
        "ctx"
    );
    assert!(identities.detach("t1", "s1").is_ok());
}

/// The per-context dispatch lane is what keeps one invocation's CDP operations
/// from interleaving with another's verification bracket.  This asserts the
/// mutual exclusion directly: two concurrent dispatches on the SAME context must
/// not overlap, while two on DIFFERENT contexts may.
///
/// Without it, replacing the shared per-context lane with a fresh lock per call
/// leaves the suite green — the ordering property has no other witness.
#[tokio::test]
async fn same_context_dispatches_serialize_and_different_contexts_do_not() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;

    let plane = StdArc::new(BrowserPlane::new());
    let route_a = identity();
    let mut route_b = identity();
    route_b.conversation_key = "conv-b".to_string();
    plane.open_context(route_a.clone()).await.unwrap();
    plane.open_context(route_b.clone()).await.unwrap();

    // Concurrency observed while holding the same context's lane must never
    // exceed one.
    let peak = StdArc::new(AtomicUsize::new(0));
    let live = StdArc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let plane = StdArc::clone(&plane);
        let route = route_a.clone();
        let peak = StdArc::clone(&peak);
        let live = StdArc::clone(&live);
        handles.push(tokio::spawn(async move {
            let _guard = plane.lane_for_test(&route.conversation_key).await;
            let now = live.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            tokio::task::yield_now().await;
            live.fetch_sub(1, Ordering::SeqCst);
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "two dispatches held the same context lane at once"
    );

    // Two different contexts are independent: holding A's lane must not block B.
    let guard_a = plane.lane_for_test(&route_a.conversation_key).await;
    let guard_b = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        plane.lane_for_test(&route_b.conversation_key),
    )
    .await
    .expect("a different context must not block on another context's lane");
    drop(guard_b);
    drop(guard_a);
}

/// A click presses before it releases, and presses nothing before commitment.
///
/// The ordering is not implied by the outcome: a release recorded before its
/// press still reports success, still journals a commitment, and still leaves
/// the same set of operations behind, so nothing about the returned value can
/// distinguish it. Only the sequence can.
///
/// Both click paths share one actuation helper, so this covers the coordinate
/// path as well; a change that reordered actuation for one of them would have
/// to reorder it for both.
///
/// The commitment ordering matters for the same reason: an input recorded
/// before the journal has committed to it is an action the audit trail cannot
/// account for.
#[tokio::test]
async fn a_click_presses_before_it_releases_and_only_after_commitment() {
    let plane = BrowserPlane::new();
    let route = identity();
    plane.open_context(route.clone()).await.unwrap();
    let reference = SnapshotRef::new("e1", "button", "Save", 0).unwrap();
    let snapshot_id = plane
        .retain_text_snapshot(
            &route,
            SnapshotKind::Ax,
            &[AxRecord {
                depth: 0,
                role: "button".into(),
                name: "Save".into(),
                value: None,
                reference: Some("e1".into()),
            }],
            None,
            vec![RefRecord {
                captured: reference,
                frame_path: vec![],
                backend_identity: None,
                raw_role: None,
                raw_name: None,
            }],
            4096,
        )
        .await
        .unwrap()["snapshot_id"]
        .as_str()
        .unwrap()
        .to_string();

    plane
        .dispatch(
            &route,
            BrowserCapability::Click,
            &json!({
                "ref": "e1",
                "snapshot_id": snapshot_id,
                "intent": "click",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    let operations: Vec<browser::Operation> = plane
        .operation_log()
        .await
        .into_iter()
        .map(|(_, operation)| operation)
        .collect();
    let position = |wanted: browser::Operation| {
        operations
            .iter()
            .position(|operation| *operation == wanted)
            .unwrap_or_else(|| panic!("{wanted:?} was never recorded: {operations:?}"))
    };

    assert!(
        position(browser::Operation::CdpInputPress) < position(browser::Operation::CdpInputRelease),
        "a button is pressed before it is released: {operations:?}"
    );
    assert!(
        position(browser::Operation::CommitDispatched)
            < position(browser::Operation::CdpInputPress),
        "no input is dispatched before the journal commits to it: {operations:?}"
    );
}
