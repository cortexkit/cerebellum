use std::time::Instant;

use cerebellum::browser::{self, BrowserCapability, BrowserPlane};
use cerebellum::cdp::{Attachment, CdpTransport, IdentityMap};
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
