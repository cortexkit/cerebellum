use super::*;
use crate::snapshot_store::{RefCandidate, RefRecord, RefResolution, SnapshotRef};

#[tokio::test]
async fn run_resolves_head_browser_snapshot_and_ref_not_run_bind_context() {
    let planes = crate::call_mode_tests::bound_run().await;
    let head = planes.routes.get(8, 3).unwrap();
    let run = planes.routes.get(9, 3).unwrap();
    planes.browser.state.lock().await.contexts.insert(
        "head-conversation".into(),
        ContextState::new(head.identity.clone()),
    );
    planes
        .browser
        .same_document_url(
            &head.identity,
            "https://example.com/page",
            snapshot_store::SameDocumentChange::ReplaceState,
        )
        .await
        .unwrap();
    let record = RefRecord {
        frame_document: None,
        captured: SnapshotRef::new("e1", "button", "Save", 0).unwrap(),
        frame_path: vec![],
        backend_identity: None,
        raw_role: Some("button".into()),
        raw_name: Some("Save".into()),
        classification: Err(crate::classification::ClassificationUnavailable::NotCaptured),
    };
    let minted = planes
        .browser
        .retain_text_snapshot(
            &head.identity,
            SnapshotKind::Ax,
            &[AxRecord {
                depth: 0,
                role: "button".into(),
                name: "Save".into(),
                value: None,
                reference: Some("e1".into()),
            }],
            None,
            vec![record.clone()],
            4096,
            None,
        )
        .await
        .unwrap();
    let id = minted["snapshot_id"].as_str().unwrap();
    let state = planes.browser.state.lock().await;
    let context = state
        .contexts
        .get(&run.identity.conversation_key)
        .expect("run uses the head's actual handle table");
    assert_eq!(
        context
            .snapshots
            .resolve_ref(
                id,
                "e1",
                context.epoch.value(),
                &[RefCandidate {
                    identity: None,
                    frame_path: vec![],
                    role: "button".into(),
                    name: "Save".into(),
                    traversal_index: 0
                }]
            )
            .unwrap(),
        RefResolution::Resolved(Box::new(record))
    );
    assert!(!state.contexts.contains_key("misleading-session"));
}
