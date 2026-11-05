use super::*;
use crate::{
    authorization::{ActionGrant, AuthorizationError, AuthorizationRequest, GrantStore, Severity},
    browser::navigation::tests::{attached_driver, FakeClock},
    snapshot_store::CommittedDocument,
};
use serde_json::json;
use std::sync::Arc;

const ORIGIN: &str = "https://example.com";

fn response(frame: &str, loader: &str, address: Option<&str>) -> Value {
    let mut response =
        json!({"url":format!("{ORIGIN}/page"),"status":200,"statusText":"OK","headers":{}});
    if let Some(address) = address {
        response["remoteIPAddress"] = json!(address);
    }
    json!({"method":"Network.responseReceived","sessionId":"session-own","params":{
        "requestId":loader,"frameId":frame,"loaderId":loader,"type":"Document","response":response
    }})
}

fn document_frames(id: u64, loader: &str, address: Option<&str>) -> Vec<Value> {
    vec![
        response("target-own", loader, address),
        json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{
            "id":"target-own","loaderId":loader,"url":format!("{ORIGIN}/page"),"securityOrigin":ORIGIN
        }}}),
        json!({"id":id,"sessionId":"session-own","result":{"currentIndex":0,"entries":[{"id":1,"url":format!("{ORIGIN}/page")}]}}),
        json!({"id":id+1,"sessionId":"session-own","result":{"frameTree":{"frame":{
            "id":"target-own","loaderId":loader,"url":format!("{ORIGIN}/page"),"securityOrigin":ORIGIN
        }}}}),
    ]
}

fn baseline() -> GrantStore {
    GrantStore::default().with_public_web_baseline(Arc::new(
        crate::browser_signed_in::SignedInDomains::default(),
    ))
}

fn authorize_snapshot(
    store: &GrantStore,
    document: &CommittedDocument,
) -> Result<crate::authorization::AuthorizationDecision, AuthorizationError> {
    store.authorize_document(
        AuthorizationRequest::snapshot("route-own", "snapshot", "agent"),
        ORIGIN,
        document.network.is_public(ORIGIN),
    )
}

#[test]
fn connected_private_document_refuses_snapshot_and_click_without_site_grant() {
    for address in [
        "192.168.1.1",
        "127.0.0.1",
        "::1",
        "::ffff:192.168.1.1",
        "100.64.0.1",
        "169.254.1.2",
        "fd00::1",
        "0.0.0.0",
        "224.0.0.1",
        "192.0.2.1",
    ] {
        let mut driver = attached_driver(document_frames(1, "private", Some(address)));
        let document = driver
            .committed_document_with_clock("route-own", 100, &mut FakeClock::new())
            .unwrap();
        let store = baseline();
        assert!(
            matches!(
                authorize_snapshot(&store, &document),
                Err(AuthorizationError::NoGrantForAction { .. })
            ),
            "snapshot at {address}"
        );
        let classification = classify_flattened_document(
            json!({"nodes":[
                {"nodeId":1,"backendNodeId":1,"nodeType":9,"localName":"#document"},
                {"nodeId":2,"parentId":1,"backendNodeId":2,"nodeType":1,"localName":"button","attributes":["type","button"]}
            ]}).as_object().unwrap(),
            &crate::snapshot_store::BackendNodeIdentity::new("target-own", "target-own", 2).unwrap(),
            1, ORIGIN,
        ).unwrap();
        let click = AuthorizationRequest::click(
            "route-own",
            Severity::new(2, false, false),
            "click",
            "agent",
            &classification,
        );
        assert!(
            matches!(
                store.authorize_document(click, ORIGIN, document.network.is_public(ORIGIN)),
                Err(AuthorizationError::NoGrantForAction { .. })
            ),
            "click at {address}"
        );
        let granted = store_with_site_grant();
        assert!(
            authorize_snapshot(&granted, &document).is_ok(),
            "site grant at {address}"
        );
    }
}

fn store_with_site_grant() -> GrantStore {
    GrantStore::new([ActionGrant::new(
        "site",
        1,
        "route-own",
        Severity::new(2, false, false),
        [ORIGIN],
    )])
}

#[test]
fn connected_public_document_keeps_the_public_baseline() {
    let mut driver = attached_driver(document_frames(1, "public", Some("93.184.216.34")));
    let document = driver
        .committed_document_with_clock("route-own", 100, &mut FakeClock::new())
        .unwrap();
    assert!(authorize_snapshot(&baseline(), &document)
        .unwrap()
        .is_public_web_baseline());
}

#[test]
fn connected_peer_follows_rebinding_and_private_history_is_sticky_only_for_unknown() {
    let frames = document_frames(1, "first", Some("93.184.216.34"))
        .into_iter()
        .chain(document_frames(3, "second", Some("192.168.1.1")))
        .chain(document_frames(5, "third", None))
        .chain(document_frames(7, "fourth", Some("93.184.216.34")));
    let mut driver = attached_driver(frames);
    let mut clock = FakeClock::new();
    let first = driver
        .committed_document_with_clock("route-own", 100, &mut clock)
        .unwrap();
    assert!(authorize_snapshot(&baseline(), &first).is_ok());
    let private = driver
        .committed_document_with_clock("route-own", 100, &mut clock)
        .unwrap();
    assert!(authorize_snapshot(&baseline(), &private).is_err());
    let unknown = driver
        .committed_document_with_clock("route-own", 100, &mut clock)
        .unwrap();
    assert!(authorize_snapshot(&baseline(), &unknown).is_err());
    let public_again = driver
        .committed_document_with_clock("route-own", 100, &mut clock)
        .unwrap();
    assert!(authorize_snapshot(&baseline(), &public_again).is_ok());
}

#[test]
fn unknown_without_private_history_keeps_name_only_publicness() {
    let mut driver = attached_driver(document_frames(1, "worker", Some("")));
    let document = driver
        .committed_document_with_clock("route-own", 100, &mut FakeClock::new())
        .unwrap();
    assert!(authorize_snapshot(&baseline(), &document).is_ok());
}

#[test]
fn connected_private_frames_are_filtered_and_blank_srcdoc_inherit_the_parent_peer() {
    let mut driver = attached_driver([response("child", "private", Some("127.0.0.1"))]);
    driver.read_turn(None, None, Instant::now()).unwrap();
    let tree = json!({"frame":{"id":"target-own","loaderId":"root","url":"https://example.com/","securityOrigin":ORIGIN},"childFrames":[
        {"frame":{"id":"child","loaderId":"private","url":"https://example.com/embedded","securityOrigin":ORIGIN},"childFrames":[
            {"frame":{"id":"blank","loaderId":"blank","url":"about:blank","securityOrigin":ORIGIN}},
            {"frame":{"id":"srcdoc","loaderId":"srcdoc","url":"about:srcdoc","securityOrigin":ORIGIN}}
        ]}
    ]});
    let mut frames = Vec::new();
    driver
        .collect_frame_documents(&tree, None, "session-own", &mut frames)
        .unwrap();
    assert_eq!(
        frames[1].network.remote_ip_address.unwrap().to_string(),
        "127.0.0.1"
    );
    let mut before_peer_observed = frames[1].clone();
    before_peer_observed.network = Default::default();
    assert!(!frames[1].same_document(&before_peer_observed));
    assert_eq!(frames[2].network, frames[1].network);
    assert_eq!(frames[3].network, frames[1].network);
    let readable = crate::browser::public_read_frames(&frames);
    assert_eq!(
        readable
            .iter()
            .map(|f| f.frame_id.as_str())
            .collect::<Vec<_>>(),
        ["target-own"]
    );
}

#[test]
fn oopif_network_observation_is_enabled_before_the_renderer_resumes() {
    let child_reply = |id| json!({"id":id,"sessionId":"child-session","result":{}});
    let mut child_response = response("child", "child-loader", Some("192.168.1.1"));
    child_response["sessionId"] = json!("child-session");
    let mut driver = attached_driver([
        json!({"method":"Target.attachedToTarget","sessionId":"session-own","params":{
            "sessionId":"child-session","waitingForDebugger":true,
            "targetInfo":{"targetId":"child","type":"iframe"}
        }}),
        child_reply(2),
        child_reply(3),
        child_reply(4),
        child_reply(5),
        child_response,
        json!({"id":1,"sessionId":"session-own","result":{"currentIndex":0,"entries":[{"id":1,"url":format!("{ORIGIN}/page")}]}}),
        json!({"id":6,"sessionId":"session-own","result":{"frameTree":{"frame":{
            "id":"target-own","loaderId":"root","url":format!("{ORIGIN}/page"),"securityOrigin":ORIGIN
        }}}}),
    ]);
    driver
        .committed_document_with_clock("route-own", 100, &mut FakeClock::new())
        .unwrap();
    let methods = driver
        .pipe
        .writes
        .iter()
        .map(|v| v["method"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        [
            "Page.getNavigationHistory",
            "Target.setAutoAttach",
            "Page.enable",
            "Network.enable",
            "Runtime.runIfWaitingForDebugger",
            "Page.getFrameTree"
        ]
    );
    assert_eq!(
        driver.pipe.writes[1]["params"]["waitForDebuggerOnStart"],
        true
    );
    assert!(!driver
        .document_network("child-session", "child", "child-loader", ORIGIN)
        .is_public(ORIGIN));
}

#[test]
fn unrelated_sessions_and_subresource_responses_cannot_change_document_publicness() {
    let mut foreign = response("target-own", "root", Some("192.168.1.1"));
    foreign["sessionId"] = json!("foreign-session");
    let mut resource = response("target-own", "root", Some("127.0.0.1"));
    resource["params"]["type"] = json!("Image");
    let mut frames = vec![foreign, resource];
    frames.extend(document_frames(1, "root", None));
    let mut driver = attached_driver(frames);
    let document = driver
        .committed_document_with_clock("route-own", 100, &mut FakeClock::new())
        .unwrap();
    assert!(authorize_snapshot(&baseline(), &document).is_ok());
}

#[tokio::test]
async fn legacy_all_sites_never_covers_a_connected_private_document() {
    use crate::agent_grants::GrantHolder;
    use crate::authorization::{with_standing_caller, Action, StandingCaller};
    use crate::browser_standing_grants::{
        InMemoryStandingGrantStorage, StandingBrowserGrants, StandingSubject,
    };
    let standing = Arc::new(StandingBrowserGrants::open(
        Arc::new(InMemoryStandingGrantStorage::new()),
        Some("machine".into()),
    ));
    standing
        .record(
            "agent",
            StandingSubject::AllSites,
            3,
            vec![],
            None,
            "all-card",
        )
        .unwrap();
    let store = baseline().with_standing_grants(standing.clone());
    let mut driver = attached_driver(document_frames(1, "private", Some("192.168.1.1")));
    let document = driver
        .committed_document_with_clock("route-own", 100, &mut FakeClock::new())
        .unwrap();
    let classification = classify_flattened_document(
        json!({"nodes":[
            {"nodeId":1,"backendNodeId":1,"nodeType":9,"localName":"#document"},
            {"nodeId":2,"parentId":1,"backendNodeId":2,"nodeType":1,"localName":"button","attributes":["type","button"]}
        ]}).as_object().unwrap(),
        &crate::snapshot_store::BackendNodeIdentity::new("target-own", "target-own", 2).unwrap(), 1, ORIGIN,
    ).unwrap();
    with_standing_caller(
        Some(StandingCaller {
            holder: GrantHolder::Head {
                agent_id: "agent".into(),
            },
        }),
        async {
            for action in [
                Action::Navigate,
                Action::Snapshot,
                Action::Screenshot,
                Action::Click,
                Action::ClickPoint,
                Action::Type,
            ] {
                let mut request = AuthorizationRequest::click(
                    "route-own",
                    Severity::new(2, false, false),
                    "call",
                    "agent",
                    &classification,
                );
                request.action = action;
                let refused = store.authorize_document(
                    request.clone(),
                    ORIGIN,
                    document.network.is_public(ORIGIN),
                );
                assert!(
                    matches!(refused, Err(AuthorizationError::NoGrantForAction { .. })),
                    "{action:?}: {refused:?}"
                );
                assert!(
                    store.authorize_document(request, ORIGIN, true).is_ok(),
                    "public {action:?}"
                );
            }
            standing
                .record(
                    "agent",
                    StandingSubject::Origin(ORIGIN.into()),
                    3,
                    vec![],
                    None,
                    "site-card",
                )
                .unwrap();
            assert!(authorize_snapshot(&store, &document).is_ok());
        },
    )
    .await;
}

#[test]
fn oopif_attached_after_navigation_ack_resumes_while_waiting_for_load() {
    let reply = |id| json!({"id":id,"sessionId":"child-session","result":{}});
    let mut driver = attached_driver([
        json!({"method":"Target.attachedToTarget","sessionId":"session-own","params":{
            "sessionId":"child-session","waitingForDebugger":true,
            "targetInfo":{"targetId":"child","type":"iframe"}
        }}),
        reply(1),
        reply(2),
        reply(3),
        reply(4),
        json!({"method":"Page.loadEventFired","sessionId":"session-own","params":{}}),
    ]);
    let mut tracker = Tracker::default();
    tracker.main_frame_navigated(Some("target-own".into()), format!("{ORIGIN}/page"));
    let mut clock = FakeClock::new();
    let deadline = clock.now() + Duration::from_millis(1000);
    driver
        .settle_navigation("route-own", &mut tracker, deadline, |_| false, &mut clock)
        .unwrap();
    assert!(tracker.settled);
    assert_eq!(
        driver
            .pipe
            .writes
            .iter()
            .map(|v| v["method"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "Target.setAutoAttach",
            "Page.enable",
            "Network.enable",
            "Runtime.runIfWaitingForDebugger"
        ]
    );
    assert!(driver.waiting_frame_sessions.is_empty());
}
