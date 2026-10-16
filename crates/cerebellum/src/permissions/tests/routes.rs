use super::*;

const CHANNEL: u16 = 19;

async fn exchange(planes: &Planes, channel: u16, corr: u64, body: Value) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        crate::control_flags(),
        channel,
        if channel == 0 { 0 } else { 1 },
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    crate::handle_frame_for_test(frame, &tx, planes)
        .await
        .unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.header.channel, channel);
    assert_eq!(response.header.corr, corr);
    response
}

async fn bind(planes: &Planes, principal: Principal, target: RouteTarget) -> Frame {
    let request = subc_protocol::session::ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: CHANNEL,
        epoch: 1,
        target,
        identity: subc_protocol::BindIdentity::new("/fixture/project", "test", "session"),
        principal: Some(principal),
        admission_facts: None,
        consumer_capabilities: None,
        scope: None,
    };
    exchange(planes, 0, 1, serde_json::to_value(request).unwrap()).await
}

fn cingulate() -> Principal {
    Principal::Reserved {
        module_id: "cingulate".into(),
    }
}

fn management_target() -> RouteTarget {
    RouteTarget::ManagementSurface {
        module_id: "cerebellum".into(),
    }
}

fn body(frame: &Frame) -> Value {
    serde_json::from_slice(&frame.body).unwrap()
}

#[tokio::test]
async fn cingulate_management_bind_reaches_permissions_list_and_revoke() {
    let (planes, store, _, _) = fixture(corpus_rows());
    let ack = bind(&planes, cingulate(), management_target()).await;
    assert_eq!(ack.header.ty, FrameType::Response, "{}", body(&ack));
    assert_eq!(body(&ack), json!({"op":"route.bind"}));
    assert!(!crate::trust_for_principal(&Some(cingulate())).is_first_party());
    let listed = exchange(&planes, CHANNEL, 2, json!({"method":LIST,"params":{}})).await;
    assert_eq!(listed.header.ty, FrameType::Response, "{}", body(&listed));
    assert_eq!(body(&listed), vector("provider-list")["reply"]);
    let revoked = exchange(
        &planes,
        CHANNEL,
        3,
        json!({"method":REVOKE,"params":{"id":"grt_01"}}),
    )
    .await;
    assert_eq!(revoked.header.ty, FrameType::Response);
    assert_eq!(body(&revoked), json!({"outcome":"revoked"}));
    assert!(!store
        .live_rows(None, NOW)
        .unwrap()
        .iter()
        .any(|row| row.id == "grt_01"));
}

#[tokio::test]
async fn cingulate_management_route_refuses_grants_list_and_every_other_method_by_name() {
    let (planes, _, _, backend) = fixture(corpus_rows());
    let ack = bind(&planes, cingulate(), management_target()).await;
    assert_eq!(ack.header.ty, FrameType::Response);
    let before = backend.load().unwrap();
    for (index, method) in management::OPERATIONS
        .into_iter()
        .chain([
            "browser.status",
            "computer_use",
            "browser_use",
            "unknown.method",
        ])
        .filter(|method| !is_operation(method))
        .enumerate()
    {
        let params = match method {
            management::LIST_GRANTS | management::REVOKE_GRANT => json!({"agent_id":"agent-alf"}),
            management::REVOKE_APP_GRANT => {
                json!({"grantee":"agent-alf","bundle_identity":"com.apple.TextEdit"})
            }
            management::OPEN_TARGET => json!({"bundle_identity":"com.apple.TextEdit"}),
            _ => json!({}),
        };
        let refused = exchange(
            &planes,
            CHANNEL,
            index as u64 + 2,
            json!({"method":method,"params":params}),
        )
        .await;
        assert_eq!(
            refused.header.ty,
            FrameType::Error,
            "{method}: {}",
            body(&refused)
        );
        assert_eq!(body(&refused)["code"], "principal_denied", "{method}");
        assert!(body(&refused)["message"]
            .as_str()
            .unwrap()
            .contains(&format!("'{method}'")));
        assert_eq!(backend.load().unwrap(), before, "{method} changed grants");
    }
    for (index, name) in ["computer_use", "browser_use", "browser.status", LIST]
        .into_iter()
        .enumerate()
    {
        let refused = exchange(
            &planes,
            CHANNEL,
            index as u64 + 100,
            json!({"name":name,"arguments":{}}),
        )
        .await;
        assert_eq!(
            refused.header.ty,
            FrameType::Error,
            "{name}: {}",
            body(&refused)
        );
        assert_eq!(body(&refused)["code"], "principal_denied");
        assert!(body(&refused)["message"]
            .as_str()
            .unwrap()
            .contains(&format!("'{name}'")));
    }
}

#[tokio::test]
async fn cingulate_session_and_other_targets_stay_principal_denied() {
    let (planes, _, _, _) = fixture(corpus_rows());
    for target in [
        RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        RouteTarget::InternalService {
            module_id: "cerebellum".into(),
            service_id: "session".into(),
        },
        RouteTarget::ManagementSurface {
            module_id: "another-module".into(),
        },
    ] {
        let denied = bind(&planes, cingulate(), target).await;
        assert_eq!(denied.header.ty, FrameType::Error);
        assert_eq!(body(&denied)["code"], "principal_denied");
        assert!(planes.routes.get(CHANNEL, 1).is_none());
    }
}

#[tokio::test]
async fn direct_management_bind_cannot_call_permissions_list() {
    let (planes, _, _, _) = fixture(corpus_rows());
    let ack = bind(&planes, Principal::Direct, management_target()).await;
    assert_eq!(ack.header.ty, FrameType::Response, "{}", body(&ack));
    let denied = exchange(&planes, CHANNEL, 2, json!({"method":LIST,"params":{}})).await;
    assert_eq!(denied.header.ty, FrameType::Error);
    assert_eq!(body(&denied)["code"], "permissions_operator_required");
}
