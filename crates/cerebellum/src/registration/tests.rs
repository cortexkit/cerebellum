use super::*;
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn channel_consumer_mints_then_presents_before_opening_routes() {
    let owner = Arc::new(ControlRequests::starting_at(FIRST_CLAIM_CORR));
    let (tx, mut rx) = mpsc::channel::<Frame>(4);
    owner.connect(&tx);
    let (mut client, mut daemon) = tokio::io::duplex(4096);
    let fake = async {
        let mint = rx.recv().await.unwrap();
        assert_eq!(mint.header.corr, FIRST_CLAIM_CORR);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&mint.body).unwrap(),
            json!({"op":"claim.mint","purpose":"self"})
        );
        owner.deliver(
            mint.header.corr,
            ControlAnswer::Response(json!({
                "op":"claim.mint","claim":"test-bearer","expires_at_ms":123
            })),
        );
        let present = read_frame(&mut daemon).await.unwrap().unwrap();
        assert_eq!(
            (
                present.header.channel,
                present.header.epoch,
                present.header.corr
            ),
            (0, 0, 1)
        );
        let request: ClaimPresentRequest = serde_json::from_slice(&present.body).unwrap();
        assert!(request.claim == Claim::new("test-bearer"));
        let ack = Frame::build(
            FrameType::Response,
            crate::control_flags(),
            0,
            0,
            1,
            serde_json::to_vec(&ClaimPresentReply::new()).unwrap(),
        )
        .unwrap();
        write_frame(&mut daemon, &ack).await.unwrap();
    };
    let (result, ()) = tokio::join!(
        bind_with_owner(&mut client, &owner, Duration::from_secs(1)),
        fake
    );
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn channel_claim_mint_unavailable_or_timed_out_never_continues_as_direct() {
    let owner = ControlRequests::starting_at(FIRST_CLAIM_CORR);
    let (mut client, mut daemon) = tokio::io::duplex(4096);
    assert_eq!(
        bind_with_owner(&mut client, &owner, Duration::from_millis(10)).await,
        Err(ClaimError::MintUnavailable)
    );
    let (tx, _rx) = mpsc::channel::<Frame>(4);
    let owner = ControlRequests::starting_at(FIRST_CLAIM_CORR);
    owner.connect(&tx);
    assert_eq!(
        bind_with_owner(&mut client, &owner, Duration::from_millis(10)).await,
        Err(ClaimError::MintUnavailable)
    );
    assert_eq!(owner.outstanding(), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), read_frame(&mut daemon))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn channel_claim_refusal_is_typed_and_does_not_present() {
    let owner = ControlRequests::starting_at(FIRST_CLAIM_CORR);
    let (tx, mut rx) = mpsc::channel::<Frame>(4);
    owner.connect(&tx);
    let (mut client, _daemon) = tokio::io::duplex(4096);
    let fake = async {
        let mint = rx.recv().await.unwrap();
        owner.deliver(
            mint.header.corr,
            ControlAnswer::Error(json!({"code":"claim_mint_not_allowed"})),
        );
    };
    let (result, ()) = tokio::join!(
        bind_with_owner(&mut client, &owner, Duration::from_secs(1)),
        fake
    );
    assert_eq!(result, Err(ClaimError::MintRefused));
}

#[tokio::test]
async fn claim_and_scope_responses_do_not_cross_even_with_colliding_ids() {
    let claims = ControlRequests::starting_at(FIRST_CLAIM_CORR);
    let scopes = ControlRequests::starting_at(FIRST_CLAIM_CORR);
    let (tx, mut rx) = mpsc::channel::<Frame>(4);
    let mint = ClaimMintRequest::new(ClaimPurpose::SelfConnection);
    let scope = json!({"op":"scope.describe","ref":"test"});
    let serve = async {
        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();
        assert_eq!(first.header.corr, second.header.corr);
        let scope_answer = ControlAnswer::Response(json!({"op":"scope.describe"}));
        let claim_answer = ControlAnswer::Response(
            json!({"op":"claim.mint","claim":"test-bearer","expires_at_ms":123}),
        );
        assert!(!claims.deliver(first.header.corr, scope_answer.clone()));
        assert!(!scopes.deliver(second.header.corr, claim_answer.clone()));
        assert!(claims.deliver(first.header.corr, claim_answer));
        assert!(scopes.deliver(second.header.corr, scope_answer));
    };
    let (claim, scope, ()) = tokio::join!(
        claims.request(&tx, &mint, Duration::from_secs(1)),
        scopes.request(&tx, &scope, Duration::from_secs(1)),
        serve
    );
    assert!(matches!(claim, Some(ControlAnswer::Response(_))));
    assert!(matches!(scope, Some(ControlAnswer::Response(_))));
}

#[test]
fn channel_routes_never_name_consumer_identity_source_check() {
    for (path, source) in [
        ("channel_route.rs", include_str!("../channel_route.rs")),
        ("registration.rs", include_str!("../registration.rs")),
    ] {
        assert!(
            !source.contains("consumer_identity"),
            "{path} names consumer_identity on the channel path"
        );
    }
    for source in [
        include_str!("../cingulate_client/route.rs"),
        include_str!("../login_capture/vault.rs"),
    ] {
        assert!(source.contains("crate::channel_route::open("));
        assert!(source.contains("crate::registration::bind_consumer("));
    }
}

#[test]
fn channel_route_body_keeps_target_identity_and_scope_without_a_nonce() {
    let target = subc_protocol::RouteTarget::ManagementSurface {
        module_id: "cingulate".into(),
    };
    let identity = subc_protocol::BindIdentity::new("cerebellum", "consent");
    let body: serde_json::Value =
        serde_json::from_slice(&crate::channel_route::open(target, &identity, None)).unwrap();
    assert_eq!(
        body,
        json!({"op":"route.open", "target":{"kind":"management_surface","module_id":"cingulate"},
        "identity":serde_json::to_value(identity).unwrap()})
    );
    let selector = subc_protocol::scope::ScopeSelector::new(
        subc_protocol::Principal::Reserved {
            module_id: "prefrontal".into(),
        },
        "session",
        Some(2),
    );
    let body: serde_json::Value = serde_json::from_slice(&crate::channel_route::open(
        subc_protocol::RouteTarget::ToolProvider {
            module_id: "occipital".into(),
        },
        &subc_protocol::BindIdentity::new("cerebellum", "tool-display"),
        Some(&selector),
    ))
    .unwrap();
    assert_eq!(
        body["target"],
        json!({"kind":"tool_provider","module_id":"occipital"})
    );
    assert_eq!(
        body["scope"],
        json!({"owner":{"kind":"reserved","module_id":"prefrontal"},"ref":"session","scope_epoch":2})
    );
    assert!(body.get("consumer_identity").is_none());
}

#[tokio::test]
async fn channel_claim_presentation_refusal_never_continues_as_direct() {
    let owner = ControlRequests::starting_at(FIRST_CLAIM_CORR);
    let (tx, mut rx) = mpsc::channel::<Frame>(4);
    owner.connect(&tx);
    let (mut client, mut daemon) = tokio::io::duplex(4096);
    let fake = async {
        let mint = rx.recv().await.unwrap();
        owner.deliver(
            mint.header.corr,
            ControlAnswer::Response(json!({
                "op":"claim.mint","claim":"test-bearer","expires_at_ms":123
            })),
        );
        read_frame(&mut daemon).await.unwrap().unwrap();
        let refusal = Frame::build(
            FrameType::Error,
            crate::control_flags(),
            0,
            0,
            1,
            serde_json::to_vec(&json!({"code":"claim_invalid"})).unwrap(),
        )
        .unwrap();
        write_frame(&mut daemon, &refusal).await.unwrap();
    };
    let (result, ()) = tokio::join!(
        bind_with_owner(&mut client, &owner, Duration::from_secs(1)),
        fake
    );
    assert_eq!(result, Err(ClaimError::PresentFailed));
}

#[tokio::test]
async fn primary_channel_runs_hmac_and_hello_without_dialing_an_endpoint() {
    let directory = cortexkit_test_support::ScratchDir::new("cerebellum-registration");
    let path = directory.join("connection.json");
    let key = subc_transport::connection_file::generate_key().unwrap();
    let daemon_id = subc_transport::connection_file::generate_daemon_id().unwrap();
    subc_transport::connection_file::write_atomic(
        &path,
        &subc_transport::ConnectionInfo {
            schema: subc_transport::connection_file::SCHEMA_VERSION,
            wire_version: None,
            endpoints: vec![subc_transport::Endpoint {
                host: "127.0.0.1".into(),
                port: 1,
            }],
            key: key.clone(),
            daemon_id,
            pid: std::process::id(),
            daemon_ver: "test".into(),
        },
    )
    .unwrap();
    let (client, mut daemon) = tokio::io::duplex(128 * 1024);
    let module = async {
        let mut stream = crate::connect_to_subc(&path, Some(Box::new(client)))
            .await
            .unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        crate::send_hello_for_test(
            &tx,
            &crate::ModuleConfigForTest {
                module_id: "cerebellum".into(),
            },
        )
        .await
        .unwrap();
        write_frame(&mut stream, &rx.recv().await.unwrap())
            .await
            .unwrap();
        crate::expect_hello_ack(&mut stream).await.unwrap();
    };
    let serve = async {
        subc_transport::authenticate_server(
            &mut daemon,
            &key,
            &daemon_id,
            "test",
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let hello = read_frame(&mut daemon).await.unwrap().unwrap();
        assert_eq!(
            (hello.header.ty, hello.header.channel, hello.header.epoch),
            (FrameType::Hello, 0, 0)
        );
        let body: serde_json::Value = serde_json::from_slice(&hello.body).unwrap();
        assert!(body.get("launch_nonce").is_none());
        assert_eq!(body["manifest"]["registration_channel"], true);
        let ack = Frame::build(
            FrameType::HelloAck,
            crate::control_flags(),
            0,
            0,
            hello.header.corr,
            serde_json::to_vec(&json!({"negotiated_ver":2,"subc_ops":[],"subc_capabilities":[]}))
                .unwrap(),
        )
        .unwrap();
        write_frame(&mut daemon, &ack).await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(module, serve);
    })
    .await
    .unwrap();
}
