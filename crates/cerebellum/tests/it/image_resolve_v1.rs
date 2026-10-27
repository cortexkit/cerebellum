//! Byte goldens for `image.resolve`: the request Broca sends for a codemode
//! program's screenshot handle, and the reply cerebellum returns, captured at
//! the production `handle_frame` entry point rather than assembled from an
//! expected JSON object.
//!
//! The handle under test is minted the way production mints it, through the
//! same store and field a capture reply uses, from a fixed fixture image: a run
//! needs no Screen Recording permission, no installed application and no
//! window server.

use std::sync::Arc;

use cerebellum::{handle_frame_for_test, handle_tool_request_for_test_with_planes};
use cerebellum::{JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subc_protocol::scope::{ScopeKind, ScopeStamp};
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget};

/// The image bytes the fixture read returns.
const FIXTURE_BYTES: &[u8] = &[
    0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, b'I', b'H', b'D', b'R',
];
/// The scope the fixture capture is made under, and the conversation it
/// belongs to.
const CAPTURE_SCOPE: &str = "vector-head";
const CONVERSATION: &str = "test-session";

fn directory() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/image-resolve-v1")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The head scope stamp every capture fixture and the Broca query name.
fn head_stamp() -> ScopeStamp {
    ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        CAPTURE_SCOPE,
        1,
        ScopeKind::Head,
    )
    .with_owner_authorized(true)
}

/// The reply a `computer_use` read returns with an image, carrying the handle
/// the production reply path would attach for a capture under `scope`.
fn held_reply(planes: &Planes, scope: &str) -> Value {
    let facts = planes
        .routes
        .accepted_bind_for_test(7, 1)
        .expect("the fixture tool route is bound");
    let facts = facts.with_scope(Some(head_stamp()));
    let bytes = cerebellum_core::serde_base64::encode(FIXTURE_BYTES);
    let reply = json!({
        "outcome": "completed",
        "image": {"image_id": "image-1", "mime": "image/png", "data_b64": bytes,
                  "width_px": 1, "height_px": 1},
    });
    cerebellum::mint_image_handle_for_test(planes, &facts, scope, reply)
}

/// A `browser_use` status call, which binds this fixture's tool route.
async fn bind_tool_route(planes: &Planes, writer: &tokio::sync::mpsc::Sender<Frame>) {
    handle_tool_request_for_test_with_planes(
        Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            7,
            1,
            1,
            serde_json::to_vec(&json!({"name":"browser_use","arguments":{"action":"status"}}))
                .unwrap(),
        )
        .unwrap(),
        writer,
        planes,
    )
    .await
    .unwrap();
}

/// The handle every vector names, in place of the random one the fixture
/// minted. A handle is 16 random bytes by design, so a corpus that pinned a
/// real one could never be regenerated: this fixed value is the one shape a
/// handle may take, and both bodies' bytes and the whole wire frame are pinned
/// with it. It is never looked up: the resolve cases answer from the store's
/// refusal path whatever handle they name.
const RECORDED_HANDLE: &str = "ih0123456789abcdef0123456789abcdef";

/// `text` with the fixture's own handle replaced by `RECORDED_HANDLE`.
fn recorded(text: &str, handle: &str) -> String {
    text.replace(handle, RECORDED_HANDLE)
}

/// Compare a captured exchange with its pinned file. With
/// `CEREBELLUM_WRITE_IMAGE_RESOLVE_VECTORS` set, rewrite the files and the
/// checksums first, for a deliberate contract change.
///
/// A JSON reply is pinned in the case file itself. A binary reply — a
/// successful resolve — has no text body to pin there: its body goes to
/// `{case}.bin` byte for byte, and the case file names that file and its
/// digest, next to the frame's own fields.
fn check(case: &str, state: &str, handle: &str, request: &Frame, reply: &Frame) {
    assert_eq!(reply.header.ty, FrameType::Response);
    let reply_body_bytes = reply.body.clone();
    let request_body = recorded(std::str::from_utf8(&request.body).unwrap(), handle);
    let mut request_bytes = request.header.encode().to_vec();
    request_bytes.extend_from_slice(request_body.as_bytes());
    let request = json!({
        "type": format!("{:?}", request.header.ty),
        "channel": request.header.channel, "epoch": request.header.epoch,
        "corr": request.header.corr, "body_length": request_body.len(),
        "body_utf8": request_body, "wire_hex": hex(&request_bytes),
    });
    let mut reply_bytes = reply.header.encode().to_vec();
    let binary = reply.header.flags.is_binary();
    let reply_common = json!({
        "type": format!("{:?}", reply.header.ty),
        "flags": reply.header.flags.0,
        "channel": reply.header.channel, "epoch": reply.header.epoch,
        "corr": reply.header.corr, "body_length": reply_body_bytes.len(),
    });
    // Bodies are compared and written under one lock, so parallel cases never
    // publish checksums describing a half-written sibling.
    static WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _write = WRITE.lock().unwrap();
    let dir = directory();
    let write = std::env::var_os("CEREBELLUM_WRITE_IMAGE_RESOLVE_VECTORS").is_some();
    let reply = if binary {
        reply_bytes.extend_from_slice(&reply_body_bytes);
        let body_path = dir.join(format!("{case}.bin"));
        if write {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&body_path, &reply_body_bytes).unwrap();
        }
        assert_eq!(
            std::fs::read(&body_path).unwrap(),
            reply_body_bytes,
            "{case} binary body changed"
        );
        let mut reply = reply_common;
        reply["binary"] = json!(true);
        reply["body_file"] = json!(format!("{case}.bin"));
        reply["body_sha256"] = json!(hex(&Sha256::digest(&reply_body_bytes)));
        reply["wire_hex"] = json!(hex(&reply_bytes));
        reply
    } else {
        let reply_body = recorded(std::str::from_utf8(&reply_body_bytes).unwrap(), handle);
        reply_bytes.extend_from_slice(reply_body.as_bytes());
        let mut reply = reply_common;
        reply["body_utf8"] = json!(reply_body);
        reply["wire_hex"] = json!(hex(&reply_bytes));
        reply
    };
    let value = json!({
        "contract": "image-resolve-v1", "case": case, "state": state,
        "principal": "reserved:broca",
        "handle": RECORDED_HANDLE,
        "request": request,
        "reply": reply,
    });
    assert!(
        !value.to_string().contains(handle),
        "{case} still names the fixture's random handle"
    );
    let bytes = format!("{}\n", serde_json::to_string_pretty(&value).unwrap());
    let path = dir.join(format!("{case}.json"));
    if write {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        std::fs::write(dir.join("SHA256SUMS"), sums()).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        bytes,
        "{case} wire bytes changed"
    );
}

fn sums() -> String {
    let mut files: Vec<_> = std::fs::read_dir(directory())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap() != "SHA256SUMS")
        .collect();
    files.sort();
    files
        .iter()
        .map(|path| {
            format!(
                "{}  {}\n",
                hex(&Sha256::digest(std::fs::read(path).unwrap())),
                path.file_name().unwrap().to_str().unwrap()
            )
        })
        .collect()
}

fn suspicious_path(text: &str) -> bool {
    ["/Users/", "/private/", "/tmp/", "/.t/"]
        .iter()
        .any(|prefix| text.contains(prefix))
}

/// Drives the real management handler for the three pinned cases and compares
/// the exact request and reply bytes.
#[tokio::test]
async fn image_resolve_wire_shapes_match_their_goldens() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        None,
        JournalPersistence::Isolated,
    );
    let (writer, mut output) = tokio::sync::mpsc::channel(8);
    // A status call binds the fixture's tool route.
    handle_tool_request_for_test_with_planes(
        Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            7,
            1,
            1,
            serde_json::to_vec(&json!({"name":"browser_use","arguments":{"action":"status"}}))
                .unwrap(),
        )
        .unwrap(),
        &writer,
        &planes,
    )
    .await
    .unwrap();
    output.recv().await.unwrap();
    assert_eq!(
        planes
            .routes
            .accepted_bind_for_test(7, 1)
            .unwrap()
            .identity
            .conversation_key,
        CONVERSATION
    );
    let held = held_reply(&planes, CAPTURE_SCOPE);
    assert_eq!(held["outcome"], "completed");
    let handle = held["image_handle"].as_str().unwrap().to_owned();

    // Bind Broca's management route through the production control path.
    let bind = ModuleControlRequest::RouteBind {
        route_channel: 9,
        epoch: 1,
        principal: Some(Principal::Reserved {
            module_id: "broca".into(),
        }),
        identity: BindIdentity::new("/fixture", "fixture", "session"),
        admission_facts: None,
        consumer_capabilities: None,
        target: RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
        scope: None,
        role_versions: None,
        call_mode: None,
    };
    let frame = |channel, corr, body: Value| {
        Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            if channel == 0 { 0 } else { 1 },
            corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap()
    };
    handle_frame_for_test(
        frame(0, 3, serde_json::to_value(bind).unwrap()),
        &writer,
        &planes,
    )
    .await
    .unwrap();
    let bound = output.recv().await.unwrap();
    assert_eq!(bound.header.ty, FrameType::Response);

    let resolve = |corr, params: Value| {
        frame(
            9,
            corr,
            json!({"method": "image.resolve", "params": params}),
        )
    };

    let request = resolve(11, json!({"handle": handle, "scope_ref": CAPTURE_SCOPE}));
    handle_frame_for_test(request.clone(), &writer, &planes)
        .await
        .unwrap();
    let reply = output.recv().await.unwrap();
    assert!(
        reply.header.flags.is_binary(),
        "a resolve success is a binary frame"
    );
    let expected_sha256: String = Sha256::digest(FIXTURE_BYTES)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    // `u32` big-endian head length, the head JSON, then the image's own bytes.
    let head_length = u32::from_be_bytes(reply.body[..4].try_into().unwrap()) as usize;
    let head: Value = serde_json::from_slice(&reply.body[4..4 + head_length]).unwrap();
    assert_eq!(
        head,
        json!({
            "content_type": "image/png",
            "sha256": expected_sha256,
            "length": FIXTURE_BYTES.len(),
        })
    );
    assert_eq!(&reply.body[4 + head_length..], FIXTURE_BYTES);
    check(
        "success",
        "a screenshot handle resolves to exactly the bytes the reply carried",
        &handle,
        &request,
        &reply,
    );

    let request = resolve(
        12,
        json!({"handle": handle, "scope_ref": CAPTURE_SCOPE, "owner": "reserved:broca"}),
    );
    handle_frame_for_test(request.clone(), &writer, &planes)
        .await
        .unwrap();
    let reply = output.recv().await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap(),
        json!({
            "outcome": "invalid_request",
            "context": Value::Null,
            "session": Value::Null,
            "detail": {"field": "owner", "reason_code": "unknown_field"},
        })
    );
    check(
        "unknown-field",
        "an unexpected parameter is refused, naming it",
        &handle,
        &request,
        &reply,
    );

    // The handle exists and was minted under a scope. Naming another scope is
    // one way to fall outside the authorized union; a handle that was never
    // minted is the other. Both answer the same bytes.
    let request = resolve(
        13,
        json!({"handle": handle, "scope_ref": "another-conversation"}),
    );
    handle_frame_for_test(request.clone(), &writer, &planes)
        .await
        .unwrap();
    let reply = output.recv().await.unwrap();
    let other_scope: Value = serde_json::from_slice(&reply.body).unwrap();
    check(
        "image-unavailable",
        "a handle outside the caller's scope is refused as if it did not exist",
        &handle,
        &request,
        &reply,
    );

    let never_minted = format!("ih{}", "0".repeat(32));
    let request = resolve(
        14,
        json!({"handle": never_minted, "scope_ref": CAPTURE_SCOPE}),
    );
    handle_frame_for_test(request, &writer, &planes)
        .await
        .unwrap();
    let unknown: Value = serde_json::from_slice(&output.recv().await.unwrap().body).unwrap();
    assert_eq!(
        other_scope,
        json!({
            "outcome": "image_unavailable",
            "context": Value::Null,
            "session": Value::Null,
            "detail": {"field": "handle"},
        })
    );
    assert_eq!(other_scope, unknown, "a refusal must not say which it is");

    let pinned = std::fs::read_to_string(directory().join("SHA256SUMS")).unwrap();
    assert_eq!(pinned, sums());
    let names: Vec<&str> = pinned
        .lines()
        .map(|line| line.split_once("  ").unwrap().1)
        .collect();
    assert_eq!(
        names,
        [
            "README.md",
            "image-unavailable.json",
            "success.bin",
            "success.json",
            "unknown-field.json"
        ]
    );
}

/// A conversation's handles go with the conversation, however young they are:
/// otherwise a closed run's screenshots would stay fetchable for their full
/// fifteen minutes.
#[tokio::test]
async fn closing_the_conversations_last_route_drops_its_handles() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        None,
        JournalPersistence::Isolated,
    );
    let (writer, mut output) = tokio::sync::mpsc::channel(8);
    handle_tool_request_for_test_with_planes(
        Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            7,
            1,
            1,
            serde_json::to_vec(&json!({"name":"browser_use","arguments":{"action":"status"}}))
                .unwrap(),
        )
        .unwrap(),
        &writer,
        &planes,
    )
    .await
    .unwrap();
    output.recv().await.unwrap();
    let handle = held_reply(&planes, CAPTURE_SCOPE)["image_handle"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(planes.image_handle_store().held(), 1);

    let (closed, _closed_output) = tokio::sync::mpsc::channel(4);
    handle_frame_for_test(
        Frame::build(
            FrameType::Goodbye,
            Flags::new(false, Priority::Interactive, false),
            7,
            1,
            2,
            Vec::new(),
        )
        .unwrap(),
        &closed,
        &planes,
    )
    .await
    .unwrap();
    assert_eq!(
        planes.image_handle_store().held(),
        0,
        "the conversation's handle outlived its conversation"
    );
    assert!(planes
        .image_handle_store()
        .resolve(
            &handle,
            &[CAPTURE_SCOPE],
            cerebellum::wall_clock_ms_for_test()
        )
        .is_none());
}

/// A route bound through the production control path, on management channel
/// 10, with `scope` as its stamp and `principal` as its caller.
async fn bind_management(
    planes: &Planes,
    writer: &tokio::sync::mpsc::Sender<Frame>,
    principal: Principal,
    conversation: &str,
    scope: Option<ScopeStamp>,
) {
    let bind = ModuleControlRequest::RouteBind {
        route_channel: 10,
        epoch: 1,
        principal: Some(principal),
        identity: BindIdentity::new("/fixture", "fixture", conversation.to_string()),
        admission_facts: None,
        consumer_capabilities: None,
        target: RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
        scope,
        role_versions: None,
        call_mode: None,
    };
    handle_frame_for_test(
        Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            0,
            0,
            20,
            serde_json::to_vec(&json!(bind)).unwrap(),
        )
        .unwrap(),
        writer,
        planes,
    )
    .await
    .unwrap();
}

/// One request on management channel 10, returning the frame type and body.
async fn management(planes: &Planes, corr: u64, body: Value) -> (FrameType, Value) {
    let (writer, mut output) = tokio::sync::mpsc::channel(4);
    handle_frame_for_test(
        Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            10,
            1,
            corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap(),
        &writer,
        planes,
    )
    .await
    .unwrap();
    let frame = output.recv().await.unwrap();
    (
        frame.header.ty,
        serde_json::from_slice(&frame.body).unwrap(),
    )
}

/// A caller that is not `reserved:broca` never reaches `image.resolve`: its
/// management bind is refused, so a handle it guessed is never even looked at.
#[tokio::test]
async fn a_non_broca_caller_cannot_resolve_a_handle() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        None,
        JournalPersistence::Isolated,
    );
    let (fixture, mut fixture_output) = tokio::sync::mpsc::channel(4);
    bind_tool_route(&planes, &fixture).await;
    fixture_output.recv().await.unwrap();
    let handle = held_reply(&planes, CAPTURE_SCOPE)["image_handle"]
        .as_str()
        .unwrap()
        .to_owned();
    let (writer, mut output) = tokio::sync::mpsc::channel(4);
    bind_management(
        &planes,
        &writer,
        Principal::Reserved {
            module_id: "basal".into(),
        },
        "basal-conversation",
        Some(head_stamp()),
    )
    .await;
    // Basal has no authority here, so the bind was refused and channel 10
    // serves nothing at all.
    let refused = output.recv().await.unwrap();
    assert_eq!(refused.header.ty, FrameType::Error);
    assert!(planes.routes.accepted_bind_for_test(10, 1).is_none());
    let (ty, body) = management(
        &planes,
        21,
        json!({
            "method": "image.resolve",
            "params": {"handle": handle, "scope_ref": CAPTURE_SCOPE},
        }),
    )
    .await;
    assert_eq!(ty, FrameType::Error, "{body}");
    assert_eq!(body["code"], "route_not_bound", "{body}");
    assert!(
        !body.to_string().contains(&handle),
        "the refusal names the handle it refused: {body}"
    );
}

/// `reserved:broca` on its management route may call the two operations it
/// serves and nothing else.
#[tokio::test]
async fn broca_management_route_serves_only_its_two_operations() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        None,
        JournalPersistence::Isolated,
    );
    let (writer, mut output) = tokio::sync::mpsc::channel(4);
    bind_management(
        &planes,
        &writer,
        Principal::Reserved {
            module_id: "broca".into(),
        },
        "broca-conversation",
        None,
    )
    .await;
    let bound = output.recv().await.unwrap();
    assert_eq!(bound.header.ty, FrameType::Response);
    let (ty, body) = management(
        &planes,
        22,
        json!({"method": "permissions.list", "params": {}}),
    )
    .await;
    assert_eq!(ty, FrameType::Error, "{body}");
    assert_eq!(body["code"], "principal_denied", "{body}");
}

/// A run's screenshot resolves for the harness that started it: the run
/// captures under its own scope, and Broca asks only with the head's scope
/// ref, which the union widens to the live run's head and so to its capture.
///
/// This is the union's contract, not a second capture path: the handle is
/// minted for the run's scope directly, and the head's route plus the run's
/// route are what the union has to walk to reach it.
#[tokio::test]
async fn a_runs_handle_resolves_through_its_head() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        None,
        JournalPersistence::Isolated,
    );
    let (writer, mut output) = tokio::sync::mpsc::channel(8);
    bind_tool_route(&planes, &writer).await;
    output.recv().await.unwrap();

    let core = Principal::Reserved {
        module_id: "prefrontal-core".into(),
    };
    let admission = json!({
        "agentProjectId": "test-project",
        "sessionKind": "primary",
        "effectiveCapabilityScope": ["*"],
    });
    // The head's own tool route.
    let head_facts = cerebellum::AcceptedBindFacts::from_bind(
        &BindIdentity::new("/fixture", "fixture", "head-conversation".to_string()),
        Some(core.clone()),
        Some(&admission),
        None,
        &RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
    )
    .with_scope(Some(
        ScopeStamp::new(core.clone(), "head-scope", 1, ScopeKind::Head)
            .with_owner_authorized(true)
            .with_attributes(
                subc_protocol::scope::ScopeAttributes::new()
                    .with_agent_id(Some("test-project".into()))
                    .with_delegates(true),
            ),
    ));
    planes.routes.insert_for_test(5, 1, head_facts.clone());

    // The run: an ephemeral scope whose linked parent is that head.
    let run_stamp = ScopeStamp::new(core, "run-scope", 1, ScopeKind::Ephemeral)
        .with_owner_authorized(true)
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new()
                .with_agent_id(Some("test-project".into()))
                .with_run_id(Some("run-scope".into())),
        )
        .with_parent(Some(subc_protocol::scope::ScopeParent::new(
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            "head-scope",
            1,
        )))
        .with_parent_state(Some(subc_protocol::scope::ParentState::Linked));
    let run_facts = cerebellum::AcceptedBindFacts::from_bind(
        &BindIdentity::new("/fixture", "fixture", "run-conversation".to_string()),
        Some(Principal::Reserved {
            module_id: "basal".into(),
        }),
        Some(&admission),
        None,
        &RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
    )
    .with_scope(Some(run_stamp));
    planes.routes.insert_for_test(6, 1, run_facts);

    // The table is what the union walks: the run under its own scope, its
    // parent naming the head, and the head itself under a head stamp.
    let stamps = planes.routes.scope_stamps_for_test();
    assert!(
        stamps.iter().any(|stamp| stamp.scope_ref == "run-scope"
            && stamp
                .parent
                .as_ref()
                .is_some_and(|head| head.scope_ref == "head-scope")),
        "the fixture's run route lost its parent: {stamps:?}"
    );
    assert!(stamps.iter().any(|stamp| stamp.scope_ref == "head-scope"));

    // A capture on the run's route names the run's scope.
    let handle = held_reply(&planes, "run-scope")["image_handle"]
        .as_str()
        .unwrap()
        .to_owned();

    // Broca binds its management route through the production control path.
    let (broca, mut broca_output) = tokio::sync::mpsc::channel(4);
    bind_management(
        &planes,
        &broca,
        Principal::Reserved {
            module_id: "broca".into(),
        },
        "broca-conversation",
        None,
    )
    .await;
    let bound = broca_output.recv().await.unwrap();
    assert_eq!(bound.header.ty, FrameType::Response);

    // The union names the run's capture when Broca names the head, and adds
    // nothing for a scope no run was bound under.
    let run_union = cerebellum::private_content_scope_union_for_test(&planes, "run-scope", None);
    assert!(
        run_union.iter().any(|scope| scope == "head-scope"),
        "naming the run must reach its head: {run_union:?}"
    );
    let head_union = cerebellum::private_content_scope_union_for_test(&planes, "head-scope", None);
    assert_eq!(head_union, ["head-scope"], "the head names no run");
    assert_eq!(
        cerebellum::private_content_scope_union_for_test(&planes, "another-scope", None),
        ["another-scope"]
    );
    // The handle itself resolves only when the run's scope is in the union.
    assert!(planes
        .image_handle_store()
        .resolve(
            &handle,
            &["head-scope", "run-scope"],
            cerebellum::wall_clock_ms_for_test()
        )
        .is_some());
    assert!(planes
        .image_handle_store()
        .resolve(
            &handle,
            &["head-scope"],
            cerebellum::wall_clock_ms_for_test()
        )
        .is_none());
}
