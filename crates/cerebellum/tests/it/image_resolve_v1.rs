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
use subc_protocol::{BindIdentity, Flags, Frame, FrameType, Priority, Principal, RouteTarget};

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
/// the production reply path would attach.
fn held_reply(planes: &Planes) -> Value {
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
    cerebellum::mint_image_handle_for_test(planes, &facts, CAPTURE_SCOPE, reply)
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
/// `CEREBELLUM_WRITE_IMAGE_RESOLVE_VECTORS` set, rewrite the file and the
/// checksums first, for a deliberate contract change.
fn check(case: &str, state: &str, handle: &str, request: &Frame, reply: &Frame) {
    assert_eq!(reply.header.ty, FrameType::Response);
    let request_body = recorded(std::str::from_utf8(&request.body).unwrap(), handle);
    let reply_body = recorded(std::str::from_utf8(&reply.body).unwrap(), handle);
    let mut request_bytes = request.header.encode().to_vec();
    request_bytes.extend_from_slice(request_body.as_bytes());
    let mut reply_bytes = reply.header.encode().to_vec();
    reply_bytes.extend_from_slice(reply_body.as_bytes());
    let value = json!({
        "contract": "image-resolve-v1", "case": case, "state": state,
        "principal": "reserved:broca",
        "handle": RECORDED_HANDLE,
        "request": {
            "type": format!("{:?}", request.header.ty),
            "channel": request.header.channel, "epoch": request.header.epoch,
            "corr": request.header.corr, "body_length": request_body.len(),
            "body_utf8": request_body, "wire_hex": hex(&request_bytes),
        },
        "reply": {
            "type": format!("{:?}", reply.header.ty),
            "channel": reply.header.channel, "epoch": reply.header.epoch,
            "corr": reply.header.corr, "body_length": reply_body.len(),
            "body_utf8": reply_body, "wire_hex": hex(&reply_bytes),
        },
    });
    assert!(
        !value.to_string().contains(handle),
        "{case} still names the fixture's random handle"
    );
    let bytes = format!("{}\n", serde_json::to_string_pretty(&value).unwrap());
    let dir = directory();
    let path = dir.join(format!("{case}.json"));
    // Parallel cases must not publish checksums describing a half-written
    // sibling.
    static WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _write = WRITE.lock().unwrap();
    if std::env::var_os("CEREBELLUM_WRITE_IMAGE_RESOLVE_VECTORS").is_some() {
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
    let held = held_reply(&planes);
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
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    let expected_sha256: String = Sha256::digest(FIXTURE_BYTES)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        body,
        json!({
            "mime": "image/png",
            "sha256": expected_sha256,
            "bytes": cerebellum_core::serde_base64::encode(FIXTURE_BYTES),
        })
    );
    assert!(!suspicious_path(&String::from_utf8_lossy(&reply.body)));
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
    let request = resolve(14, json!({"handle": never_minted, "scope_ref": CAPTURE_SCOPE}));
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
    let handle = held_reply(&planes)["image_handle"]
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
        .resolve(&handle, &[CAPTURE_SCOPE], cerebellum::wall_clock_ms_for_test())
        .is_none());
}
