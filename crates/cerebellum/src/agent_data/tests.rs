use super::*;
use crate::{
    private_content::{ReplyPlane, Retention},
    HealthState,
};
use sha2::{Digest, Sha256};
use subc_protocol::{FrameType, Principal, RouteTarget};

const CUT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AGENT: &str = "agent-x";

/// Remove precisely the participant's role and capability for historical HELLO
/// comparisons. The current HELLO keeps separate full-byte pins.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn without_agent_data(current: &Value) -> Value {
    let mut previous = current.clone();
    let roles = previous["provides"].as_array_mut().unwrap();
    let index = roles
        .iter()
        .position(|role| role["service_id"] == "agent-data")
        .unwrap();
    let removed = roles.remove(index);
    assert_eq!(
        removed,
        json!({"role":"internal_service","service_id":"agent-data","transport":"bulk","agent_facing":false,"operations":Op::ALL.into_iter().map(|op|op.method()).collect::<Vec<_>>()})
    );
    let provides = previous["capabilities"]["provides"].as_array_mut().unwrap();
    let index = provides
        .iter()
        .position(|cap| cap == "agent-data/v1")
        .unwrap();
    provides.remove(index);
    assert!(!provides.iter().any(|cap| cap == "agent-data/v1"));
    previous
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../target/scratch/agent-data-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        cerebellum_core::private_fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn production_startup_creates_private_backup_directory_without_touching_existing_one() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new();
    let directory = scratch.0.join("cortexkit/cerebellum/agent-data");
    assert!(!directory.exists());

    Participant::with_data_home(Some(&scratch.0));
    assert!(directory.is_dir(), "startup did not create {directory:?}");
    assert!(directory.read_dir().unwrap().next().is_none());
    #[cfg(unix)]
    assert_eq!(
        directory.metadata().unwrap().permissions().mode() & 0o777,
        0o700
    );

    let existing_record = directory.join("existing-record");
    std::fs::write(&existing_record, b"keep").unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o710)).unwrap();

    Participant::with_data_home(Some(&scratch.0));
    assert_eq!(std::fs::read(&existing_record).unwrap(), b"keep");
    #[cfg(unix)]
    assert_eq!(
        directory.metadata().unwrap().permissions().mode() & 0o777,
        0o710
    );
}

#[derive(Default)]
struct FakeDoor {
    streams: Mutex<BTreeMap<String, Vec<u8>>>,
    sealed: Mutex<BTreeMap<String, Value>>,
    calls: Mutex<Vec<(String, Value)>>,
    fail_cover: std::sync::atomic::AtomicBool,
}

impl door::Door for FakeDoor {
    fn call<'a>(
        &'a self,
        method: &'a str,
        params: Value,
    ) -> crate::login_capture::vault::BoxFuture<'a, Result<Value, ErrorBody>> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .push((method.into(), params.clone()));
            if method == "cut.read" {
                return self
                    .sealed
                    .lock()
                    .unwrap()
                    .get(params["cutId"].as_str().unwrap())
                    .cloned()
                    .ok_or_else(|| unavailable("cut not sealed"));
            }
            let session = params["sessionRef"].as_str().unwrap();
            let mut streams = self.streams.lock().unwrap();
            let bytes = streams.entry(session.into()).or_default();
            match method {
                "session.admit" => {
                    let offset = params["fromOffset"].as_u64().unwrap() as usize;
                    if offset != bytes.len() {
                        return Err(detailed(
                            RefusalCode::Unknown("offset_mismatch".into()),
                            "offset differs",
                            json!({"expectedOffset":bytes.len()}),
                        ));
                    }
                    bytes.extend(door::unhex(params["bytes"].as_str().unwrap()).unwrap());
                    Ok(json!({"durableOffset":bytes.len()}))
                }
                "session.cover" => {
                    if self
                        .fail_cover
                        .swap(false, std::sync::atomic::Ordering::Relaxed)
                    {
                        return Err(unavailable("temporary cloud failure"));
                    }
                    Ok(json!({"durableOffset":bytes.len(),"cloudOffset":bytes.len()}))
                }
                "session.read" => {
                    let offset = params["fromOffset"].as_u64().unwrap() as usize;
                    let limit = params["limit"].as_u64().unwrap() as usize;
                    if let Some(cut) = params["cutId"].as_str() {
                        assert!(
                            self.sealed.lock().unwrap().contains_key(cut),
                            "receiver must name the sealed cut"
                        );
                    }
                    Ok(
                        json!({"fromOffset":offset,"endOffset":offset+limit,"streamEnd":bytes.len(),"digest":door::hex(&Sha256::digest(&*bytes)),"bytes":door::hex(&bytes[offset..offset+limit])}),
                    )
                }
                _ => panic!("unexpected door operation {method}"),
            }
        })
    }
}

fn planes(door: &Arc<FakeDoor>) -> Planes {
    let planes = Planes::new(Arc::new(HealthState::new()));
    planes.agent_data.set_door(door.clone());
    planes
}

fn params() -> Value {
    json!({"refs":[{"ref_kind":"agent","ref":AGENT}],"cutId":CUT})
}

fn facts(module: &str) -> AcceptedBindFacts {
    AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("test", "agent-data"),
        Some(Principal::Reserved {
            module_id: module.into(),
        }),
        None,
        None,
        &RouteTarget::InternalService {
            module_id: "cerebellum".into(),
            service_id: "agent-data".into(),
        },
    )
}

async fn wire(planes: &Planes, caller: AcceptedBindFacts, body: Value) -> (FrameType, Value) {
    planes.routes.insert(10, 1, caller);
    let frame = Frame::build(
        FrameType::Request,
        crate::control_flags(),
        10,
        1,
        1,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    crate::handle_route_request(frame, &tx, planes)
        .await
        .unwrap();
    let frame = rx.recv().await.unwrap();
    (
        frame.header.ty,
        serde_json::from_slice(&frame.body).unwrap(),
    )
}

async fn call(planes: &Planes, method: &str, params: Value) -> Value {
    let (ty, reply) = wire(
        planes,
        facts("entorhinal"),
        json!({"method":method,"params":params}),
    )
    .await;
    assert_eq!(ty, FrameType::Response, "{method}: {reply}");
    let result = reply
        .get("result")
        .expect("success must be wrapped")
        .clone();
    use cortexkit_role_agent_data as contract;
    macro_rules! check {
        ($ty:ty) => {
            serde_json::from_value::<$ty>(result.clone()).map(|_| ())
        };
    }
    match Op::from_method(method).unwrap() {
        Op::Describe => check!(contract::describe::DescribeReply),
        Op::Busy => check!(contract::busy::BusyReply),
        Op::Status => check!(contract::status::StatusReply),
        Op::Prepare => check!(contract::prepare::PrepareReply),
        Op::Export => check!(contract::export::ExportReply),
        Op::Diverged => check!(contract::diverged::DivergedReply),
        Op::Import => check!(contract::import::ImportReply),
        Op::Activate | Op::Abort => check!(contract::EmptyReply),
        Op::Release => check!(contract::release::ReleaseReply),
    }
    .unwrap_or_else(|e| panic!("{method} violated reply contract: {e}"));
    result
}

fn seal(door: &FakeDoor, id: &str, prepared: &Value) {
    let items: Vec<_>=prepared["items"].as_array().unwrap().iter().map(|i|json!({"sessionRef":i["sessionRef"],"stream":i["stream"],"endOffset":i["endOffset"],"digest":i["digest"]})).collect();
    door.sealed
        .lock()
        .unwrap()
        .insert(id.into(), json!({"items":items}));
}

#[tokio::test]
async fn round_trip_through_engram_preserves_marks_and_release_keeps_source_copy() {
    let door = Arc::new(FakeDoor::default());
    let source = planes(&door);
    let receiver = planes(&door);
    let stamp = subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal".into(),
        },
        "old-scope",
        1,
        subc_protocol::scope::ScopeKind::Head,
    )
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new().with_agent_id(Some(AGENT.into())),
    );
    let marked = facts("prefrontal").with_scope(Some(stamp));
    crate::private_content::mark_delivered(
        &source,
        &marked,
        ReplyPlane::PersonBrowser,
        &json!({"state_text":"private text never exported"}),
    )
    .await;
    let prepared = call(&source, "agent_data.prepare", params()).await;
    assert_eq!(prepared["items"][0]["ref_kind"], "agent");
    assert_eq!(prepared["items"][0]["frozen"], false);
    let bytes = door
        .streams
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        r#"{"v":1,"agent_id":"agent-x","sources":["person_browser"]}"#
    );
    call(&source, "agent_data.export", params()).await;
    seal(&door, CUT, &prepared);
    let imported = call(&receiver, "agent_data.import", params()).await;
    assert_eq!(
        imported["items"][0]["digest"],
        prepared["items"][0]["digest"]
    );
    assert_eq!(
        receiver.private_content.export_agent(AGENT),
        BTreeSet::from([Source::PersonBrowser])
    );
    let before = door.calls.lock().unwrap().len();
    assert_eq!(
        call(&receiver, "agent_data.activate", params()).await,
        json!({})
    );
    assert_eq!(
        door.calls.lock().unwrap().len(),
        before,
        "activation does not access marks or door"
    );
    let mut release = params();
    release["holder"] = json!("02020202020202020202020202020202");
    release["holderBox"] = json!("0123456789abcdef0123456789abcdef");
    assert_eq!(
        call(&source, "agent_data.release", release.clone()).await,
        json!({"enforced":false})
    );
    assert_eq!(
        source.private_content.export_agent(AGENT),
        BTreeSet::from([Source::PersonBrowser])
    );
    assert_eq!(
        call(&source, "agent_data.release", release.clone()).await,
        json!({"enforced":false})
    );
    release["holder"] = json!("03030303030303030303030303030303");
    let (ty, e) = wire(
        &source,
        facts("entorhinal"),
        json!({"method":"agent_data.release","params":release}),
    )
    .await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(e["code"], "id_reused");
    // A finished cut keeps only its step and saved replies: no later op reads
    // its snapshot or ref set, and repeats still get their first replies.
    for participant in [&source, &receiver] {
        let state = participant.agent_data.state.lock().await;
        let cut = &state.cuts[CUT];
        assert!(cut.payloads.is_empty() && cut.refs.is_none());
    }
    assert_eq!(
        call(&source, "agent_data.prepare", params()).await,
        prepared
    );
    assert_eq!(
        call(&receiver, "agent_data.import", params()).await,
        imported
    );
}

#[tokio::test]
async fn unknown_agent_diverged_is_at_cut_without_any_outbound_call() {
    let door = Arc::new(FakeDoor::default());
    let planes = planes(&door);
    assert_eq!(
        call(&planes, "agent_data.diverged", params()).await,
        json!({"refs":[{"state":"at_cut"}]})
    );
    assert!(door.calls.lock().unwrap().is_empty());
    assert_eq!(
        call(&planes, "agent_data.busy", json!({"refs":params()["refs"]})).await,
        json!({"refs":[{"state":"idle"}]})
    );
}

#[tokio::test]
async fn unmarked_agent_exports_no_item_and_union_import_never_loses_local_marks() {
    let door = Arc::new(FakeDoor::default());
    let source = planes(&door);
    let receiver = planes(&door);
    // No item and no admitted stream: the driver may then skip a receiver
    // without cerebellum, since nothing in the cut could be lost there.
    let prepared = call(&source, "agent_data.prepare", params()).await;
    assert_eq!(prepared["items"], json!([]));
    assert_eq!(
        call(&source, "agent_data.export", params()).await,
        json!({"items":[]})
    );
    assert!(door.streams.lock().unwrap().is_empty());
    seal(&door, CUT, &prepared);
    let fresh = planes(&door);
    assert_eq!(
        call(&fresh, "agent_data.import", params()).await,
        json!({"items":[]})
    );
    assert!(fresh.private_content.export_agent(AGENT).is_empty());
    receiver
        .private_content
        .import_agent(AGENT, &BTreeSet::from([Source::DesktopApp]))
        .await;
    assert_eq!(
        call(&receiver, "agent_data.diverged", params()).await["refs"][0]["state"],
        "advanced"
    );
    call(&receiver, "agent_data.import", params()).await;
    assert_eq!(
        receiver.private_content.export_agent(AGENT),
        BTreeSet::from([Source::DesktopApp])
    );
}

#[tokio::test]
async fn legacy_scope_marks_ship_only_unattributed_not_scope_refs_or_times() {
    let door = Arc::new(FakeDoor::default());
    let source = planes(&door);
    let receiver = planes(&door);
    source
        .private_content
        .mark("legacy-scope", Retention::Head, Source::PersonBrowser)
        .await;
    let prepared = call(&source, "agent_data.prepare", params()).await;
    seal(&door, CUT, &prepared);
    let bytes = door
        .streams
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        r#"{"v":1,"agent_id":"agent-x","sources":["unattributed"]}"#
    );
    call(&receiver, "agent_data.import", params()).await;
    assert_eq!(
        receiver.private_content.export_agent(AGENT),
        BTreeSet::from([Source::Unattributed])
    );
}

#[tokio::test]
async fn admission_and_strict_envelope_precede_any_state_or_door_access() {
    let door = Arc::new(FakeDoor::default());
    let planes = planes(&door);
    for module in ["prefrontal", "broca", "cingulate", "callosum", "cerebellum"] {
        // Call the internal handler directly to verify its own admission even
        // when a caller bypasses the daemon's earlier bind rejection.
        let frame = Frame::build(
            FrameType::Request,
            crate::control_flags(),
            10,
            1,
            1,
            b"not-json".to_vec(),
        )
        .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        handle(&frame, &tx, &facts(module), &planes).await.unwrap();
        let frame = rx.recv().await.unwrap();
        assert_eq!(frame.header.ty, FrameType::Error);
        assert_eq!(
            serde_json::from_slice::<Value>(&frame.body).unwrap()["code"],
            "caller_forbidden"
        );
    }
    let (ty, e) = wire(
        &planes,
        facts("entorhinal"),
        json!({"method":"agent_data.describe","params":{},"extra":true}),
    )
    .await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(e["code"], "invalid_request");
    let (ty, e) = wire(
        &planes,
        facts("entorhinal"),
        json!({"method":"agent_data.prepare","params":{"refs":params()["refs"],"cutId":"BAD"}}),
    )
    .await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(e["code"], "invalid_request");
    assert!(door.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cut_steps_and_replays_survive_restart_and_checkpoint_failure_is_retryable() {
    let scratch = Scratch::new();
    let path = scratch.0.join("cuts.json");
    let door = Arc::new(FakeDoor::default());
    let mut source = planes(&door);
    source.agent_data = Arc::new(Participant {
        path: Some(path.clone()),
        ..Participant::in_memory()
    });
    source.agent_data.set_door(door.clone());
    assert!(!path.exists());
    let prepared = call(&source, "agent_data.prepare", params()).await;
    call(&source, "agent_data.export", params()).await;
    source.agent_data = Arc::new(Participant {
        path: Some(path.clone()),
        ..Participant::in_memory()
    });
    source.agent_data.set_door(door.clone());
    assert_eq!(
        call(&source, "agent_data.prepare", params()).await,
        prepared
    );
    assert_eq!(
        call(&source, "agent_data.status", params()).await,
        json!({"step":"exported"})
    );
    let (ty, e) = wire(
        &source,
        facts("entorhinal"),
        json!({"method":"agent_data.activate","params":params()}),
    )
    .await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(e["code"], "invalid_state");
    assert_eq!(e["detail"]["step"], "exported");
    std::fs::write(&path, b"unreadable").unwrap();
    let (ty, e) = wire(
        &source,
        facts("entorhinal"),
        json!({"method":"agent_data.describe","params":{}}),
    )
    .await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(e["code"], "unavailable");
    assert_eq!(
        source
            .private_content
            .answer(&["public"], crate::wall_clock_ms())["private_content"],
        false
    );
}

fn pinned_release_vector_file(name: &str, sha256: &str) -> Value {
    let bytes = cortexkit_role_agent_data::vectors::file(name).unwrap();
    assert_eq!(
        door::hex(&Sha256::digest(bytes.as_bytes())),
        sha256,
        "{name}"
    );
    serde_json::from_str(bytes).unwrap()
}

#[tokio::test]
async fn release_vectors_validate_before_save_and_compare_holder_box_after_restart() {
    let requests = pinned_release_vector_file(
        "requests.json",
        "1f09e1ce476f4db143536c9900fd7e9906460a3f839fd3928fa490cbd8a472b0",
    );
    let replies = pinned_release_vector_file(
        "replies.json",
        "7431aab0a16df7b36974d0ad0499b0a524dac2496d3786bc58a2030a8488366c",
    );
    let method = "agent_data.release";
    let adapt = |section: &str, name: &str| {
        let mut sample = requests[section]
            .as_array()
            .unwrap()
            .iter()
            .find(|sample| sample["name"] == name)
            .unwrap()
            .clone();
        assert_eq!(sample["method"], method);
        // The published samples use other participants' ref kinds.
        sample["params"]["refs"] = params()["refs"].clone();
        sample
    };
    let legacy = adapt("requests", "release names the new holder");
    let boxed = adapt("requests", "release names the new holder with a box id");
    let malformed = adapt("refused", "release with malformed holderBox");
    let expected = &replies["replies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sample| sample["method"] == method && sample["reply"]["enforced"] == false)
        .unwrap()["reply"];
    let mut changed = boxed["params"].clone();
    changed["holderBox"] = json!("fedcba9876543210fedcba9876543210");
    let cut_id = legacy["params"]["cutId"].as_str().unwrap();
    let cut = json!({"cutId":cut_id,"refs":params()["refs"]});

    for (release, conflicts) in [
        (&legacy["params"], &[&boxed["params"]][..]),
        (&boxed["params"], &[&legacy["params"], &changed][..]),
    ] {
        let scratch = Scratch::new();
        let path = scratch.0.join("cuts.json");
        let open = || {
            Arc::new(Participant {
                path: Some(path.clone()),
                ..Participant::in_memory()
            })
        };
        let mut source = Planes::new(Arc::new(HealthState::new()));
        source.agent_data = open();
        call(&source, "agent_data.prepare", cut.clone()).await;
        call(&source, "agent_data.export", cut.clone()).await;
        let before = std::fs::read(&path).unwrap();
        let (ty, refusal) = wire(
            &source,
            facts("entorhinal"),
            json!({"method":method,"params":malformed["params"]}),
        )
        .await;
        assert_eq!(ty, FrameType::Error);
        assert_eq!(refusal["code"], malformed["code"]);
        assert!(refusal["message"].as_str().unwrap().contains("holderBox"));
        assert_eq!(std::fs::read(&path).unwrap(), before);

        assert_eq!(&call(&source, method, release.clone()).await, expected);
        let saved = std::fs::read(&path).unwrap();
        let checkpoint: Value = serde_json::from_slice(&saved).unwrap();
        assert_eq!(checkpoint["format_version"], 1);
        // A request without holderBox must keep the old v1 shape, with no null field.
        assert_eq!(
            checkpoint["cuts"][cut_id]["replies"][method],
            json!({"request":release,"reply":expected})
        );

        source.agent_data = open();
        assert_eq!(&call(&source, method, release.clone()).await, expected);
        for repeat in conflicts {
            let (ty, refusal) = wire(
                &source,
                facts("entorhinal"),
                json!({"method":method,"params":repeat}),
            )
            .await;
            assert_eq!(ty, FrameType::Error, "{release} repeated as {repeat}");
            assert_eq!(refusal["code"], "id_reused");
        }
        assert_eq!(std::fs::read(&path).unwrap(), saved);
    }
}

#[tokio::test]
async fn abort_unknown_cut_prevents_delayed_prepare_and_status_names_aborted() {
    let door = Arc::new(FakeDoor::default());
    let planes = planes(&door);
    call(&planes, "agent_data.abort", params()).await;
    assert_eq!(
        call(&planes, "agent_data.status", params()).await,
        json!({"step":"aborted"})
    );
    let (ty, e) = wire(
        &planes,
        facts("entorhinal"),
        json!({"method":"agent_data.prepare","params":params()}),
    )
    .await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(e["code"], "invalid_state");
    assert!(door.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_prepare_retries_its_original_snapshot_and_checks_admitted_prefix() {
    let door = Arc::new(FakeDoor::default());
    let source = planes(&door);
    // A marked agent, so the snapshot has an item to upload and retry.
    source
        .private_content
        .import_agent(AGENT, &BTreeSet::from([Source::PersonBrowser]))
        .await;
    door.fail_cover
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let (ty, e) = wire(
        &source,
        facts("entorhinal"),
        json!({"method":"agent_data.prepare","params":params()}),
    )
    .await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(e["code"], "unavailable");
    source
        .private_content
        .mark("arrived-after-cut", Retention::Head, Source::DesktopApp)
        .await;
    let prepared = call(&source, "agent_data.prepare", params()).await;
    let bytes = door
        .streams
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        r#"{"v":1,"agent_id":"agent-x","sources":["person_browser"]}"#
    );
    assert_eq!(
        prepared["items"][0]["digest"],
        door::hex(&Sha256::digest(
            br#"{"v":1,"agent_id":"agent-x","sources":["person_browser"]}"#
        ))
    );
    assert!(door
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|(m, p)| m == "session.read" && p.get("cutId").is_none()));
    door.streams.lock().unwrap().values_mut().next().unwrap()[0] = b'!';
    let (ty, refusal) = wire(
        &source,
        facts("entorhinal"),
        json!({"method":"agent_data.export","params":params()}),
    )
    .await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(refusal["code"], "invalid_state");
    assert_eq!(refusal["detail"]["step"], "prepared");
}

#[tokio::test]
async fn import_refuses_corrupt_cut_and_failed_marks_persistence_without_advancing() {
    let door = Arc::new(FakeDoor::default());
    let source = planes(&door);
    let mut receiver = planes(&door);
    source
        .private_content
        .mark("legacy", Retention::Head, Source::DesktopApp)
        .await;
    let prepared = call(&source, "agent_data.prepare", params()).await;
    seal(&door, CUT, &prepared);
    let session = prepared["items"][0]["sessionRef"].as_str().unwrap();
    let original = door.streams.lock().unwrap()[session].clone();
    door.streams.lock().unwrap().get_mut(session).unwrap()[0] = b'!';
    let (ty, e) = wire(
        &receiver,
        facts("entorhinal"),
        json!({"method":"agent_data.import","params":params()}),
    )
    .await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(e["code"], "digest_mismatch");
    assert!(receiver.private_content.export_agent(AGENT).is_empty());
    *door.streams.lock().unwrap().get_mut(session).unwrap() = original;
    let scratch = Scratch::new();
    let path = scratch.0.join("marks.json");
    std::fs::create_dir(&path).unwrap();
    receiver.private_content = Arc::new(PrivateContent::open_at(path, crate::wall_clock_ms()));
    receiver
        .private_content
        .set_write_deadline(crate::test_support::HANG_GUARD);
    let (ty, e) = wire(
        &receiver,
        facts("entorhinal"),
        json!({"method":"agent_data.import","params":params()}),
    )
    .await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(e["code"], "unavailable");
    assert_eq!(
        call(&receiver, "agent_data.status", params()).await,
        json!({"step":"none"})
    );
}

#[tokio::test]
async fn pinned_entorhinal_requests_decode_and_agent_ref_adaptations_are_answered() {
    let sums = include_str!("../../tests/vectors/agent-data-requests-v1/SHA256SUMS");
    for (name, bytes) in [
        (
            "new-format.json",
            include_str!("../../tests/vectors/agent-data-requests-v1/new-format.json"),
        ),
        (
            "old-format.json",
            include_str!("../../tests/vectors/agent-data-requests-v1/old-format.json"),
        ),
    ] {
        let expected = sums
            .lines()
            .find_map(|line| {
                let (digest, file) = line.split_once("  ")?;
                (file == name).then_some(digest)
            })
            .unwrap();
        assert_eq!(door::hex(&Sha256::digest(bytes.as_bytes())), expected);
        replay_samples(bytes).await;
    }
}

async fn replay_samples(bytes: &str) {
    let samples: Vec<Value> = serde_json::from_str(bytes).unwrap();
    let door = Arc::new(FakeDoor::default());
    let source = planes(&door);
    let receiver = planes(&door);
    let aborted = planes(&door);
    let mut count = 0;
    for sample in samples {
        let mut request = sample["request"].clone();
        let method = request["method"].as_str().unwrap().to_owned();
        if !method.starts_with("agent_data.") {
            continue;
        }
        Request::decode(&method, &request["params"]).unwrap();
        if let Some(refs) = request
            .get_mut("params")
            .and_then(|p| p.get_mut("refs"))
            .and_then(Value::as_array_mut)
        {
            for r in refs {
                *r = json!({"ref_kind":"agent","ref":AGENT});
            }
        }
        let planes = match sample["side"].as_str().unwrap() {
            "source" => &source,
            "receiver" => &receiver,
            "source-abort" => &aborted,
            _ => unreachable!(),
        };
        let result = call(planes, &method, request["params"].clone()).await;
        if method == "agent_data.prepare" {
            seal(&door, request["params"]["cutId"].as_str().unwrap(), &result);
        }
        count += 1;
    }
    assert_eq!(count, 14);
}
