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
    cut_pages: Mutex<BTreeMap<usize, Result<Value, ErrorBody>>>,
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
            if method.starts_with("cut.") {
                return Err(error(
                    RefusalCode::CallerForbidden,
                    "only entorhinal may call cut.*",
                ));
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
                    let (stream_end, digest) = if let Some(cut) = params["cutId"].as_str() {
                        if let Some(page) = self.cut_pages.lock().unwrap().get(&offset) {
                            return page.clone();
                        }
                        let sealed = self.sealed.lock().unwrap();
                        let items = sealed
                            .get(cut)
                            .ok_or_else(|| refusal("cut_not_published"))?;
                        let item = items
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|item| item["sessionRef"] == session && item["stream"] == STREAM)
                            .ok_or_else(|| refusal("cut_item_missing"))?;
                        (
                            item["endOffset"].as_u64().unwrap() as usize,
                            item["digest"].clone(),
                        )
                    } else {
                        (bytes.len(), json!(door::hex(&Sha256::digest(&*bytes))))
                    };
                    let end = (offset + limit).min(stream_end);
                    Ok(json!({
                        "fromOffset": offset, "endOffset": end, "streamEnd": stream_end,
                        "digest": digest, "bytes": door::hex(&bytes[offset..end]),
                    }))
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
    door.sealed
        .lock()
        .unwrap()
        .insert(id.into(), prepared["items"].clone());
}

fn refusal(code: &str) -> ErrorBody {
    serde_json::from_value(json!({"code":code,"message":"test door refusal"})).unwrap()
}

async fn op_refusal(planes: &Planes, op: Op) -> ErrorBody {
    let (ty, body) = wire(
        planes,
        facts("entorhinal"),
        json!({"method":op.method(),"params":params()}),
    )
    .await;
    assert_eq!(ty, FrameType::Error, "{}: {body}", op.method());
    let refusal: ErrorBody = serde_json::from_value(body).unwrap();
    assert!(
        cortexkit_role_agent_data::errors::allowed_refusals(op).contains(&refusal.code),
        "{} cannot refuse with {}",
        op.method(),
        refusal.code,
    );
    refusal
}

mod session_door_refusals {
    use super::*;
    use RefusalCode::{CutNotReady, DigestMismatch, ParticipantFailed};

    async fn check(op: Op, door_error: ErrorBody, expected: Option<RefusalCode>) {
        let door = Arc::new(FakeDoor::default());
        let receiver = planes(&door);
        let code = door_error.code.clone();
        door.cut_pages.lock().unwrap().insert(0, Err(door_error));
        if op == Op::Diverged {
            assert!(
                receiver
                    .private_content
                    .import_agent(AGENT, &BTreeSet::from([Source::DesktopApp]))
                    .await
            );
        }

        if let Some(expected) = expected {
            let refusal = op_refusal(&receiver, op).await;
            assert_eq!(refusal.code, expected, "door refused with {code}");
            if matches!(expected, ParticipantFailed | DigestMismatch) {
                assert_eq!(
                    refusal.detail.unwrap()["reason"],
                    format!("session_door:{code}"),
                );
            }
        } else {
            let reply = call(&receiver, op.method(), params()).await;
            let expected_reply = if op == Op::Import {
                json!({"items":[]})
            } else {
                json!({"refs":[{"state":"advanced"}]})
            };
            assert_eq!(reply, expected_reply);
        }
        let calls = door.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "{}: {code}", op.method());
        assert_eq!(calls[0].0, "session.read", "{}: {code}", op.method());
        assert_eq!(calls[0].1["cutId"], CUT);
        assert_eq!(calls[0].1["fromOffset"], 0);
    }

    macro_rules! case {
        ($code:ident, $import:expr, $diverged:expr) => {
            mod $code {
                use super::*;

                #[tokio::test]
                async fn import() {
                    check(Op::Import, refusal(stringify!($code)), $import).await;
                }

                #[tokio::test]
                async fn diverged() {
                    check(Op::Diverged, refusal(stringify!($code)), $diverged).await;
                }
            }
        };
        ($code:ident, $import:ident) => {
            case!($code, Some($import), Some(CutNotReady));
        };
    }

    case!(invalid_request, ParticipantFailed);
    case!(caller_forbidden, ParticipantFailed);
    case!(stream_label_too_long, ParticipantFailed);
    case!(record_too_large, ParticipantFailed);
    case!(response_too_large, ParticipantFailed);
    case!(offset_out_of_range, ParticipantFailed);
    case!(below_floor, ParticipantFailed);
    case!(cut_not_published, ParticipantFailed);
    case!(cut_takeover_closed, ParticipantFailed);
    case!(cut_range_not_local, ParticipantFailed);
    case!(verify_failed, DigestMismatch);
    case!(cut_item_missing, None, None);
    case!(unavailable, CutNotReady);
    case!(lease_unavailable, CutNotReady);
    case!(cut_import_pending, CutNotReady);
    case!(not_found, CutNotReady);
    case!(unexpected_door_code, CutNotReady);

    #[tokio::test]
    async fn import_transport_failure() {
        check(
            Op::Import,
            unavailable("door connection closed"),
            Some(CutNotReady),
        )
        .await;
    }

    #[tokio::test]
    async fn diverged_transport_failure() {
        check(
            Op::Diverged,
            unavailable("door connection closed"),
            Some(CutNotReady),
        )
        .await;
    }
}

async fn prepare_paged_cut(door: &Arc<FakeDoor>) -> (String, usize, String) {
    let source = planes(door);
    assert!(
        source
            .private_content
            .import_agent(AGENT, &BTreeSet::from([Source::DesktopApp]))
            .await
    );
    let mut prepared = call(&source, Op::Prepare.method(), params()).await;
    let session = prepared["items"][0]["sessionRef"]
        .as_str()
        .unwrap()
        .to_owned();
    let stream_end = 32 * 1024 + 17;
    let digest = {
        let mut streams = door.streams.lock().unwrap();
        let bytes = streams.get_mut(&session).unwrap();
        // Trailing JSON whitespace forces a second page without changing the marks.
        bytes.resize(stream_end, b' ');
        door::hex(&Sha256::digest(bytes))
    };
    prepared["items"][0]["endOffset"] = json!(stream_end);
    prepared["items"][0]["digest"] = json!(digest);
    seal(door, CUT, &prepared);
    door.calls.lock().unwrap().clear();
    (session, stream_end, digest)
}

#[tokio::test]
async fn receivers_read_multipage_cut_only_through_session_door() {
    let door = Arc::new(FakeDoor::default());
    let (session, stream_end, digest) = prepare_paged_cut(&door).await;
    let receiver = planes(&door);
    assert!(
        receiver
            .private_content
            .import_agent(AGENT, &BTreeSet::from([Source::DesktopApp]))
            .await
    );
    let (ty, reply) = wire(
        &receiver,
        facts("entorhinal"),
        json!({"method":Op::Diverged.method(),"params":params()}),
    )
    .await;
    let calls = vec![
        (
            "session.read".into(),
            json!({"sessionRef":session,"fromOffset":0,"limit":32768,"cutId":CUT}),
        ),
        (
            "session.read".into(),
            json!({"sessionRef":session,"fromOffset":32768,"limit":17,"cutId":CUT}),
        ),
    ];
    assert_eq!(
        *door.calls.lock().unwrap(),
        calls,
        "unexpected divergence calls"
    );
    assert_eq!(ty, FrameType::Response, "{reply}");
    assert_eq!(reply["result"], json!({"refs":[{"state":"at_cut"}]}));

    door.calls.lock().unwrap().clear();
    assert_eq!(
        call(&receiver, Op::Import.method(), params()).await,
        json!({"items":[{"sessionRef":session,"endOffset":stream_end,"digest":digest}]}),
    );
    assert_eq!(
        *door.calls.lock().unwrap(),
        calls,
        "unexpected import calls"
    );
}

#[tokio::test]
async fn late_missing_cut_item_is_not_an_empty_mark_set() {
    let door = Arc::new(FakeDoor::default());
    prepare_paged_cut(&door).await;
    door.cut_pages
        .lock()
        .unwrap()
        .insert(32 * 1024, Err(refusal("cut_item_missing")));
    let receiver = planes(&door);
    let refusal = op_refusal(&receiver, Op::Import).await;
    assert_eq!(refusal.code, RefusalCode::ParticipantFailed);
    assert_eq!(
        refusal.detail.unwrap()["reason"],
        "session_door:cut_item_missing"
    );
    assert!(receiver.private_content.export_agent(AGENT).is_empty());

    assert!(
        receiver
            .private_content
            .import_agent(AGENT, &BTreeSet::from([Source::DesktopApp]))
            .await
    );
    assert_eq!(
        op_refusal(&receiver, Op::Diverged).await.code,
        RefusalCode::CutNotReady
    );
    let calls = door.calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[1].1["fromOffset"], 32768);
    assert_eq!(calls[3].1["fromOffset"], 32768);
}

#[tokio::test]
async fn receivers_refuse_invalid_cut_pages_without_accepting_marks() {
    let door = Arc::new(FakeDoor::default());
    let (session, stream_end, digest) = prepare_paged_cut(&door).await;
    let receiver = planes(&door);
    assert!(
        receiver
            .private_content
            .import_agent(AGENT, &BTreeSet::from([Source::PersonBrowser]))
            .await
    );
    let first_page_bytes = door::hex(&door.streams.lock().unwrap()[&session][..32768]);
    for invalid_page in [
        json!({"fromOffset":0,"endOffset":0,"streamEnd":0,
            "digest":door::hex(&Sha256::digest([])),"bytes":""}),
        json!({"fromOffset":0,"endOffset":32768,"streamEnd":256 * 1024 + 1,
            "digest":digest,"bytes":first_page_bytes}),
    ] {
        door.calls.lock().unwrap().clear();
        door.cut_pages.lock().unwrap().insert(0, Ok(invalid_page));
        assert_eq!(
            op_refusal(&receiver, Op::Import).await.code,
            RefusalCode::DigestMismatch
        );
        assert_eq!(
            op_refusal(&receiver, Op::Diverged).await.code,
            RefusalCode::CutNotReady
        );
        let calls = door.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|(_, params)| params["fromOffset"] == 0));
    }
    let good_page = json!({
        "fromOffset":32768,"endOffset":stream_end,"streamEnd":stream_end,
        "digest":digest,"bytes":"20".repeat(17),
    });
    for (field, wrong) in [
        ("fromOffset", json!(32769)),
        ("endOffset", json!(stream_end - 1)),
        ("streamEnd", json!(stream_end + 1)),
        ("digest", json!("different")),
        ("bytes", json!("00".repeat(17))),
    ] {
        let mut page = good_page.clone();
        page[field] = wrong;
        {
            let mut pages = door.cut_pages.lock().unwrap();
            pages.clear();
            pages.insert(32 * 1024, Ok(page));
        }
        assert_eq!(
            op_refusal(&receiver, Op::Import).await.code,
            RefusalCode::DigestMismatch,
            "{field}"
        );
        assert_eq!(
            op_refusal(&receiver, Op::Diverged).await.code,
            RefusalCode::CutNotReady,
            "{field}"
        );
    }
    assert_eq!(
        receiver.private_content.export_agent(AGENT),
        BTreeSet::from([Source::PersonBrowser])
    );
}

#[tokio::test]
async fn receivers_refuse_unreadable_marks_with_incompatible_version() {
    let door = Arc::new(FakeDoor::default());
    let receiver = planes(&door);
    assert!(
        receiver
            .private_content
            .import_agent(AGENT, &BTreeSet::from([Source::DesktopApp]))
            .await
    );
    let bytes = b"not json";
    door.cut_pages.lock().unwrap().insert(
        0,
        Ok(json!({
            "fromOffset":0,"endOffset":bytes.len(),"streamEnd":bytes.len(),
            "digest":door::hex(&Sha256::digest(bytes)),"bytes":door::hex(bytes),
        })),
    );
    for op in [Op::Import, Op::Diverged] {
        assert_eq!(
            op_refusal(&receiver, op).await.code,
            RefusalCode::IncompatibleVersion
        );
    }
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
