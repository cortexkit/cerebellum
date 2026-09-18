#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cerebellum::management::{ManagementPlane, TargetResolver, REBIND_PROFILE_ROOT};
use cerebellum::profile::{
    stamped_bind_context, BindFacts, DurableResolution, InvocationToken, JournalReservationHandle,
    PrepareResult, ProfileLifecycle, RebindProvenance, RebindRefusal, RegistryConfig,
    RegistryError, UntrustworthyRegistryReason, PROFILE_ROOT_REBINDS_FILE,
};
use cerebellum::{HealthState, JournalPersistence, Planes};
use cerebellum_computer::platform::TargetResolution;
use serde_json::{json, Value};
use subc_protocol::session::{ModuleControlRequest, ModuleControlResponse};
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget, PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

const REGISTRY_FILE: &str = ".ck-browser-profile-registry-v1.json";
const REGISTRY_TEMPORARY_FILE: &str = ".ck-browser-profile-registry-v1.tmp";
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ck-profile-root-rebind-{label}-{}-{nonce}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("test root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn registry_config() -> RegistryConfig {
    RegistryConfig {
        uuid_protocol_compatible: true,
        grant_verifier_available: true,
        grant_accepted: true,
        sealing_available: true,
        ..RegistryConfig::default()
    }
}

fn profile_context(project_id: &str) -> cerebellum::profile::StampedBindContext {
    stamped_bind_context(BindFacts {
        principal: "direct:agent".to_string(),
        conversation_key: format!("conversation-{project_id}"),
        agent_project_id: project_id.to_string(),
        session_kind: Some("primary".to_string()),
        session_kind_attested: true,
        profile_disposition: Some("durable".to_string()),
        effective_capability_scope: Some(vec!["browser.launch".to_string()]),
        provenance: "daemon_attested_spec_a".to_string(),
    })
    .expect("strict profile context")
}

fn mint_durable_record(root: &Path, project_id: &str) -> cerebellum::profile::RegistryRecord {
    let mut lifecycle = ProfileLifecycle::open_with_config(root, registry_config())
        .expect("production-configured lifecycle");
    let invocation = InvocationToken::for_test(format!("invocation-{project_id}"));
    let reservation =
        JournalReservationHandle::for_test(&invocation, format!("reservation-{project_id}"));
    assert!(matches!(
        lifecycle.prepare_context_open(&invocation, &reservation, &profile_context(project_id),),
        PrepareResult::Prepared(_)
    ));
    match lifecycle
        .registry()
        .resolve_durable(project_id)
        .expect("fresh record resolves")
    {
        DurableResolution::TrustworthyExisting(record) => record,
        other => panic!("minted record did not resolve: {other:?}"),
    }
}

fn recreate_root(root: &Path) {
    let displaced =
        root.with_extension(format!("old-{}", NEXT_ROOT.fetch_add(1, Ordering::Relaxed)));
    fs::rename(root, &displaced).expect("move old root aside");
    fs::create_dir(root).expect("create a different root at the same path");
    for entry in fs::read_dir(&displaced).expect("read displaced root") {
        let entry = entry.expect("root entry");
        fs::rename(entry.path(), root.join(entry.file_name())).expect("restore root contents");
    }
    fs::remove_dir(displaced).expect("displaced root is empty");
}

fn registry_bytes(root: &Path) -> Vec<u8> {
    fs::read(root.join(REGISTRY_FILE)).expect("registry bytes")
}

fn registry_document(root: &Path) -> Value {
    serde_json::from_slice(&registry_bytes(root)).expect("registry JSON")
}

fn provenance(label: &str) -> RebindProvenance {
    RebindProvenance {
        ask_id: format!("ask-{label}"),
        conversation_key: format!("conversation-{label}"),
        at_unix_ms: 1_757_846_400_000,
    }
}

fn assert_identity_mismatch(lifecycle: &ProfileLifecycle, project_id: &str) {
    assert!(matches!(
        lifecycle.registry().resolve_durable(project_id),
        Err(RegistryError::Untrustworthy(
            UntrustworthyRegistryReason::ManagedRootIdentityChanged
        ))
    ));
}

#[test]
fn recreated_root_is_refused_then_rebound_without_changing_the_record() {
    let root = TestRoot::new("heal");
    let project_id = "project-heal";
    let original_record = mint_durable_record(root.path(), project_id);
    recreate_root(root.path());

    let lifecycle = ProfileLifecycle::open_with_config(root.path(), registry_config())
        .expect("recreated root opens");
    assert_identity_mismatch(&lifecycle, project_id);
    let before = registry_document(root.path());
    let old_identity = before["managed_root_identity"]
        .as_str()
        .expect("old identity")
        .to_string();
    let generation_before = before["generation"].as_u64().expect("generation");

    let report = lifecycle
        .registry()
        .rebind_managed_root(&provenance("heal"))
        .expect("root rebind succeeds");

    let resolved = match lifecycle
        .registry()
        .resolve_durable(project_id)
        .expect("rebound registry resolves")
    {
        DurableResolution::TrustworthyExisting(record) => record,
        other => panic!("rebound record did not resolve: {other:?}"),
    };
    assert_eq!(resolved, original_record);

    let after = registry_document(root.path());
    let new_identity = after["managed_root_identity"]
        .as_str()
        .expect("new identity");
    assert_ne!(old_identity, new_identity);
    assert_eq!(after["generation"], generation_before + 1);
    assert_eq!(report.generation_before, generation_before);
    assert_eq!(report.generation_after, generation_before + 1);
    assert_eq!(report.record_count, 1);

    let record_bytes = fs::read_to_string(root.path().join(PROFILE_ROOT_REBINDS_FILE))
        .expect("durable rebind record");
    let lines: Vec<&str> = record_bytes.lines().collect();
    assert_eq!(lines.len(), 1, "one rebind writes one provenance line");
    let durable: Value = serde_json::from_str(lines[0]).expect("rebind record JSON");
    assert_eq!(durable["schema"], "ck-browser-profile-root-rebind/v1");
    assert_eq!(durable["old_identity"], old_identity);
    assert_eq!(durable["new_identity"], new_identity);
    assert_eq!(durable["generation_before"], generation_before);
    assert_eq!(durable["generation_after"], generation_before + 1);
    assert_eq!(durable["record_count"], 1);
    assert_eq!(durable["elicited"]["ask_id"], "ask-heal");
    assert_eq!(durable["elicited"]["conversation_key"], "conversation-heal");
}

#[test]
fn rebind_never_adopts_an_unaccounted_profile_directory() {
    let root = TestRoot::new("never-adopt");
    let project_id = "project-never-adopt";
    mint_durable_record(root.path(), project_id);
    recreate_root(root.path());
    fs::create_dir_all(root.path().join("profiles/restored-attacker-profile"))
        .expect("plausible unaccounted profile directory");
    let before = registry_bytes(root.path());
    let lifecycle = ProfileLifecycle::open_with_config(root.path(), registry_config()).unwrap();
    assert_identity_mismatch(&lifecycle, project_id);

    let refusal = lifecycle
        .registry()
        .rebind_managed_root(&provenance("never-adopt"))
        .expect_err("unaccounted profile must refuse");
    match refusal {
        RebindRefusal::PossiblyManagedPath { unaccounted } => {
            assert_eq!(unaccounted, vec!["restored-attacker-profile"])
        }
        other => panic!("wrong refusal: {other:?}"),
    }
    assert_eq!(registry_bytes(root.path()), before);
    assert!(!root.path().join(PROFILE_ROOT_REBINDS_FILE).exists());
}

#[test]
fn rebind_checks_integrity_before_considering_profile_paths() {
    let root = TestRoot::new("integrity");
    let project_id = "project-integrity";
    mint_durable_record(root.path(), project_id);
    recreate_root(root.path());

    let mut document = registry_document(root.path());
    document["records"][project_id]["target"] = Value::String("profiles/edited-target".to_string());
    fs::write(
        root.path().join(REGISTRY_FILE),
        serde_json::to_vec(&document).unwrap(),
    )
    .expect("write parseable edited registry");
    let edited = registry_bytes(root.path());
    let lifecycle = ProfileLifecycle::open_with_config(root.path(), registry_config()).unwrap();

    assert!(matches!(
        lifecycle
            .registry()
            .rebind_managed_root(&provenance("integrity")),
        Err(RebindRefusal::IntegrityMismatch)
    ));
    assert_eq!(registry_bytes(root.path()), edited);
    assert!(!root.path().join(PROFILE_ROOT_REBINDS_FILE).exists());
}

/// Integrity is checked BEFORE the identity compare. A registry whose root
/// still matches but whose records were edited must refuse as tampered, not
/// as "nothing to do": `AlreadyBound` is a statement about a document the
/// primitive has decided to trust, and it may not make that statement about
/// bytes whose digest does not verify. The other integrity test cannot see this
/// -- its root is recreated, so either order reaches the digest check.
#[test]
fn tampered_records_refuse_as_integrity_even_when_the_root_is_already_bound() {
    let root = TestRoot::new("integrity-first");
    let project_id = "project-integrity-first";
    mint_durable_record(root.path(), project_id);

    let mut document = registry_document(root.path());
    document["records"][project_id]["target"] = Value::String("profiles/edited-target".to_string());
    fs::write(
        root.path().join(REGISTRY_FILE),
        serde_json::to_vec(&document).unwrap(),
    )
    .expect("write parseable edited registry");
    let edited = registry_bytes(root.path());
    let lifecycle = ProfileLifecycle::open_with_config(root.path(), registry_config()).unwrap();

    let refusal = lifecycle
        .registry()
        .rebind_managed_root(&provenance("integrity-first"))
        .expect_err("tampered records must refuse");
    assert!(
        matches!(refusal, RebindRefusal::IntegrityMismatch),
        "expected IntegrityMismatch ahead of AlreadyBound, got {refusal:?}"
    );
    assert_eq!(registry_bytes(root.path()), edited);
    assert!(!root.path().join(PROFILE_ROOT_REBINDS_FILE).exists());
}

#[test]
fn already_bound_registry_is_byte_identical_after_refusal() {
    let root = TestRoot::new("already-bound");
    mint_durable_record(root.path(), "project-already-bound");
    let before = registry_bytes(root.path());
    let lifecycle = ProfileLifecycle::open_with_config(root.path(), registry_config()).unwrap();

    assert!(matches!(
        lifecycle
            .registry()
            .rebind_managed_root(&provenance("already-bound")),
        Err(RebindRefusal::AlreadyBound)
    ));
    assert_eq!(registry_bytes(root.path()), before);
    assert!(!root.path().join(PROFILE_ROOT_REBINDS_FILE).exists());
}

#[test]
fn durable_rebind_record_is_synced_before_registry_rewrite_is_attempted() {
    let root = TestRoot::new("record-first");
    let project_id = "project-record-first";
    mint_durable_record(root.path(), project_id);
    recreate_root(root.path());
    let old_identity = registry_document(root.path())["managed_root_identity"]
        .as_str()
        .unwrap()
        .to_string();
    fs::create_dir(root.path().join(REGISTRY_TEMPORARY_FILE))
        .expect("block the registry temporary file");
    let lifecycle = ProfileLifecycle::open_with_config(root.path(), registry_config()).unwrap();
    assert_identity_mismatch(&lifecycle, project_id);

    assert!(matches!(
        lifecycle
            .registry()
            .rebind_managed_root(&provenance("record-first")),
        Err(RebindRefusal::Io(_))
    ));
    assert!(root.path().join(PROFILE_ROOT_REBINDS_FILE).is_file());
    assert_eq!(
        registry_document(root.path())["managed_root_identity"],
        old_identity
    );
    assert_identity_mismatch(&lifecycle, project_id);
}

#[derive(Debug)]
struct NothingRunning;

impl TargetResolver for NothingRunning {
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        TargetResolution::NotRunning
    }
}

fn management_planes(root: &Path) -> Planes {
    let lifecycle = Arc::new(
        ProfileLifecycle::open_with_config(root, registry_config())
            .expect("management registry opens"),
    );
    let management = Arc::new(ManagementPlane::with_profile_lifecycle(
        Arc::new(NothingRunning),
        lifecycle,
    ));
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::default()),
        None,
        JournalPersistence::Isolated,
    );
    planes.management = management;
    planes
}

async fn bind_management_route(
    planes: &Planes,
    writer: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
) {
    let request = ModuleControlRequest::RouteBind {
        route_channel: 4,
        epoch: 1,
        target: RouteTarget::ManagementSurface {
            module_id: "cerebellum".to_string(),
        },
        identity: BindIdentity::new(
            PathBuf::from("/tmp/profile-root-rebind-project"),
            "opencode".to_string(),
            "profile-root-rebind-conversation".to_string(),
        ),
        principal: Some(Principal::Direct),
        consumer_capabilities: Some(vec!["elicitation".to_string()]),
        admission_facts: Some(json!({
            "agentProjectId": "profile-root-rebind-project",
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
        })),
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        0,
        0,
        1,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    cerebellum::handle_frame_for_test(frame, writer, planes)
        .await
        .expect("management bind is handled");
    let response = rx.recv().await.expect("route bind response");
    let body: ModuleControlResponse = serde_json::from_slice(&response.body).unwrap();
    assert!(matches!(body, ModuleControlResponse::RouteBindAck {}));
}

fn rebind_request(corr: u64, params: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        4,
        1,
        corr,
        serde_json::to_vec(&json!({
            "method": REBIND_PROFILE_ROOT,
            "params": params,
        }))
        .unwrap(),
    )
    .unwrap()
}

async fn open_rebind_over_wire(
    planes: &Planes,
    writer: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
) -> (Value, Frame, Value) {
    cerebellum::handle_frame_for_test(rebind_request(10, json!({})), writer, planes)
        .await
        .expect("rebind request is handled");
    let mut reply = None;
    let mut question = None;
    for _ in 0..2 {
        let frame = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("management reply and question are prompt")
            .expect("writer stays open");
        let body: Value = serde_json::from_slice(&frame.body).unwrap();
        if frame.header.ty == FrameType::Request {
            question = Some((frame, body));
        } else {
            reply = Some(body);
        }
    }
    let reply = reply.expect("immediate reply");
    let (question_frame, question) = question.expect("elicitation question");
    (reply, question_frame, question)
}

async fn answer_rebind(
    planes: &Planes,
    writer: &mpsc::Sender<Frame>,
    question: &Frame,
    decision: &str,
) {
    let answer = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        question.header.channel,
        question.header.epoch,
        question.header.corr,
        serde_json::to_vec(&json!({"decision": decision})).unwrap(),
    )
    .unwrap();
    cerebellum::handle_frame_for_test(answer, writer, planes)
        .await
        .expect("elicitation answer is handled");
    tokio::time::timeout(Duration::from_secs(1), async {
        while planes.management.profile_root_rebind_pending_count().await != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("settlement completes");
}

#[tokio::test]
async fn management_wire_allows_rebinding_the_recreated_root() {
    let root = TestRoot::new("wire-allow");
    let project_id = "project-wire-allow";
    let original = mint_durable_record(root.path(), project_id);
    recreate_root(root.path());
    let before = ProfileLifecycle::open_with_config(root.path(), registry_config()).unwrap();
    assert_identity_mismatch(&before, project_id);
    drop(before);
    let planes = management_planes(root.path());

    let (writer, mut rx) = mpsc::channel(8);
    bind_management_route(&planes, &writer, &mut rx).await;
    let (reply, question_frame, question) = open_rebind_over_wire(&planes, &writer, &mut rx).await;
    assert_eq!(reply["outcome"], "consent_pending");
    assert_eq!(
        question["params"]["root_path"],
        fs::canonicalize(root.path()).unwrap().display().to_string()
    );
    assert_eq!(question["params"]["old_identity"], reply["old_identity"]);
    assert_eq!(question["params"]["new_identity"], reply["new_identity"]);
    assert_eq!(question["params"]["record_count"], 1);
    assert_eq!(question["params"]["generation_before"], reply["generation"]);

    answer_rebind(&planes, &writer, &question_frame, "allow").await;
    let lifecycle = ProfileLifecycle::open_with_config(root.path(), registry_config()).unwrap();
    match lifecycle.registry().resolve_durable(project_id).unwrap() {
        DurableResolution::TrustworthyExisting(record) => assert_eq!(record, original),
        other => panic!("wire rebind did not heal resolution: {other:?}"),
    }
    assert!(root.path().join(PROFILE_ROOT_REBINDS_FILE).is_file());
}

#[tokio::test]
async fn management_wire_denial_writes_nothing_and_leaves_the_root_refused() {
    let root = TestRoot::new("wire-deny");
    let project_id = "project-wire-deny";
    mint_durable_record(root.path(), project_id);
    recreate_root(root.path());
    let planes = management_planes(root.path());
    let (writer, mut rx) = mpsc::channel(8);
    bind_management_route(&planes, &writer, &mut rx).await;
    let (reply, question_frame, _) = open_rebind_over_wire(&planes, &writer, &mut rx).await;
    assert_eq!(reply["outcome"], "consent_pending");

    answer_rebind(&planes, &writer, &question_frame, "deny").await;
    let lifecycle = ProfileLifecycle::open_with_config(root.path(), registry_config()).unwrap();
    assert_identity_mismatch(&lifecycle, project_id);
    assert!(!root.path().join(PROFILE_ROOT_REBINDS_FILE).exists());
}

#[tokio::test]
async fn management_wire_rebind_params_are_closed() {
    let root = TestRoot::new("wire-params");
    let project_id = "project-wire-params";
    mint_durable_record(root.path(), project_id);
    recreate_root(root.path());
    let planes = management_planes(root.path());
    let (writer, mut rx) = mpsc::channel(8);
    bind_management_route(&planes, &writer, &mut rx).await;

    cerebellum::handle_frame_for_test(
        rebind_request(11, json!({"unexpected": true})),
        &writer,
        &planes,
    )
    .await
    .expect("invalid request is handled");
    let response = rx.recv().await.expect("invalid request response");
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["outcome"], "invalid_request");
    assert_eq!(body["detail"]["field"], "unexpected");
    assert_eq!(body["detail"]["reason_code"], "unknown_field");
    assert_eq!(
        planes.management.profile_root_rebind_pending_count().await,
        0
    );
    assert!(!root.path().join(PROFILE_ROOT_REBINDS_FILE).exists());
}
