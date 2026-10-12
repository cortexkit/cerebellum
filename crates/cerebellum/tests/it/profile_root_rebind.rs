#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cerebellum::browser_launch::map_profile_outcome;
use cerebellum::management::{ManagementPlane, TargetResolver, REBIND_PROFILE_ROOT};
use cerebellum::profile::{
    read_root_metadata_facts, stamped_bind_context, BindFacts, DurableResolution, InvocationToken,
    JournalReservationHandle, ManagedRootIdentity, PrepareResult, ProfileLifecycle, ProfileOutcome,
    RebindProvenance, RebindRefusal, RegistryConfig, RegistryError, RootMetadataFacts,
    UntrustworthyRegistryReason, PROFILE_ROOT_REBINDS_FILE,
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

/// `recreate_root` creates the new directory while the old one still exists,
/// so the new one always has a different inode.
fn assert_identity_mismatch(lifecycle: &ProfileLifecycle, project_id: &str) {
    assert_resolution_refuses(
        lifecycle,
        project_id,
        UntrustworthyRegistryReason::ManagedRootInodeChanged,
    );
}

fn assert_resolution_refuses(
    lifecycle: &ProfileLifecycle,
    project_id: &str,
    expected: UntrustworthyRegistryReason,
) {
    match lifecycle.registry().resolve_durable(project_id) {
        Err(RegistryError::Untrustworthy(reason)) => assert_eq!(reason, expected),
        other => panic!("expected refusal {expected:?}, got {other:?}"),
    }
}

/// The identity facts the real filesystem reports for `root`, as a registry
/// document would record them.
fn recorded_facts(root: &Path) -> Value {
    let canonical = fs::canonicalize(root).expect("canonical root");
    let facts = read_root_metadata_facts(&fs::metadata(&canonical).expect("root metadata"));
    let birth_time = facts
        .birth_time
        .expect("test filesystem reports birth time");
    json!({
        "formula": 2,
        "path": canonical.to_string_lossy(),
        "inode": facts.inode,
        "birth_time": {
            "unix_seconds": birth_time.unix_seconds,
            "nanoseconds": birth_time.nanoseconds,
        },
    })
}

// Readers that present the root as the disk holds it except for one fact.

fn reboot_shaped_facts(metadata: &fs::Metadata) -> RootMetadataFacts {
    let mut facts = read_root_metadata_facts(metadata);
    facts.device = facts.device.wrapping_add(1);
    facts
}

fn replaced_inode_facts(metadata: &fs::Metadata) -> RootMetadataFacts {
    let mut facts = read_root_metadata_facts(metadata);
    facts.inode = facts.inode.wrapping_add(1);
    facts
}

fn recreated_birth_time_facts(metadata: &fs::Metadata) -> RootMetadataFacts {
    let mut facts = read_root_metadata_facts(metadata);
    if let Some(birth_time) = facts.birth_time.as_mut() {
        birth_time.unix_seconds += 1;
    }
    facts
}

fn birth_time_unavailable_facts(metadata: &fs::Metadata) -> RootMetadataFacts {
    let mut facts = read_root_metadata_facts(metadata);
    facts.birth_time = None;
    facts
}

fn config_reading(reader: fn(&fs::Metadata) -> RootMetadataFacts) -> RegistryConfig {
    RegistryConfig {
        root_facts: reader,
        ..registry_config()
    }
}

fn prepare_durable(
    lifecycle: &mut ProfileLifecycle,
    project_id: &str,
    label: &str,
) -> PrepareResult {
    let invocation = InvocationToken::for_test(format!("invocation-{label}"));
    let reservation =
        JournalReservationHandle::for_test(&invocation, format!("reservation-{label}"));
    lifecycle.prepare_context_open(&invocation, &reservation, &profile_context(project_id))
}

fn assert_launch_refuses(
    lifecycle: &mut ProfileLifecycle,
    project_id: &str,
    expected: UntrustworthyRegistryReason,
) -> Value {
    match prepare_durable(lifecycle, project_id, "refused") {
        PrepareResult::Closed(outcome) => {
            assert_eq!(
                outcome,
                ProfileOutcome::UntrustworthyRegistry { reason: expected }
            );
            map_profile_outcome(outcome).as_json()
        }
        PrepareResult::Prepared(_) => panic!("launch preparation must refuse with {expected:?}"),
    }
}

const HASH_ONLY_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/profile-registry-v1-formula1.json"
);
const HASH_ONLY_PROJECT: &str = "project-fixture";

/// Place the frozen hash-only registry in `root`, with the profile directory
/// its one record names, and return the stored digest.
fn install_hash_only_registry(root: &Path) -> String {
    let bytes = fs::read(HASH_ONLY_FIXTURE).expect("hash-only fixture");
    let document: Value = serde_json::from_slice(&bytes).expect("fixture JSON");
    let target = document["records"][HASH_ONLY_PROJECT]["target"]
        .as_str()
        .expect("fixture target");
    fs::create_dir_all(root.join(target)).expect("fixture profile directory");
    fs::write(root.join(REGISTRY_FILE), bytes).expect("install fixture registry");
    document["managed_root_identity"]
        .as_str()
        .expect("fixture identity is a hash-only string")
        .to_string()
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
    let old_identity = before["managed_root_identity"].clone();
    assert_eq!(old_identity["formula"], 2, "fresh registries record facts");
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
    let new_identity = after["managed_root_identity"].clone();
    assert_ne!(old_identity, new_identity);
    assert_eq!(new_identity, recorded_facts(root.path()));
    assert_eq!(after["generation"], generation_before + 1);
    assert_eq!(report.generation_before, generation_before);
    assert_eq!(report.generation_after, generation_before + 1);
    assert_eq!(report.record_count, 1);

    let record_bytes = fs::read_to_string(root.path().join(PROFILE_ROOT_REBINDS_FILE))
        .expect("durable rebind record");
    let lines: Vec<&str> = record_bytes.lines().collect();
    assert_eq!(lines.len(), 1, "one rebind writes one provenance line");
    let durable: Value = serde_json::from_str(lines[0]).expect("rebind record JSON");
    assert_eq!(durable["schema"], "ck-browser-profile-root-rebind/v2");
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
    let old_identity = registry_document(root.path())["managed_root_identity"].clone();
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

/// A reboot moves the device number on macOS but keeps the directory, so it
/// must not be mistaken for a replaced root.
#[test]
fn reboot_shaped_device_change_keeps_the_root_trusted_and_launch_preparation_proceeds() {
    let root = TestRoot::new("reboot");
    let project_id = "project-reboot";
    let original = mint_durable_record(root.path(), project_id);
    let before = registry_bytes(root.path());

    let mut lifecycle =
        ProfileLifecycle::open_with_config(root.path(), config_reading(reboot_shaped_facts))
            .expect("root opens after a reboot");
    match lifecycle.registry().resolve_durable(project_id) {
        Ok(DurableResolution::TrustworthyExisting(record)) => assert_eq!(record, original),
        other => panic!("a device change alone must not refuse: {other:?}"),
    }
    assert!(matches!(
        prepare_durable(&mut lifecycle, project_id, "after-reboot"),
        PrepareResult::Prepared(_)
    ));
    assert_eq!(
        registry_document(root.path())["managed_root_identity"],
        serde_json::from_slice::<Value>(&before).unwrap()["managed_root_identity"],
        "no rebind is needed or performed"
    );
    assert!(!root.path().join(PROFILE_ROOT_REBINDS_FILE).exists());
}

#[test]
fn replaced_root_with_a_new_inode_refuses_with_the_inode_reason() {
    let root = TestRoot::new("new-inode");
    let project_id = "project-new-inode";
    mint_durable_record(root.path(), project_id);
    let mut lifecycle =
        ProfileLifecycle::open_with_config(root.path(), config_reading(replaced_inode_facts))
            .unwrap();
    assert_resolution_refuses(
        &lifecycle,
        project_id,
        UntrustworthyRegistryReason::ManagedRootInodeChanged,
    );
    let wire = assert_launch_refuses(
        &mut lifecycle,
        project_id,
        UntrustworthyRegistryReason::ManagedRootInodeChanged,
    );
    assert_eq!(
        wire["reason_code"],
        "profile_registry_managed_root_inode_changed"
    );
}

#[test]
fn recreated_root_with_a_reused_inode_refuses_with_the_birth_time_reason() {
    let root = TestRoot::new("new-birth-time");
    let project_id = "project-new-birth-time";
    mint_durable_record(root.path(), project_id);
    let mut lifecycle =
        ProfileLifecycle::open_with_config(root.path(), config_reading(recreated_birth_time_facts))
            .unwrap();
    assert_resolution_refuses(
        &lifecycle,
        project_id,
        UntrustworthyRegistryReason::ManagedRootBirthTimeChanged,
    );
    let wire = assert_launch_refuses(
        &mut lifecycle,
        project_id,
        UntrustworthyRegistryReason::ManagedRootBirthTimeChanged,
    );
    assert_eq!(
        wire["reason_code"],
        "profile_registry_managed_root_birth_time_changed"
    );
}

/// A real rename: the directory, and so its inode and birth time, stay the
/// same while the canonical path changes.
#[test]
fn moved_root_refuses_with_the_path_reason() {
    let parent = TestRoot::new("moved");
    let original_path = parent.path().join("root");
    fs::create_dir(&original_path).unwrap();
    let project_id = "project-moved";
    mint_durable_record(&original_path, project_id);
    let moved_path = parent.path().join("moved-root");
    fs::rename(&original_path, &moved_path).unwrap();

    let mut lifecycle = ProfileLifecycle::open_with_config(&moved_path, registry_config()).unwrap();
    assert_resolution_refuses(
        &lifecycle,
        project_id,
        UntrustworthyRegistryReason::ManagedRootPathChanged,
    );
    let wire = assert_launch_refuses(
        &mut lifecycle,
        project_id,
        UntrustworthyRegistryReason::ManagedRootPathChanged,
    );
    assert_eq!(
        wire["reason_code"],
        "profile_registry_managed_root_path_changed"
    );
}

#[test]
fn birth_time_unavailable_refuses_by_name_and_never_as_an_identity_change() {
    let root = TestRoot::new("no-birth-time");
    let project_id = "project-no-birth-time";
    mint_durable_record(root.path(), project_id);
    let before = registry_bytes(root.path());

    let mut lifecycle = ProfileLifecycle::open_with_config(
        root.path(),
        config_reading(birth_time_unavailable_facts),
    )
    .unwrap();
    assert_resolution_refuses(
        &lifecycle,
        project_id,
        UntrustworthyRegistryReason::ManagedRootBirthTimeUnavailable,
    );
    let wire = assert_launch_refuses(
        &mut lifecycle,
        project_id,
        UntrustworthyRegistryReason::ManagedRootBirthTimeUnavailable,
    );
    assert_eq!(
        wire["reason_code"],
        "profile_registry_managed_root_birth_time_unavailable"
    );

    // The rebind cannot record an identity for this root either, and says
    // which root it is.
    match lifecycle
        .registry()
        .rebind_managed_root(&provenance("no-birth-time"))
    {
        Err(RebindRefusal::BirthTimeUnavailable { root_path }) => {
            assert_eq!(root_path, fs::canonicalize(root.path()).unwrap())
        }
        other => panic!("rebind must refuse on missing birth time: {other:?}"),
    }
    assert_eq!(registry_bytes(root.path()), before);
    assert!(!root.path().join(PROFILE_ROOT_REBINDS_FILE).exists());

    // A root with no registry yet is not minted one without an identity.
    let fresh = TestRoot::new("no-birth-time-fresh");
    let mut fresh_lifecycle = ProfileLifecycle::open_with_config(
        fresh.path(),
        config_reading(birth_time_unavailable_facts),
    )
    .unwrap();
    assert!(matches!(
        prepare_durable(&mut fresh_lifecycle, "project-fresh", "fresh"),
        PrepareResult::Closed(_)
    ));
    assert!(!fresh.path().join(REGISTRY_FILE).exists());
}

#[test]
fn hash_only_registry_refuses_with_the_migration_reason_until_rebound_to_facts() {
    let root = TestRoot::new("hash-only");
    let old_digest = install_hash_only_registry(root.path());

    let mut lifecycle = ProfileLifecycle::open_with_config(root.path(), registry_config()).unwrap();
    assert_resolution_refuses(
        &lifecycle,
        HASH_ONLY_PROJECT,
        UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts,
    );
    let wire = assert_launch_refuses(
        &mut lifecycle,
        HASH_ONLY_PROJECT,
        UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts,
    );
    assert_eq!(
        wire["reason_code"],
        "profile_registry_managed_root_identity_predates_facts"
    );
    assert!(
        wire["remedy"]
            .as_str()
            .is_some_and(|remedy| remedy.contains("browser.rebind_profile_root")),
        "{wire}"
    );

    let generation_before = registry_document(root.path())["generation"]
        .as_u64()
        .unwrap();
    let report = lifecycle
        .registry()
        .rebind_managed_root(&provenance("hash-only"))
        .expect("rebind migrates the hash-only identity");
    assert_eq!(
        report.old_identity,
        ManagedRootIdentity::HashOnly(old_digest.clone())
    );
    assert_eq!(
        serde_json::to_value(&report.new_identity).unwrap(),
        recorded_facts(root.path())
    );
    assert_eq!(report.generation_after, generation_before + 1);

    let after = registry_document(root.path());
    assert_eq!(after["managed_root_identity"], recorded_facts(root.path()));
    let lines =
        fs::read_to_string(root.path().join(PROFILE_ROOT_REBINDS_FILE)).expect("rebind record");
    let durable: Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
    assert_eq!(durable["schema"], "ck-browser-profile-root-rebind/v2");
    assert_eq!(durable["old_identity"], old_digest);
    assert_eq!(durable["new_identity"], recorded_facts(root.path()));

    match lifecycle
        .registry()
        .resolve_durable(HASH_ONLY_PROJECT)
        .expect("migrated registry resolves")
    {
        DurableResolution::TrustworthyExisting(record) => {
            assert_eq!(record.project_id, HASH_ONLY_PROJECT)
        }
        other => panic!("migrated record did not resolve: {other:?}"),
    }
}

#[test]
fn hash_only_migration_writes_the_rebind_record_before_a_failed_registry_rewrite() {
    let root = TestRoot::new("hash-only-record-first");
    let old_digest = install_hash_only_registry(root.path());
    fs::create_dir(root.path().join(REGISTRY_TEMPORARY_FILE))
        .expect("block the registry temporary file");
    let lifecycle = ProfileLifecycle::open_with_config(root.path(), registry_config()).unwrap();

    assert!(matches!(
        lifecycle
            .registry()
            .rebind_managed_root(&provenance("hash-only-record-first")),
        Err(RebindRefusal::Io(_))
    ));
    let lines = fs::read_to_string(root.path().join(PROFILE_ROOT_REBINDS_FILE))
        .expect("the rebind record survives the failed rewrite");
    let durable: Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
    assert_eq!(durable["old_identity"], old_digest);
    assert_eq!(durable["new_identity"], recorded_facts(root.path()));
    assert_eq!(
        registry_document(root.path())["managed_root_identity"],
        old_digest
    );
    assert_resolution_refuses(
        &lifecycle,
        HASH_ONLY_PROJECT,
        UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts,
    );
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
    bind_management_route_as(planes, writer, rx, Some(Principal::Direct)).await;
}

async fn bind_management_route_as(
    planes: &Planes,
    writer: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
    principal: Option<Principal>,
) {
    let request = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
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
        principal,
        consumer_capabilities: Some(vec!["elicitation".to_string()]),
        admission_facts: Some(json!({
            "agentProjectId": "profile-root-rebind-project",
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
        })),
        scope: None,
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
        question["params"]["facts"][0]["value"],
        fs::canonicalize(root.path()).unwrap().display().to_string()
    );
    assert_eq!(question["params"]["facts"][1]["value"], "1");
    assert_eq!(question["params"]["kind"], "consent");
    assert_eq!(question["params"]["default"], "deny");
    assert_eq!(question["params"]["on_expiry"], "deny");
    // The rebind call replied consent_pending without waiting for the
    // answer, so the card is not an interrupting alert.
    assert_eq!(question["params"]["urgency"], "normal");
    // The scope carries the generation and root identity the reply discloses,
    // which an allowing answer applies, but never the root's path.
    let scope = &question["params"]["scope"];
    assert_eq!(scope["generation"], reply["generation"]);
    assert_eq!(
        scope["new_identity"]["inode"],
        reply["new_identity"]["inode"]
    );
    assert_eq!(
        scope["new_identity"]["birth_time"],
        reply["new_identity"]["birth_time"]
    );
    assert!(scope["new_identity"].get("path").is_none(), "{scope}");
    assert!(
        !scope
            .to_string()
            .contains(&fs::canonicalize(root.path()).unwrap().display().to_string()),
        "{scope}"
    );
    assert_eq!(
        question["params"]["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["allow", "deny"]
    );
    assert_eq!(
        question["params"]["requestedSchema"]["properties"]["decision"]["enum"],
        json!(["allow", "deny"])
    );

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

/// A rebind question settled by nobody being asked is named on the next rebind
/// request from the same conversation, and no other ending is, while none of
/// them rebinds anything.
///
/// The pending reply says to wait for the person to answer. For a question
/// nobody was shown no answer comes, so the next reply has to say so; silence
/// from a person who was asked is not reported this way, or the field would
/// only repeat "not answered yet".
#[tokio::test]
async fn management_wire_names_a_rebind_question_nobody_was_asked() {
    // The ending, and whether the next request reports it. `refused` is an
    // error frame in place of an answer, which is how a consumer with no
    // handler for questions refuses one.
    let cases = [
        ("deny", false),
        ("no_answer", false),
        ("not_put_to_anyone", true),
        ("refused", true),
        ("undeliverable", false),
        ("some_future_word", false),
    ];
    for (ending, reported) in cases {
        let root = TestRoot::new("wire-endings");
        let project_id = "project-wire-endings";
        mint_durable_record(root.path(), project_id);
        recreate_root(root.path());
        let planes = management_planes(root.path());
        let (writer, mut rx) = mpsc::channel(8);
        bind_management_route(&planes, &writer, &mut rx).await;

        let first_ask = if ending == "undeliverable" {
            // A closed carrier: neither the question nor the reply can be
            // sent, so only the settlement is observable.
            let (closed, mut closed_rx) = mpsc::channel(8);
            closed_rx.close();
            let _ =
                cerebellum::handle_frame_for_test(rebind_request(20, json!({})), &closed, &planes)
                    .await;
            None
        } else {
            let (reply, question, _) = open_rebind_over_wire(&planes, &writer, &mut rx).await;
            assert_eq!(reply["outcome"], "consent_pending", "{reply}");
            assert!(reply.get("previous_request").is_none(), "{reply}");
            end_rebind_question(&planes, &writer, &question, ending).await;
            Some(reply["ask_id"].as_str().unwrap().to_string())
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while planes.management.profile_root_rebind_pending_count().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("settlement completes");
        let lifecycle = ProfileLifecycle::open_with_config(root.path(), registry_config()).unwrap();
        assert_identity_mismatch(&lifecycle, project_id);
        drop(lifecycle);
        assert!(
            !root.path().join(PROFILE_ROOT_REBINDS_FILE).exists(),
            "{ending} rebound the root"
        );

        cerebellum::handle_frame_for_test(rebind_request(21, json!({})), &writer, &planes)
            .await
            .expect("rebind request is handled");
        let mut next = None;
        for _ in 0..2 {
            let frame = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .expect("management reply and question are prompt")
                .expect("writer stays open");
            if frame.header.ty != FrameType::Request {
                next = Some(serde_json::from_slice::<Value>(&frame.body).unwrap());
            }
        }
        let next = next.expect("immediate reply");
        assert_eq!(next["outcome"], "consent_pending", "{ending}: {next}");
        if reported {
            let previous = &next["previous_request"];
            assert_eq!(previous["ask_id"], json!(first_ask), "{ending}: {next}");
            assert_eq!(previous["disposition"], "not_put_to_anyone", "{next}");
            let remedy = previous["remedy"].as_str().unwrap().to_lowercase();
            for loop_word in ["ask again", "retry", "wait"] {
                assert!(
                    !remedy.contains(loop_word),
                    "a question nobody was shown sends the caller round a loop: {remedy}"
                );
            }
        } else {
            assert!(
                next.get("previous_request").is_none(),
                "{ending} was reported as unreached: {next}"
            );
        }
    }
}

/// End a rebind question with the decision word `ending`, or for `refused`
/// with an error frame in place of an answer.
async fn end_rebind_question(
    planes: &Planes,
    writer: &mpsc::Sender<Frame>,
    question: &Frame,
    ending: &str,
) {
    let (ty, body) = if ending == "refused" {
        (
            FrameType::Error,
            serde_json::to_vec(&subc_protocol::ErrorBody {
                code: "REVERSE_REQUEST_UNHANDLED".to_string(),
                message: "no reverse-request handler is registered".to_string(),
                detail: None,
            })
            .unwrap(),
        )
    } else {
        (
            FrameType::Response,
            serde_json::to_vec(&json!({"decision": ending})).unwrap(),
        )
    };
    let answer = Frame::build_with_version(
        PROTOCOL_VERSION,
        ty,
        Flags::new(false, Priority::Interactive, false),
        question.header.channel,
        question.header.epoch,
        question.header.corr,
        body,
    )
    .unwrap();
    cerebellum::handle_frame_for_test(answer, writer, planes)
        .await
        .expect("the ending is handled");
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

/// Rebind the recreated root through the wire as `principal` and return the
/// conversation the durable provenance record attributes the rebind to.
async fn rebind_attributed_conversation(label: &str, principal: Option<Principal>) -> Value {
    let root = TestRoot::new(label);
    mint_durable_record(root.path(), &format!("project-{label}"));
    recreate_root(root.path());
    let planes = management_planes(root.path());
    let (writer, mut rx) = mpsc::channel(8);
    bind_management_route_as(&planes, &writer, &mut rx, principal).await;
    let (reply, question_frame, _) = open_rebind_over_wire(&planes, &writer, &mut rx).await;
    assert_eq!(reply["outcome"], "consent_pending", "{label}: {reply}");
    answer_rebind(&planes, &writer, &question_frame, "allow").await;
    let record_bytes = fs::read_to_string(root.path().join(PROFILE_ROOT_REBINDS_FILE))
        .expect("durable rebind record");
    let durable: Value =
        serde_json::from_str(record_bytes.lines().next().expect("one provenance line"))
            .expect("rebind record JSON");
    durable["elicited"]["conversation_key"].clone()
}

/// A `direct` desk route may rebind the profile root, and does so outside any
/// conversation: the route names one, and the rebind is attributed to none.
/// Prefrontal's core module, which acts in the conversation its route names,
/// keeps the attribution.
///
/// The attribution is the one place a rebind reads the route's conversation,
/// so it shows whether the operator's call saw that conversation at all.
#[tokio::test]
async fn an_operator_rebind_runs_outside_the_conversation_its_route_names() {
    assert_eq!(
        rebind_attributed_conversation("operator-direct", Some(Principal::Direct)).await,
        "",
        "an operator's rebind is attributed to no conversation"
    );
    assert_eq!(
        rebind_attributed_conversation(
            "session-caller",
            Some(Principal::Reserved {
                module_id: "prefrontal-core".to_string(),
            }),
        )
        .await,
        "profile-root-rebind-conversation",
        "the session caller's rebind keeps its conversation"
    );
}
