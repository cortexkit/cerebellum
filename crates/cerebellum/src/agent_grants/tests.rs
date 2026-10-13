use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::browser_standing_grants::{
    InMemoryStandingGrantStorage, StandingGrantStorage, StandingGrantStoreState, StandingSubject,
};
use crate::computer_grants::{
    AlwaysGrantRecord, GrantStorage, GrantStoreState, InMemoryGrantStorage,
};

use super::*;

const NOW: u64 = 1_000;
const MACHINE: &str = "this-machine";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "agent-grants-tests-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn browser(machine: &str) -> StandingBrowserGrant {
    StandingBrowserGrant {
        agent_id: "head".into(),
        subject: StandingSubject::Origin("https://example.com".into()),
        max_level: 3,
        hazards: Vec::new(),
        expires_at_ms: None,
        granted_at_ms: 10,
        consent_ref: format!("el-{machine}"),
        revoked_at_ms: None,
        machine_uuid: machine.into(),
    }
}
fn app(machine: &str) -> AlwaysGrantRecord {
    AlwaysGrantRecord {
        agent_project_id: "head".into(),
        bundle_identity: "app.example".into(),
        team_id: Some("TEAM".into()),
        designated_requirement: Some("identifier app.example and anchor apple generic".into()),
        machine_uuid: machine.into(),
        created_at_ms: 10,
    }
}
fn legacy(
    browser_rows: Vec<StandingBrowserGrant>,
    user_rows: Vec<StandingBrowserGrant>,
    apps: Vec<AlwaysGrantRecord>,
) -> LegacyGrantStores {
    let browser = Arc::new(InMemoryStandingGrantStorage::new());
    browser
        .save(&StandingGrantStoreState {
            version: 2,
            grants: browser_rows,
        })
        .unwrap();
    let user_browser = Arc::new(InMemoryStandingGrantStorage::new());
    user_browser
        .save(&StandingGrantStoreState {
            version: 2,
            grants: user_rows,
        })
        .unwrap();
    let app_store = Arc::new(InMemoryGrantStorage::new());
    app_store
        .save(&GrantStoreState {
            records: apps,
            ..Default::default()
        })
        .unwrap();
    LegacyGrantStores {
        browser,
        user_browser,
        apps: app_store,
    }
}
fn empty_legacy() -> LegacyGrantStores {
    legacy(Vec::new(), Vec::new(), Vec::new())
}
fn open(storage: Arc<dyn AgentGrantStorage>, legacy: &dyn LegacyGrantSource) -> AgentGrants {
    AgentGrants::open(storage, legacy, Some(MACHINE.into()))
}
fn row() -> AgentGrant {
    AgentGrant {
        id: "candidate".into(),
        holder: GrantHolder::Head {
            agent_id: "head".into(),
        },
        subject: GrantSubject::App("app.new".into()),
        browser_target: None,
        machine_uuid: MACHINE.into(),
        granted_at_ms: NOW,
        expires_at_ms: Some(NOW + 30 * 60 * 1000),
        card_ref: Some("el-new".into()),
        max_level: 4,
        hazards: Vec::new(),
        team_id: Some("TEAM".into()),
        designated_requirement: Some("signed requirement".into()),
    }
}

#[test]
fn startup_and_list_are_read_only_then_first_mutation_imports_all_targets() {
    let scratch = Scratch::new();
    let path = scratch.0.join("journal").join(AGENT_GRANT_STORE_FILE);
    let storage = Arc::new(FilesystemAgentGrantStorage::new(&path));
    let legacy = legacy(
        vec![browser(MACHINE)],
        vec![browser(MACHINE)],
        vec![app(MACHINE)],
    );
    let grants = open(storage.clone(), &legacy);
    assert!(!path.parent().unwrap().exists());
    let before = grants.live_rows(None, NOW).unwrap();
    assert_eq!(before.len(), 3);
    assert!(!path.parent().unwrap().exists());
    assert_eq!(
        before
            .iter()
            .map(|row| &row.id)
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    let id = grants.upsert(row(), NOW).unwrap();
    assert!(id.starts_with("grt_"));
    assert_ne!(id, "candidate");
    assert_eq!(storage.load().unwrap().unwrap().grants.len(), 4);
    let after = open(storage, &empty_legacy()).live_rows(None, NOW).unwrap();
    for previous in &before {
        assert!(after.contains(previous));
    }
}

#[test]
fn original_legacy_app_id_survives_list_restart_revoke_and_restart() {
    let scratch = Scratch::new();
    let storage = Arc::new(FilesystemAgentGrantStorage::new(
        scratch.0.join(AGENT_GRANT_STORE_FILE),
    ));
    let legacy = legacy(Vec::new(), Vec::new(), vec![app(MACHINE)]);
    let listed = open(storage.clone(), &legacy)
        .live_rows(None, NOW)
        .unwrap()
        .remove(0);
    assert!(storage.load().unwrap().is_none());
    let restarted = open(storage.clone(), &legacy);
    assert_eq!(restarted.live_rows(None, NOW).unwrap()[0].id, listed.id);
    assert!(restarted.revoke(&listed.id, NOW).unwrap());
    assert!(storage.load().unwrap().unwrap().grants.is_empty());
    assert!(open(storage, &legacy)
        .live_rows(None, NOW)
        .unwrap()
        .is_empty());
    assert_eq!(listed.card_ref, None);
}

#[test]
fn revoked_and_expired_legacy_rows_are_not_imported() {
    let mut revoked = browser(MACHINE);
    revoked.revoked_at_ms = Some(20);
    let mut expired = browser(MACHINE);
    expired.consent_ref = "el-expired".into();
    expired.subject = StandingSubject::Origin("https://expired.example".into());
    expired.expires_at_ms = Some(NOW);
    let storage = Arc::new(InMemoryAgentGrantStorage::default());
    let legacy = legacy(vec![revoked, expired], Vec::new(), Vec::new());
    let grants = open(storage.clone(), &legacy);
    assert!(grants.live_rows(None, NOW).unwrap().is_empty());
    assert!(!grants.revoke("unknown", NOW).unwrap());
    assert!(storage.load().unwrap().unwrap().grants.is_empty());
}

#[test]
fn foreign_machine_imports_are_inert_in_either_order() {
    for (reverse, shared_card) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut browsers = vec![browser(MACHINE), browser("foreign")];
        if shared_card {
            browsers[1].consent_ref = browsers[0].consent_ref.clone();
        }
        let mut apps = vec![app(MACHINE), app("foreign")];
        if reverse {
            browsers.reverse();
            apps.reverse();
        }
        let legacy = legacy(browsers.clone(), browsers, apps);
        let storage = Arc::new(InMemoryAgentGrantStorage::default());
        let grants = open(storage.clone(), &legacy);
        let before = grants.live_rows(None, NOW).unwrap();
        assert_eq!(before.len(), 3);
        assert!(before
            .iter()
            .all(|row| row.machine_uuid == MACHINE && row.is_usable(NOW, Some(MACHINE))));
        assert!(!grants.revoke("unrelated", NOW).unwrap());
        let saved = storage.load().unwrap().unwrap();
        assert_eq!(saved.grants.len(), 6);
        for row in saved
            .grants
            .iter()
            .filter(|row| row.machine_uuid == "foreign")
        {
            assert!(!row.is_usable(NOW, Some(MACHINE)));
            if !before.iter().any(|live| live.id == row.id) {
                assert!(!grants.revoke(&row.id, NOW).unwrap());
            }
        }
        let reopened = open(storage.clone(), &empty_legacy());
        assert_eq!(before, reopened.live_rows(None, NOW).unwrap());
        assert!(AgentGrants::open(storage, &empty_legacy(), None)
            .live_rows(None, NOW)
            .unwrap()
            .is_empty());
    }
}

struct CountedLegacy {
    reads: AtomicUsize,
    fail: bool,
}
impl LegacyGrantSource for CountedLegacy {
    fn load(&self) -> Result<AgentGrantStoreState, AgentGrantStoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            Err(AgentGrantStoreError::Legacy {
                store: "test",
                detail: "failed".into(),
            })
        } else {
            Ok(AgentGrantStoreState::default())
        }
    }
}

#[test]
fn migrated_store_never_reads_legacy_even_when_legacy_is_unreadable() {
    let storage = Arc::new(InMemoryAgentGrantStorage::default());
    open(storage.clone(), &empty_legacy())
        .upsert(row(), NOW)
        .unwrap();
    let legacy = CountedLegacy {
        reads: AtomicUsize::new(0),
        fail: true,
    };
    let reopened = open(storage, &legacy);
    assert!(reopened.store_error().is_none());
    assert_eq!(reopened.live_rows(None, NOW).unwrap().len(), 1);
    reopened.upsert(row(), NOW).unwrap();
    reopened.revoke("missing", NOW).unwrap();
    assert_eq!(legacy.reads.load(Ordering::Relaxed), 0);
}

#[test]
fn each_failed_legacy_store_blocks_migration_and_every_write() {
    for file in [
        crate::browser_standing_grants::STANDING_GRANT_STORE_FILE,
        "user-browser-standing-grants.json",
        crate::computer_grants::GRANT_STORE_FILE,
    ] {
        for bad in [
            "invalid json",
            "{\"version\":999,\"grants\":[],\"records\":[]}",
        ] {
            let scratch = Scratch::new();
            fs::write(scratch.0.join(file), bad).unwrap();
            let path = scratch.0.join(AGENT_GRANT_STORE_FILE);
            let grants = open(
                Arc::new(FilesystemAgentGrantStorage::new(&path)),
                &LegacyGrantStores::beside(&path),
            );
            assert!(matches!(
                grants.store_error(),
                Some(AgentGrantStoreError::Legacy { .. })
            ));
            assert!(grants.upsert(row(), NOW).is_err());
            assert!(grants.revoke("anything", NOW).is_err());
            assert!(grants.revoke_matching(NOW, |_| true).is_err());
            assert!(!path.exists());
            assert_eq!(fs::read_to_string(scratch.0.join(file)).unwrap(), bad);
        }
    }
}

#[test]
fn failed_agent_store_never_falls_back_or_overwrites() {
    for bytes in ["invalid", "{\"version\":999}", "{\"grants\":[]}"] {
        let scratch = Scratch::new();
        let path = scratch.0.join(AGENT_GRANT_STORE_FILE);
        fs::write(&path, bytes).unwrap();
        let legacy = CountedLegacy {
            reads: AtomicUsize::new(0),
            fail: false,
        };
        let grants = open(Arc::new(FilesystemAgentGrantStorage::new(&path)), &legacy);
        assert!(grants.store_error().is_some());
        assert!(grants.upsert(row(), NOW).is_err());
        assert!(grants.revoke("anything", NOW).is_err());
        assert_eq!(legacy.reads.load(Ordering::Relaxed), 0);
        assert_eq!(fs::read_to_string(&path).unwrap(), bytes);
    }
}

#[test]
fn floor_raise_failure_leaves_no_grant_bytes_or_memory_change() {
    let scratch = Scratch::new();
    let floor_path = scratch.0.join("blocked-floor");
    fs::create_dir(&floor_path).unwrap();
    let path = scratch.0.join("journal").join(AGENT_GRANT_STORE_FILE);
    let storage = Arc::new(
        FilesystemAgentGrantStorage::new(&path)
            .with_format_floor(cerebellum_core::format_floor::FormatFloor::at(&floor_path)),
    );
    let grants = open(storage, &empty_legacy());
    assert!(matches!(
        grants.upsert(row(), NOW),
        Err(AgentGrantStoreError::WriteFailed { .. })
    ));
    assert!(!path.parent().unwrap().exists());
    assert!(grants.live_rows(None, NOW).unwrap().is_empty());
}

#[test]
fn durable_store_raises_registered_floor_and_uses_private_permissions() {
    let scratch = Scratch::new();
    let directory = scratch.0.join("journal");
    let floor_path = directory.join("format-floor.json");
    let storage = Arc::new(
        FilesystemAgentGrantStorage::new(directory.join(AGENT_GRANT_STORE_FILE))
            .with_format_floor(cerebellum_core::format_floor::FormatFloor::at(&floor_path)),
    );
    assert!(crate::durable_formats::readable_formats().contains(&AGENT_GRANT_STORE_FORMAT));
    open(storage.clone(), &empty_legacy())
        .upsert(row(), NOW)
        .unwrap();
    let floors = cerebellum_core::format_floor::read_floors(&floor_path).unwrap();
    assert_eq!(
        floors.get(AGENT_GRANT_STORE_FORMAT.name),
        Some(&AGENT_GRANT_STORE_FORMAT.version)
    );
    assert_eq!(storage.load().unwrap().unwrap().grants.len(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let isolated_directory = scratch.0.join("isolated-journal");
        let isolated =
            FilesystemAgentGrantStorage::new(isolated_directory.join(AGENT_GRANT_STORE_FILE))
                .with_format_floor(cerebellum_core::format_floor::FormatFloor::isolated());
        isolated.save(&AgentGrantStoreState::default()).unwrap();
        assert_eq!(
            fs::metadata(&isolated_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(storage.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn upgrade_keeps_id_and_target_and_machine_are_independent_identities() {
    let storage = Arc::new(InMemoryAgentGrantStorage::default());
    let legacy = legacy(vec![browser(MACHINE)], vec![browser(MACHINE)], Vec::new());
    let grants = open(storage.clone(), &legacy);
    let before = grants.live_rows(None, NOW).unwrap();
    let mut upgraded = before
        .iter()
        .find(|row| row.browser_target == Some(BrowserTarget::AgentProfile))
        .unwrap()
        .clone();
    upgraded.granted_at_ms = NOW;
    upgraded.expires_at_ms = Some(NOW + 1);
    upgraded.card_ref = Some("el-upgrade".into());
    let id = grants.upsert(upgraded.clone(), NOW).unwrap();
    assert_eq!(id, upgraded.id);
    let other = before
        .iter()
        .find(|row| row.browser_target == Some(BrowserTarget::UserBrowser))
        .unwrap();
    assert!(grants.live_rows(None, NOW).unwrap().contains(other));
    assert_eq!(storage.load().unwrap().unwrap().grants.len(), 2);
    assert_eq!(
        grants.live_rows(None, NOW + 1).unwrap(),
        vec![other.clone()]
    );
    assert!(!grants.revoke(&id, NOW + 1).unwrap());
    assert!(grants
        .live_rows(Some("different-head"), NOW)
        .unwrap()
        .is_empty());
    let mut foreign = row();
    foreign.machine_uuid = "foreign".into();
    assert_eq!(
        grants.upsert(foreign, NOW),
        Err(AgentGrantStoreError::NoMachineIdentity)
    );
}

#[test]
fn unsigned_legacy_app_can_be_listed_but_never_authorizes() {
    for requirement in [None, Some("".into()), Some("  ".into())] {
        let mut unsigned = app(MACHINE);
        unsigned.designated_requirement = requirement;
        let storage = Arc::new(InMemoryAgentGrantStorage::default());
        let grants = open(
            storage.clone(),
            &legacy(Vec::new(), Vec::new(), vec![unsigned]),
        );
        let before = grants.live_rows(None, NOW).unwrap().remove(0);
        assert!(!before.is_usable(NOW, Some(MACHINE)));
        grants.revoke("unrelated", NOW).unwrap();
        let after = open(storage, &empty_legacy())
            .live_rows(None, NOW)
            .unwrap()
            .remove(0);
        assert_eq!(after, before);
        assert!(!after.is_usable(NOW, Some(MACHINE)));
    }
}

struct FailedSave(InMemoryAgentGrantStorage);
impl AgentGrantStorage for FailedSave {
    fn load(&self) -> Result<Option<AgentGrantStoreState>, AgentGrantStoreError> {
        self.0.load()
    }
    fn save(&self, _: &AgentGrantStoreState) -> Result<(), AgentGrantStoreError> {
        Err(AgentGrantStoreError::WriteFailed {
            detail: "injected failure".into(),
        })
    }
}

#[test]
fn failed_save_preserves_read_only_projection_for_retry_and_restart() {
    let storage = Arc::new(FailedSave(InMemoryAgentGrantStorage::default()));
    let legacy = legacy(Vec::new(), Vec::new(), vec![app(MACHINE)]);
    let grants = open(storage.clone(), &legacy);
    let before = grants.live_rows(None, NOW).unwrap();
    assert!(grants.revoke(&before[0].id, NOW).is_err());
    assert_eq!(grants.live_rows(None, NOW).unwrap(), before);
    assert!(grants.upsert(row(), NOW).is_err());
    assert_eq!(grants.live_rows(None, NOW).unwrap(), before);
    assert!(storage.load().unwrap().is_none());
    assert_eq!(open(storage, &legacy).live_rows(None, NOW).unwrap(), before);
}

#[test]
fn invalid_durable_rows_block_every_write() {
    let mut invalid = Vec::new();
    let mut candidate = row();
    candidate.id.clear();
    invalid.push(candidate);
    let mut candidate = row();
    candidate.holder = GrantHolder::Head {
        agent_id: String::new(),
    };
    invalid.push(candidate);
    let mut candidate = row();
    candidate.machine_uuid.clear();
    invalid.push(candidate);
    let mut candidate = row();
    candidate.browser_target = Some(BrowserTarget::UserBrowser);
    invalid.push(candidate);
    let mut candidate = row();
    candidate.subject = GrantSubject::AllSites;
    invalid.push(candidate);
    for (owner, scope_ref, expires) in [
        ("", "scope", Some(NOW + 1)),
        ("owner", "", Some(NOW + 1)),
        ("owner", "scope", None),
        ("owner", "scope", Some(NOW)),
        ("owner", "scope", Some(NOW + 30 * 60 * 1000 + 1)),
    ] {
        let mut candidate = row();
        candidate.holder = GrantHolder::Worker {
            agent_id: "head".into(),
            owner: owner.into(),
            scope_ref: scope_ref.into(),
            scope_epoch: 1,
        };
        candidate.expires_at_ms = expires;
        invalid.push(candidate);
    }
    for candidate in [
        (GrantSubject::AllSites, 4),
        (GrantSubject::Origin("https://example.com".into()), 0),
    ] {
        let mut bad_browser = row();
        bad_browser.subject = candidate.0;
        bad_browser.browser_target = Some(BrowserTarget::AgentProfile);
        bad_browser.max_level = candidate.1;
        invalid.push(bad_browser);
    }
    for candidate in invalid {
        let scratch = Scratch::new();
        let path = scratch.0.join(AGENT_GRANT_STORE_FILE);
        let bytes = serde_json::to_vec(&AgentGrantStoreState {
            grants: vec![candidate],
            ..Default::default()
        })
        .unwrap();
        fs::write(&path, &bytes).unwrap();
        let grants = open(
            Arc::new(FilesystemAgentGrantStorage::new(&path)),
            &empty_legacy(),
        );
        assert!(matches!(
            grants.store_error(),
            Some(AgentGrantStoreError::Corrupt { .. })
        ));
        assert!(grants.upsert(row(), NOW).is_err());
        assert!(grants.revoke("missing", NOW).is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn duplicate_durable_ids_and_identities_are_rejected() {
    for duplicate_id in [true, false] {
        let first = row();
        let mut second = first.clone();
        if duplicate_id {
            second.subject = GrantSubject::App("different".into());
        } else {
            second.id = "different-id".into();
        }
        let state = AgentGrantStoreState {
            grants: vec![first, second],
            ..Default::default()
        };
        assert!(matches!(
            state.check(),
            Err(AgentGrantStoreError::Corrupt { .. })
        ));
    }
}

#[test]
fn legacy_browser_validation_is_not_bypassed_by_migration() {
    for invalid_kind in [0, 1, 2] {
        let mut state = StandingGrantStoreState {
            version: 1,
            grants: vec![browser(MACHINE)],
        };
        match invalid_kind {
            0 => state.version = 999,
            1 => state.grants[0].subject = StandingSubject::Domain("example.com".into()),
            _ => state.grants[0].max_level = 0,
        }
        let storage = Arc::new(InMemoryStandingGrantStorage::new());
        storage.save(&state).unwrap();
        let mut legacy = empty_legacy();
        legacy.browser = storage;
        let destination = Arc::new(InMemoryAgentGrantStorage::default());
        let grants = open(destination.clone(), &legacy);
        assert!(grants.store_error().is_some());
        assert!(grants.upsert(row(), NOW).is_err());
        assert!(destination.load().unwrap().is_none());
    }
}

#[test]
fn both_contract_corpora_match_their_frozen_sha256_pins() {
    use sha2::{Digest, Sha256};
    for (name, pin, count) in [
        (
            "permissions-v1",
            "afec5cc3bcca2fdff8fbdd0ed8735e635f1a0425ea6caac002c5d81664c47b85",
            67,
        ),
        (
            "danger-option-group-v1",
            "b12c50344340930b688ab2f4a1536960e079138d774958f10071ea05d22e2619",
            31,
        ),
    ] {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors")
            .join(name);
        let sums = fs::read(directory.join("SHA256SUMS")).unwrap();
        assert_eq!(hex(&Sha256::digest(&sums)), pin);
        let sums = String::from_utf8(sums).unwrap();
        assert_eq!(sums.lines().count(), count);
        for line in sums.lines() {
            let (expected, filename) = line.split_once("  ").unwrap();
            assert_eq!(
                hex(&Sha256::digest(fs::read(directory.join(filename)).unwrap())),
                expected,
                "{name}/{filename}"
            );
        }
    }
}

#[test]
fn every_holder_subject_target_and_machine_has_its_own_identity() {
    let storage = Arc::new(InMemoryAgentGrantStorage::default());
    let mut first = row();
    first.id = "first".into();
    let mut holder = first.clone();
    holder.id = "holder".into();
    holder.holder = GrantHolder::Head {
        agent_id: "other-head".into(),
    };
    let mut subject = first.clone();
    subject.id = "subject".into();
    subject.subject = GrantSubject::App("other-app".into());
    let mut machine = first.clone();
    machine.id = "machine".into();
    machine.machine_uuid = "foreign".into();
    let mut site = first.clone();
    site.id = "site".into();
    site.subject = GrantSubject::Origin("https://example.com".into());
    site.browser_target = Some(BrowserTarget::AgentProfile);
    let mut user = site.clone();
    user.id = "user".into();
    user.browser_target = Some(BrowserTarget::UserBrowser);
    let mut worker = first.clone();
    worker.id = "worker".into();
    worker.holder = GrantHolder::Worker {
        agent_id: "head".into(),
        owner: "owner".into(),
        scope_ref: "scope".into(),
        scope_epoch: 1,
    };
    let mut epoch = worker.clone();
    epoch.id = "epoch".into();
    if let GrantHolder::Worker { scope_epoch, .. } = &mut epoch.holder {
        *scope_epoch = 2;
    }
    let mut owner = worker.clone();
    owner.id = "owner".into();
    if let GrantHolder::Worker { owner, .. } = &mut owner.holder {
        *owner = "other-owner".into();
    }
    let state = AgentGrantStoreState {
        grants: vec![
            first.clone(),
            holder,
            subject,
            machine,
            site,
            user,
            worker,
            epoch,
            owner,
        ],
        ..Default::default()
    };
    storage.save(&state).unwrap();
    let grants = open(storage.clone(), &empty_legacy());
    first.card_ref = Some("replacement".into());
    assert_eq!(grants.upsert(first.clone(), NOW).unwrap(), "first");
    let saved = storage.load().unwrap().unwrap();
    assert_eq!(saved.grants.len(), state.grants.len());
    assert_eq!(saved.grants[0], first);
    assert_eq!(saved.grants[1..], state.grants[1..]);
}

#[test]
fn state_and_filesystem_versions_are_checked_before_row_decoding() {
    let state = AgentGrantStoreState {
        version: 999,
        ..Default::default()
    };
    assert_eq!(
        state.check(),
        Err(AgentGrantStoreError::UnknownVersion { found: 999 })
    );
    let scratch = Scratch::new();
    let path = scratch.0.join(AGENT_GRANT_STORE_FILE);
    fs::write(&path, "{\"version\":999,\"future_field\":true}").unwrap();
    assert_eq!(
        FilesystemAgentGrantStorage::new(path).load(),
        Err(AgentGrantStoreError::UnknownVersion { found: 999 })
    );
    let mut legacy = empty_legacy();
    let apps = Arc::new(InMemoryGrantStorage::new());
    apps.save(&GrantStoreState {
        version: 999,
        records: vec![app(MACHINE)],
    })
    .unwrap();
    legacy.apps = apps;
    assert!(matches!(
        legacy.load(),
        Err(AgentGrantStoreError::Legacy { store: "apps", .. })
    ));
}

#[test]
fn repeated_legacy_answers_choose_newest_in_either_order_and_new_ids_are_random() {
    for reverse in [false, true] {
        let mut older = browser(MACHINE);
        older.granted_at_ms = 1;
        older.consent_ref = "older".into();
        let newer = browser(MACHINE);
        let mut answers = vec![older, newer.clone()];
        if reverse {
            answers.reverse();
        }
        let source = legacy(answers, Vec::new(), Vec::new());
        let grants = open(Arc::new(InMemoryAgentGrantStorage::default()), &source);
        let listed = grants.live_rows(None, NOW).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].card_ref.as_deref(),
            Some(newer.consent_ref.as_str())
        );
        let first = grants.upsert(row(), NOW).unwrap();
        let mut other = row();
        other.subject = GrantSubject::App("different-app".into());
        let second = grants.upsert(other, NOW).unwrap();
        assert_ne!(first, second);
    }
}
