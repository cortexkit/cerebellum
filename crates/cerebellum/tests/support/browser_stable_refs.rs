use super::*;
use cerebellum::browser_type::{BrowserTypeResult, TypeDispatch};
use cerebellum::classification::NonTypeClassificationRecord;

#[derive(Default)]
pub(super) struct Dropdowns {
    pub selected: BTreeSet<u64>,
    pub removed: BTreeSet<u64>,
    pub menu: Option<u64>,
    pub typed: String,
}

impl Dropdowns {
    fn classification(backend: u64, epoch: u64, origin: &str) -> NonTypeClassificationRecord {
        let (scheme, rest) = origin.split_once("://").unwrap();
        let origin = format!("{scheme}://{}", rest.split(['/', '?', '#']).next().unwrap());
        classify_click(&NonTypeClassificationInput::new(
            epoch,
            ElementClassificationInput::new(
                NodeIdentityInput::new("target", "frame-main", backend),
                if backend == 500 {
                    TargetKind::Input
                } else {
                    TargetKind::Button
                },
            )
            .input_type(if backend == 500 { "text" } else { "button" }),
            &origin,
        ))
        .unwrap()
    }

    pub fn observation(&self, epoch: u64, origin: &str) -> BrowserSnapshotObservation {
        let mut observation = BrowserSnapshotObservation {
            records: Vec::new(),
            refs: Vec::new(),
            dom_text: None,
            facts: Default::default(),
            ax_truncated: false,
            refs_truncated: false,
        };
        let mut push = |depth, role: &str, name: String, backend| {
            let reference = format!("e{}", observation.refs.len() + 1);
            observation.records.push(AxRecord {
                depth,
                role: role.into(),
                name: name.clone(),
                value: None,
                reference: Some(reference.clone()),
            });
            observation.refs.push(RefRecord {
                frame_document: None,
                captured: SnapshotRef::new(&reference, role, &name, 0).unwrap(),
                frame_path: vec!["frame-main".into()],
                backend_identity: Some(
                    BackendNodeIdentity::new("target", "frame-main", backend).unwrap(),
                ),
                raw_role: None,
                raw_name: None,
                classification: Ok(Box::new(Self::classification(backend, epoch, origin))),
            });
        };
        push(0, "main", "Permissions".into(), 1);
        push(1, "list", "Permission list".into(), 2);
        for item in 0..40 {
            if self.removed.contains(&item) {
                continue;
            }
            let name = format!("Permission {item:02}");
            push(2, "listitem", name.clone(), 10 + item);
            if self.selected.contains(&item) {
                push(3, "StaticText", "Selected".into(), 300 + item);
            }
            push(3, "button", format!("Access: {name}"), 100 + item);
            if self.menu == Some(item) {
                push(3, "menuitem", format!("Read: {name}"), 200 + item);
            }
        }
        push(1, "textbox", "Notes".into(), 500);
        observation
    }

    pub fn click(
        &mut self,
        identity: &BackendNodeIdentity,
        epoch: u64,
        origin: &str,
        expected: Option<&NonTypeClassificationRecord>,
    ) -> Result<(), ClickDriveError> {
        let backend = identity.backend_node_id;
        if identity.target_id != "target"
            || identity.frame_id != "frame-main"
            || Some(&Self::classification(backend, epoch, origin)) != expected
        {
            return Err(ClickDriveError::ClassificationChanged);
        }
        match backend {
            100..=139 if !self.removed.contains(&(backend - 100)) => {
                self.menu = Some(backend - 100)
            }
            200..=239 if self.menu == Some(backend - 200) => {
                self.selected.insert(backend - 200);
                self.menu = None;
            }
            _ => return Err(ClickDriveError::ClassificationChanged),
        }
        Ok(())
    }

    pub fn type_text(&mut self, target: &TypeDispatch, text: &str) -> BrowserTypeResult {
        if target.identity.backend_node_id != 500 {
            return BrowserTypeResult::StaleSnapshot {
                reason: cerebellum::browser_type::StaleReason::ResolvedNodeChanged,
            };
        }
        self.typed = text.into();
        BrowserTypeResult::Ok
    }
}

async fn fixture() -> (Planes, Arc<RecordingLauncher>, Arc<Mutex<Dropdowns>>) {
    let dropdowns = Arc::new(Mutex::new(Dropdowns::default()));
    let launcher = Arc::new(RecordingLauncher {
        dropdowns: Some(dropdowns.clone()),
        ..Default::default()
    });
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    grant_browser(
        &planes,
        "https://page.example:8443",
        vec![HazardClass::CredentialFormSubmit],
    )
    .await;
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;
    (planes, launcher, dropdowns)
}

async fn call(planes: &Planes, action: &str, args: Value) -> Value {
    let reply = invoke(planes, 90, "browser_use", {
        let mut args = args.as_object().unwrap().clone();
        args.insert("action".into(), json!(action));
        Value::Object(args)
    })
    .await;
    serde_json::from_slice(&reply.body).unwrap()
}

fn ref_named(snapshot: &Value, name: &str) -> String {
    snapshot["state_text"]
        .as_str()
        .unwrap()
        .lines()
        .find(|line| line.ends_with(name))
        .unwrap_or_else(|| panic!("missing {name}: {snapshot}"))
        .split_whitespace()
        .next()
        .unwrap()
        .into()
}

async fn click(planes: &Planes, snapshot: &Value, reference: &str) -> Value {
    call(planes, "click", json!({"ref":reference,"snapshot_id":snapshot["snapshot_id"],"intent":"fixture dropdown", "severity":{"tier":2,"credential":false,"financial":false}})).await
}

#[tokio::test]
async fn stable_refs_wire_insertions_keep_later_refs_and_old_clicks() {
    let (planes, _, dropdowns) = fixture().await;
    let before = call(&planes, "snapshot", json!({"role_filter":["AXButton"]})).await;
    assert_eq!(before["outcome"], "ok", "{before}");
    let later = ref_named(&before, "Access: Permission 39");
    let first = ref_named(&before, "Access: Permission 00");
    assert_eq!(click(&planes, &before, &first).await["outcome"], "ok");
    let menu = call(
        &planes,
        "snapshot",
        json!({"text_filter":"Permission 00", "role_filter":["menuitem"]}),
    )
    .await;
    assert_eq!(
        click(&planes, &menu, &ref_named(&menu, "Read: Permission 00")).await["outcome"],
        "ok"
    );
    let after = call(&planes, "snapshot", json!({"role_filter":["button"]})).await;
    assert_eq!(ref_named(&after, "Access: Permission 39"), later);
    assert_eq!(click(&planes, &before, &later).await["outcome"], "ok");
    assert_eq!(dropdowns.lock().unwrap().menu, Some(39));
    assert!(planes.browser.result_schema_findings().is_empty());
}

#[tokio::test]
async fn stable_refs_wire_removed_zoom_shows_outline_and_click_refuses_without_reassignment() {
    let (planes, launcher, dropdowns) = fixture().await;
    let before = call(&planes, "snapshot", json!({"role_filter":["button"]})).await;
    let removed = ref_named(&before, "Access: Permission 00");
    dropdowns.lock().unwrap().removed.insert(0);
    let zoom = call(&planes, "snapshot", json!({"zoom":removed})).await;
    assert_eq!(zoom["outcome"], "ok", "{zoom}");
    let message = format!("zoom {removed}: no such element on the page now; showing the outline");
    let text = zoom["state_text"].as_str().unwrap();
    assert!(text.contains(&message), "{text}");
    assert!(text.contains("Permissions"), "{text}");
    assert!(!text.contains("Access: Permission 00"), "{text}");
    let clicked = click(&planes, &before, &removed).await;
    assert_eq!(clicked["outcome"], "stale_snapshot", "{clicked}");
    assert!(!launcher.effects.lock().unwrap().contains(&"input_press"));
    let after = call(&planes, "snapshot", json!({"role_filter":["button"]})).await;
    assert_ne!(ref_named(&after, "Access: Permission 01"), removed);
    let old_zoom = call(&planes, "snapshot", json!({"zoom":removed})).await;
    assert_eq!(old_zoom["outcome"], "ok", "{old_zoom}");
    assert!(old_zoom["state_text"].as_str().unwrap().contains(&message));
}

#[tokio::test]
async fn stable_refs_wire_filters_keep_only_matches_under_ancestors() {
    let (planes, _, _) = fixture().await;
    let filtered = call(
        &planes,
        "snapshot",
        json!({"text_filter":"permission 17", "role_filter":["AXButton"]}),
    )
    .await;
    let text = filtered["state_text"].as_str().unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("button Access:"))
            .count(),
        1
    );
    assert!(text.contains("listitem Permission 17"), "{text}");
    assert!(text.contains("list Permission list"), "{text}");
    assert!(!text.contains("Permission 18"));
    let empty = call(&planes, "snapshot", json!({"text_filter":"missing"})).await;
    assert!(empty["state_text"].as_str().unwrap().contains("No matches"));
}

#[tokio::test]
async fn stable_refs_wire_type_uses_named_older_snapshot_and_ledger() {
    let (planes, launcher, dropdowns) = fixture().await;
    let before = call(&planes, "snapshot", json!({"role_filter":["textbox"]})).await;
    let notes = ref_named(&before, "textbox Notes");
    call(
        &planes,
        "snapshot",
        json!({"text_filter":"Permission 17","role_filter":["button"]}),
    )
    .await;
    let typed = call(
        &planes,
        "type",
        json!({"ref":notes,"snapshot_id":before["snapshot_id"],"text":"older"}),
    )
    .await;
    assert_eq!(typed["outcome"], "ok", "{typed}");
    assert_eq!(dropdowns.lock().unwrap().typed, "older");
    let typed = call(&planes, "type", json!({"ref":notes,"text":"ledger"})).await;
    assert_eq!(typed["outcome"], "ok", "{typed}");
    launcher.page.commit("https://page.example:8443/reloaded");
    let stale = call(&planes, "type", json!({"ref":notes,"text":"not sent"})).await;
    assert_eq!(stale["outcome"], "stale_snapshot", "{stale}");
    assert_eq!(
        stale["detail"]["reason_code"],
        "page_changed_since_snapshot"
    );
    assert_eq!(dropdowns.lock().unwrap().typed, "ledger");
}

#[tokio::test]
async fn stable_refs_wire_old_refs_survive_views_but_not_snapshot_eviction() {
    let (planes, launcher, _) = fixture().await;
    let before = call(
        &planes,
        "snapshot",
        json!({"text_filter":"Permission 39","role_filter":["button"]}),
    )
    .await;
    let old = ref_named(&before, "Access: Permission 39");
    let narrowed = call(
        &planes,
        "snapshot",
        json!({"text_filter":"Permission 00","role_filter":["button"]}),
    )
    .await;
    assert_eq!(narrowed["outcome"], "ok");
    let retained_zoom = call(&planes, "snapshot", json!({"zoom":old})).await;
    assert_eq!(retained_zoom["outcome"], "ok", "{retained_zoom}");
    assert_eq!(ref_named(&retained_zoom, "Access: Permission 39"), old);
    for _ in 0..20 {
        let narrowed = call(
            &planes,
            "snapshot",
            json!({"text_filter":"Permission 00","role_filter":["button"]}),
        )
        .await;
        assert_eq!(narrowed["outcome"], "ok");
    }
    let stale = click(&planes, &before, &old).await;
    assert_eq!(stale["outcome"], "stale_snapshot", "{stale}");
    assert!(!launcher.effects.lock().unwrap().contains(&"input_press"));
    // Eviction removes proof of what the caller saw, even if the name cache
    // remembers the node. An unknown zoom shows the outline, not that node.
    let zoom = call(&planes, "snapshot", json!({"zoom":old})).await;
    assert_eq!(zoom["outcome"], "ok", "{zoom}");
    let text = zoom["state_text"].as_str().unwrap();
    assert!(
        text.contains(&format!(
            "zoom {old}: no such element on the page now; showing the outline"
        )),
        "{text}"
    );
    assert!(!text.contains("Access: Permission 39"), "{text}");
    let fresh = call(
        &planes,
        "snapshot",
        json!({"text_filter":"Permission 39","role_filter":["button"]}),
    )
    .await;
    assert_eq!(fresh["outcome"], "ok", "{fresh}");
    assert_eq!(ref_named(&fresh, "Access: Permission 39"), old);
    assert_eq!(click(&planes, &fresh, &old).await["outcome"], "ok");
}

#[tokio::test]
async fn stable_refs_wire_frame_same_document_url_keeps_old_click() {
    let fixture = frame_fixture();
    let launcher = Arc::new(RecordingLauncher {
        frame_fixture: Some(fixture.clone()),
        ..Default::default()
    });
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    grant_browser(&planes, "https://page.example:8443", vec![]).await;
    grant_browser(&planes, "https://payment.example:8443", vec![]).await;
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;
    let before = call(&planes, "snapshot", json!({})).await;
    let old = first_ref(&before);
    {
        let mut frame = fixture.lock().unwrap();
        frame.documents[1].url.push_str("#pushstate");
        frame.documents[1].navigation_revision += 1;
    }
    assert_eq!(click(&planes, &before, &old).await["outcome"], "ok");
    let zoom = call(&planes, "snapshot", json!({"zoom":old})).await;
    assert_eq!(zoom["outcome"], "ok", "{zoom}");
    assert_eq!(first_ref(&zoom), old);
    fixture.lock().unwrap().documents[1].loader_id = "reloaded-frame".into();
    let stale = click(&planes, &before, &old).await;
    assert_eq!(stale["outcome"], "stale_snapshot", "{stale}");
}
