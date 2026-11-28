use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering};

use cerebellum_computer::platform::vocabulary::validate_capability_result;
use cerebellum_linux::atspi::fixture::{Effects, TestAtspiBus};
use cerebellum_linux::{process_generation, ProcessGeneration, ProcessGenerationReading};
use subc_protocol::FrameType;

use super::tests::{bind_fixture, request};
use super::*;

fn fixture_proof(pid: u32) -> Result<VerifiedApp, IdentityRefusal> {
    let ProcessGenerationReading::Started {
        boot_id,
        start_ticks,
    } = process_generation(pid)
    else {
        return Err(IdentityRefusal::StaleReference);
    };
    let exe = format!("/proc/{pid}/exe");
    let metadata = std::fs::metadata(&exe).map_err(|_| IdentityRefusal::StaleReference)?;
    let path = std::fs::read_link(exe).map_err(|_| IdentityRefusal::StaleReference)?;
    Ok(VerifiedApp {
        generation: ProcessGeneration {
            pid,
            boot_id,
            start_ticks,
        },
        exe_device: metadata.dev(),
        exe_inode: metadata.ino(),
        path,
        subject: "dpkg:semantic-fixture".into(),
    })
}

type SessionControl = Arc<Mutex<Option<DesktopSession>>>;

fn rig(
    kind: SessionKind,
    accessibility: AccessibilityBus,
    native_proof: bool,
) -> (crate::Planes, SessionControl) {
    let admitted = Arc::new(
        [
            "list_apps",
            "read_state",
            "press_element",
            "write_text",
            "wait",
        ]
        .into_iter()
        .map(|action| format!("computer.{action}"))
        .collect(),
    );
    let mut session = LinuxSession::new(true, Arc::clone(&admitted));
    let desktop = Arc::new(Mutex::new(Some(DesktopSession {
        id: "semantic-fixture".into(),
        kind,
        locked: false,
        environment: Default::default(),
        accessibility: Some(accessibility),
    })));
    let reading = desktop.clone();
    session.read = Box::new(move || {
        let reading = reading.clone();
        Box::pin(async move {
            let desktop = reading.lock().await.clone();
            Ok(SessionReading {
                desktop: desktop.ok_or(session::NoSupportedSession)?,
                x11_connection: None,
                permissions: PermissionLivenessReport::default(),
            })
        })
    });
    if native_proof {
        session.identity = Some(Arc::default());
    } else {
        session.proof_for_test = Some(fixture_proof);
    }
    let session = Arc::new(session);
    let driver_session = session.clone();
    let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        computer_audit(JournalPersistence::Isolated).unwrap(),
        ResultSchemaEnforcement::Withhold,
        move || driver_session.driver(),
    )
    .with_app_state_source(Arc::new(Source(session.clone())));
    let mut planes = crate::Planes::with_browser_config_journaling(
        Arc::default(),
        None,
        JournalPersistence::Isolated,
    );
    planes.computer_admitted = admitted;
    planes.computer = Ok(Arc::new(ComputerPlane {
        linux_session: Some(session),
        ..plane
    }));
    bind_fixture(&planes);
    (
        crate::computer_grants::tests::CardService::install(planes, 7, 1),
        desktop,
    )
}

async fn wire(planes: &crate::Planes, action: &str, args: Value) -> Value {
    wire_observing_consent(planes, action, args, || {
        panic!("unexpected consent for {action}")
    })
    .await
}

async fn wire_observing_consent(
    planes: &crate::Planes,
    action: &str,
    args: Value,
    mut before_consent: impl FnMut(),
) -> Value {
    static NEXT: AtomicU64 = AtomicU64::new(100);
    let name = format!("computer.{action}");
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame_for_test(
        request(NEXT.fetch_add(1, Ordering::Relaxed), &name, args),
        &tx,
        planes,
    )
    .await
    .unwrap();
    tokio::time::timeout(crate::test_support::HANG_GUARD, async {
        loop {
            let service = planes.consent_test.as_ref().unwrap();
            tokio::select! {
                question = service.card(7, 1) => {
                    before_consent();
                    assert!(service.answer(question.header.corr, crate::cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"}))));
                }
                frame = rx.recv() => {
                    let frame = frame.unwrap();
                    let reply: Value = serde_json::from_slice(&frame.body).unwrap();
                    assert_eq!(frame.header.ty, FrameType::Response, "{reply}");
                    validate_capability_result(&name, &reply).unwrap();
                    return reply;
                }
            }
        }
    }).await.expect("Linux semantic call failed to settle")
}

fn state_text(reply: &Value) -> &str {
    assert_eq!(reply["outcome"], "completed", "{reply}");
    reply["state_text"].as_str().unwrap()
}

fn element(reply: &Value, name: &str) -> String {
    state_text(reply)
        .lines()
        .find(|line| line.contains(name))
        .unwrap_or_else(|| panic!("{name} missing from {reply}"))
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

fn wait_args(app: &str, timeout_ms: u32) -> Value {
    json!({"app":app, "predicate":{"kind":"element_present", "element":{"RoleAndTitle":{"role":"label","title":"Ready"}}}, "timeout_ms":timeout_ms})
}

async fn poll_started(effects: &Effects, baseline: usize) {
    tokio::time::timeout(crate::test_support::HANG_GUARD, async {
        while effects.polls.load(Ordering::SeqCst) <= baseline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the authorized fixture was not polled");
}

#[tokio::test]
async fn linux_semantic_wire_uses_exact_peer_and_applies_addressed_floors() {
    for kind in [SessionKind::X11, SessionKind::Wayland] {
        let bus = TestAtspiBus::start().await;
        let editor = bus.app("Semantic Editor").await;
        let other = bus.app("Unrelated Editor").await;
        let (planes, _) = rig(kind, bus.selected.clone(), false);
        let listed = wire(&planes, "list_apps", json!({})).await;
        assert_eq!(listed["outcome"], "completed", "{listed}");
        assert!(listed.to_string().contains("Semantic Editor"), "{listed}");

        let first =
            wire_observing_consent(&planes, "wait", wait_args("Semantic Editor", 350), || {
                assert_eq!(editor.effects.polls.load(Ordering::SeqCst), 0);
            })
            .await;
        assert_eq!(first["outcome"], "timeout", "{first}");
        assert_eq!(other.effects.polls.load(Ordering::SeqCst), 0);
        let baseline = editor.effects.polls.load(Ordering::SeqCst);
        let other_changed = async {
            poll_started(&editor.effects, baseline).await;
            other.effects.ready.store(true, Ordering::SeqCst);
        };
        let (waited, ()) = tokio::join!(
            wire(&planes, "wait", wait_args("Semantic Editor", 350)),
            other_changed
        );
        assert_eq!(waited["outcome"], "timeout", "{waited}");

        let filtered = wire(
            &planes,
            "read_state",
            json!({"target":"Semantic Editor","role_filter":"button"}),
        )
        .await;
        assert!(state_text(&filtered).contains("button Apply"), "{filtered}");
        assert!(!state_text(&filtered).contains("no open window"));
        let read = wire(&planes, "read_state", json!({"target":"Semantic Editor"})).await;
        let entry = element(&read, "Message");
        let button = element(&read, "Apply");
        let written = wire(
            &planes,
            "write_text",
            json!({"element_id": entry, "text":"Hello 🦀", "write_mode":"replace_value"}),
        )
        .await;
        assert_eq!(written["effect_status"], "effect_observed", "{written}");
        assert_eq!(*editor.effects.text.lock().unwrap(), "Hello 🦀");
        assert!(other.effects.text.lock().unwrap().is_empty());
        let pressed = wire(&planes, "press_element", json!({"element_id":button})).await;
        assert_eq!(pressed["outcome"], "completed", "{pressed}");
        assert!(editor.effects.ready.load(Ordering::SeqCst));
        assert_eq!(other.effects.posts.load(Ordering::SeqCst), 0);
        assert_eq!(
            wire(&planes, "wait", wait_args("Semantic Editor", 700)).await["outcome"],
            "predicate_satisfied"
        );

        editor.effects.unreadable_role.store(true, Ordering::SeqCst);

        for (field, reason) in [
            ("Password", "secure_field_focused"),
            ("Payment", "secure_field_focused"),
            ("Card child", "secure_field_focused"),
            ("Unknown field", "focus_unreadable"),
            ("Unknown role", "focus_unreadable"),
        ] {
            let element_id = element(&read, field);
            for (action, args) in [
                ("press_element", json!({"element_id":element_id})),
                (
                    "write_text",
                    json!({"element_id":element_id,"text":"blocked","write_mode":"replace_value"}),
                ),
            ] {
                let reply = wire(&planes, action, args).await;
                assert_eq!(reply["outcome"], "secure_field_refused", "{reply}");
                assert_eq!(reply["reason"], reason, "{reply}");
            }
        }
        *editor.effects.text.lock().unwrap() = "changed outside cerebellum".into();
        let changed = wire(
            &planes,
            "write_text",
            json!({"element_id":entry,"text":"must not overwrite","write_mode":"replace_value"}),
        )
        .await;
        assert_eq!(changed["outcome"], "state_changed_by_person", "{changed}");
        assert_eq!(changed["reason"], "readback_mismatch", "{changed}");
        assert_eq!(
            *editor.effects.text.lock().unwrap(),
            "changed outside cerebellum"
        );
        editor.effects.entry_payment.store(true, Ordering::SeqCst);
        let changed = wire(
            &planes,
            "write_text",
            json!({"element_id":entry,"text":"blocked","write_mode":"replace_value"}),
        )
        .await;
        assert_eq!(changed["reason"], "secure_field_focused", "{changed}");
        assert_eq!(editor.effects.posts.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn linux_semantic_owner_loss_does_not_rebind_on_the_same_bus() {
    for kind in [SessionKind::X11, SessionKind::Wayland] {
        let bus = TestAtspiBus::start().await;
        let editor = bus.app("Semantic Editor").await;
        let (planes, _) = rig(kind, bus.selected.clone(), false);
        let read = wire_observing_consent(
            &planes,
            "read_state",
            json!({"target":"Semantic Editor"}),
            || {},
        )
        .await;
        let button = element(&read, "Apply");
        let baseline = editor.effects.polls.load(Ordering::SeqCst);
        let replace = async {
            poll_started(&editor.effects, baseline).await;
            editor.close().await;
            let replacement = bus.app("Semantic Editor").await;
            replacement.effects.ready.store(true, Ordering::SeqCst);
            replacement
        };
        let (waited, replacement) = tokio::join!(
            wire(&planes, "wait", wait_args("Semantic Editor", 2000)),
            replace
        );
        assert_eq!(waited["reason"], "stale_reference", "{waited}");
        let refused = wire(&planes, "press_element", json!({"element_id":button})).await;
        assert_eq!(refused["reason"], "stale_reference", "{refused}");
        assert_eq!(replacement.effects.polls.load(Ordering::SeqCst), 0);
        assert_eq!(replacement.effects.posts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn linux_semantic_wait_and_element_do_not_rebind_after_epoch_change() {
    for kind in [SessionKind::X11, SessionKind::Wayland] {
        let address = format!(
            "unix:abstract=ck-atspi-restart-{}-{kind:?}",
            std::process::id()
        );
        let bus = TestAtspiBus::start_at(Some(&address)).await;
        let editor = bus.app("Semantic Editor").await;
        let initial = bus.selected.clone();
        let (planes, desktop) = rig(kind, bus.selected.clone(), false);
        let read = wire_observing_consent(
            &planes,
            "read_state",
            json!({"target":"Semantic Editor"}),
            || {},
        )
        .await;
        let button = element(&read, "Apply");
        let baseline = editor.effects.polls.load(Ordering::SeqCst);
        let replace = async {
            poll_started(&editor.effects, baseline).await;
            let mut reading = desktop.lock().await;
            drop(bus);
            let replacement_bus = TestAtspiBus::start_at(Some(&address)).await;
            let replacement = replacement_bus.app("Semantic Editor").await;
            assert_eq!(initial.address, replacement_bus.selected.address);
            assert_ne!(initial.id, replacement_bus.selected.id);
            assert_eq!(editor.peer(), replacement.peer());
            replacement.effects.ready.store(true, Ordering::SeqCst);
            reading.as_mut().unwrap().accessibility = Some(replacement_bus.selected.clone());
            (replacement_bus, replacement)
        };
        let (waited, (_replacement_bus, replacement)) = tokio::join!(
            wire(&planes, "wait", wait_args("Semantic Editor", 2000)),
            replace
        );
        assert_eq!(waited["reason"], "stale_reference", "{waited}");
        let refused = wire(&planes, "press_element", json!({"element_id":button})).await;
        assert_eq!(refused["reason"], "stale_reference", "{refused}");
        assert_eq!(replacement.effects.polls.load(Ordering::SeqCst), 0);
        assert_eq!(replacement.effects.posts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
#[ignore = "requires the hosted GTK fixture, a private AT-SPI bus, and Xvfb/Openbox or Weston with a virtual seat"]
async fn native_gtk_semantic_actions() {
    let required = |key| std::env::var(key).unwrap_or_else(|_| panic!("fixture requires {key}"));
    let kind = match required("CK_SEMANTIC_KIND").as_str() {
        "x11" => SessionKind::X11,
        "wayland" => SessionKind::Wayland,
        kind => panic!("unexpected GTK fixture backend {kind}"),
    };
    let selected = atspi::Bus::identify(&required("AT_SPI_BUS_ADDRESS"))
        .await
        .unwrap();
    let (planes, _) = rig(kind, selected.clone(), true);
    let target_file = required("CK_SEMANTIC_TARGET");
    let other_file = required("CK_SEMANTIC_OTHER");
    let assert_focus_unchanged = || {
        assert!(std::fs::read_to_string(&target_file)
            .unwrap()
            .starts_with("0\t"));
        assert_eq!(std::fs::read_to_string(&other_file).unwrap(), "1\t0\t\n");
    };

    let listed = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let listed = wire(&planes, "list_apps", json!({})).await;
            let text = listed.to_string();
            if text.contains("Semantic Target") && text.contains("Semantic Other") {
                break listed;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("GTK fixtures did not register on the accessibility bus");
    assert!(
        !listed.to_string().contains("Semantic Operator"),
        "{listed}"
    );
    assert!(
        !listed.to_string().contains("Semantic Hidden Tree"),
        "{listed}"
    );
    assert_focus_unchanged();

    let unregistered = wire(
        &planes,
        "read_state",
        json!({"target":"Semantic Hidden Tree"}),
    )
    .await;
    match kind {
        SessionKind::X11 => assert_eq!(
            unregistered["reason"], "backend_unavailable",
            "{unregistered}"
        ),
        SessionKind::Wayland => {
            assert_eq!(unregistered["outcome"], "not_running", "{unregistered}")
        }
    }

    let blocked = wire(&planes, "read_state", json!({"target":"Semantic Operator"})).await;
    assert_eq!(blocked["reason"], "operator_app_blocked", "{blocked}");
    let target = "Semantic Target";
    let (bus, field) = tokio::time::timeout(
        Duration::from_secs(2),
        print_gtk_state_words(&selected, target),
    )
    .await
    .expect("reading GTK fixture state words timed out");
    let read =
        wire_observing_consent(&planes, "read_state", json!({"target": target}), || {}).await;
    assert!(
        state_text(&read).contains("window Semantic Target"),
        "{read}"
    );
    let target_app = listed["apps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|app| app["name"] == target)
        .unwrap();
    let subject = target_app["bundle_identity"].as_str().unwrap();
    let ambiguous = wire(&planes, "read_state", json!({"target":subject})).await;
    assert_eq!(ambiguous["reason"], "ambiguous_app", "{ambiguous}");
    let filtered = wire(
        &planes,
        "read_state",
        json!({"target": target, "role_filter":"button"}),
    )
    .await;
    assert!(
        state_text(&filtered).contains("Fixture Apply"),
        "{filtered}"
    );
    assert!(!state_text(&filtered).contains("no open window"));
    let password = element(&read, "Fixture Password");
    let refused = wire(
        &planes,
        "write_text",
        json!({"element_id": password, "text":"blocked", "write_mode":"replace_value"}),
    )
    .await;
    assert_eq!(refused["reason"], "secure_field_focused", "{refused}");
    let text = "owned GTK field 🦀";
    print_gtk_field(&bus, &field, &target_file, "Before write").await;
    let write = wire(&planes, "write_text", json!({"element_id":element(&read, "Fixture Message"),"text":text,"write_mode":"replace_value"})).await;
    print_gtk_field(&bus, &field, &target_file, "After write").await;
    assert_eq!(write["effect_status"], "effect_observed", "{write}");
    assert_eq!(
        std::fs::read_to_string(&target_file).unwrap(),
        format!("0\t0\t{text}\n")
    );
    let press = wire(
        &planes,
        "press_element",
        json!({"element_id":element(&read, "Fixture Apply")}),
    )
    .await;
    assert_eq!(press["outcome"], "completed", "{press}");
    assert_eq!(
        std::fs::read_to_string(&target_file).unwrap(),
        format!("0\t1\t{text}\n")
    );
    let wait = wire(&planes, "wait", wait_args(target, 2000)).await;
    assert_eq!(wait["outcome"], "predicate_satisfied", "{wait}");
    assert_focus_unchanged();
}

async fn print_gtk_field(bus: &atspi::Bus, field: &atspi::Object, fixture_file: &str, phase: &str) {
    let readback = tokio::time::timeout(Duration::from_secs(2), bus.text(field)).await;
    let gtk_value = std::fs::read_to_string(fixture_file).unwrap();
    println!("{phase}: AT-SPI text {readback:?}; GTK fixture record {gtk_value:?}");
}

async fn print_gtk_state_words(
    selected: &AccessibilityBus,
    target: &str,
) -> (atspi::Bus, atspi::Object) {
    let bus = atspi::Bus::connect(selected).await.unwrap();
    let mut root = None;
    for app in bus.applications().await.unwrap() {
        if bus.name(&app).await.as_deref() == Ok(target) {
            root = Some(app);
            break;
        }
    }
    let mut pending = vec![root.expect("GTK target on the accessibility bus")];
    let mut seen = std::collections::HashSet::new();
    let mut field = None;
    while let Some(object) = pending.pop() {
        if !seen.insert(object.clone()) {
            continue;
        }
        assert!(seen.len() <= 32, "unexpected GTK test tree size");
        let name = bus.name(&object).await.unwrap_or_default();
        let role = bus.role(&object).await.unwrap();
        let words = bus.state(&object).await.unwrap();
        println!("GTK GetState {name:?} ({role:?}): {words:#010x?}");
        if name == "Fixture Message" {
            assert!(
                field.replace(object.clone()).is_none(),
                "duplicate fixture field"
            );
        }
        pending.extend(
            bus.children(&object)
                .await
                .unwrap()
                .into_iter()
                .flatten()
                .filter(|child| child.peer == object.peer),
        );
    }
    (bus, field.expect("ordinary GTK fixture entry"))
}
