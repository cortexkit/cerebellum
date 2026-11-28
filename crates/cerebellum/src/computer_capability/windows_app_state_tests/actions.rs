use super::*;
use crate::computer_grants::{AppCode, AppIdentity, AppIdentityUnreadable};
use cerebellum_computer::app_state::{
    image::ImageMapping,
    person::SeenMarks,
    session::RegisteredImage,
    source::{
        ElementActionError, ElementFacts, ElementHandle, ElementValue, HitScope, RawAppState,
        RawElement, ReadBounds, TextAttribute, WindowMark,
    },
};
use std::sync::Mutex;

pub(super) const ROWS: [&str; 3] = [
    "computer.press_element",
    "computer.press_point",
    "computer.write_text",
];

pub(super) fn block(context: &CapabilityAdvertisementContext) -> Option<&'static str> {
    app_state_block(context).or_else(|| {
        context
            .inputs
            .windows_element_addressed_review_revision
            .is_none()
            .then_some("windows element-addressed review unbound")
    })
}

fn inputs() -> CapabilityAdvertisementContext {
    let mut context = exact_inputs();
    context.inputs.windows_element_addressed_review_revision = Some("addressed-fixture".into());
    context.inputs.windows_actuation_review_revision = None;
    context
}

#[test]
fn addressed_test_route_needs_exact_keys_and_does_not_advertise_production() {
    let context = inputs();
    assert!(ROWS.iter().all(|row| rows(&context).contains(*row)));
    assert!(WindowsPlatformDriver::default()
        .declarations(&context)
        .iter()
        .all(|row| !row.advertised));
    for (change, reason) in [
        (0, "windows app identity review unbound"),
        (1, "windows app state review unbound"),
        (2, "windows element-addressed review unbound"),
        (3, "release signing topology unbound"),
        (4, "computer action vocabulary input unresolved"),
        (5, "cerebellum is running elevated"),
        (6, "integrity unreadable"),
    ] {
        let mut missing = context.clone();
        match change {
            0 => missing.inputs.windows_app_identity_review_revision = None,
            1 => missing.inputs.windows_app_state_review_revision = None,
            2 => missing.inputs.windows_element_addressed_review_revision = None,
            3 => missing.inputs.release_signing_topology_revision = None,
            4 => missing.inputs.vocabulary_digests.source_lock_digest = None,
            5 => missing.startup.windows_elevation = WindowsElevation::ElevatedOrAboveMedium,
            _ => missing.startup.windows_elevation = WindowsElevation::UnreadableOrBelowMedium,
        }
        assert_eq!(block(&missing), Some(reason));
        assert!(ROWS.iter().all(|row| !rows(&missing).contains(*row)));
    }
}

const CONVERSATION: &str = "test-session";
const WINDOW: u32 = 111;

struct FixtureCode;
impl AppCode for FixtureCode {
    fn identity(&self) -> Result<AppIdentity, AppIdentityUnreadable> {
        Ok(AppIdentity {
            team_id: None,
            designated_requirement: "signed-action-fixture".into(),
            ad_hoc: false,
            apple_anchored: false,
        })
    }

    fn satisfies(&self, requirement: &str) -> Result<bool, AppIdentityUnreadable> {
        Ok(requirement == "signed-action-fixture")
    }
}

struct Resolver(ProcessGrant);
impl crate::management::TargetResolver for Resolver {
    fn resolve(&self, target: &str) -> TargetResolution {
        if target == self.0.bundle_identity {
            TargetResolution::Resolved(self.0.clone())
        } else {
            TargetResolution::NotRunning
        }
    }

    fn process_for_pid(&self, pid: u32) -> Option<ProcessGrant> {
        (pid == self.0.pid).then(|| self.0.clone())
    }

    fn app_code(&self, _: &ProcessGrant) -> Arc<dyn AppCode> {
        Arc::new(FixtureCode)
    }
}

struct ActionFixture {
    pid: u32,
    frontmost: bool,
    mutations: AtomicUsize,
    value: Mutex<String>,
}

impl ActionFixture {
    fn edit(&self) -> RawElement {
        let mut edit = RawElement::fixture(2, "AXTextField").titled("Action fixture edit");
        edit.value = ElementValue::Text(self.value.lock().unwrap().clone());
        edit.value_settable = true;
        edit
    }
}

impl AppStateSource for ActionFixture {
    fn read_app_state(
        &self,
        _: &ProcessGrant,
        _: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        Ok(RawAppState {
            roots: vec![RawElement::fixture(1, "AXWindow").with_children(vec![self.edit()])],
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        })
    }

    fn element_facts(&self, element: &ElementHandle) -> Result<ElementFacts, ElementActionError> {
        let edit = element.same_element(self.edit().handle.as_ref());
        Ok(ElementFacts {
            pid: Some(self.pid),
            role: Some(if edit { "AXTextField" } else { "AXWindow" }.into()),
            value_settable: edit,
            actions: if edit {
                vec!["AXPress".into()]
            } else {
                Vec::new()
            },
            ..Default::default()
        })
    }

    fn element_parent(
        &self,
        element: &ElementHandle,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        Ok(element
            .same_element(self.edit().handle.as_ref())
            .then(|| RawElement::fixture(1, "AXWindow").handle))
    }

    fn press(&self, _: &ElementHandle) -> Result<(), ElementActionError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn write_text(
        &self,
        _: &ElementHandle,
        _: TextAttribute,
        text: &str,
    ) -> Result<(), ElementActionError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        *self.value.lock().unwrap() = text.into();
        Ok(())
    }

    fn text_value(&self, _: &ElementHandle) -> Result<Option<String>, ElementActionError> {
        Ok(Some(self.value.lock().unwrap().clone()))
    }

    fn focused_element(
        &self,
        _: &ProcessGrant,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        Ok(None)
    }

    fn focused_window(&self, _: &ProcessGrant) -> Result<Option<WindowMark>, ElementActionError> {
        Ok(None)
    }

    fn frontmost_pid(&self) -> Option<u32> {
        Some(if self.frontmost { self.pid } else { 1 })
    }

    fn visible_window_numbers(&self, _: &ProcessGrant) -> Option<Vec<u32>> {
        Some(vec![WINDOW])
    }

    fn element_window_number(&self, _: &ElementHandle) -> Option<u32> {
        Some(WINDOW)
    }

    fn window_frame(&self, _: &ProcessGrant, _: u32) -> Option<[f64; 4]> {
        Some([10.0, 20.0, 100.0, 80.0])
    }

    fn element_at(
        &self,
        _: HitScope,
        point: (f64, f64),
    ) -> Result<Option<(ElementHandle, Option<u32>)>, ElementActionError> {
        assert_eq!(point, (60.0, 60.0));
        Ok(Some((self.edit().handle, Some(self.pid))))
    }
}

fn seed(planes: &crate::Planes, grant: &ProcessGrant, fixture: &ActionFixture) -> (String, String) {
    let sessions = planes.management.app_state_sessions();
    let read = sessions.observe(
        CONVERSATION,
        grant,
        &fixture
            .read_app_state(grant, ReadBounds::default())
            .unwrap(),
    );
    sessions.remember_seen(CONVERSATION, grant, SeenMarks::read(fixture, grant));
    let image = sessions.register_framed_window_image(
        CONVERSATION,
        RegisteredImage {
            bundle_identity: grant.bundle_identity.clone(),
            pid: grant.pid,
            process_generation: grant.process_generation_evidence.clone(),
            width_px: 50,
            height_px: 40,
            mapping: ImageMapping::for_window((10.0, 20.0), (100.0, 80.0), (100, 80), (50, 40))
                .unwrap(),
        },
        WINDOW,
        [10.0, 20.0, 100.0, 80.0],
    );
    (read.roots[0].children[0].element_id.clone().unwrap(), image)
}

#[tokio::test]
async fn addressed_served_rows_require_current_generation_app_grant_and_person_check() {
    for (case, decision) in [
        ("generation", "allow_30m"),
        ("grant", "deny"),
        ("person", "allow_30m"),
        ("current", "allow_30m"),
    ] {
        for row in ROWS {
            let action = row.strip_prefix("computer.").unwrap();
            let grant = ProcessGrant {
                pid: 4242,
                bundle_identity: "Action fixture".into(),
                process_generation_evidence: "42".into(),
            };
            let mut live = grant.clone();
            if case == "generation" {
                live.process_generation_evidence = "43".into();
            }
            let fixture = Arc::new(ActionFixture {
                pid: live.pid,
                frontmost: case == "person",
                mutations: AtomicUsize::new(0),
                value: Mutex::new("before".into()),
            });
            let planes = rig(&inputs(), Arc::new(Resolver(live)), Some(fixture.clone()));
            let (element, image) = seed(&planes, &grant, &fixture);
            let arguments = match action {
                "press_element" => json!({"element_id":element}),
                "press_point" => json!({"image_id":image,"x":25,"y":20}),
                _ => json!({"element_id":element,"text":"after","write_mode":"replace_value"}),
            };
            let (reply, questions) =
                wire_with_decision(&planes, action, arguments, decision, || {}).await;
            let expected = match case {
                "generation" if action == "press_point" => "image_reference_unknown",
                "generation" => "stale_element",
                "grant" => "consent_denied",
                "person" => "observer_unavailable",
                _ => "completed",
            };
            assert_eq!(reply["outcome"], expected, "{case}/{row}: {reply}");
            assert_eq!(questions, usize::from(case != "generation"));
            assert_eq!(
                fixture.mutations.load(Ordering::SeqCst),
                usize::from(case == "current")
            );
        }
    }
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing fixture input {name}"))
}

fn native() -> (ProcessGrant, u32) {
    assert_eq!(
        WindowsElevation::read_current_process(),
        WindowsElevation::Medium
    );
    assert_eq!(
        cerebellum_windows::current_process_token_elevation_type(),
        Some(cerebellum_windows::TokenElevationType::Limited)
    );
    assert_eq!(cerebellum_windows::input_desktop_name().unwrap(), "Default");
    let pid = required("CK_WINDOWS_APP_STATE_FIXTURE_PID")
        .parse()
        .unwrap();
    let grant = windows_identity::grant_for_pid(pid).expect("verified fixture identity");
    assert!(grant.bundle_identity.starts_with("win-signed:"));
    let foreground = cerebellum_windows::foreground_window_number().unwrap();
    assert_ne!(cerebellum_windows::window_owner(foreground).unwrap().0, pid);
    (grant, foreground)
}

fn element_ids(reply: &Value, title: &str) -> Vec<String> {
    assert_eq!(reply["outcome"], "completed", "{reply}");
    reply["state_text"]
        .as_str()
        .unwrap()
        .lines()
        .filter(|line| line.contains(title))
        .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
        .collect()
}

async fn assert_value(planes: &crate::Planes, grant: &ProcessGrant, id: &str, expected: &str) {
    let reply = wire(planes, "wait", json!({
        "app":grant.bundle_identity,
        "predicate":{"kind":"element_value_equals", "element":{"Identifier":id}, "expected":expected},
        "timeout_ms":4000,
    })).await;
    assert_eq!(reply["outcome"], "predicate_satisfied", "{reply}");
}

#[tokio::test]
#[ignore = "requires the interactive split-token Windows fixture with duplicate buttons and recorded pattern effects"]
async fn native_addressed_press_dispatches_each_pattern_and_rejects_removed_duplicate() {
    let (grant, foreground) = native();
    let mut context = inputs();
    context.inputs.windows_actuation_review_revision = Some("wait-fixture".into());
    let planes = rig(&context, Arc::new(NativeFixture(grant.clone())), None);
    let marker = required("CK_WINDOWS_S7_EFFECT_AUTOMATION_ID");
    for (control, matches, index, expected) in [
        ("CK_WINDOWS_S7_DUPLICATE_TITLE", 2, 1, "second-invoke"),
        ("CK_WINDOWS_S7_CHECKBOX_TITLE", 1, 0, "toggle"),
        ("CK_WINDOWS_S7_SELECTION_TITLE", 1, 0, "select"),
        ("CK_WINDOWS_S7_EXPANDER_TITLE", 1, 0, "expand"),
        ("CK_WINDOWS_S7_EXPANDER_TITLE", 1, 0, "collapse"),
    ] {
        let read = wire(
            &planes,
            "read_state",
            json!({"target":grant.bundle_identity}),
        )
        .await;
        let ids = element_ids(&read, &required(control));
        assert_eq!(ids.len(), matches, "{read}");
        let press = wire(&planes, "press_element", json!({"element_id":ids[index]})).await;
        assert_eq!(press["outcome"], "completed", "{press}");
        assert_value(&planes, &grant, &marker, expected).await;
        assert_eq!(
            cerebellum_windows::foreground_window_number(),
            Some(foreground)
        );
        if expected == "second-invoke" {
            let stale = wire(&planes, "press_element", json!({"element_id":ids[index]})).await;
            assert_eq!(stale["outcome"], "stale_element", "{stale}");
        }
    }
}

#[tokio::test]
#[ignore = "requires the interactive split-token Windows fixture with an ordinary and a protected edit"]
async fn native_addressed_write_uses_value_pattern_and_refuses_password() {
    let (grant, foreground) = native();
    let planes = rig(&inputs(), Arc::new(NativeFixture(grant.clone())), None);
    let read = wire(
        &planes,
        "read_state",
        json!({"target":grant.bundle_identity}),
    )
    .await;
    for (control, outcome) in [
        ("CK_WINDOWS_S7_EDIT_TITLE", "completed"),
        ("CK_WINDOWS_S7_PASSWORD_TITLE", "secure_field_refused"),
    ] {
        let ids = element_ids(&read, &required(control));
        assert_eq!(ids.len(), 1, "{read}");
        let write = wire(
            &planes,
            "write_text",
            json!({"element_id":ids[0],"text":"replacement λ","write_mode":"replace_value"}),
        )
        .await;
        assert_eq!(write["outcome"], outcome, "{write}");
        if outcome == "completed" {
            assert_eq!(write["effect_status"], "effect_observed", "{write}");
        }
        assert_eq!(
            cerebellum_windows::foreground_window_number(),
            Some(foreground)
        );
    }
}

#[tokio::test]
#[ignore = "requires the interactive split-token Windows fixture with owned cover, resampled image and nested hit labels"]
async fn native_addressed_point_presses_imaged_window_through_cover() {
    let (grant, foreground) = native();
    cerebellum_windows::set_process_per_monitor_v2();
    assert!(cerebellum_windows::per_monitor_v2());
    let mut context = inputs();
    context.inputs.windows_actuation_review_revision = Some("wait-fixture".into());
    context.inputs.windows_capture_review_revision = Some("capture-fixture".into());
    let planes = rig(&context, Arc::new(NativeFixture(grant.clone())), None);
    let read = wire(
        &planes,
        "read_state",
        json!({"target":grant.bundle_identity,"include_image":true}),
    )
    .await;
    let id = read["image"]["image_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{read}"));
    let (hwnd, frame) = planes
        .management
        .app_state_sessions()
        .image_window_geometry(CONVERSATION, id)
        .unwrap();
    assert_eq!(
        hwnd,
        required("CK_WINDOWS_CAPTURE_FIXTURE_HWND")
            .parse::<u32>()
            .unwrap()
    );
    let image = planes
        .management
        .app_state_sessions()
        .resolve_image(CONVERSATION, id)
        .unwrap();
    assert!(f64::from(image.width_px) < frame.unwrap()[2]);
    let oob = wire(
        &planes,
        "press_point",
        json!({"image_id":id,"x":image.width_px,"y":0}),
    )
    .await;
    assert_eq!(oob["outcome"], "point_out_of_bounds", "{oob}");
    let x = required("CK_WINDOWS_S7_IMAGE_BUTTON_X")
        .parse::<u32>()
        .unwrap();
    let y = required("CK_WINDOWS_S7_IMAGE_BUTTON_Y")
        .parse::<u32>()
        .unwrap();
    let press = wire(&planes, "press_point", json!({"image_id":id,"x":x,"y":y})).await;
    assert_eq!(press["outcome"], "completed", "{press}");
    assert_value(
        &planes,
        &grant,
        &required("CK_WINDOWS_S7_EFFECT_AUTOMATION_ID"),
        "covered-button",
    )
    .await;
    assert_eq!(
        cerebellum_windows::foreground_window_number(),
        Some(foreground)
    );
}

#[tokio::test]
#[ignore = "requires the interactive split-token Windows fixture with a control that activates its own window"]
async fn native_addressed_foreground_change_is_reported_without_restore() {
    let (grant, foreground) = native();
    let planes = rig(&inputs(), Arc::new(NativeFixture(grant.clone())), None);
    let read = wire(
        &planes,
        "read_state",
        json!({"target":grant.bundle_identity}),
    )
    .await;
    let ids = element_ids(&read, &required("CK_WINDOWS_S7_ACTIVATOR_TITLE"));
    assert_eq!(ids.len(), 1, "{read}");
    let press = wire(&planes, "press_element", json!({"element_id":ids[0]})).await;
    assert_eq!(press["outcome"], "completed", "{press}");
    assert_eq!(
        press["fronting"],
        json!({"mode":"background","fronted":false,"purpose":"none","restore":"left_in_front"}),
        "{press}"
    );
    let after = cerebellum_windows::foreground_window_number().unwrap();
    assert_ne!(after, foreground);
    assert_eq!(
        cerebellum_windows::window_owner(after).unwrap().0,
        grant.pid
    );
}

#[tokio::test]
#[ignore = "requires the interactive split-token Windows fixture and a supervisor that restarts it on the Restart control"]
async fn native_addressed_restarted_fixture_refuses_old_ids() {
    let (grant, _) = native();
    let resolver = Arc::new(RestartingResolver(Mutex::new(grant.clone())));
    let planes = rig(&inputs(), resolver.clone(), None);
    let read = wire(
        &planes,
        "read_state",
        json!({"target":grant.bundle_identity}),
    )
    .await;
    let ids = element_ids(&read, &required("CK_WINDOWS_S7_RESTART_TITLE"));
    assert_eq!(ids.len(), 1, "{read}");
    let _ = wire(&planes, "press_element", json!({"element_id":ids[0]})).await;
    let end = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(TargetResolution::Resolved(live)) =
            windows_identity::resolve_target(&grant.bundle_identity)
        {
            if live.pid != grant.pid
                || live.process_generation_evidence != grant.process_generation_evidence
            {
                *resolver.0.lock().unwrap() = live;
                break;
            }
        }
        assert!(
            std::time::Instant::now() < end,
            "no live replacement for the fixture principal"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let reply = wire(&planes, "press_element", json!({"element_id":ids[0]})).await;
    assert_eq!(reply["outcome"], "stale_element", "{reply}");
}

struct RestartingResolver(Mutex<ProcessGrant>);
impl crate::management::TargetResolver for RestartingResolver {
    fn resolve(&self, target: &str) -> TargetResolution {
        let current = self.0.lock().unwrap();
        if target == current.bundle_identity {
            TargetResolution::Resolved(current.clone())
        } else {
            TargetResolution::NotRunning
        }
    }

    fn process_for_pid(&self, pid: u32) -> Option<ProcessGrant> {
        let current = self.0.lock().unwrap();
        (current.pid == pid).then(|| current.clone())
    }

    fn app_code(&self, grant: &ProcessGrant) -> Arc<dyn AppCode> {
        Arc::new(windows_identity::RunningCode(grant.clone()))
    }
}

#[tokio::test]
async fn windows_foreground_read_is_unavailable_with_all_windows_review_keys() {
    let grant = ProcessGrant {
        pid: 4242,
        bundle_identity: "Action fixture".into(),
        process_generation_evidence: "42".into(),
    };
    let fixture = Arc::new(ActionFixture {
        pid: grant.pid,
        frontmost: false,
        mutations: AtomicUsize::new(0),
        value: Mutex::new("before".into()),
    });
    let mut context = inputs();
    all_fronting_inputs(&mut context);
    let mut planes = rig(&context, Arc::new(Resolver(grant.clone())), Some(fixture));
    foreground_without_driver(&mut planes);
    let reply = wire(
        &planes,
        "read_state",
        json!({"target":grant.bundle_identity}),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(
        reply["fronting"],
        json!({
            "mode":"foreground", "fronted":false, "purpose":"foreground_mode", "restore":"not_needed", "not_fronted_reason":"fronting_unavailable"
        }),
        "{reply}"
    );
}

#[tokio::test]
#[ignore = "requires a signed fixture control that activates its own HWND, and a restorable fixture foreground"]
async fn windows_background_activation_restores_the_original_with_fronting_review() {
    let (grant, foreground) = native();
    let mut context = inputs();
    // Background restoration needs only its own review, not input-bracket authority.
    context.inputs.windows_fronting_review_revision = Some("restore-fixture".into());
    let planes = rig(&context, Arc::new(NativeFixture(grant.clone())), None);
    let read = wire(
        &planes,
        "read_state",
        json!({"target":grant.bundle_identity}),
    )
    .await;
    let ids = element_ids(&read, &required("CK_WINDOWS_S7_ACTIVATOR_TITLE"));
    assert_eq!(ids.len(), 1, "{read}");
    let press = wire(&planes, "press_element", json!({"element_id":ids[0]})).await;
    assert_eq!(press["outcome"], "completed", "{press}");
    assert_eq!(
        press["fronting"],
        json!({"mode":"background","fronted":false,"purpose":"none","restore":"restored"}),
        "{press}"
    );
    assert_eq!(
        cerebellum_windows::foreground_window_number(),
        Some(foreground)
    );
}
