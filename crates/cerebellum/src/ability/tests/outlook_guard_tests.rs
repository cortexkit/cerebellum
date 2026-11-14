use super::*;
use crate::outlook_guard::{
    required_locations, AntivirusHealth, Bitness, GuardEnvironment, GuardInput, GuardValue,
    GuardValues, Guarded, Hive, Installation, InstallationIdentity, InstallationKind, LocationRead,
    Setting,
};

struct OutlookMembers {
    input: Mutex<GuardInput>,
    invoked: Arc<AtomicUsize>,
    invalidate_after_status: bool,
}

impl GuardEnvironment for OutlookMembers {
    fn guard_input(&self) -> GuardInput {
        self.input.lock().unwrap().clone()
    }
}

impl StatusSource for OutlookMembers {
    fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        if self.invalidate_after_status {
            self.input.lock().unwrap().installation = InstallationIdentity::Unknown;
        }
        Ok(tokens
            .iter()
            .map(|&token| {
                (
                    token,
                    Availability {
                        unavailable_reason: None,
                    },
                )
            })
            .collect())
    }

    fn choices(&self, _: Token) -> Result<Vec<ScopeChoice>, Refusal> {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }

    fn read(
        &self,
        _: Token,
        _: &str,
        _: &ValidatedArgs,
        _: &BoundScope,
    ) -> Result<SourceRead, Refusal> {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        Ok(SourceRead {
            containers: ["bound".to_owned()].into(),
            time_zone: Some("UTC".into()),
            records: vec![],
        })
    }
}

fn snapshot() -> GuardInput {
    let installation = Installation {
        major: 16,
        minor: 0,
        bitness: Bitness::X64,
        kind: InstallationKind::Msi,
    };
    GuardInput {
        installation: InstallationIdentity::Unique(installation),
        registry: required_locations(installation)
            .unwrap()
            .into_iter()
            .map(|location| (location, LocationRead::Read(GuardValues::new())))
            .collect(),
        antivirus: AntivirusHealth::Good,
    }
}

fn guard_fixture(input: GuardInput, invalidate_after_status: bool) -> (Planes, Arc<AtomicUsize>) {
    let invoked = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(Guarded(OutlookMembers {
        input: Mutex::new(input),
        invoked: invoked.clone(),
        invalidate_after_status,
    }));
    let mut planes = fixture(source, Platform::Windows);
    Arc::get_mut(&mut planes.management)
        .unwrap()
        .abilities
        .binding = Arc::new(Bound);
    (planes, invoked)
}

async fn assert_unavailable_without_members(input: GuardInput, reason: &str) {
    let (planes, invoked) = guard_fixture(input, false);
    let description = exchange(&planes, &flow(), json!({"method": DESCRIBE})).await;
    let description = body(&description);
    let tokens = description["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 4);
    for &token in Platform::Windows.tokens() {
        let entry = tokens
            .iter()
            .find(|entry| entry["token"] == token.as_str())
            .unwrap();
        assert_eq!(entry["available"], false);
        assert_eq!(entry["unavailable_reason"], reason);
        for request in [
            list(token, 10),
            call(
                token,
                match token {
                    Token::Calendar => "events.get",
                    Token::Reminders => "reminders.get",
                    Token::Contacts => "contacts.get",
                    Token::Mail => "messages.get",
                    Token::Messages => unreachable!(),
                },
                json!({"id":"unknown"}),
            ),
            json!({"method": SCOPE_CHOICES, "params": {"token":token.as_str(),"key":token.info().scope_key}}),
        ] {
            assert_refusal(&reserved(&planes, request).await, reason);
        }
        let setup = reserved(
            &planes,
            json!({"method": SETUP, "params": {"token":token.as_str()}}),
        )
        .await;
        assert_eq!(body(&setup), json!({"state":"not_required"}));
    }
    // Even the fake member-backed status method must remain untouched. The
    // parsed snapshot is obtained without starting or attaching to Outlook.
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn outlook_guard_unknown_and_unreadable_configurations_refuse_every_windows_token_without_members(
) {
    let mut unknown = snapshot();
    unknown.installation = InstallationIdentity::Unknown;
    assert_unavailable_without_members(unknown, "outlook_guard_may_prompt").await;
    for index in 0..8 {
        let mut unreadable = snapshot();
        unreadable.registry[index].1 = LocationRead::Unreadable;
        assert_unavailable_without_members(unreadable, "outlook_guard_may_prompt").await;
    }
}

#[tokio::test]
async fn outlook_guard_click_to_run_and_default_unhealthy_refuse_without_members() {
    let mut c2r = snapshot();
    let InstallationIdentity::Unique(ref mut installation) = c2r.installation else {
        unreachable!()
    };
    installation.kind = InstallationKind::ClickToRun;
    assert_unavailable_without_members(c2r, "outlook_guard_may_prompt").await;
    let mut unhealthy = snapshot();
    unhealthy.antivirus = AntivirusHealth::Poor;
    assert_unavailable_without_members(unhealthy, "outlook_guard_may_prompt").await;
}

#[tokio::test]
async fn outlook_guard_documented_denial_reports_permission_missing_without_members() {
    let mut denied = snapshot();
    for (location, read) in &mut denied.registry {
        if location.hive == Hive::CurrentUser && location.key.contains("Policies") {
            let LocationRead::Read(values) = read else {
                unreachable!()
            };
            values.insert(Setting::AdminSecurityMode, GuardValue::Dword(3));
            values.insert(Setting::PromptOOMAddressBookAccess, GuardValue::Dword(0));
        }
    }
    assert_unavailable_without_members(denied, "permission_missing").await;
}

#[tokio::test]
async fn outlook_guard_healthy_default_reaches_fake_member_source() {
    let (planes, invoked) = guard_fixture(snapshot(), false);
    let description = exchange(&planes, &flow(), json!({"method":DESCRIBE})).await;
    for entry in body(&description)["tokens"].as_array().unwrap() {
        assert_eq!(entry["available"], true);
    }
    for &token in Platform::Windows.tokens() {
        let reply = reserved(&planes, list(token, 10)).await;
        assert_eq!(body(&reply)["items"], json!([]));
    }
    assert_eq!(invoked.load(Ordering::SeqCst), 9);
}

#[tokio::test]
async fn outlook_guard_rechecks_before_members_after_successful_status() {
    let (planes, invoked) = guard_fixture(snapshot(), true);
    let reply = reserved(&planes, list(Token::Calendar, 10)).await;
    assert_refusal(&reply, "outlook_guard_may_prompt");
    assert_eq!(
        invoked.load(Ordering::SeqCst),
        1,
        "only the previously permitted status ran"
    );
}
