use super::*;
use crate::ability::outlook::{source::*, zones};
use crate::outlook_guard::*;
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::{Barrier, Mutex},
    thread::ThreadId,
};

fn guard() -> GuardInput {
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

fn id(entry: &str) -> Id {
    Id {
        store: b"store".to_vec(),
        entry: entry.as_bytes().to_vec(),
    }
}

fn folder(token: Token, name: &str) -> Folder {
    Folder {
        id: id(name),
        token,
        title: Some(name.into()),
        store_display_name: Some("Store display name".into()),
    }
}

fn raw(token: Token, entry: &str, parent: &str) -> (Header, Fields) {
    let class = match token {
        Token::Calendar => Class::Appointment,
        Token::Reminders => Class::Task,
        Token::Contacts => Class::Contact,
        Token::Mail => Class::Mail,
        Token::Messages => unreachable!(),
    };
    let fields = match token {
        Token::Calendar => Fields::Appointment(Event {
            start_ms: Some(10),
            end_ms: Some(20),
            ..Default::default()
        }),
        Token::Reminders => Fields::Task(Reminder::default(), None),
        Token::Contacts => Fields::Contact(Contact::default()),
        Token::Mail => Fields::Mail(
            MailMessage {
                date_ms: Some(10),
                ..Default::default()
            },
            Body::Text("Outlook Body text from HTML message".into()),
        ),
        Token::Messages => unreachable!(),
    };
    (
        Header {
            id: id(entry),
            parent: id(parent),
            class,
            original_start_ms: None,
        },
        fields,
    )
}

type ThreadEvent = (usize, &'static str, ThreadId);

struct FakeFactory {
    guard: Mutex<GuardInput>,
    attach_error: Option<AttachError>,
    folders: Vec<Folder>,
    // Enumeration deliberately leaks other-parent items to exercise the filter.
    items: Vec<(Header, Fields)>,
    opened: AtomicUsize,
    members: AtomicUsize,
    events: Mutex<Vec<ThreadEvent>>,
    barrier: Option<Arc<Barrier>>,
    block: Option<Arc<Block>>,
    zone: Option<String>,
    invalidate_guard_after_folders: bool,
}

impl Default for FakeFactory {
    fn default() -> Self {
        Self {
            guard: Mutex::new(guard()),
            attach_error: None,
            folders: vec![],
            items: vec![],
            opened: AtomicUsize::new(0),
            members: AtomicUsize::new(0),
            events: Mutex::new(vec![]),
            barrier: None,
            block: None,
            zone: Some("Eastern Standard Time".into()),
            invalidate_guard_after_folders: false,
        }
    }
}

struct FakeSession {
    factory: Arc<FakeFactory>,
    serial: usize,
    thread: ThreadId,
    // Models an apartment-bound COM interface; this session cannot be Send/Sync.
    _apartment: PhantomData<Rc<()>>,
}

struct Factory(Arc<FakeFactory>);

impl SessionFactory for Factory {
    fn attach_running(&self) -> Result<Box<dyn Session>, AttachError> {
        if let Some(error) = self.0.attach_error {
            return Err(error);
        }
        let serial = self.0.opened.fetch_add(1, Ordering::SeqCst);
        self.0
            .events
            .lock()
            .unwrap()
            .push((serial, "open", std::thread::current().id()));
        Ok(Box::new(FakeSession {
            factory: self.0.clone(),
            serial,
            thread: std::thread::current().id(),
            _apartment: PhantomData,
        }))
    }
}

impl FakeSession {
    fn event(&self, name: &'static str) {
        assert_eq!(self.thread, std::thread::current().id());
        self.factory
            .events
            .lock()
            .unwrap()
            .push((self.serial, name, self.thread));
    }
    fn member(&self) {
        self.event("member");
        self.factory.members.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for FakeSession {
    fn drop(&mut self) {
        self.event("drop");
    }
}

impl Session for FakeSession {
    fn guard_input(&self) -> GuardInput {
        self.event("guard");
        self.factory.guard.lock().unwrap().clone()
    }
    fn windows_zone_id(&self) -> Option<String> {
        self.event("zone");
        self.factory.zone.clone()
    }
    fn folders(&mut self) -> Result<Vec<Folder>, Refusal> {
        self.member();
        if self.factory.invalidate_guard_after_folders {
            self.factory.guard.lock().unwrap().installation = InstallationIdentity::Unknown;
        }
        Ok(self.factory.folders.clone())
    }
    fn items(&mut self, _: &Folder, _: &ValidatedArgs) -> Result<Vec<Header>, Refusal> {
        self.member();
        Ok(self
            .factory
            .items
            .iter()
            .map(|(header, _)| header.clone())
            .collect())
    }
    fn lookup(&mut self, _: Token, requested: &str) -> Result<Option<Header>, Refusal> {
        self.member();
        Ok(self
            .factory
            .items
            .iter()
            .find(|(header, _)| {
                let mut encoded = header.id.encode();
                if let Some(original) = header.original_start_ms {
                    encoded.push_str(&format!(".{original}"));
                }
                encoded == requested
            })
            .map(|(header, _)| header.clone()))
    }
    fn fields(&mut self, header: &Header, _: bool) -> Result<Fields, Refusal> {
        self.member();
        assert_ne!(
            header.class,
            Class::Other,
            "other classes must be left out before field access"
        );
        if let Some(barrier) = &self.factory.barrier {
            barrier.wait();
        }
        if let Some(block) = &self.factory.block {
            block.started.notify_one();
            let mut done = block.done.lock().unwrap();
            while !*done {
                done = block.wake.wait(done).unwrap();
            }
        }
        self.factory
            .items
            .iter()
            .find(|(candidate, _)| {
                candidate.id == header.id && candidate.original_start_ms == header.original_start_ms
            })
            .map(|(_, fields)| fields.clone())
            .ok_or(Refusal::SourceFailed)
    }
}

#[tokio::test]
async fn outlook_source_contact_folders_are_accounts_and_mailbox_uses_store_display_name() {
    let (planes, _) = outlook_fixture(FakeFactory {
        folders: vec![
            folder(Token::Contacts, "bound"),
            folder(Token::Contacts, "outside"),
            folder(Token::Mail, "bound"),
        ],
        ..Default::default()
    });
    let choices = body(&reserved(&planes, json!({"method":SCOPE_CHOICES,"params":{"token":Token::Contacts.as_str(),"key":"group"}})).await);
    assert_eq!(choices["choices"].as_array().unwrap().len(), 2);
    for choice in choices["choices"].as_array().unwrap() {
        assert_eq!(choice["kind"], "account");
    }
    let groups = body(
        &reserved(
            &planes,
            outlook_call(Token::Contacts, "groups.list", json!({})),
        )
        .await,
    );
    assert_eq!(
        groups["items"],
        json!([{"id":id("bound").encode(),"title":"bound","kind":"account","truncated":[]}])
    );
    let mailboxes = body(
        &reserved(
            &planes,
            outlook_call(Token::Mail, "mailboxes.list", json!({})),
        )
        .await,
    );
    assert_eq!(mailboxes["items"][0]["account"], "Store display name");
    // Independent fixed expectation, not an encode/decode self-comparison.
    assert_eq!(id("bound").encode(), "c3RvcmU.Ym91bmQ");
    assert_eq!(
        Id {
            store: vec![0xff, 0xfe],
            entry: vec![0xfb, 0xff]
        }
        .encode(),
        "__4.-_8"
    );
}

#[tokio::test]
async fn outlook_source_no_date_and_outlook_body_states_are_normalized() {
    use cerebellum_ability::time::NaiveDate;
    let sentinel = NaiveDate::from_ymd_opt(4501, 1, 1).unwrap();
    for due in [
        ReminderDue::Date(sentinel),
        ReminderDue::LocalDateTime(sentinel.and_hms_opt(0, 0, 0).unwrap()),
    ] {
        let mut item = raw(Token::Reminders, "task", "bound");
        item.1 = Fields::Task(
            Reminder {
                due_ms: Some(123),
                ..Default::default()
            },
            Some(due),
        );
        let (planes, _) = outlook_fixture(FakeFactory {
            folders: vec![folder(Token::Reminders, "bound")],
            items: vec![item],
            ..Default::default()
        });
        for request in [
            outlook_call(Token::Reminders, "reminders.list", json!({})),
            outlook_call(
                Token::Reminders,
                "reminders.get",
                json!({"id":id("task").encode()}),
            ),
        ] {
            let reply = body(&reserved(&planes, request).await);
            let task = reply.get("item").unwrap_or(&reply["items"][0]);
            assert_eq!(task["due_ms"], Value::Null);
        }
    }
    for (body_read, state, text) in [
        (
            Body::Text("Outlook Body text from HTML message".into()),
            "ok",
            json!("Outlook Body text from HTML message"),
        ),
        (Body::HeaderOnly, "not_downloaded", Value::Null),
        (Body::Failed, "undecodable", Value::Null),
    ] {
        let mut item = raw(Token::Mail, "mail", "bound");
        item.1 = Fields::Mail(
            MailMessage {
                body: Some("untrusted precomputed body".into()),
                body_state: BodyState::NoPlainText,
                ..Default::default()
            },
            body_read,
        );
        let (planes, _) = outlook_fixture(FakeFactory {
            folders: vec![folder(Token::Mail, "bound")],
            items: vec![item],
            ..Default::default()
        });
        let reply = body(
            &reserved(
                &planes,
                outlook_call(
                    Token::Mail,
                    "messages.get",
                    json!({"id":id("mail").encode()}),
                ),
            )
            .await,
        );
        assert_eq!(reply["item"]["body_state"], state);
        assert_eq!(reply["item"]["body"], text);
    }
}

#[tokio::test]
async fn outlook_source_missing_running_and_guard_refusals_touch_no_members() {
    let mut denied = guard();
    for (location, read) in &mut denied.registry {
        if location.hive == Hive::CurrentUser && location.key.contains("Policies") {
            let LocationRead::Read(values) = read else {
                unreachable!()
            };
            values.insert(Setting::AdminSecurityMode, GuardValue::Dword(3));
            values.insert(Setting::PromptOOMAddressBookAccess, GuardValue::Dword(0));
        }
    }
    let mut may_prompt = guard();
    may_prompt.installation = InstallationIdentity::Unknown;
    for (attach_error, input, reason) in [
        (
            Some(AttachError::Unregistered),
            guard(),
            "classic_outlook_missing",
        ),
        (
            Some(AttachError::NotRunning),
            guard(),
            "outlook_not_running",
        ),
        (None, may_prompt, "outlook_guard_may_prompt"),
        (None, denied, "permission_missing"),
    ] {
        let (planes, data) = outlook_fixture(FakeFactory {
            attach_error,
            guard: Mutex::new(input),
            ..Default::default()
        });
        let description = body(&exchange(&planes, &flow(), json!({"method":DESCRIBE})).await);
        assert_eq!(description["tokens"].as_array().unwrap().len(), 4);
        for entry in description["tokens"].as_array().unwrap() {
            assert_eq!(entry["unavailable_reason"], reason);
        }
        for &token in Platform::Windows.tokens() {
            for request in [
                outlook_call(token, list_op(token), list_args(token, 10)),
                outlook_call(token, get_op(token), json!({"id":"unknown"})),
                json!({"method":SCOPE_CHOICES,"params":{"token":token.as_str(),"key":token.info().scope_key}}),
            ] {
                assert_refusal(&reserved(&planes, request).await, reason);
            }
            let before = data.opened.load(Ordering::SeqCst);
            let setup = body(
                &reserved(
                    &planes,
                    json!({"method":SETUP,"params":{"token":token.as_str()}}),
                )
                .await,
            );
            assert_eq!(setup, json!({"state":"not_required"}));
            assert_eq!(
                data.opened.load(Ordering::SeqCst),
                before,
                "setup must not even attach"
            );
        }
        assert_eq!(data.members.load(Ordering::SeqCst), 0);
        if attach_error.is_some() {
            assert_eq!(data.opened.load(Ordering::SeqCst), 0);
        }
    }
    let source = OutlookSource::new(None);
    assert_eq!(
        source.status(Platform::Windows.tokens()).unwrap()[0]
            .1
            .unavailable_reason,
        Some("classic_outlook_missing")
    );
}

#[tokio::test]
async fn outlook_source_rechecks_guard_before_each_member() {
    let (planes, data) = outlook_fixture(FakeFactory {
        folders: vec![folder(Token::Contacts, "bound")],
        invalidate_guard_after_folders: true,
        ..Default::default()
    });
    assert_refusal(
        &reserved(
            &planes,
            outlook_call(Token::Contacts, "contacts.list", json!({})),
        )
        .await,
        "outlook_guard_may_prompt",
    );
    assert_eq!(
        data.members.load(Ordering::SeqCst),
        1,
        "enumeration must not follow a newly may-prompt guard"
    );
}

#[test]
fn outlook_source_windows_zones_are_known_iana_names() {
    use cerebellum_ability::time::SourceTimeZone;
    assert_eq!(zones::WINDOWS_ZONES.len(), 139);
    let mut seen = BTreeSet::new();
    for &(windows, iana) in zones::WINDOWS_ZONES {
        assert!(seen.insert(windows));
        assert_eq!(zones::iana_zone(windows), Some(iana));
        SourceTimeZone::from_iana_name(Some(iana)).unwrap();
    }
    assert_eq!(
        zones::iana_zone("Eastern Standard Time"),
        Some("America/New_York")
    );
    assert_eq!(zones::iana_zone("UTC"), Some("Etc/UTC"));
    assert_eq!(zones::iana_zone("unknown"), None);
}

#[tokio::test]
async fn outlook_source_unknown_zone_refuses_all_events_and_reminders_ops_even_when_empty() {
    for zone in [None, Some("Unknown Windows zone".into())] {
        for token in [Token::Calendar, Token::Reminders] {
            let (planes, _) = outlook_fixture(FakeFactory {
                folders: vec![folder(token, "bound")],
                zone: zone.clone(),
                ..Default::default()
            });
            for request in [
                outlook_call(token, list_op(token), list_args(token, 10)),
                outlook_call(token, get_op(token), json!({"id":"missing"})),
            ] {
                assert_refusal(&reserved(&planes, request).await, "ability_source_failed");
            }
        }
    }
}

#[tokio::test]
async fn outlook_source_stale_scope_oversized_item_and_source_failure_refuse() {
    for &token in Platform::Windows.tokens() {
        let (planes, data) = outlook_fixture(FakeFactory::default());
        assert_refusal(
            &reserved(
                &planes,
                outlook_call(token, list_op(token), list_args(token, 10)),
            )
            .await,
            "ability_scope_stale",
        );
        assert_eq!(
            data.members.load(Ordering::SeqCst),
            1,
            "no items read after detecting stale scope"
        );
        let (planes, _) = outlook_fixture(FakeFactory {
            folders: vec![folder(token, "bound")],
            items: vec![raw(token, &"x".repeat(1600), "bound")],
            ..Default::default()
        });
        assert_refusal(
            &reserved(
                &planes,
                outlook_call(token, list_op(token), list_args(token, 10)),
            )
            .await,
            "ability_source_failed",
        );
    }
    let (planes, _) = outlook_fixture(FakeFactory {
        attach_error: Some(AttachError::Failed),
        ..Default::default()
    });
    assert_refusal(
        &reserved(
            &planes,
            outlook_call(Token::Contacts, "contacts.list", json!({})),
        )
        .await,
        "ability_source_failed",
    );
}

fn assert_session_threads(
    data: &FakeFactory,
    expected: usize,
) -> std::collections::HashSet<ThreadId> {
    let events = data.events.lock().unwrap();
    assert_eq!(
        data.opened.load(Ordering::SeqCst),
        expected,
        "one session per request, not one per preflight/read"
    );
    let mut threads = std::collections::HashSet::new();
    for serial in 0..expected {
        let session = events
            .iter()
            .filter(|(id, _, _)| *id == serial)
            .collect::<Vec<_>>();
        assert_eq!(session.first().unwrap().1, "open");
        assert_eq!(session.last().unwrap().1, "drop");
        assert!(session.iter().any(|(_, name, _)| *name == "member"));
        let owner = session[0].2;
        assert!(session.iter().all(|(_, _, thread)| *thread == owner));
        threads.insert(owner);
    }
    threads
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outlook_source_sessions_open_use_and_drop_on_each_of_two_pool_threads() {
    // Independent AbilityPlane instances force two pool threads without
    // permitting concurrent requests in one instance's Outlook source queue.
    let (first, data) = outlook_fixture(FakeFactory {
        folders: vec![folder(Token::Contacts, "bound")],
        items: vec![raw(Token::Contacts, "contact", "bound")],
        barrier: Some(Arc::new(Barrier::new(2))),
        ..Default::default()
    });
    let second = planes_for(data.clone());
    let (a, b) = tokio::join!(
        reserved(
            &first,
            outlook_call(Token::Contacts, "contacts.list", json!({}))
        ),
        reserved(
            &second,
            outlook_call(Token::Contacts, "contacts.list", json!({}))
        )
    );
    assert_eq!(body(&a)["items"].as_array().unwrap().len(), 1);
    assert_eq!(body(&b)["items"].as_array().unwrap().len(), 1);
    assert_eq!(assert_session_threads(&data, 2).len(), 2);
}

#[tokio::test(start_paused = true)]
async fn outlook_source_late_session_drops_on_its_thread_after_deadline_reply() {
    let block = Arc::new(Block::default());
    let release = Release(block.clone());
    let (planes, data) = outlook_fixture(FakeFactory {
        folders: vec![folder(Token::Contacts, "bound")],
        items: vec![raw(Token::Contacts, "contact", "bound")],
        block: Some(block.clone()),
        ..Default::default()
    });
    let planes = Arc::new(planes);
    let work = {
        let planes = planes.clone();
        tokio::spawn(async move {
            reserved(
                &planes,
                outlook_call(Token::Contacts, "contacts.list", json!({})),
            )
            .await
        })
    };
    block.started.notified().await;
    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    assert_refusal(&work.await.unwrap(), "ability_source_timeout");
    assert!(!data
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|(_, name, _)| *name == "drop"));
    let unit = planes
        .management
        .abilities
        .units
        .for_token(Token::Contacts)
        .unwrap();
    assert!(unit.quarantined());
    assert_refusal(
        &reserved(
            &planes,
            outlook_call(Token::Contacts, "contacts.list", json!({})),
        )
        .await,
        "ability_source_timeout",
    );
    assert_eq!(data.opened.load(Ordering::SeqCst), 1);
    drop(release);
    while unit.quarantined() {
        tokio::task::yield_now().await;
    }
    assert_eq!(assert_session_threads(&data, 1).len(), 1);
}

struct OutlookBinding;
impl BindingReader for OutlookBinding {
    fn read<'a>(&'a self, _: &'a str) -> BindingRead<'a> {
        Box::pin(async {
            Ok(BindingRecord {
                install_id: "outlook-test".into(),
                version: "1".into(),
                _description: Value::Null,
                entries: Platform::Windows
                    .tokens()
                    .iter()
                    .map(|&token| BindingEntry {
                        key: token.as_str().into(),
                        token,
                        ids: [id("bound").encode()].into(),
                    })
                    .collect(),
            })
        })
    }
}

fn outlook_fixture(data: FakeFactory) -> (Planes, Arc<FakeFactory>) {
    let data = Arc::new(data);
    (planes_for(data.clone()), data)
}

fn planes_for(data: Arc<FakeFactory>) -> Planes {
    let mut planes = fixture(
        Arc::new(OutlookSource::new(Some(Arc::new(Factory(data))))),
        Platform::Windows,
    );
    Arc::get_mut(&mut planes.management)
        .unwrap()
        .abilities
        .binding = Arc::new(OutlookBinding);
    planes
}

fn outlook_call(token: Token, op: &str, args: Value) -> Value {
    json!({"method":CALL,"params":{"key":token.as_str(),"token":token.as_str(),"op":op,"args":args,"scope":{token.info().scope_key:[id("bound").encode()]}}})
}

fn list_op(token: Token) -> &'static str {
    match token {
        Token::Calendar => "events.list",
        Token::Reminders => "reminders.list",
        Token::Contacts => "contacts.list",
        Token::Mail => "messages.list",
        _ => unreachable!(),
    }
}

fn list_args(token: Token, limit: usize) -> Value {
    match token {
        Token::Calendar => json!({"from_ms":0,"to_ms":100,"limit":limit}),
        Token::Mail => json!({"mailbox":id("bound").encode(),"limit":limit}),
        _ => json!({"limit":limit}),
    }
}

fn get_op(token: Token) -> &'static str {
    match token {
        Token::Calendar => "events.get",
        Token::Reminders => "reminders.get",
        Token::Contacts => "contacts.get",
        Token::Mail => "messages.get",
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn outlook_source_filters_parent_and_class_before_paging_for_all_four_tokens() {
    for &token in Platform::Windows.tokens() {
        let mut items = (0..6)
            .map(|n| raw(token, &format!("item{n}"), "bound"))
            .collect::<Vec<_>>();
        // Sort-ahead and page-boundary outsiders must not shorten the page or
        // shape a cursor, even though the enumeration is for a bound folder.
        items.insert(0, raw(token, "aaa-outside", "outside"));
        items.insert(3, raw(token, "boundary-outside", "outside"));
        let mut other = raw(token, "000-other-class", "bound");
        other.0.class = Class::Other;
        items.insert(0, other);
        let (planes, data) = outlook_fixture(FakeFactory {
            folders: vec![folder(token, "bound"), folder(token, "outside")],
            items,
            ..Default::default()
        });
        let mut args = list_args(token, 2);
        let mut seen = BTreeSet::new();
        loop {
            let reply =
                body(&reserved(&planes, outlook_call(token, list_op(token), args.clone())).await);
            assert_eq!(reply["items"].as_array().unwrap().len(), 2, "{reply}");
            for item in reply["items"].as_array().unwrap() {
                let encoded = item["id"].as_str().unwrap();
                assert!(seen.insert(encoded.to_owned()));
                assert!((0..6).any(|n| encoded == id(&format!("item{n}")).encode()));
                let parent = match token {
                    Token::Calendar => &item["calendar"],
                    Token::Reminders => &item["list"],
                    Token::Contacts => &item["groups"][0],
                    Token::Mail => &item["mailbox"],
                    _ => unreachable!(),
                };
                assert_eq!(parent, &json!(id("bound").encode()));
            }
            let Some(cursor) = reply.get("next_cursor") else {
                break;
            };
            args["cursor"] = cursor.clone();
        }
        assert_eq!(seen.len(), 6);
        let outside = reserved(
            &planes,
            outlook_call(
                token,
                get_op(token),
                json!({"id":id("aaa-outside").encode()}),
            ),
        )
        .await;
        let unknown = reserved(
            &planes,
            outlook_call(token, get_op(token), json!({"id":id("unknown").encode()})),
        )
        .await;
        assert_refusal(&outside, "ability_item_not_found");
        assert_eq!(outside.body, unknown.body);
        assert!(data.members.load(Ordering::SeqCst) > 0);
    }
}
