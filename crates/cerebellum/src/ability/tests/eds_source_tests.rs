use super::*;
use crate::ability::{
    binding::{BindingEntry, BindingRead, BindingReader, BindingRecord},
    eds::{
        self, Bus, BusFactory, Client, EdsSource, Kind, Source as EdsContainer, ACCEPTED_BUS_NAMES,
    },
};
use cerebellum_ability::events::occurrence_id;
use std::collections::BTreeMap;

#[derive(Clone)]
struct FakeData {
    owned: Vec<String>,
    _activatable: Vec<String>,
    sources: Vec<EdsContainer>,
    objects: BTreeMap<String, Vec<(String, String)>>,
    redirected: Option<String>,
    zone: Option<String>,
    calls: Arc<Mutex<Vec<String>>>,
}

impl Default for FakeData {
    fn default() -> Self {
        Self {
            owned: ACCEPTED_BUS_NAMES.map(str::to_owned).into(),
            _activatable: ACCEPTED_BUS_NAMES.map(str::to_owned).into(),
            sources: vec![],
            objects: BTreeMap::new(),
            redirected: None,
            zone: Some("UTC".into()),
            calls: Arc::new(Mutex::new(vec![])),
        }
    }
}

impl BusFactory for FakeData {
    fn connect(&self) -> Result<Box<dyn Bus>, Refusal> {
        self.calls.lock().unwrap().push("connect".into());
        Ok(Box::new(self.clone()))
    }
}

impl Bus for FakeData {
    fn owned_names(&self) -> Result<Vec<String>, Refusal> {
        self.calls.lock().unwrap().push("owned_names".into());
        Ok(self.owned.clone())
    }
    fn system_iana_zone(&self) -> Option<String> {
        self.zone.clone()
    }
    fn sources(&mut self) -> Result<Vec<EdsContainer>, Refusal> {
        self.calls.lock().unwrap().push("sources".into());
        Ok(self.sources.clone())
    }
    fn open_client(&mut self, source: &EdsContainer) -> Result<Box<dyn Client>, Refusal> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("client:{}:{:?}", source.uid, source.kind));
        let actual = self.redirected.as_ref().unwrap_or(&source.uid).clone();
        Ok(Box::new(FakeClient {
            objects: self.objects.get(&actual).cloned().unwrap_or_default(),
            source: actual,
            calls: self.calls.clone(),
        }))
    }
}

struct FakeClient {
    source: String,
    objects: Vec<(String, String)>,
    calls: Arc<Mutex<Vec<String>>>,
}
impl Client for FakeClient {
    fn source_uid(&self) -> &str {
        &self.source
    }
    fn objects(&mut self) -> Result<Vec<String>, Refusal> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("objects:{}", self.source));
        Ok(self.objects.iter().map(|(_, text)| text.clone()).collect())
    }
    fn object(&mut self, uid: &str) -> Result<Option<String>, Refusal> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("object:{}:{uid}", self.source));
        Ok(self
            .objects
            .iter()
            .find(|(id, _)| id == uid)
            .map(|(_, text)| text.clone()))
    }
}

struct EdsBinding;
impl BindingReader for EdsBinding {
    fn read<'a>(&'a self, _: &'a str) -> BindingRead<'a> {
        Box::pin(async {
            Ok(BindingRecord {
                install_id: "eds-fixture".into(),
                version: "1".into(),
                _description: Value::Null,
                entries: Platform::Linux
                    .tokens()
                    .iter()
                    .map(|&token| BindingEntry {
                        key: token.as_str().into(),
                        token,
                        ids: ["bound".into(), "other".into()].into(),
                    })
                    .collect(),
            })
        })
    }
}

fn eds_fixture(data: FakeData) -> (Planes, Arc<Mutex<Vec<String>>>) {
    let calls = data.calls.clone();
    let mut planes = fixture(
        Arc::new(EdsSource::new(Some(Arc::new(data)))),
        Platform::Linux,
    );
    Arc::get_mut(&mut planes.management)
        .unwrap()
        .abilities
        .binding = Arc::new(EdsBinding);
    (planes, calls)
}
fn source(token: Token, uid: &str) -> EdsContainer {
    EdsContainer {
        uid: uid.into(),
        label: uid.into(),
        kind: match token {
            Token::Calendar => Kind::Calendar,
            Token::Reminders => Kind::TaskList,
            Token::Contacts => Kind::AddressBook,
            _ => unreachable!(),
        },
    }
}
fn call(token: Token, op: &str, args: Value) -> Value {
    json!({"method":CALL,"params":{"key":token.as_str(),"token":token.as_str(),"op":op,"args":args,"scope":{token.info().scope_key:["bound"]}}})
}
fn list_op(token: Token) -> &'static str {
    match token {
        Token::Calendar => "events.list",
        Token::Reminders => "reminders.list",
        Token::Contacts => "contacts.list",
        _ => unreachable!(),
    }
}
fn get_op(token: Token) -> &'static str {
    match token {
        Token::Calendar => "events.get",
        Token::Reminders => "reminders.get",
        Token::Contacts => "contacts.get",
        _ => unreachable!(),
    }
}
fn args(token: Token) -> Value {
    if token == Token::Calendar {
        json!({"from_ms":1735689600000_i64,"to_ms":1735776000000_i64})
    } else {
        json!({})
    }
}
fn calendar(properties: &str, extra: &str) -> String {
    format!("BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:series\n{properties}\nEND:VEVENT\n{extra}\nEND:VCALENDAR")
}
fn text(token: Token, uid: &str) -> String {
    match token {
        Token::Calendar => format!("BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:{uid}\nDTSTART:20250101T090000Z\nDTEND:20250101T100000Z\nEND:VEVENT\nEND:VCALENDAR"),
        Token::Reminders => format!("BEGIN:VCALENDAR\nBEGIN:VTODO\nUID:{uid}\nSUMMARY:{uid}\nDUE:20250101T090000\nEND:VTODO\nEND:VCALENDAR"),
        Token::Contacts => format!("BEGIN:VCARD\nVERSION:3.0\nUID:{uid}\nN:{uid};Given;;;\nEND:VCARD"),
        _ => unreachable!(),
    }
}
fn data(token: Token, objects: Vec<(String, String)>) -> FakeData {
    FakeData {
        sources: vec![source(token, "bound"), source(token, "outside")],
        objects: [("bound".into(), objects)].into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn eds_source_owner_only_preflight_never_activates_absent_services() {
    for activatable in [vec![], ACCEPTED_BUS_NAMES.map(str::to_owned).to_vec()] {
        let fake = FakeData {
            owned: vec![],
            _activatable: activatable,
            ..Default::default()
        };
        // An activatable name is deliberately not exposed through the Bus trait.
        let (planes, calls) = eds_fixture(fake);
        let reply = body(&reserved(&planes, json!({"method":DESCRIBE})).await);
        for token in reply["tokens"].as_array().unwrap() {
            assert_eq!(token["unavailable_reason"], "data_service_missing");
        }
        for &token in Platform::Linux.tokens() {
            assert_refusal(
                &reserved(&planes, call(token, list_op(token), args(token))).await,
                "data_service_missing",
            );
        }
        assert!(calls
            .lock()
            .unwrap()
            .iter()
            .all(|c| c == "connect" || c == "owned_names"));
    }
    let absent = EdsSource::new(None);
    for (_, status) in StatusSource::status(&absent, Platform::Linux.tokens()).unwrap() {
        assert_eq!(status.unavailable_reason, Some("data_service_missing"));
    }
}

#[tokio::test]
async fn eds_source_availability_and_interface_versions_are_per_token() {
    for missing in 0..3 {
        let mut fake = FakeData::default();
        fake.owned.remove(missing);
        let (planes, _) = eds_fixture(fake);
        let reply = body(&reserved(&planes, json!({"method":DESCRIBE})).await);
        for (i, token) in Platform::Linux.tokens().iter().enumerate() {
            let unavailable = missing == 0
                || (missing == 1 && *token != Token::Contacts)
                || (missing == 2 && *token == Token::Contacts);
            assert_eq!(reply["tokens"][i]["available"], !unavailable);
            if unavailable {
                assert_eq!(
                    reply["tokens"][i]["unavailable_reason"],
                    "data_service_missing"
                );
            }
        }
    }
    for (changed, accepted) in ACCEPTED_BUS_NAMES.iter().enumerate() {
        let mut fake = FakeData::default();
        fake.owned[changed] = format!("{accepted}999");
        let (planes, calls) = eds_fixture(fake);
        for &token in Platform::Linux.tokens() {
            if changed == 0
                || (changed == 1 && token != Token::Contacts)
                || (changed == 2 && token == Token::Contacts)
            {
                assert_refusal(
                    &reserved(&planes, call(token, list_op(token), args(token))).await,
                    "format_unrecognized",
                );
            }
        }
        assert!(!calls.lock().unwrap().iter().any(|c| c == "sources"));
    }
    let mut fake = data(
        Token::Calendar,
        vec![("event".into(), text(Token::Calendar, "event"))],
    );
    fake.sources.push(source(Token::Reminders, "bound"));
    fake.owned.pop();
    let (planes, _) = eds_fixture(fake);
    for token in [Token::Calendar, Token::Reminders] {
        let reply = reserved(&planes, call(token, list_op(token), args(token))).await;
        assert!(body(&reply)["items"].is_array());
    }
    assert_refusal(
        &reserved(&planes, call(Token::Contacts, "contacts.list", json!({}))).await,
        "data_service_missing",
    );
}

#[tokio::test]
async fn eds_source_filters_actual_source_before_paging_and_get_for_three_tokens() {
    for &token in Platform::Linux.tokens() {
        let objects = (0..6)
            .map(|n| {
                let id = format!("item{n}");
                (id.clone(), text(token, &id))
            })
            .collect();
        let mut fake = data(token, objects);
        fake.objects.insert(
            "outside".into(),
            vec![("000-outside".into(), "malformed outside data".into())],
        );
        let (planes, calls) = eds_fixture(fake);
        let mut list_args = args(token);
        list_args["limit"] = json!(2);
        let mut seen = BTreeSet::new();
        loop {
            let reply =
                body(&reserved(&planes, call(token, list_op(token), list_args.clone())).await);
            assert_eq!(reply["items"].as_array().unwrap().len(), 2);
            for item in reply["items"].as_array().unwrap() {
                let id = item["id"].as_str().unwrap();
                assert!(seen.insert(id.to_owned()));
                let parent = if token == Token::Contacts {
                    &item["groups"][0]
                } else {
                    &item[token.info().scope_key]
                };
                assert_eq!(parent, "bound");
                assert_eq!(
                    body(&reserved(&planes, call(token, get_op(token), json!({"id":id}))).await)
                        ["item"],
                    *item
                );
            }
            let Some(cursor) = reply.get("next_cursor") else {
                break;
            };
            list_args["cursor"] = cursor.clone();
        }
        assert_eq!(seen.len(), 6);
        let unknown = reserved(
            &planes,
            call(
                token,
                get_op(token),
                json!({"id":eds::encode_id("bound", "unknown").unwrap()}),
            ),
        )
        .await;
        let outside = reserved(
            &planes,
            call(
                token,
                get_op(token),
                json!({"id":eds::encode_id("outside", "000-outside").unwrap()}),
            ),
        )
        .await;
        assert_refusal(&unknown, "ability_item_not_found");
        assert_eq!(unknown.body, outside.body);
        assert!(!calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.starts_with("client:outside")));
        let mut fake = data(token, vec![]);
        fake.redirected = Some("outside".into());
        fake.objects
            .insert("outside".into(), vec![("bad".into(), "malformed".into())]);
        let (planes, calls) = eds_fixture(fake);
        assert_eq!(
            body(&reserved(&planes, call(token, list_op(token), args(token))).await)["items"],
            json!([])
        );
        assert!(!calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.starts_with("objects:")));
    }
}

#[tokio::test]
async fn eds_source_unsupported_shared_corpus_reaches_handler_row_13() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/eds/unsupported-events.json"
    ))
    .unwrap();
    for case in corpus.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let object = calendar(
            case["properties"].as_str().unwrap(),
            case["extra"].as_str().unwrap_or(""),
        );
        let (planes, _) = eds_fixture(data(Token::Calendar, vec![("series".into(), object)]));
        let mut window = args(Token::Calendar);
        if case["later_window"] == true {
            window = json!({"from_ms":1736467200000_i64,"to_ms":1736553600000_i64});
        }
        let reply = reserved(&planes, call(Token::Calendar, "events.list", window)).await;
        if case["outside"] == true {
            assert_eq!(body(&reply)["items"], json!([]), "{name}");
        } else {
            assert_refusal(&reply, "ability_recurrence_unsupported");
        }
        let get = reserved(
            &planes,
            call(
                Token::Calendar,
                "events.get",
                json!({"id":eds::encode_id("bound", "series").unwrap()}),
            ),
        )
        .await;
        assert_refusal(&get, "ability_recurrence_unsupported");
    }
}

#[tokio::test]
async fn eds_source_calendar_object_keeps_master_and_moved_overrides_together() {
    let object = calendar("DTSTART:20250101T090000Z\nDTEND:20250101T100000Z\nRRULE:FREQ=DAILY;COUNT=4\nEXDATE:20250104T090000Z\nRDATE:20250106T090000Z",
        "BEGIN:VEVENT\nUID:series\nRECURRENCE-ID:20250102T090000Z\nDTSTART:20250103T090000Z\nDTEND:20250103T100000Z\nSUMMARY:Moved\nEND:VEVENT");
    let (planes, calls) = eds_fixture(data(Token::Calendar, vec![("series".into(), object)]));
    let mut window = json!({"from_ms":1735689600000_i64,"to_ms":1736208000000_i64,"limit":1});
    let mut events = vec![];
    loop {
        let reply = body(
            &reserved(
                &planes,
                call(Token::Calendar, "events.list", window.clone()),
            )
            .await,
        );
        let item = reply["items"][0].clone();
        assert_eq!(
            body(
                &reserved(
                    &planes,
                    call(Token::Calendar, "events.get", json!({"id":item["id"]}))
                )
                .await
            )["item"],
            item
        );
        events.push(item);
        let Some(cursor) = reply.get("next_cursor") else {
            break;
        };
        window["cursor"] = cursor.clone();
    }
    assert_eq!(events.len(), 4);
    assert_eq!(events[1]["start_ms"], events[2]["start_ms"]);
    assert_ne!(events[1]["id"], events[2]["id"]);
    let excluded = occurrence_id("series", 1735981200000_i64).unwrap();
    assert_refusal(
        &reserved(
            &planes,
            call(
                Token::Calendar,
                "events.get",
                json!({"id":eds::encode_id("bound", &excluded).unwrap()}),
            ),
        )
        .await,
        "ability_item_not_found",
    );
    assert!(calls
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c.starts_with("object:"))
        .all(|c| c == "object:bound:series"));
}

#[tokio::test]
async fn eds_source_malformed_card_refuses_list_but_not_good_sibling_get_or_other_book() {
    let mut fake = data(
        Token::Contacts,
        vec![
            ("good".into(), text(Token::Contacts, "good")),
            (
                "bad".into(),
                "BEGIN:VCARD\nVERSION:3.0\nUID:bad\nN:invalid\nEND:VCARD".into(),
            ),
            ("good2".into(), text(Token::Contacts, "good2")),
        ],
    );
    fake.sources.push(source(Token::Contacts, "other"));
    fake.objects.insert(
        "other".into(),
        vec![("fine".into(), text(Token::Contacts, "fine"))],
    );
    let (planes, calls) = eds_fixture(fake);
    assert_refusal(
        &reserved(&planes, call(Token::Contacts, "contacts.list", json!({}))).await,
        "ability_source_failed",
    );
    for id in ["good", "good2"] {
        assert_eq!(
            body(
                &reserved(
                    &planes,
                    call(
                        Token::Contacts,
                        "contacts.get",
                        json!({"id":eds::encode_id("bound", id).unwrap()})
                    )
                )
                .await
            )["item"]["family_name"],
            id
        );
    }
    assert_refusal(
        &reserved(
            &planes,
            call(
                Token::Contacts,
                "contacts.get",
                json!({"id":eds::encode_id("bound", "bad").unwrap()}),
            ),
        )
        .await,
        "ability_source_failed",
    );
    let mut request = call(Token::Contacts, "contacts.list", json!({}));
    request["params"]["scope"]["group"] = json!(["other"]);
    assert_eq!(
        body(&reserved(&planes, request).await)["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(calls
        .lock()
        .unwrap()
        .iter()
        .any(|c| c == "object:bound:good"));
}

#[tokio::test]
async fn eds_source_kinds_contacts_accounts_and_id_bounds() {
    for &token in Platform::Linux.tokens() {
        let mut fake = data(token, vec![("item".into(), text(token, "item"))]);
        // An unrelated source kind must not be opened for this token.
        let wrong = if token == Token::Calendar {
            Token::Reminders
        } else {
            Token::Calendar
        };
        fake.sources.push(source(wrong, "wrong-kind"));
        fake.objects.insert(
            "wrong-kind".into(),
            vec![("bad".into(), "malformed".into())],
        );
        fake.sources.push(source(token, &"x".repeat(2049)));
        let (planes, calls) = eds_fixture(fake);
        let choices = body(&reserved(&planes, json!({"method":SCOPE_CHOICES,"params":{"token":token.as_str(),"key":token.info().scope_key}})).await);
        assert_eq!(choices["choices"].as_array().unwrap().len(), 2);
        if token == Token::Contacts {
            assert!(choices["choices"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["kind"] == "account"));
            let groups = body(&reserved(&planes, call(token, "groups.list", json!({}))).await);
            assert_eq!(groups["items"][0]["kind"], "account");
        }
        assert_eq!(
            body(&reserved(&planes, call(token, list_op(token), args(token))).await)["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(!calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.contains("wrong-kind")));
        let mut stale = call(token, list_op(token), args(token));
        stale["params"]["scope"][token.info().scope_key] = json!(["other"]);
        assert_refusal(&reserved(&planes, stale).await, "ability_scope_stale");
        let huge = "h".repeat(1600);
        let (planes, _) = eds_fixture(data(token, vec![(huge.clone(), text(token, &huge))]));
        assert_refusal(
            &reserved(&planes, call(token, list_op(token), args(token))).await,
            "ability_source_failed",
        );
    }
    let id = eds::encode_id("source.with:delimiters", "uid.é").unwrap();
    assert_ne!(
        id,
        eds::encode_id("source", "with:delimiters.uid.é").unwrap()
    );
}

#[tokio::test]
async fn eds_source_supplies_iana_zone_and_refuses_every_event_task_read_without_it() {
    for zone in [None, Some("Unknown/Zone".to_owned())] {
        for token in [Token::Calendar, Token::Reminders] {
            let mut fake = data(token, vec![("item".into(), text(token, "item"))]);
            fake.zone = zone.clone();
            let (planes, _) = eds_fixture(fake);
            assert_refusal(
                &reserved(&planes, call(token, list_op(token), args(token))).await,
                "ability_source_failed",
            );
            assert_refusal(
                &reserved(
                    &planes,
                    call(
                        token,
                        get_op(token),
                        json!({"id":eds::encode_id("bound", "item").unwrap()}),
                    ),
                )
                .await,
                "ability_source_failed",
            );
        }
    }
    for (due, expected) in [
        (";VALUE=DATE:20251102", 1762056000000_i64),
        (":20251102T013000", 1762061400000_i64),
        (":20250309T023000", 1741503600000_i64),
    ] {
        let object =
            format!("BEGIN:VCALENDAR\nBEGIN:VTODO\nUID:task\nDUE{due}\nEND:VTODO\nEND:VCALENDAR");
        let mut fake = data(Token::Reminders, vec![("task".into(), object)]);
        fake.zone = Some("America/New_York".into());
        let (planes, _) = eds_fixture(fake);
        let item =
            body(&reserved(&planes, call(Token::Reminders, "reminders.list", json!({}))).await)
                ["items"][0]
                .clone();
        assert_eq!(item["due_ms"], expected);
        assert_eq!(
            body(
                &reserved(
                    &planes,
                    call(Token::Reminders, "reminders.get", json!({"id":item["id"]}))
                )
                .await
            )["item"],
            item
        );
    }
}

#[tokio::test]
async fn eds_source_one_client_per_bound_source_preserves_duplicate_local_uids() {
    for &token in Platform::Linux.tokens() {
        let mut fake = data(token, vec![("same".into(), text(token, "same"))]);
        fake.sources.push(source(token, "other"));
        fake.objects
            .insert("other".into(), vec![("same".into(), text(token, "same"))]);
        let (planes, calls) = eds_fixture(fake);
        let mut request = call(token, list_op(token), args(token));
        request["params"]["scope"][token.info().scope_key] = json!(["bound", "other"]);
        let reply = body(&reserved(&planes, request).await);
        let items = reply["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_ne!(items[0]["id"], items[1]["id"]);
        let parents: BTreeSet<_> = items
            .iter()
            .map(|item| {
                if token == Token::Contacts {
                    item["groups"][0].as_str().unwrap()
                } else {
                    item[token.info().scope_key].as_str().unwrap()
                }
            })
            .collect();
        assert_eq!(parents, ["bound", "other"].into());
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.starts_with("client:bound:"))
                .count(),
            1
        );
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.starts_with("client:other:"))
                .count(),
            1
        );
        assert!(!calls.iter().any(|c| c.starts_with("client:outside:")));
    }
}

#[tokio::test]
async fn eds_source_calendar_get_parses_only_its_uid_and_redirected_get_does_not_parse() {
    let fake = data(
        Token::Calendar,
        vec![
            ("good".into(), text(Token::Calendar, "good")),
            (
                "bad".into(),
                "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:bad\ninvalid\nEND:VEVENT\nEND:VCALENDAR".into(),
            ),
        ],
    );
    let (planes, _) = eds_fixture(fake);
    assert_refusal(
        &reserved(
            &planes,
            call(Token::Calendar, "events.list", args(Token::Calendar)),
        )
        .await,
        "ability_source_failed",
    );
    assert_eq!(
        body(
            &reserved(
                &planes,
                call(
                    Token::Calendar,
                    "events.get",
                    json!({"id":eds::encode_id("bound", "good").unwrap()})
                )
            )
            .await
        )["item"]["calendar"],
        "bound"
    );
    for &token in Platform::Linux.tokens() {
        let mut fake = data(token, vec![]);
        fake.redirected = Some("outside".into());
        fake.objects
            .insert("outside".into(), vec![("bad".into(), "malformed".into())]);
        let (planes, calls) = eds_fixture(fake);
        assert_refusal(
            &reserved(
                &planes,
                call(
                    token,
                    get_op(token),
                    json!({"id":eds::encode_id("bound", "bad").unwrap()}),
                ),
            )
            .await,
            "ability_item_not_found",
        );
        assert!(!calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.starts_with("object:")));
    }
}

#[tokio::test]
async fn eds_source_oversized_recurring_id_refuses_source_failed_not_recurrence() {
    let uid = "u".repeat(1600);
    let object = format!("BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:{uid}\nDTSTART:20250101T090000Z\nRRULE:FREQ=DAILY;COUNT=1\nEND:VEVENT\nEND:VCALENDAR");
    let (planes, _) = eds_fixture(data(Token::Calendar, vec![(uid, object)]));
    assert_refusal(
        &reserved(
            &planes,
            call(Token::Calendar, "events.list", args(Token::Calendar)),
        )
        .await,
        "ability_source_failed",
    );
}
