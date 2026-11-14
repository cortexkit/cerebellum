use super::*;
use crate::ability::{
    binding::{BindingEntry, BindingRead, BindingRecord},
    serving::{ScopeChoice, SourceRead, SourceRecord},
};
use cerebellum_ability::{filter::TaggedItem, items::*, time::ReminderDue, Item};
use std::collections::{BTreeMap, BTreeSet};

#[path = "helper_tests.rs"]
mod helper_tests;
#[path = "journal_tests.rs"]
mod journal_tests;
#[path = "outlook_guard_tests.rs"]
mod outlook_guard_tests;

struct Bound;
impl BindingReader for Bound {
    fn read<'a>(&'a self, _: &'a str) -> BindingRead<'a> {
        Box::pin(async {
            Ok(BindingRecord {
                install_id: "install".into(),
                version: "1".into(),
                _description: Value::Null,
                entries: Platform::MacOs
                    .tokens()
                    .iter()
                    .flat_map(|&token| {
                        ["first", "second"].map(move |key| BindingEntry {
                            key: format!("{}-{key}", token.as_str()),
                            token,
                            ids: ["bound", "also-bound", "other"].map(str::to_owned).into(),
                        })
                    })
                    .collect(),
            })
        })
    }
}

struct Data {
    items: Vec<Item>,
    choices: Vec<ScopeChoice>,
    containers: BTreeSet<String>,
    zone: Option<String>,
    due: BTreeMap<String, ReminderDue>,
    unavailable: Option<&'static str>,
    calls: AtomicUsize,
    block: Option<Arc<Block>>,
}

impl Default for Data {
    fn default() -> Self {
        Self {
            items: vec![],
            choices: vec![],
            containers: ["bound", "also-bound", "outside"].map(str::to_owned).into(),
            zone: Some("UTC".into()),
            due: BTreeMap::new(),
            unavailable: None,
            calls: AtomicUsize::new(0),
            block: None,
        }
    }
}

impl StatusSource for Data {
    fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(tokens
            .iter()
            .map(|&token| {
                (
                    token,
                    Availability {
                        unavailable_reason: self.unavailable,
                    },
                )
            })
            .collect())
    }

    fn choices(&self, _: Token) -> Result<Vec<ScopeChoice>, Refusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.choices.clone())
    }

    fn read(
        &self,
        _: Token,
        _: &str,
        _: &ValidatedArgs,
        _: &BoundScope,
    ) -> Result<SourceRead, Refusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(block) = &self.block {
            block.started.notify_one();
            let mut done = block.done.lock().unwrap();
            while !*done {
                done = block.wake.wait(done).unwrap();
            }
        }
        Ok(SourceRead {
            containers: self.containers.clone(),
            time_zone: self.zone.clone(),
            records: self
                .items
                .iter()
                .cloned()
                .map(|item| SourceRecord {
                    reminder_due: self.due.get(item.id()).copied(),
                    tagged: TaggedItem::from_item(item),
                })
                .collect(),
        })
    }
}

fn setup(data: Data, platform: Platform) -> (Planes, Arc<Data>) {
    let source = Arc::new(data);
    let mut planes = fixture(source.clone(), platform);
    Arc::get_mut(&mut planes.management)
        .unwrap()
        .abilities
        .binding = Arc::new(Bound);
    (planes, source)
}

fn call(token: Token, op: &str, args: Value) -> Value {
    json!({"method":CALL,"params":{"key":format!("{}-first", token.as_str()),"token":token.as_str(),"op":op,"args":args,
        "scope":{token.info().scope_key:["bound"]}}})
}

async fn reserved(planes: &Planes, request_body: Value) -> Frame {
    let frame = request(request_body.clone());
    let gate = Arc::new(TerminalArbiter::new(frame.clone()));
    let method = request_body["method"].as_str().unwrap();
    let route = if method == CALL {
        flow()
    } else {
        facts("prefrontal-core")
    };
    let result = dispatch(
        &planes.management.abilities,
        &planes.browser,
        &route,
        method,
        request_body.as_object().unwrap(),
        gate.clone(),
    )
    .await;
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    respond(&frame, &tx, &gate, result).await.unwrap();
    rx.recv().await.unwrap()
}

fn item(token: Token, id: &str, container: &str) -> Item {
    match token {
        Token::Calendar => Item::Event(Event {
            id: id.into(),
            calendar: container.into(),
            start_ms: Some(10),
            end_ms: Some(20),
            ..Default::default()
        }),
        Token::Reminders => Item::Reminder(Reminder {
            id: id.into(),
            list: container.into(),
            ..Default::default()
        }),
        Token::Contacts => Item::Contact(Contact {
            id: id.into(),
            groups: vec![container.into()],
            ..Default::default()
        }),
        Token::Messages => Item::Message(Message {
            id: id.into(),
            conversation: container.into(),
            sent_ms: Some(10),
            ..Default::default()
        }),
        Token::Mail => Item::MailSummary(MailSummary {
            id: id.into(),
            mailbox: container.into(),
            date_ms: Some(10),
            ..Default::default()
        }),
    }
}

fn list(token: Token, limit: usize) -> Value {
    match token {
        Token::Calendar => call(
            token,
            "events.list",
            json!({"from_ms":0,"to_ms":30,"limit":limit}),
        ),
        Token::Reminders => call(token, "reminders.list", json!({"limit":limit})),
        Token::Contacts => call(token, "contacts.list", json!({"limit":limit})),
        Token::Messages => call(
            token,
            "messages.list",
            json!({"conversation":"bound","limit":limit}),
        ),
        Token::Mail => call(
            token,
            "messages.list",
            json!({"mailbox":"bound","limit":limit}),
        ),
    }
}

#[tokio::test]
async fn all_tokens_filter_before_ordering_and_page_cut_using_reported_containers() {
    for &token in Platform::MacOs.tokens() {
        let mut items = vec![
            item(token, "000-outside", "outside"),
            item(token, "003-outside", "outside"),
        ];
        items.extend(["001", "002", "004", "005", "006"].map(|id| item(token, id, "bound")));
        let (planes, _) = setup(
            Data {
                items,
                ..Default::default()
            },
            Platform::MacOs,
        );
        let mut request = list(token, 2);
        let mut seen = Vec::new();
        loop {
            let reply = body(&reserved(&planes, request.clone()).await);
            let items = reply["items"].as_array().unwrap();
            seen.extend(items.iter().map(|v| v["id"].as_str().unwrap().to_owned()));
            if let Some(cursor) = reply.get("next_cursor") {
                assert_eq!(items.len(), 2);
                let args = validate_args(
                    token,
                    request["params"]["op"].as_str().unwrap(),
                    &request["params"]["args"],
                )
                .unwrap();
                let scope = validate_scope(token, &request["params"]["scope"]).unwrap();
                let last = Item::from_json(
                    token
                        .operation(request["params"]["op"].as_str().unwrap())
                        .unwrap()
                        .item_kind,
                    items.last().unwrap().clone(),
                )
                .unwrap();
                assert_eq!(
                    cursor,
                    &json!(CursorContext::for_call(
                        token,
                        request["params"]["op"].as_str().unwrap(),
                        &args,
                        &scope
                    )
                    .unwrap()
                    .mint(&last)
                    .unwrap())
                );
                request["params"]["args"]["cursor"] = cursor.clone();
            } else {
                break;
            }
        }
        assert_eq!(seen, ["001", "002", "004", "005", "006"]);
    }
}

#[tokio::test]
async fn every_get_hides_scope_misses_and_rejects_oversized_source_ids() {
    for &token in Platform::MacOs.tokens() {
        for op in token.info().ops.iter().filter(|op| !op.is_list) {
            let mut outside = item(token, "outside-item", "outside");
            if token == Token::Mail {
                outside = Item::MailMessage(MailMessage {
                    id: "outside-item".into(),
                    mailbox: "outside".into(),
                    ..Default::default()
                });
            }
            let (planes, _) = setup(
                Data {
                    items: vec![outside],
                    ..Default::default()
                },
                Platform::MacOs,
            );
            let miss = reserved(&planes, call(token, op.name, json!({"id":"unknown"}))).await;
            let hidden =
                reserved(&planes, call(token, op.name, json!({"id":"outside-item"}))).await;
            assert_refusal(&miss, "ability_item_not_found");
            assert_eq!(miss.body, hidden.body);
        }
        let (planes, _) = setup(
            Data {
                items: vec![item(token, &"x".repeat(2049), "bound")],
                ..Default::default()
            },
            Platform::MacOs,
        );
        assert_refusal(
            &reserved(&planes, list(token, 100)).await,
            "ability_source_failed",
        );
    }
}

#[tokio::test]
async fn choices_are_sorted_paged_capped_and_only_groups_have_kind() {
    for &token in Platform::MacOs.tokens() {
        let kind = (token == Token::Contacts).then_some(GroupKind::Account);
        let choices = ["z".into(), "é".into(), "a".into(), "x".repeat(2049)]
            .map(|id| ScopeChoice {
                id,
                label: "é".repeat(600),
                kind,
            })
            .into();
        let (planes, _) = setup(
            Data {
                choices,
                ..Default::default()
            },
            Platform::MacOs,
        );
        let mut request = json!({"method":SCOPE_CHOICES,"params":{"token":token.as_str(),"key":token.info().scope_key,"limit":2}});
        let first = body(&reserved(&planes, request.clone()).await);
        assert_eq!(
            first["choices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["a", "z"]
        );
        for choice in first["choices"].as_array().unwrap() {
            assert_eq!(choice["label"].as_str().unwrap().len(), 1024);
            assert_eq!(choice.get("kind").is_some(), token == Token::Contacts);
        }
        request["params"]["cursor"] = first["next_cursor"].clone();
        let last = body(&reserved(&planes, request).await);
        assert_eq!(last["choices"].as_array().unwrap().len(), 1);
        assert_eq!(last["choices"][0]["id"], "é");
        assert!(last.get("next_cursor").is_none());
    }
}

#[tokio::test]
async fn four_hundred_fifty_items_allow_changing_limits_defaults_keys_and_scope_order() {
    let items = (0..450)
        .map(|n| item(Token::Reminders, &format!("{n:03}"), "bound"))
        .collect();
    let (planes, source) = setup(
        Data {
            items,
            ..Default::default()
        },
        Platform::MacOs,
    );
    let mut request = list(Token::Reminders, 73);
    request["params"]["scope"] = json!({"list":["bound", "also-bound"]});
    let first = body(&reserved(&planes, request.clone()).await);
    let cursor = first["next_cursor"].clone();
    let calls_before = source.calls.load(Ordering::SeqCst);
    for (field, value) in [
        ("args", json!({"include_completed":true,"cursor":cursor})),
        ("scope", json!({"list":["bound"]})),
    ] {
        let mut invalid = request.clone();
        invalid["params"]["args"]["cursor"] = cursor.clone();
        invalid["params"][field] = value;
        assert_refusal(&reserved(&planes, invalid).await, "ability_args_invalid");
    }
    assert_eq!(source.calls.load(Ordering::SeqCst), calls_before);
    request["params"]["scope"] = json!({"list":["also-bound", "bound"]});
    request["params"]["key"] = json!(format!("{}-second", Token::Reminders.as_str()));
    request["params"]["args"]["include_completed"] = json!(false);
    let mut seen: Vec<String> = first["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap().into())
        .collect();
    let mut next = Some(cursor);
    let mut page_number = 0;
    while let Some(cursor) = next {
        let limit = [1, 137, 200, 19][page_number % 4];
        request["params"]["args"]["limit"] = json!(limit);
        request["params"]["args"]["cursor"] = cursor;
        let page = body(&reserved(&planes, request.clone()).await);
        let items = page["items"].as_array().unwrap();
        next = page.get("next_cursor").cloned();
        if next.is_some() {
            assert_eq!(items.len(), limit);
        }
        seen.extend(items.iter().map(|v| v["id"].as_str().unwrap().to_owned()));
        page_number += 1;
    }
    assert_eq!(
        seen,
        (0..450).map(|n| format!("{n:03}")).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn reply_byte_cut_keeps_whole_items_and_normalized_truncation_flags() {
    let items = (0..100)
        .map(|n| {
            Item::Contact(Contact {
                id: format!("{n:03}"),
                groups: vec!["bound".into()],
                given_name: Some("x".repeat(17_000)),
                family_name: Some("y".repeat(17_000)),
                organization: Some("z".repeat(17_000)),
                ..Default::default()
            })
        })
        .collect();
    let (planes, _) = setup(
        Data {
            items,
            ..Default::default()
        },
        Platform::MacOs,
    );
    let mut request = list(Token::Contacts, 100);
    let first = body(&reserved(&planes, request.clone()).await);
    let items = first["items"].as_array().unwrap();
    assert!(!items.is_empty() && items.len() < 100);
    assert!(serde_json::to_vec(items).unwrap().len() <= cerebellum_ability::page::MAX_PAGE_BYTES);
    for item in items {
        assert_eq!(item["given_name"].as_str().unwrap().len(), 16 * 1024);
        assert_eq!(
            item["truncated"],
            json!(["given_name", "family_name", "organization"])
        );
    }
    request["params"]["args"]["cursor"] = first["next_cursor"].clone();
    let second = body(&reserved(&planes, request).await);
    assert_eq!(second["items"][0]["id"], format!("{:03}", items.len()));
}

#[tokio::test]
async fn production_dispatch_serves_with_a_real_journal_reservation() {
    let (planes, source) = setup(
        Data {
            items: vec![item(Token::Calendar, "one", "bound")],
            ..Default::default()
        },
        Platform::MacOs,
    );
    assert_eq!(
        body(&exchange(&planes, &flow(), list(Token::Calendar, 100)).await)["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(body(&exchange(&planes, &facts("prefrontal-core"), json!({"method":SCOPE_CHOICES,"params":{"token":Token::Calendar.as_str(),"key":"calendar"}})).await)["choices"], json!([]));
    assert_eq!(source.calls.load(Ordering::SeqCst), 4);
    assert_eq!(
        planes
            .browser
            .journal_export_for_test()
            .await
            .lines()
            .count(),
        2
    );
}

#[tokio::test]
async fn non_mac_setup_neither_uses_source_nor_takes_a_busy_unit() {
    for platform in [Platform::Windows, Platform::Linux] {
        for unavailable in [
            None,
            Some("permission_missing"),
            Some("source_unresponsive"),
        ] {
            let (planes, source) = setup(
                Data {
                    unavailable,
                    ..Default::default()
                },
                platform,
            );
            let unit = planes
                .management
                .abilities
                .units
                .for_token(Token::Calendar)
                .unwrap();
            let holder = unit
                .arrive(Arc::new(TerminalArbiter::new(request(
                    json!({"method":SETUP}),
                ))))
                .unwrap()
                .wait()
                .await
                .unwrap();
            for &token in platform.tokens() {
                let frame = exchange(
                    &planes,
                    &facts("prefrontal-core"),
                    json!({"method":SETUP,"params":{"token":token.as_str()}}),
                )
                .await;
                assert_eq!(body(&frame), json!({"state":"not_required"}));
                assert!(unit.has_users_for_test(1));
            }
            assert_eq!(source.calls.load(Ordering::SeqCst), 0);
            drop(holder);
        }
    }
}

#[tokio::test]
async fn event_and_reminder_lists_and_gets_never_substitute_utc_for_a_missing_zone() {
    for zone in [None, Some("not/an/IANA-zone")] {
        for (token, list_op, get_op) in [
            (Token::Calendar, "events.list", "events.get"),
            (Token::Reminders, "reminders.list", "reminders.get"),
        ] {
            for items in [vec![], vec![item(token, "one", "bound")]] {
                let (planes, _) = setup(
                    Data {
                        zone: zone.map(str::to_owned),
                        items,
                        ..Default::default()
                    },
                    Platform::MacOs,
                );
                for request in [
                    call(
                        token,
                        list_op,
                        if token == Token::Calendar {
                            json!({"from_ms":0,"to_ms":30})
                        } else {
                            json!({})
                        },
                    ),
                    call(token, get_op, json!({"id":"one"})),
                ] {
                    assert_refusal(&reserved(&planes, request).await, "ability_source_failed");
                }
            }
        }
    }
}

#[tokio::test]
async fn reminders_convert_date_and_floating_due_times_in_the_pinned_zone_for_list_and_get() {
    let cases = [
        (
            "date",
            ReminderDue::Date("2025-11-02".parse().unwrap()),
            1_762_056_000_000_i64,
        ),
        (
            "fold",
            ReminderDue::LocalDateTime("2025-11-02T01:30:00".parse().unwrap()),
            1_762_061_400_000,
        ),
        (
            "gap",
            ReminderDue::LocalDateTime("2025-03-09T02:30:00".parse().unwrap()),
            1_741_503_600_000,
        ),
    ];
    let data = Data {
        zone: Some("America/New_York".into()),
        items: cases
            .iter()
            .map(|(id, _, _)| item(Token::Reminders, id, "bound"))
            .collect(),
        due: cases
            .iter()
            .map(|(id, due, _)| ((*id).into(), *due))
            .collect(),
        ..Default::default()
    };
    let (planes, _) = setup(data, Platform::MacOs);
    let page = body(&reserved(&planes, list(Token::Reminders, 100)).await);
    for (id, _, expected) in cases {
        let listed = page["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == id)
            .unwrap();
        assert_eq!(listed["due_ms"], expected);
        let got = body(
            &reserved(
                &planes,
                call(Token::Reminders, "reminders.get", json!({"id":id})),
            )
            .await,
        );
        assert_eq!(&got["item"], listed);
    }
}

#[tokio::test]
async fn contacts_match_original_values_and_expose_only_bound_groups() {
    let items = vec![
        Item::Contact(Contact {
            id: "both".into(),
            groups: vec!["outside".into(), "bound".into()],
            organization: Some("ÉCOLE".into()),
            ..Default::default()
        }),
        Item::Contact(Contact {
            id: "email".into(),
            groups: vec!["bound".into()],
            emails: vec![LabeledValue {
                label: None,
                value: "family@example.test".into(),
            }],
            ..Default::default()
        }),
        Item::Contact(Contact {
            id: "word".into(),
            groups: vec!["bound".into()],
            given_name: Some("Somewhere".into()),
            ..Default::default()
        }),
        Item::Contact(Contact {
            id: "unbound".into(),
            groups: vec!["outside".into()],
            given_name: Some("Somewhere".into()),
            ..Default::default()
        }),
    ];
    let (planes, _) = setup(
        Data {
            items,
            ..Default::default()
        },
        Platform::MacOs,
    );
    for (query, expected) in [("éco", "both"), ("EXAMPLE", "email"), ("mewh", "word")] {
        let reply = body(
            &reserved(
                &planes,
                call(
                    Token::Contacts,
                    "contacts.list",
                    json!({"query":query,"limit":1}),
                ),
            )
            .await,
        );
        assert_eq!(reply["items"].as_array().unwrap().len(), 1);
        assert_eq!(reply["items"][0]["id"], expected);
        assert_eq!(reply["items"][0]["groups"], json!(["bound"]));
        assert!(reply.get("next_cursor").is_none());
    }
    assert_refusal(
        &reserved(
            &planes,
            call(Token::Contacts, "contacts.list", json!({"query":""})),
        )
        .await,
        "ability_args_invalid",
    );
}

#[tokio::test]
async fn messages_since_filters_before_paging_and_unbound_container_never_reads_source() {
    for token in [Token::Messages, Token::Mail] {
        let mut null_date = item(token, "null", "bound");
        match &mut null_date {
            Item::Message(v) => v.sent_ms = None,
            Item::MailSummary(v) => v.date_ms = None,
            _ => unreachable!(),
        }
        let mut earlier = item(token, "earlier", "bound");
        match &mut earlier {
            Item::Message(v) => v.sent_ms = Some(9),
            Item::MailSummary(v) => v.date_ms = Some(9),
            _ => unreachable!(),
        }
        let (planes, source) = setup(
            Data {
                items: vec![
                    null_date,
                    earlier,
                    item(token, "edge", "bound"),
                    item(token, "outside", "outside"),
                ],
                ..Default::default()
            },
            Platform::MacOs,
        );
        let mut request = list(token, 1);
        request["params"]["args"]["since_ms"] = json!(10);
        let page = body(&reserved(&planes, request.clone()).await);
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
        assert_eq!(page["items"][0]["id"], "edge");
        assert!(page.get("next_cursor").is_none());
        let calls = source.calls.load(Ordering::SeqCst);
        for container in ["outside", "unknown"] {
            request["params"]["args"][token.info().scope_key] = json!(container);
            assert_refusal(
                &reserved(&planes, request.clone()).await,
                "ability_out_of_scope",
            );
        }
        assert_eq!(source.calls.load(Ordering::SeqCst), calls);
    }
}

#[tokio::test]
async fn events_preserve_occurrence_identity_window_edges_and_all_day_members() {
    use cerebellum_ability::events::occurrence_id;
    let mut items = Vec::new();
    for (id, start, end) in [
        ("ends-at-window", 0, 10),
        ("crosses-start", 9, 11),
        ("starts-at-window", 20, 21),
        ("zero-at-start", 10, 10),
        ("zero-at-end", 20, 20),
    ] {
        items.push(Item::Event(Event {
            id: id.into(),
            calendar: "bound".into(),
            start_ms: Some(start),
            end_ms: Some(end),
            ..Default::default()
        }));
    }
    for original in [11, 12] {
        items.push(Item::Event(Event {
            id: occurrence_id("series", original).unwrap(),
            calendar: "bound".into(),
            start_ms: Some(12),
            end_ms: Some(13),
            recurring: Some(true),
            title: Some(format!("original {original}")),
            ..Default::default()
        }));
    }
    let (planes, _) = setup(
        Data {
            items,
            ..Default::default()
        },
        Platform::MacOs,
    );
    let mut request = call(
        Token::Calendar,
        "events.list",
        json!({"from_ms":10,"to_ms":20,"limit":1}),
    );
    let mut seen = vec![];
    loop {
        let page = body(&reserved(&planes, request.clone()).await);
        for listed in page["items"].as_array().unwrap() {
            let got = body(
                &reserved(
                    &planes,
                    call(Token::Calendar, "events.get", json!({"id":listed["id"]})),
                )
                .await,
            );
            assert_eq!(&got["item"], listed);
            seen.push(listed["id"].as_str().unwrap().to_owned());
        }
        if let Some(cursor) = page.get("next_cursor") {
            request["params"]["args"]["cursor"] = cursor.clone();
        } else {
            break;
        }
    }
    assert_eq!(
        seen,
        [
            "crosses-start".into(),
            "zero-at-start".into(),
            occurrence_id("series", 11).unwrap(),
            occurrence_id("series", 12).unwrap()
        ]
    );
    assert_refusal(
        &reserved(
            &planes,
            call(
                Token::Calendar,
                "events.get",
                json!({"id":occurrence_id("series", 13).unwrap()}),
            ),
        )
        .await,
        "ability_item_not_found",
    );

    let (planes, _) = setup(
        Data {
            zone: Some("America/Sao_Paulo".into()),
            items: vec![Item::Event(Event {
                id: "all-day".into(),
                calendar: "bound".into(),
                all_day: Some(true),
                start_date: Some("2018-11-04".into()),
                end_date: Some("2018-11-05".into()),
                ..Default::default()
            })],
            ..Default::default()
        },
        Platform::MacOs,
    );
    let page = body(
        &reserved(
            &planes,
            call(
                Token::Calendar,
                "events.list",
                json!({"from_ms":1_541_300_400_000_i64,"to_ms":1_541_383_200_000_i64}),
            ),
        )
        .await,
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(page["items"][0]["start_ms"], 1_541_300_400_000_i64);
    assert_eq!(page["items"][0]["start_date"], "2018-11-04");
    assert_eq!(page["items"][0]["end_date"], "2018-11-05");
    let got = body(
        &reserved(
            &planes,
            call(Token::Calendar, "events.get", json!({"id":"all-day"})),
        )
        .await,
    );
    assert_eq!(got["item"], page["items"][0]);
}

#[tokio::test]
async fn largest_ability_reply_fits_one_management_frame_using_the_real_serializer() {
    use cerebellum_ability::{
        ids::MAX_ID_BYTES,
        page::{ChoicePage, ItemPage, MAX_PAGE_BYTES},
    };
    // Serde is not const: measure the real management serializer in this test.
    // A NUL requires six JSON bytes, the maximum per UTF-8 input byte. i64::MIN
    // has the longest timestamp spelling. The digest has fixed ASCII length,
    // and the resulting base64url cursor requires no JSON escaping.
    let scope = validate_scope(Token::Reminders, &json!({"list":["bound"]})).unwrap();
    let args = validate_args(Token::Reminders, "reminders.list", &json!({})).unwrap();
    let context =
        CursorContext::for_call(Token::Reminders, "reminders.list", &args, &scope).unwrap();
    let cursor = context
        .mint(&Item::Reminder(Reminder {
            id: "\0".repeat(MAX_ID_BYTES),
            due_ms: Some(i64::MIN),
            ..Default::default()
        }))
        .unwrap();
    assert_eq!(serde_json::to_vec(&cursor).unwrap().len(), cursor.len() + 2);
    let envelopes = [
        serde_json::to_value(ItemPage {
            items: vec![],
            next_cursor: Some(cursor.clone()),
        })
        .unwrap(),
        serde_json::to_value(ChoicePage {
            choices: vec![],
            next_cursor: Some(cursor),
        })
        .unwrap(),
    ];
    for envelope in envelopes {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        crate::send_tool_response(&tx, 1, 19, 1, 7, envelope.clone())
            .await
            .unwrap();
        let frame = rx.recv().await.unwrap();
        assert_eq!(frame.body.as_ref(), serde_json::to_vec(&envelope).unwrap());
        let empty_array_bytes = serde_json::to_vec(&Vec::<Value>::new()).unwrap().len();
        let envelope_bytes = frame.body.len() - empty_array_bytes;
        assert!(MAX_PAGE_BYTES + envelope_bytes <= subc_protocol::MAX_FRAME_BODY_LEN as usize);
    }
}

#[tokio::test(start_paused = true)]
async fn queued_call_taken_just_before_limit_reports_source_timeout_not_arbiter_deadline() {
    let block = Arc::new(Block::default());
    let release = Release(block.clone());
    let (planes, _) = setup(
        Data {
            block: Some(block.clone()),
            ..Default::default()
        },
        Platform::MacOs,
    );
    planes.routes.insert(19, 1, flow());
    let planes = Arc::new(planes);
    let unit = planes
        .management
        .abilities
        .units
        .for_token(Token::Calendar)
        .unwrap();
    let holder = unit
        .arrive(Arc::new(TerminalArbiter::new(request(
            json!({"method":CALL}),
        ))))
        .unwrap()
        .wait()
        .await
        .unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let started = tokio::time::Instant::now();
    crate::handle_frame_for_test(request(list(Token::Calendar, 100)), &tx, &planes)
        .await
        .unwrap();
    while !unit.has_users_for_test(2) {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(std::time::Duration::from_millis(9_999)).await;
    drop(holder);
    block.started.notified().await;
    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    let reply = rx.recv().await.unwrap();
    assert_refusal(&reply, "ability_source_timeout");
    assert_eq!(started.elapsed(), std::time::Duration::from_millis(19_999));
    drop(release);
    while unit.quarantined() {
        tokio::task::yield_now().await;
    }
    wait_for_status_to_release(unit).await;
    assert!(
        rx.try_recv().is_err(),
        "late source completion sent a second reply"
    );
}

#[tokio::test]
async fn stopped_status_preflight_never_starts_read_or_choices() {
    use crate::terminal_arbiter::TerminalCause;

    struct StopDuringStatus {
        gate: Arc<TerminalArbiter>,
        status_calls: AtomicUsize,
        data_calls: AtomicUsize,
    }
    impl StatusSource for StopDuringStatus {
        fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            assert!(self.gate.stop(TerminalCause::Cancelled));
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
            self.data_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        }

        fn read(
            &self,
            _: Token,
            _: &str,
            _: &ValidatedArgs,
            _: &BoundScope,
        ) -> Result<SourceRead, Refusal> {
            self.data_calls.fetch_add(1, Ordering::SeqCst);
            Err(Refusal::SourceFailed)
        }
    }

    for request_body in [
        list(Token::Calendar, 100),
        json!({"method":SCOPE_CHOICES,"params":{"token":Token::Calendar.as_str(),"key":"calendar"}}),
    ] {
        let frame = request(request_body.clone());
        let gate = Arc::new(TerminalArbiter::new(frame));
        let source = Arc::new(StopDuringStatus {
            gate: gate.clone(),
            status_calls: AtomicUsize::new(0),
            data_calls: AtomicUsize::new(0),
        });
        let mut planes = fixture(source.clone(), Platform::MacOs);
        Arc::get_mut(&mut planes.management)
            .unwrap()
            .abilities
            .binding = Arc::new(Bound);
        let method = request_body["method"].as_str().unwrap();
        let route = if method == CALL {
            flow()
        } else {
            facts("prefrontal-core")
        };
        let result = dispatch(
            &planes.management.abilities,
            &planes.browser,
            &route,
            method,
            request_body.as_object().unwrap(),
            gate,
        )
        .await;
        assert!(
            matches!(result, Ok(None)),
            "stopped closure returned a reply"
        );
        assert_eq!(source.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(source.data_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn stale_scope_refuses_whole_read_even_with_matching_items() {
    for &token in Platform::MacOs.tokens() {
        let (planes, _) = setup(
            Data {
                items: vec![item(token, "one", "bound")],
                ..Default::default()
            },
            Platform::MacOs,
        );
        let mut request = list(token, 100);
        request["params"]["scope"][token.info().scope_key] = json!(["bound", "other"]);
        assert_refusal(&reserved(&planes, request).await, "ability_scope_stale");
    }
}

#[tokio::test]
async fn unavailable_reasons_refuse_choices_and_calls_but_unresponsive_is_not_a_code() {
    for reason in [
        "helper_unverified",
        "helper_revision_mismatch",
        "permission_missing",
        "source_missing",
        "format_unrecognized",
        "classic_outlook_missing",
        "outlook_not_running",
        "outlook_guard_may_prompt",
        "data_service_missing",
        "source_unresponsive",
    ] {
        let (planes, data) = setup(
            Data {
                unavailable: Some(reason),
                ..Default::default()
            },
            Platform::MacOs,
        );
        for request in [
            list(Token::Calendar, 100),
            json!({"method":SCOPE_CHOICES,"params":{"token":Token::Calendar.as_str(),"key":"calendar"}}),
        ] {
            assert_refusal(
                &reserved(&planes, request).await,
                if reason == "source_unresponsive" {
                    "ability_source_timeout"
                } else {
                    reason
                },
            );
        }
        assert_eq!(
            data.calls.load(Ordering::SeqCst),
            2,
            "unavailable source accessed data"
        );
    }
}
