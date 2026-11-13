//! Filtering precedes ordering and keyset paging on every host.

use crate::{
    caps,
    contacts::matches_query,
    cursor::CursorContext,
    events::overlaps_window,
    filter::{retain_in_scope, TaggedItem},
    ids::validate_id,
    items::{GroupKind, Item},
    order::{matches_since_ms, sort_items, sort_key, SortKey},
    schema::{DEFAULT_LIMIT, MAX_LIMIT},
    BoundScope, Token, ValidatedArgs, ValidationError,
};
use serde::Serialize;

/// Serialized `items` or `choices` array bound. The serving layer must prove at
/// compile time that `page::MAX_PAGE_BYTES` plus its reply envelope fits within
/// `subc_protocol::MAX_FRAME_BODY_LEN`; this crate has no protocol dependency.
pub const MAX_PAGE_BYTES: usize = 2 * 1024 * 1024;
pub const CHOICE_LABEL_BYTES: usize = 1024;

#[derive(Debug, Serialize)]
pub struct ItemPage {
    pub items: Vec<Item>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScopeChoice {
    pub id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<GroupKind>,
}

#[derive(Debug, Serialize)]
pub struct ChoicePage {
    pub choices: Vec<ScopeChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Supply the complete source result, not a pre-cut source page. Tags must come
/// from each record's own containers. Filtering a source page would create gaps
/// and let excluded records influence the continuation point.
pub fn build_page(
    token: Token,
    op: &str,
    args: &ValidatedArgs,
    scope: &BoundScope,
    source: impl IntoIterator<Item = TaggedItem>,
) -> Result<ItemPage, ValidationError> {
    let context = CursorContext::for_call(token, op, args, scope)?;
    let last = context.seek(args.cursor())?;
    let op = token.operation(op).expect("context checked operation");
    for key in ["conversation", "mailbox"] {
        if let Some(id) = args.as_json().get(key).and_then(serde_json::Value::as_str) {
            if !scope.contains(id) {
                return Err(ValidationError::new(
                    key,
                    "requested container is not bound",
                ));
            }
        }
    }
    let mut items = Vec::new();
    for tagged in source {
        let Some(mut item) = retain_in_scope(scope, tagged) else {
            continue;
        };
        if item.kind() != op.item_kind {
            return Err(ValidationError::new(
                "items",
                "item kind does not match operation",
            ));
        }
        // Predicates inspect original content, before normalization can cut it.
        if !matches_args(&item, args) {
            continue;
        }
        item.normalize()?;
        items.push(item);
    }
    sort_items(op, &mut items)?;
    let (items, next_cursor) = cut_page(
        items,
        args.limit().expect("list args"),
        &context,
        last.as_ref(),
        sort_key,
    )?;
    Ok(ItemPage { items, next_cursor })
}

fn matches_args(item: &Item, args: &ValidatedArgs) -> bool {
    let args_json = args.as_json();
    let since = args_json
        .get("since_ms")
        .and_then(serde_json::Value::as_i64);
    match item {
        Item::Contact(contact) => matches_query(
            contact,
            args_json.get("query").and_then(serde_json::Value::as_str),
        ),
        Item::Event(event) => overlaps_window(
            event.start_ms,
            event.end_ms,
            args_json["from_ms"].as_i64().expect("window args"),
            args_json["to_ms"].as_i64().expect("window args"),
        ),
        Item::Reminder(reminder) => args.include_completed() || reminder.completed != Some(true),
        Item::Message(message) => {
            args_json["conversation"].as_str() == Some(message.conversation.as_str())
                && matches_since_ms(message.sent_ms, since)
        }
        Item::MailSummary(message) => {
            args_json["mailbox"].as_str() == Some(message.mailbox.as_str())
                && matches_since_ms(message.date_ms, since)
        }
        _ => true,
    }
}

/// Choice enumeration has no binding yet. Invalid container ids are not offered
/// for selection, and label caps are applied before measuring the page.
pub fn build_choices_page(
    token: Token,
    key: &str,
    limit: Option<usize>,
    cursor: Option<&str>,
    source: impl IntoIterator<Item = ScopeChoice>,
) -> Result<ChoicePage, ValidationError> {
    let context = CursorContext::for_choices(token, key)?;
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ValidationError::new("limit", "out of range"));
    }
    let last = context.seek(cursor)?;
    let mut choices = Vec::new();
    for mut choice in source {
        if validate_id("id", &choice.id).is_err() {
            continue;
        }
        if (token == Token::Contacts) != choice.kind.is_some() {
            return Err(ValidationError::new(
                "kind",
                "choice kind must appear only for contacts",
            ));
        }
        caps::cut_string(&mut choice.label, CHOICE_LABEL_BYTES);
        choices.push(choice);
    }
    choices.sort_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
    let (choices, next_cursor) =
        cut_page(choices, limit, &context, last.as_ref(), |choice| SortKey {
            time_ms: None,
            id: choice.id.clone(),
        })?;
    Ok(ChoicePage {
        choices,
        next_cursor,
    })
}

fn cut_page<T: Serialize>(
    items: Vec<T>,
    limit: usize,
    context: &CursorContext,
    last: Option<&SortKey>,
    key: impl Fn(&T) -> SortKey,
) -> Result<(Vec<T>, Option<String>), ValidationError> {
    let mut page = Vec::new();
    let mut bytes = 2; // The surrounding array brackets count toward the bound.
    let mut last_returned = None;
    for item in items {
        let item_key = key(&item);
        if last.is_some_and(|last| !context.after(&item_key, last)) {
            continue;
        }
        let item_bytes = serde_json::to_vec(&item)
            .expect("serializable page item")
            .len();
        let additional = item_bytes + usize::from(!page.is_empty());
        if page.len() == limit || bytes + additional > MAX_PAGE_BYTES {
            let last = last_returned.ok_or_else(|| {
                ValidationError::new("items", "item exceeds normalized item caps")
            })?;
            return Ok((page, Some(context.encode(last)?)));
        }
        bytes += additional;
        last_returned = Some(item_key);
        page.push(item);
    }
    Ok((page, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        events::{occurrence_id, parse_occurrence_id},
        filter::check_page_scope,
        items::{test_items, Address, Contact, Event, MailSummary, Message, Reminder},
        tokens::ArgsKind,
        validate_args, validate_scope, TOKENS,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde_json::{json, Value};

    fn scoped(mut item: Item, container: &str) -> TaggedItem {
        match &mut item {
            Item::Event(v) => v.calendar = container.into(),
            Item::Reminder(v) => v.list = container.into(),
            Item::Contact(v) => v.groups = vec![container.into()],
            Item::Message(v) => v.conversation = container.into(),
            Item::MailSummary(v) => v.mailbox = container.into(),
            _ => {}
        }
        TaggedItem::new(item, [container.into()])
    }

    fn with_id(item: &Item, id: &str) -> Item {
        let mut value = serde_json::to_value(item).unwrap();
        value["id"] = json!(id);
        if value.get("completed").is_some() {
            value["completed"] = json!(false);
        }
        Item::from_json(item.kind(), value).unwrap()
    }

    #[test]
    fn out_of_scope_items_never_shorten_pages_or_shape_cursors_for_any_list() {
        for info in TOKENS {
            for op in info.ops.iter().filter(|op| op.is_list) {
                let template = test_items()
                    .into_iter()
                    .find(|item| item.kind() == op.item_kind)
                    .unwrap();
                let container_listing = matches!(
                    op.item_kind,
                    crate::ItemKind::Container
                        | crate::ItemKind::Group
                        | crate::ItemKind::Mailbox
                        | crate::ItemKind::Conversation
                );
                let bound_ids = if container_listing {
                    vec!["01", "02", "04", "05", "07"]
                } else {
                    vec!["bound"]
                };
                let scope =
                    validate_scope(info.token, &json!({info.scope_key: bound_ids})).unwrap();
                let mut args = match op.args_kind {
                    ArgsKind::Window => json!({"from_ms": i64::MIN, "to_ms": i64::MIN + 1}),
                    ArgsKind::Conversation => json!({"conversation": "bound"}),
                    ArgsKind::Mailbox => json!({"mailbox": "bound"}),
                    _ => json!({}),
                };
                // Keep the template's event within this test's query window.
                let mut value = serde_json::to_value(&template).unwrap();
                if op.args_kind == ArgsKind::Window {
                    value["start_ms"] = json!(0);
                    value["end_ms"] = json!(1);
                    args = json!({"from_ms": 0, "to_ms": 10});
                }
                let template = Item::from_json(op.item_kind, value).unwrap();
                args["limit"] = json!(2);
                let mut seen = Vec::new();
                loop {
                    let source = [
                        ("00-dropped", "outside"),
                        ("01", "bound"),
                        ("02", "bound"),
                        ("03-dropped", "outside"),
                        ("04", "bound"),
                        ("05", "bound"),
                        ("06-dropped", "outside"),
                        ("07", "bound"),
                    ]
                    .into_iter()
                    .map(|(id, scope)| {
                        scoped(
                            with_id(&template, id),
                            if container_listing { id } else { scope },
                        )
                    });
                    let page = build_page(
                        info.token,
                        op.name,
                        &validate_args(info.token, op.name, &args).unwrap(),
                        &scope,
                        source,
                    )
                    .unwrap();
                    check_page_scope(&scope, &page.items).unwrap();
                    seen.extend(page.items.iter().map(|item| item.id().to_owned()));
                    if let Some(cursor) = page.next_cursor {
                        assert_eq!(page.items.len(), 2, "{}", op.name);
                        let payload: Value =
                            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&cursor).unwrap())
                                .unwrap();
                        assert_eq!(payload["last"]["id"], page.items.last().unwrap().id());
                        assert!(!payload["last"]["id"].as_str().unwrap().contains("dropped"));
                        CursorContext::for_call(
                            info.token,
                            op.name,
                            &validate_args(info.token, op.name, &args).unwrap(),
                            &scope,
                        )
                        .unwrap()
                        .validate(&cursor)
                        .unwrap();
                        args["cursor"] = json!(cursor);
                    } else {
                        break;
                    }
                }
                assert_eq!(seen, ["01", "02", "04", "05", "07"], "{}", op.name);
            }
        }
    }

    #[test]
    fn four_hundred_fifty_items_are_exhausted_with_changing_limits() {
        let scope = validate_scope(Token::Reminders, &json!({"list": ["bound"]})).unwrap();
        let mut args = json!({});
        let mut seen = Vec::new();
        for (iteration, limit) in [1, 200, 7, 83, 159].into_iter().cycle().enumerate() {
            assert!(iteration < 20, "paging failed to finish");
            args["limit"] = json!(limit);
            let source = (0..450).rev().map(|n| {
                TaggedItem::from_item(Item::Reminder(Reminder {
                    id: format!("{n:03}"),
                    list: "bound".into(),
                    due_ms: if n < 400 { Some(n / 3) } else { None },
                    ..Default::default()
                }))
            });
            let page = build_page(
                Token::Reminders,
                "reminders.list",
                &validate_args(Token::Reminders, "reminders.list", &args).unwrap(),
                &scope,
                source,
            )
            .unwrap();
            seen.extend(page.items.iter().map(|item| item.id().to_owned()));
            if let Some(cursor) = page.next_cursor {
                assert_eq!(page.items.len(), limit);
                args["cursor"] = json!(cursor);
            } else {
                break;
            }
        }
        assert_eq!(
            seen,
            (0..450).map(|n| format!("{n:03}")).collect::<Vec<_>>()
        );
    }

    #[test]
    fn contacts_query_is_applied_after_scope_and_before_cuts_sorting_and_paging() {
        let scope = validate_scope(Token::Contacts, &json!({"group": ["bound"]})).unwrap();
        let mut args = json!({"query": "needle", "limit": 1});
        let mut seen = Vec::new();
        loop {
            let source = [
                ("00", "outside", "needle".into()),
                ("01", "bound", "no match".into()),
                ("02", "bound", "midNEEDLEword".into()),
                ("03", "bound", "no match".into()),
                (
                    "04",
                    "bound",
                    format!("{}needle", "x".repeat(caps::FREE_TEXT_BYTES)),
                ),
                ("05", "bound", "no match".into()),
            ]
            .into_iter()
            .map(|(id, group, name)| {
                TaggedItem::from_item(Item::Contact(Contact {
                    id: id.into(),
                    groups: vec![group.into()],
                    given_name: Some(name),
                    ..Default::default()
                }))
            });
            let page = build_page(
                Token::Contacts,
                "contacts.list",
                &validate_args(Token::Contacts, "contacts.list", &args).unwrap(),
                &scope,
                source,
            )
            .unwrap();
            check_page_scope(&scope, &page.items).unwrap();
            seen.extend(page.items.iter().map(|item| item.id().to_owned()));
            if let Some(cursor) = page.next_cursor {
                assert_eq!(page.items.len(), 1);
                args["cursor"] = json!(cursor);
            } else {
                assert_eq!(page.items.len(), 1);
                break;
            }
        }
        assert_eq!(seen, ["02", "04"]);
    }

    #[test]
    fn moved_occurrences_with_equal_start_survive_a_page_cut() {
        let scope = validate_scope(Token::Calendar, &json!({"calendar": ["bound"]})).unwrap();
        let source = || {
            [10, 20].into_iter().map(|original| {
                TaggedItem::from_item(Item::Event(Event {
                    id: occurrence_id("series", original).unwrap(),
                    calendar: "bound".into(),
                    start_ms: Some(20),
                    end_ms: Some(21),
                    recurring: Some(true),
                    ..Default::default()
                }))
            })
        };
        let mut args = json!({"from_ms": 20, "to_ms": 30, "limit": 1});
        let first = build_page(
            Token::Calendar,
            "events.list",
            &validate_args(Token::Calendar, "events.list", &args).unwrap(),
            &scope,
            source(),
        )
        .unwrap();
        args["cursor"] = json!(first.next_cursor.unwrap());
        let second = build_page(
            Token::Calendar,
            "events.list",
            &validate_args(Token::Calendar, "events.list", &args).unwrap(),
            &scope,
            source(),
        )
        .unwrap();
        assert!(second.next_cursor.is_none());
        assert_eq!(first.items.len(), 1);
        assert_eq!(second.items.len(), 1);
        assert_eq!(
            parse_occurrence_id(first.items[0].id()).unwrap(),
            ("series".into(), 10)
        );
        assert_eq!(
            parse_occurrence_id(second.items[0].id()).unwrap(),
            ("series".into(), 20)
        );
    }

    #[test]
    fn message_lists_page_toward_older_times_include_since_and_exclude_null() {
        for token in [Token::Messages, Token::Mail] {
            let key = token.info().scope_key;
            let scope = validate_scope(token, &json!({key: ["bound", "other"]})).unwrap();
            let mut args = json!({key: "bound", "since_ms": 10, "limit": 1});
            let mut seen = Vec::new();
            loop {
                let source = [
                    ("a", Some(20)),
                    ("b", Some(20)),
                    ("c", Some(10)),
                    ("d", Some(9)),
                    ("e", None),
                ]
                .into_iter()
                .map(|(id, time)| {
                    let item = if token == Token::Messages {
                        Item::Message(Message {
                            id: id.into(),
                            conversation: "bound".into(),
                            sent_ms: time,
                            ..Default::default()
                        })
                    } else {
                        Item::MailSummary(MailSummary {
                            id: id.into(),
                            mailbox: "bound".into(),
                            date_ms: time,
                            ..Default::default()
                        })
                    };
                    TaggedItem::from_item(item)
                });
                let page = build_page(
                    token,
                    "messages.list",
                    &validate_args(token, "messages.list", &args).unwrap(),
                    &scope,
                    source,
                )
                .unwrap();
                assert_eq!(page.items.len(), 1);
                seen.push(page.items[0].id().to_owned());
                if let Some(cursor) = page.next_cursor {
                    args["cursor"] = json!(cursor);
                } else {
                    break;
                }
            }
            assert_eq!(seen, ["a", "b", "c"]);
            let invalid = validate_args(token, "messages.list", &json!({key: "unbound"})).unwrap();
            let never_read = std::iter::from_fn(|| -> Option<TaggedItem> {
                panic!("unbound container must not read a source")
            });
            assert!(build_page(token, "messages.list", &invalid, &scope, never_read).is_err());
        }
    }

    #[test]
    fn byte_bound_cuts_at_a_whole_normalized_item_without_losing_one() {
        let scope = validate_scope(Token::Mail, &json!({"mailbox": ["bound"]})).unwrap();
        let source = || {
            (0..20).map(|n| {
                TaggedItem::from_item(Item::MailSummary(MailSummary {
                    id: format!("{n:02}"),
                    mailbox: "bound".into(),
                    date_ms: Some(100 - n),
                    subject: Some("é".repeat(caps::FREE_TEXT_BYTES)),
                    to: vec![
                        Address {
                            name: Some("\0".repeat(1000)),
                            address: "\0".repeat(1000)
                        };
                        caps::ADDRESS_ENTRIES
                    ],
                    cc: vec![
                        Address {
                            name: Some("\0".repeat(1000)),
                            address: "\0".repeat(1000)
                        };
                        caps::ADDRESS_ENTRIES
                    ],
                    ..Default::default()
                }))
            })
        };
        let mut args = json!({"mailbox": "bound", "limit": 200});
        let mut seen = Vec::new();
        let mut previous_page_bytes = None;
        loop {
            let page = build_page(
                Token::Mail,
                "messages.list",
                &validate_args(Token::Mail, "messages.list", &args).unwrap(),
                &scope,
                source(),
            )
            .unwrap();
            let bytes = serde_json::to_vec(&page.items).unwrap().len();
            assert!(bytes <= MAX_PAGE_BYTES);
            assert!(!page.items.is_empty());
            if let Some(previous) = previous_page_bytes {
                assert!(
                    previous + 1 + serde_json::to_vec(&page.items[0]).unwrap().len()
                        > MAX_PAGE_BYTES
                );
            }
            for item in &page.items {
                assert!(serde_json::to_vec(item).unwrap().len() < caps::ITEM_BYTES);
                let Item::MailSummary(item) = item else {
                    unreachable!()
                };
                assert_eq!(item.truncated, ["to", "cc", "subject"]);
            }
            seen.extend(page.items.iter().map(|item| item.id().to_owned()));
            if let Some(cursor) = page.next_cursor {
                assert!(page.items.len() < 200);
                previous_page_bytes = Some(bytes);
                args["cursor"] = json!(cursor);
            } else {
                break;
            }
        }
        assert_eq!(seen, (0..20).map(|n| format!("{n:02}")).collect::<Vec<_>>());
    }

    #[test]
    fn choices_obey_byte_bound_label_cap_and_skip_overlong_ids_before_paging() {
        let source = || {
            (0..205).map(|n| ScopeChoice {
                id: if n == 0 {
                    "x".repeat(2049)
                } else {
                    format!("{n:03}{}", "\0".repeat(2045))
                },
                label: "\0".repeat(1000),
                kind: None,
            })
        };
        let mut cursor = None;
        let mut seen = Vec::new();
        let mut first = true;
        loop {
            let page = build_choices_page(
                Token::Calendar,
                "calendar",
                Some(200),
                cursor.as_deref(),
                source(),
            )
            .unwrap();
            assert!(serde_json::to_vec(&page.choices).unwrap().len() <= MAX_PAGE_BYTES);
            assert!(!page.choices.is_empty());
            for choice in &page.choices {
                assert!(caps::serialized_string_bytes(&choice.label) <= CHOICE_LABEL_BYTES);
            }
            seen.extend(page.choices.iter().map(|choice| choice.id.clone()));
            if let Some(next) = page.next_cursor {
                CursorContext::for_choices(Token::Calendar, "calendar")
                    .unwrap()
                    .validate(&next)
                    .unwrap();
                if first {
                    assert!(page.choices.len() < 200, "size must cut before count limit");
                }
                cursor = Some(next);
            } else {
                break;
            }
            first = false;
        }
        assert_eq!(
            seen,
            (1..205)
                .map(|n| format!("{n:03}{}", "\0".repeat(2045)))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn helper_scope_check_rejects_a_whole_mixed_page_and_invalid_item_ids_refuse() {
        let scope = validate_scope(Token::Reminders, &json!({"list": ["bound"]})).unwrap();
        let inside = Item::Reminder(Reminder {
            id: "i".into(),
            list: "bound".into(),
            ..Default::default()
        });
        let outside = Item::Reminder(Reminder {
            id: "o".into(),
            list: "outside".into(),
            ..Default::default()
        });
        assert!(check_page_scope(&scope, &[inside.clone(), outside]).is_err());
        let args = validate_args(Token::Reminders, "reminders.list", &json!({})).unwrap();
        assert!(build_page(
            Token::Reminders,
            "reminders.list",
            &args,
            &scope,
            [scoped(with_id(&inside, &"i".repeat(2049)), "bound")]
        )
        .is_err());
    }
}
