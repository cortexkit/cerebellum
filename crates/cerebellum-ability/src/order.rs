use std::cmp::Ordering;

use crate::{
    items::{Item, ItemKind},
    tokens::Operation,
    ValidationError,
};

/// Descending order reverses only the primary key: ids always ascend by bytes,
/// and a missing primary key is last in either direction.
pub fn sort_items(op: &Operation, items: &mut [Item]) -> Result<(), ValidationError> {
    if items.iter().any(|item| item.kind() != op.item_kind) {
        return Err(ValidationError::new(
            "items",
            "item kind does not match operation",
        ));
    }
    let descending = matches!(
        op.item_kind,
        ItemKind::Conversation | ItemKind::Message | ItemKind::MailSummary | ItemKind::MailMessage
    );
    items.sort_by(|a, b| {
        compare_optional(primary_key(a), primary_key(b), descending)
            .then_with(|| a.id().as_bytes().cmp(b.id().as_bytes()))
    });
    Ok(())
}

fn primary_key(item: &Item) -> Option<i64> {
    match item {
        Item::Event(v) => v.start_ms,
        Item::Reminder(v) => v.due_ms,
        Item::Conversation(v) => v.last_message_ms,
        Item::Message(v) => v.sent_ms,
        Item::MailSummary(v) => v.date_ms,
        Item::MailMessage(v) => v.date_ms,
        _ => None,
    }
}

fn compare_optional(a: Option<i64>, b: Option<i64>, descending: bool) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) if descending => b.cmp(&a),
        (Some(a), Some(b)) => a.cmp(&b),
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (None, None) => Ordering::Equal,
    }
}

pub fn matches_since_ms(time: Option<i64>, since_ms: Option<i64>) -> bool {
    since_ms.is_none_or(|since| time.is_some_and(|time| time >= since))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ids::{apple_nanoseconds_to_unix_ms, apple_store_seconds_to_unix_ms},
        items::{test_items, Conversation, Message},
        Token, TOKENS,
    };
    use serde_json::json;

    #[test]
    fn all_operations_use_pinned_byte_ties_and_nulls_last() {
        for info in TOKENS {
            for op in info.ops {
                let template = test_items()
                    .into_iter()
                    .find(|item| item.kind() == op.item_kind)
                    .unwrap();
                let mut items = Vec::new();
                for (id, time) in [
                    ("é", Some(20)),
                    ("z", None),
                    ("ä", Some(20)),
                    ("a", Some(10)),
                    ("Z", Some(20)),
                    ("中", None),
                    ("\u{80}", Some(20)),
                    ("b", Some(30)),
                ] {
                    let mut value = serde_json::to_value(&template).unwrap();
                    value["id"] = json!(id);
                    for key in [
                        "start_ms",
                        "due_ms",
                        "last_message_ms",
                        "sent_ms",
                        "date_ms",
                    ] {
                        if value.get(key).is_some() {
                            value[key] = json!(time);
                        }
                    }
                    items.push(Item::from_json(op.item_kind, value).unwrap());
                }
                sort_items(op, &mut items).unwrap();
                let expected = match op.item_kind {
                    ItemKind::Event | ItemKind::Reminder => {
                        ["a", "Z", "\u{80}", "ä", "é", "b", "z", "中"]
                    }
                    ItemKind::Conversation
                    | ItemKind::Message
                    | ItemKind::MailSummary
                    | ItemKind::MailMessage => ["b", "Z", "\u{80}", "ä", "é", "a", "z", "中"],
                    _ => ["Z", "a", "b", "z", "\u{80}", "ä", "é", "中"],
                };
                assert_eq!(
                    items.iter().map(Item::id).collect::<Vec<_>>(),
                    expected,
                    "{} {}",
                    info.token.as_str(),
                    op.name
                );
            }
        }
        let mut items = test_items();
        assert!(sort_items(
            Token::Calendar.operation("events.list").unwrap(),
            &mut items
        )
        .is_err());
    }

    #[test]
    fn zero_store_dates_sort_last_and_are_excluded_by_since() {
        let mut messages = vec![
            Item::Message(Message {
                id: "missing".into(),
                conversation: "chat".into(),
                sent_ms: apple_nanoseconds_to_unix_ms(0),
                ..Default::default()
            }),
            Item::Message(Message {
                id: "dated".into(),
                conversation: "chat".into(),
                sent_ms: apple_nanoseconds_to_unix_ms(1_000_000_000),
                ..Default::default()
            }),
        ];
        sort_items(
            Token::Messages.operation("messages.list").unwrap(),
            &mut messages,
        )
        .unwrap();
        assert_eq!(
            messages.iter().map(Item::id).collect::<Vec<_>>(),
            ["dated", "missing"]
        );
        let missing = serde_json::to_value(&messages[1]).unwrap();
        assert!(missing["sent_ms"].is_null());
        let mut conversations = vec![
            Item::Conversation(Conversation {
                id: "missing".into(),
                last_message_ms: apple_store_seconds_to_unix_ms(0.0),
                ..Default::default()
            }),
            Item::Conversation(Conversation {
                id: "dated".into(),
                last_message_ms: apple_store_seconds_to_unix_ms(1.0),
                ..Default::default()
            }),
        ];
        sort_items(
            Token::Messages.operation("conversations.list").unwrap(),
            &mut conversations,
        )
        .unwrap();
        assert_eq!(
            conversations.iter().map(Item::id).collect::<Vec<_>>(),
            ["dated", "missing"]
        );
        assert!(serde_json::to_value(&conversations[1]).unwrap()["last_message_ms"].is_null());
        assert!(!matches_since_ms(None, Some(0)));
        assert!(matches_since_ms(None, None));
        assert!(!matches_since_ms(Some(9), Some(10)));
        assert!(matches_since_ms(Some(10), Some(10)));
        assert!(matches_since_ms(Some(11), Some(10)));
    }
}
