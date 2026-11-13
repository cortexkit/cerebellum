use serde::{Deserialize, Deserializer, Serialize};

use crate::{caps, ids::validate_id, ValidationError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemKind {
    Container,
    Mailbox,
    Group,
    Event,
    Reminder,
    Contact,
    Conversation,
    Message,
    MailSummary,
    MailMessage,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    Group,
    #[default]
    Account,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextState {
    Ok,
    #[default]
    Absent,
    Undecodable,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyState {
    Ok,
    NoPlainText,
    #[default]
    NotDownloaded,
    Undecodable,
}

// A nullable field must still be present on the wire. Serde's usual Option
// handling would also accept a missing member, which is a different shape.
fn required<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<T, D::Error> {
    T::deserialize(d)
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabeledValue {
    #[serde(deserialize_with = "required")]
    pub label: Option<String>,
    pub value: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    #[serde(deserialize_with = "required")]
    pub name: Option<String>,
    pub address: String,
}

macro_rules! wire_item {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            $(#[serde(deserialize_with = "required")] pub $field: $ty,)*
            pub truncated: Vec<String>,
        }
        impl $name {
            pub const MEMBERS: &'static [&'static str] = &[$(stringify!($field),)* "truncated"];
        }
    };
}

wire_item!(Container { id: String, title: Option<String> });
wire_item!(Mailbox { id: String, title: Option<String>, account: Option<String> });
wire_item!(Group { id: String, title: Option<String>, kind: GroupKind });
wire_item!(Event {
    id: String, calendar: String, title: Option<String>, start_ms: Option<i64>,
    end_ms: Option<i64>, all_day: Option<bool>, start_date: Option<String>,
    end_date: Option<String>, location: Option<String>, notes: Option<String>,
    recurring: Option<bool>,
});
wire_item!(Reminder {
    id: String, list: String, title: Option<String>, notes: Option<String>,
    due_ms: Option<i64>, completed: Option<bool>, completed_ms: Option<i64>,
});
wire_item!(Contact {
    id: String, groups: Vec<String>, given_name: Option<String>, family_name: Option<String>,
    organization: Option<String>, emails: Vec<LabeledValue>, phones: Vec<LabeledValue>,
});
wire_item!(Conversation {
    id: String, title: Option<String>, participants: Vec<String>, last_message_ms: Option<i64>,
});
wire_item!(Message {
    id: String, conversation: String, sent_ms: Option<i64>, from_me: Option<bool>,
    sender: Option<String>, text: Option<String>, text_state: TextState,
});
wire_item!(MailSummary {
    id: String, mailbox: String, date_ms: Option<i64>, from: Option<Address>,
    to: Vec<Address>, cc: Vec<Address>, subject: Option<String>, read: Option<bool>, flagged: Option<bool>,
});
wire_item!(MailMessage {
    id: String, mailbox: String, date_ms: Option<i64>, from: Option<Address>,
    to: Vec<Address>, cc: Vec<Address>, subject: Option<String>, read: Option<bool>, flagged: Option<bool>,
    body: Option<String>, body_state: BodyState,
});

/// The variant is local metadata, never an extra wire member.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Item {
    Container(Container),
    Mailbox(Mailbox),
    Group(Group),
    Event(Event),
    Reminder(Reminder),
    Contact(Contact),
    Conversation(Conversation),
    Message(Message),
    MailSummary(MailSummary),
    MailMessage(MailMessage),
}

impl ItemKind {
    pub fn members(self) -> &'static [&'static str] {
        match self {
            Self::Container => Container::MEMBERS,
            Self::Mailbox => Mailbox::MEMBERS,
            Self::Group => Group::MEMBERS,
            Self::Event => Event::MEMBERS,
            Self::Reminder => Reminder::MEMBERS,
            Self::Contact => Contact::MEMBERS,
            Self::Conversation => Conversation::MEMBERS,
            Self::Message => Message::MEMBERS,
            Self::MailSummary => MailSummary::MEMBERS,
            Self::MailMessage => MailMessage::MEMBERS,
        }
    }
}

impl Item {
    /// Decode with the operation's expected kind. An untagged union decoder
    /// could otherwise accept a mailbox missing `account` as a plain container.
    /// Content may exceed the caps here; normalize it before building a reply.
    pub fn from_json(kind: ItemKind, value: serde_json::Value) -> Result<Self, ValidationError> {
        let item = match kind {
            ItemKind::Container => serde_json::from_value(value).map(Self::Container),
            ItemKind::Mailbox => serde_json::from_value(value).map(Self::Mailbox),
            ItemKind::Group => serde_json::from_value(value).map(Self::Group),
            ItemKind::Event => serde_json::from_value(value).map(Self::Event),
            ItemKind::Reminder => serde_json::from_value(value).map(Self::Reminder),
            ItemKind::Contact => serde_json::from_value(value).map(Self::Contact),
            ItemKind::Conversation => serde_json::from_value(value).map(Self::Conversation),
            ItemKind::Message => serde_json::from_value(value).map(Self::Message),
            ItemKind::MailSummary => serde_json::from_value(value).map(Self::MailSummary),
            ItemKind::MailMessage => serde_json::from_value(value).map(Self::MailMessage),
        };
        item.map_err(|_| ValidationError::new("item", "does not match expected item shape"))
    }

    pub fn kind(&self) -> ItemKind {
        match self {
            Self::Container(_) => ItemKind::Container,
            Self::Mailbox(_) => ItemKind::Mailbox,
            Self::Group(_) => ItemKind::Group,
            Self::Event(_) => ItemKind::Event,
            Self::Reminder(_) => ItemKind::Reminder,
            Self::Contact(_) => ItemKind::Contact,
            Self::Conversation(_) => ItemKind::Conversation,
            Self::Message(_) => ItemKind::Message,
            Self::MailSummary(_) => ItemKind::MailSummary,
            Self::MailMessage(_) => ItemKind::MailMessage,
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::Container(v) => &v.id,
            Self::Mailbox(v) => &v.id,
            Self::Group(v) => &v.id,
            Self::Event(v) => &v.id,
            Self::Reminder(v) => &v.id,
            Self::Contact(v) => &v.id,
            Self::Conversation(v) => &v.id,
            Self::Message(v) => &v.id,
            Self::MailSummary(v) => &v.id,
            Self::MailMessage(v) => &v.id,
        }
    }

    /// Validate identifiers before shortening content. Source adapters must
    /// already have restricted a contact's groups to its bound memberships.
    pub fn normalize(&mut self) -> Result<(), ValidationError> {
        validate_id("id", self.id())?;
        match self {
            Self::Event(v) => {
                validate_id("calendar", &v.calendar)?;
                for date in [&v.start_date, &v.end_date].into_iter().flatten() {
                    if !valid_date(date) {
                        return Err(ValidationError::new("date", "expected YYYY-MM-DD"));
                    }
                }
            }
            Self::Reminder(v) => validate_id("list", &v.list)?,
            Self::Contact(v) => {
                if v.groups.len() > crate::scope::MAX_BOUND_IDS {
                    return Err(ValidationError::new("groups", "more groups than bound ids"));
                }
                for group in &v.groups {
                    validate_id("groups", group)?;
                }
            }
            Self::Message(v) => validate_id("conversation", &v.conversation)?,
            Self::MailSummary(v) => validate_id("mailbox", &v.mailbox)?,
            Self::MailMessage(v) => validate_id("mailbox", &v.mailbox)?,
            _ => {}
        }
        match self {
            Self::Container(v) => mark(
                &mut v.truncated,
                &[("title", caps::free_text(&mut v.title))],
            ),
            Self::Mailbox(v) => mark(
                &mut v.truncated,
                &[
                    ("title", caps::free_text(&mut v.title)),
                    ("account", caps::free_text(&mut v.account)),
                ],
            ),
            Self::Group(v) => mark(
                &mut v.truncated,
                &[("title", caps::free_text(&mut v.title))],
            ),
            Self::Event(v) => {
                if v.all_day != Some(true) {
                    v.start_date = None;
                    v.end_date = None;
                }
                mark(
                    &mut v.truncated,
                    &[
                        ("title", caps::free_text(&mut v.title)),
                        ("location", caps::free_text(&mut v.location)),
                        ("notes", caps::free_text(&mut v.notes)),
                    ],
                )
            }
            Self::Reminder(v) => mark(
                &mut v.truncated,
                &[
                    ("title", caps::free_text(&mut v.title)),
                    ("notes", caps::free_text(&mut v.notes)),
                ],
            ),
            Self::Contact(v) => {
                v.groups.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                mark(
                    &mut v.truncated,
                    &[
                        ("given_name", caps::free_text(&mut v.given_name)),
                        ("family_name", caps::free_text(&mut v.family_name)),
                        ("organization", caps::free_text(&mut v.organization)),
                        ("emails", caps::labeled_values(&mut v.emails)),
                        ("phones", caps::labeled_values(&mut v.phones)),
                    ],
                )
            }
            Self::Conversation(v) => {
                v.participants
                    .sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                mark(
                    &mut v.truncated,
                    &[
                        ("title", caps::free_text(&mut v.title)),
                        ("participants", caps::participants(&mut v.participants)),
                    ],
                )
            }
            Self::Message(v) => {
                if v.from_me == Some(true) {
                    v.sender = None;
                }
                if v.text_state != TextState::Ok {
                    v.text = None;
                }
                mark(
                    &mut v.truncated,
                    &[
                        (
                            "sender",
                            caps::optional_string(&mut v.sender, caps::ENTRY_BYTES),
                        ),
                        ("text", caps::free_text(&mut v.text)),
                    ],
                )
            }
            Self::MailSummary(v) => mark(
                &mut v.truncated,
                &[
                    ("from", caps::optional_address(&mut v.from)),
                    ("to", caps::addresses(&mut v.to)),
                    ("cc", caps::addresses(&mut v.cc)),
                    ("subject", caps::free_text(&mut v.subject)),
                ],
            ),
            Self::MailMessage(v) => {
                if v.body_state != BodyState::Ok {
                    v.body = None;
                }
                mark(
                    &mut v.truncated,
                    &[
                        ("from", caps::optional_address(&mut v.from)),
                        ("to", caps::addresses(&mut v.to)),
                        ("cc", caps::addresses(&mut v.cc)),
                        ("subject", caps::free_text(&mut v.subject)),
                        ("body", caps::optional_string(&mut v.body, caps::BODY_BYTES)),
                    ],
                )
            }
        }
    }
}

fn mark(truncated: &mut Vec<String>, fields: &[(&str, bool)]) -> Result<(), ValidationError> {
    if truncated
        .iter()
        .any(|name| !fields.iter().any(|(field, _)| field == name))
    {
        return Err(ValidationError::new(
            "truncated",
            "unknown shortened member",
        ));
    }
    // Preserve cuts a decoder already made, but canonicalize order and duplicates.
    *truncated = fields
        .iter()
        .filter(|(name, cut)| *cut || truncated.iter().any(|old| old == name))
        .map(|(name, _)| (*name).to_owned())
        .collect();
    Ok(())
}

pub(crate) fn valid_date(date: &str) -> bool {
    let b = date.as_bytes();
    if b.len() != 10
        || b[4] != b'-'
        || b[7] != b'-'
        || b.iter()
            .enumerate()
            .any(|(i, c)| i != 4 && i != 7 && !c.is_ascii_digit())
    {
        return false;
    }
    let year: u32 = date[..4].parse().unwrap_or(0);
    let month: u32 = date[5..7].parse().unwrap_or(0);
    let day: u32 = date[8..].parse().unwrap_or(0);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    year > 0 && day > 0 && day <= days
}

#[cfg(test)]
pub(crate) fn test_items() -> Vec<Item> {
    vec![
        Item::Container(Container {
            id: "id".into(),
            ..Default::default()
        }),
        Item::Mailbox(Mailbox {
            id: "id".into(),
            ..Default::default()
        }),
        Item::Group(Group {
            id: "id".into(),
            ..Default::default()
        }),
        Item::Event(Event {
            id: "id".into(),
            calendar: "calendar".into(),
            ..Default::default()
        }),
        Item::Reminder(Reminder {
            id: "id".into(),
            list: "list".into(),
            ..Default::default()
        }),
        Item::Contact(Contact {
            id: "id".into(),
            ..Default::default()
        }),
        Item::Conversation(Conversation {
            id: "id".into(),
            ..Default::default()
        }),
        Item::Message(Message {
            id: "id".into(),
            conversation: "conversation".into(),
            ..Default::default()
        }),
        Item::MailSummary(MailSummary {
            id: "id".into(),
            mailbox: "mailbox".into(),
            ..Default::default()
        }),
        Item::MailMessage(MailMessage {
            id: "id".into(),
            mailbox: "mailbox".into(),
            ..Default::default()
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn items_have_exact_table_members_null_scalars_and_array_lists() {
        let expected: &[&[&str]] = &[
            &["id", "title", "truncated"],
            &["id", "title", "account", "truncated"],
            &["id", "title", "kind", "truncated"],
            &[
                "id",
                "calendar",
                "title",
                "start_ms",
                "end_ms",
                "all_day",
                "start_date",
                "end_date",
                "location",
                "notes",
                "recurring",
                "truncated",
            ],
            &[
                "id",
                "list",
                "title",
                "notes",
                "due_ms",
                "completed",
                "completed_ms",
                "truncated",
            ],
            &[
                "id",
                "groups",
                "given_name",
                "family_name",
                "organization",
                "emails",
                "phones",
                "truncated",
            ],
            &[
                "id",
                "title",
                "participants",
                "last_message_ms",
                "truncated",
            ],
            &[
                "id",
                "conversation",
                "sent_ms",
                "from_me",
                "sender",
                "text",
                "text_state",
                "truncated",
            ],
            &[
                "id",
                "mailbox",
                "date_ms",
                "from",
                "to",
                "cc",
                "subject",
                "read",
                "flagged",
                "truncated",
            ],
            &[
                "id",
                "mailbox",
                "date_ms",
                "from",
                "to",
                "cc",
                "subject",
                "read",
                "flagged",
                "body",
                "body_state",
                "truncated",
            ],
        ];
        for (item, expected) in test_items().into_iter().zip(expected) {
            assert_eq!(item.kind().members(), *expected);
            let value = serde_json::to_value(&item).unwrap();
            assert_eq!(value.as_object().unwrap().len(), expected.len());
            for &name in *expected {
                let member = &value[name];
                match name {
                    "id" | "calendar" | "list" | "conversation" | "mailbox" | "kind"
                    | "text_state" | "body_state" => assert!(member.is_string()),
                    "groups" | "emails" | "phones" | "participants" | "to" | "cc" | "truncated" => {
                        assert_eq!(member, &json!([]))
                    }
                    _ => assert!(member.is_null(), "{name}"),
                }
                let mut missing = value.clone();
                missing.as_object_mut().unwrap().remove(name);
                assert!(
                    Item::from_json(item.kind(), missing).is_err(),
                    "missing {name}"
                );
            }
            assert_eq!(Item::from_json(item.kind(), value.clone()).unwrap(), item);
            let mut unknown = value;
            unknown["unexpected"] = json!(false);
            assert!(Item::from_json(item.kind(), unknown).is_err());
        }
        let address: Address =
            serde_json::from_value(json!({"name": null, "address": "a@b"})).unwrap();
        assert_eq!(address.name, None);
        assert!(serde_json::from_value::<Address>(json!({"address": "a@b"})).is_err());
        assert!(serde_json::from_value::<LabeledValue>(json!({"value": "a@b"})).is_err());
        let labeled = LabeledValue {
            label: None,
            value: "123".into(),
        };
        assert_eq!(
            serde_json::to_value(labeled).unwrap(),
            json!({"label": null, "value": "123"})
        );
    }

    #[test]
    fn absent_or_undecodable_text_is_null_and_outgoing_sender_is_null() {
        for state in [TextState::Ok, TextState::Absent, TextState::Undecodable] {
            let mut item = Item::Message(Message {
                id: "id".into(),
                conversation: "chat".into(),
                from_me: Some(true),
                sender: Some("must not remain".into()),
                text: Some("body".into()),
                text_state: state,
                ..Default::default()
            });
            item.normalize().unwrap();
            let value = serde_json::to_value(item).unwrap();
            assert_eq!(value["sender"], Value::Null);
            assert_eq!(
                value["text"],
                if state == TextState::Ok {
                    json!("body")
                } else {
                    Value::Null
                }
            );
        }
        for state in [
            BodyState::Ok,
            BodyState::NoPlainText,
            BodyState::NotDownloaded,
            BodyState::Undecodable,
        ] {
            let mut item = Item::MailMessage(MailMessage {
                id: "id".into(),
                mailbox: "mailbox".into(),
                body: Some("body".into()),
                body_state: state,
                ..Default::default()
            });
            item.normalize().unwrap();
            assert_eq!(
                serde_json::to_value(item).unwrap()["body"],
                if state == BodyState::Ok {
                    json!("body")
                } else {
                    Value::Null
                }
            );
        }
    }

    #[test]
    fn timed_events_have_null_dates_and_invalid_source_ids_are_not_shortened() {
        let mut event = Item::Event(Event {
            id: "id".into(),
            calendar: "calendar".into(),
            all_day: Some(false),
            start_date: Some("2025-11-02".into()),
            end_date: Some("2025-11-03".into()),
            ..Default::default()
        });
        event.normalize().unwrap();
        assert!(serde_json::to_value(event).unwrap()["start_date"].is_null());
        for id in ["".to_owned(), "a".repeat(2049)] {
            let mut item = Item::Container(Container {
                id: id.clone(),
                ..Default::default()
            });
            assert!(item.normalize().is_err());
            assert_eq!(item.id(), id);
        }
        assert!(valid_date("2024-02-29"));
        for date in [
            "2025-02-29",
            "2025-00-01",
            "2025-01-00",
            "2025-04-31",
            "é025-01-01",
        ] {
            assert!(!valid_date(date));
        }
    }
}
