use serde::{Deserialize, Serialize};

use crate::items::ItemKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Token {
    #[serde(rename = "cap/calendar.read@1")]
    Calendar,
    #[serde(rename = "cap/reminders.read@1")]
    Reminders,
    #[serde(rename = "cap/contacts.read@1")]
    Contacts,
    #[serde(rename = "cap/messages.read@1")]
    Messages,
    #[serde(rename = "cap/mail.read@1")]
    Mail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    MacOs,
    Windows,
    Linux,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgsKind {
    Empty,
    Window,
    Get,
    Reminders,
    Contacts,
    Conversation,
    Mailbox,
}

#[derive(Clone, Copy, Debug)]
pub struct Operation {
    pub name: &'static str,
    pub item_kind: ItemKind,
    pub is_list: bool,
    pub args_kind: ArgsKind,
}

#[derive(Clone, Copy, Debug)]
pub struct TokenInfo {
    pub token: Token,
    pub scope_key: &'static str,
    pub ops: &'static [Operation],
}

const fn list(name: &'static str, item_kind: ItemKind, args_kind: ArgsKind) -> Operation {
    Operation {
        name,
        item_kind,
        is_list: true,
        args_kind,
    }
}

const fn get(name: &'static str, item_kind: ItemKind) -> Operation {
    Operation {
        name,
        item_kind,
        is_list: false,
        args_kind: ArgsKind::Get,
    }
}

/// The order of this table is the wire order, not an alphabetic sort.
pub const TOKENS: [TokenInfo; 5] = [
    TokenInfo {
        token: Token::Calendar,
        scope_key: "calendar",
        ops: &[
            list("calendars.list", ItemKind::Container, ArgsKind::Empty),
            list("events.list", ItemKind::Event, ArgsKind::Window),
            get("events.get", ItemKind::Event),
        ],
    },
    TokenInfo {
        token: Token::Reminders,
        scope_key: "list",
        ops: &[
            list("lists.list", ItemKind::Container, ArgsKind::Empty),
            list("reminders.list", ItemKind::Reminder, ArgsKind::Reminders),
            get("reminders.get", ItemKind::Reminder),
        ],
    },
    TokenInfo {
        token: Token::Contacts,
        scope_key: "group",
        ops: &[
            list("groups.list", ItemKind::Group, ArgsKind::Empty),
            list("contacts.list", ItemKind::Contact, ArgsKind::Contacts),
            get("contacts.get", ItemKind::Contact),
        ],
    },
    TokenInfo {
        token: Token::Messages,
        scope_key: "conversation",
        ops: &[
            list(
                "conversations.list",
                ItemKind::Conversation,
                ArgsKind::Empty,
            ),
            list("messages.list", ItemKind::Message, ArgsKind::Conversation),
        ],
    },
    TokenInfo {
        token: Token::Mail,
        scope_key: "mailbox",
        ops: &[
            list("mailboxes.list", ItemKind::Mailbox, ArgsKind::Empty),
            list("messages.list", ItemKind::MailSummary, ArgsKind::Mailbox),
            get("messages.get", ItemKind::MailMessage),
        ],
    },
];

impl Token {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Calendar => "cap/calendar.read@1",
            Self::Reminders => "cap/reminders.read@1",
            Self::Contacts => "cap/contacts.read@1",
            Self::Messages => "cap/messages.read@1",
            Self::Mail => "cap/mail.read@1",
        }
    }

    pub fn info(self) -> &'static TokenInfo {
        &TOKENS[self as usize]
    }

    pub fn operation(self, name: &str) -> Option<&'static Operation> {
        self.info().ops.iter().find(|op| op.name == name)
    }

    pub fn parse(value: &str) -> Option<Self> {
        TOKENS
            .iter()
            .find(|info| info.token.as_str() == value)
            .map(|info| info.token)
    }
}

impl Platform {
    /// Runtime source availability must not change this declared set.
    pub fn tokens(self) -> &'static [Token] {
        match self {
            Self::MacOs => &[
                Token::Calendar,
                Token::Reminders,
                Token::Contacts,
                Token::Messages,
                Token::Mail,
            ],
            Self::Windows => &[
                Token::Calendar,
                Token::Reminders,
                Token::Contacts,
                Token::Mail,
            ],
            Self::Linux => &[Token::Calendar, Token::Reminders, Token::Contacts],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_and_op_order_is_the_wire_order_on_every_platform() {
        assert_eq!(
            TOKENS.map(|t| (t.token.as_str(), t.scope_key)),
            [
                ("cap/calendar.read@1", "calendar"),
                ("cap/reminders.read@1", "list"),
                ("cap/contacts.read@1", "group"),
                ("cap/messages.read@1", "conversation"),
                ("cap/mail.read@1", "mailbox"),
            ]
        );
        let expected: &[&[&str]] = &[
            &["calendars.list", "events.list", "events.get"],
            &["lists.list", "reminders.list", "reminders.get"],
            &["groups.list", "contacts.list", "contacts.get"],
            &["conversations.list", "messages.list"],
            &["mailboxes.list", "messages.list", "messages.get"],
        ];
        for (info, names) in TOKENS.iter().zip(expected) {
            assert_eq!(
                info.ops.iter().map(|op| op.name).collect::<Vec<_>>(),
                *names
            );
            assert_eq!(Token::parse(info.token.as_str()), Some(info.token));
        }
        assert_eq!(
            Platform::MacOs.tokens(),
            &[
                Token::Calendar,
                Token::Reminders,
                Token::Contacts,
                Token::Messages,
                Token::Mail
            ]
        );
        assert_eq!(
            Platform::Windows.tokens(),
            &[
                Token::Calendar,
                Token::Reminders,
                Token::Contacts,
                Token::Mail
            ]
        );
        assert_eq!(
            Platform::Linux.tokens(),
            &[Token::Calendar, Token::Reminders, Token::Contacts]
        );
        assert_eq!(Token::parse("unknown"), None);
    }
}
