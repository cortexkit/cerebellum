//! Request-local Outlook sessions. Only the factory is shared between threads.

use std::{cell::RefCell, collections::BTreeSet, sync::Arc};

use cerebellum_ability::{
    events::occurrence_id,
    filter::TaggedItem,
    ids::windows_id,
    items::{
        BodyState, Contact, Container, Event, Group, GroupKind, MailMessage, MailSummary, Mailbox,
        Reminder,
    },
    time::{NaiveDate, ReminderDue},
    BoundScope, Item, Token, ValidatedArgs,
};
use serde_json::Value;

use super::super::{
    serving::{self, ReadAccess, ReadRequest, SourceRead, SourceRecord},
    Availability, Refusal, StatusSource,
};
use crate::{
    outlook_guard::{decide, GuardInput},
    terminal_arbiter::TerminalArbiter,
};

/// StoreID and EntryID are the bytes of Outlook's strings, not hex-decoded MAPI
/// identifiers. Folder ids have exactly two unpadded base64url components.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::ability) struct Id {
    pub store: Vec<u8>,
    pub entry: Vec<u8>,
}

impl Id {
    pub(in crate::ability) fn encode(&self) -> Result<String, Refusal> {
        windows_id(&self.store, &self.entry).map_err(|_| Refusal::SourceFailed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::ability) enum AttachError {
    Unregistered,
    NotRunning,
    Failed,
}

impl AttachError {
    fn refusal(self) -> Refusal {
        match self {
            Self::Unregistered => Refusal::Unavailable("classic_outlook_missing"),
            Self::NotRunning => Refusal::Unavailable("outlook_not_running"),
            Self::Failed => Refusal::SourceFailed,
        }
    }
}

/// The native implementation initializes COM on the calling pool thread and
/// attaches through the running-object table only. No activation operation is
/// exposed. Drop releases all interfaces before uninitializing COM there.
pub(in crate::ability) trait SessionFactory: Send + Sync + 'static {
    fn attach_running(&self) -> Result<Box<dyn Session>, AttachError>;
}

#[derive(Clone, Debug)]
pub(in crate::ability) struct Folder {
    pub id: Id,
    pub token: Token,
    pub title: Option<String>,
    pub store_display_name: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::ability) enum Class {
    Appointment,
    Task,
    Contact,
    Mail,
    Other,
}

impl Class {
    fn for_token(token: Token) -> Option<Self> {
        match token {
            Token::Calendar => Some(Self::Appointment),
            Token::Reminders => Some(Self::Task),
            Token::Contacts => Some(Self::Contact),
            Token::Mail => Some(Self::Mail),
            Token::Messages => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::ability) struct Header {
    pub id: Id,
    /// Read from the item's Parent, never copied from the folder being queried.
    pub parent: Id,
    pub class: Class,
    /// Series-assigned start, before an exception moves the occurrence. The
    /// native lookup must resolve this occurrence, not return its series master.
    pub original_start_ms: Option<i64>,
}

impl Header {
    fn item_id(&self) -> Result<String, Refusal> {
        let id = self.id.encode()?;
        if let Some(original) = self.original_start_ms {
            occurrence_id(&id, original).map_err(|_| Refusal::SourceFailed)
        } else {
            Ok(id)
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::ability) enum Body {
    /// MailItem.Body, even when the original message is HTML. Never HTMLBody.
    Text(String),
    /// DownloadState says only the header has been downloaded; do not read Body.
    HeaderOnly,
    /// Body was read and returned an error, not a missing plain-text MIME part.
    Failed,
}

/// Content fields reuse the wire structs, but their id/container fields are
/// ignored and replaced from Header. Task due and mail body are normalized here,
/// rather than trusting an adapter's precomputed wire state.
#[derive(Clone)]
pub(in crate::ability) enum Fields {
    Appointment(Event),
    Task(Reminder, Option<ReminderDue>),
    Contact(Contact),
    Mail(MailMessage, Body),
}

/// Deliberately not Send or Sync: the entire session, including Drop, stays in
/// one blocking closure. All returned data is owned and contains no COM handles.
pub(in crate::ability) trait Session {
    /// Uses process, registry and Windows Security Center evidence only, without
    /// invoking an Outlook member.
    fn guard_input(&self) -> GuardInput;
    /// Reads the system zone id, not an Outlook member. Unknown ids fail closed.
    fn windows_zone_id(&self) -> Option<String>;
    fn folders(&mut self) -> Result<Vec<Folder>, Refusal>;
    /// Appointment enumeration expands occurrences in the requested window.
    /// Only headers are read here; fields of another class must not be read.
    fn items(&mut self, folder: &Folder, args: &ValidatedArgs) -> Result<Vec<Header>, Refusal>;
    /// Store-wide lookup; the returned header carries the item's actual Parent.
    fn lookup(&mut self, token: Token, id: &str) -> Result<Option<Header>, Refusal>;
    fn fields(&mut self, header: &Header, include_body: bool) -> Result<Fields, Refusal>;
}

pub(in crate::ability) struct OutlookSource {
    factory: Option<Arc<dyn SessionFactory>>,
}

impl OutlookSource {
    pub(in crate::ability) fn new(factory: Option<Arc<dyn SessionFactory>>) -> Self {
        Self { factory }
    }

    fn open(&self, gate: Option<Arc<TerminalArbiter>>) -> Result<Access, Refusal> {
        let factory = self
            .factory
            .as_ref()
            .ok_or(Refusal::Unavailable("classic_outlook_missing"))?;
        let session = factory.attach_running().map_err(AttachError::refusal)?;
        if let Some(reason) = decide(&session.guard_input()).unavailable_reason() {
            return Err(Refusal::Unavailable(reason));
        }
        Ok(Access {
            session: RefCell::new(session),
            gate,
        })
    }
}

impl StatusSource for OutlookSource {
    fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
        let availability = match self.open(None) {
            Ok(_) => Availability {
                unavailable_reason: None,
            },
            Err(Refusal::Unavailable(reason)) => Availability::unavailable(reason),
            Err(_) => return Err(()),
        };
        Ok(tokens.iter().map(|&token| (token, availability)).collect())
    }

    fn request(&self, request: ReadRequest) -> Result<Option<Value>, Refusal> {
        let gate = request.gate.clone();
        if gate.gate.stopped() {
            return Ok(None);
        }
        let result = self
            .open(Some(gate.clone()))
            .and_then(|access| serving::read_inner(&access, request));
        // If cancellation arrived inside a member call, no subsequent member is
        // invoked. Returning no result lets the ability journal record stopped
        // rather than the synthetic error used to leave the member loop.
        if gate.gate.stopped() {
            Ok(None)
        } else {
            result
        }
    }
}

struct Access {
    session: RefCell<Box<dyn Session>>,
    gate: Option<Arc<TerminalArbiter>>,
}

impl Access {
    fn stopped(&self) -> bool {
        self.gate.as_ref().is_some_and(|gate| gate.gate.stopped())
    }

    fn check(&self) -> Result<(), Refusal> {
        if self.stopped() {
            return Err(Refusal::SourceFailed);
        }
        // Recheck before every member-backed source step, not just attachment.
        if let Some(reason) = decide(&self.session.borrow().guard_input()).unavailable_reason() {
            return Err(Refusal::Unavailable(reason));
        }
        Ok(())
    }

    fn folders(&self, token: Token) -> Result<Vec<Folder>, Refusal> {
        self.check()?;
        Ok(self
            .session
            .borrow_mut()
            .folders()?
            .into_iter()
            .filter(|f| f.token == token)
            .collect())
    }
}

impl ReadAccess for Access {
    fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
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

    fn choices(&self, token: Token) -> Result<Vec<serving::ScopeChoice>, Refusal> {
        Ok(self
            .folders(token)?
            .into_iter()
            .filter_map(|folder| {
                folder.id.encode().ok().map(|id| serving::ScopeChoice {
                    id,
                    label: folder.title.unwrap_or_default(),
                    kind: (token == Token::Contacts).then_some(GroupKind::Account),
                })
            })
            .collect())
    }

    fn read(
        &self,
        token: Token,
        op: &str,
        args: &ValidatedArgs,
        scope: &BoundScope,
    ) -> Result<SourceRead, Refusal> {
        // Unbindable folders are omitted from both scope choices and container
        // listings. Item ids, in contrast, refuse the read rather than disappear.
        let folders: Vec<_> = self
            .folders(token)?
            .into_iter()
            .filter_map(|folder| folder.id.encode().ok().map(|id| (id, folder)))
            .collect();
        let containers: BTreeSet<_> = folders.iter().map(|(id, _)| id.clone()).collect();
        let mut read = SourceRead {
            containers,
            time_zone: self
                .session
                .borrow()
                .windows_zone_id()
                .as_deref()
                .and_then(super::zones::iana_zone)
                .map(str::to_owned),
            records: vec![],
        };
        // Refuse stale scope before looking up or decoding any item.
        if !scope.ids().is_subset(&read.containers) {
            return Err(Refusal::ScopeStale);
        }
        if matches!(
            op,
            "calendars.list" | "lists.list" | "groups.list" | "mailboxes.list"
        ) {
            read.records = folders
                .into_iter()
                .map(|(id, f)| {
                    let item = match token {
                        Token::Mail => Item::Mailbox(Mailbox {
                            id,
                            title: f.title,
                            account: f.store_display_name,
                            ..Default::default()
                        }),
                        Token::Contacts => Item::Group(Group {
                            id,
                            title: f.title,
                            kind: GroupKind::Account,
                            ..Default::default()
                        }),
                        _ => Item::Container(Container {
                            id,
                            title: f.title,
                            ..Default::default()
                        }),
                    };
                    SourceRecord {
                        tagged: TaggedItem::from_item(item),
                        reminder_due: None,
                    }
                })
                .collect();
            return Ok(read);
        }
        let mut headers = vec![];
        if op.ends_with(".get") {
            self.check()?;
            if let Some(header) = self.session.borrow_mut().lookup(
                token,
                args.as_json()["id"].as_str().ok_or(Refusal::ArgsInvalid)?,
            )? {
                headers.push(header);
            }
        } else {
            for (_, folder) in folders.iter().filter(|(id, _)| scope.ids().contains(id)) {
                self.check()?;
                headers.extend(self.session.borrow_mut().items(folder, args)?);
            }
        }
        for header in headers {
            // Class filtering precedes field reads, sorting and paging. A meeting
            // request or distribution list is not a malformed mail/contact item.
            if Some(header.class) != Class::for_token(token) {
                continue;
            }
            let Ok(parent) = header.parent.encode() else {
                continue;
            };
            if !scope.ids().contains(&parent) {
                continue;
            }
            self.check()?;
            let fields = self
                .session
                .borrow_mut()
                .fields(&header, op == "messages.get")?;
            read.records.push(record(header, parent, fields, op)?);
        }
        Ok(read)
    }
}

fn record(
    header: Header,
    parent: String,
    fields: Fields,
    op: &str,
) -> Result<SourceRecord, Refusal> {
    let id = header.item_id()?;
    let mut reminder_due = None;
    let item = match (header.class, fields) {
        (Class::Appointment, Fields::Appointment(mut event)) => {
            event.id = id;
            event.calendar = parent;
            event.recurring = Some(header.original_start_ms.is_some());
            Item::Event(event)
        }
        (Class::Task, Fields::Task(mut task, due)) => {
            task.id = id;
            task.list = parent;
            task.due_ms = None;
            let no_date = NaiveDate::from_ymd_opt(4501, 1, 1).expect("Outlook sentinel date");
            reminder_due = due.filter(|due| match due {
                ReminderDue::Date(date) => *date != no_date,
                ReminderDue::LocalDateTime(local) => local.date() != no_date,
                ReminderDue::InstantMs(ms) => {
                    *ms != no_date
                        .and_hms_opt(0, 0, 0)
                        .unwrap()
                        .and_utc()
                        .timestamp_millis()
                }
            });
            Item::Reminder(task)
        }
        (Class::Contact, Fields::Contact(mut contact)) => {
            contact.id = id;
            contact.groups = vec![parent];
            Item::Contact(contact)
        }
        (Class::Mail, Fields::Mail(mut mail, body)) => {
            mail.id = id;
            mail.mailbox = parent;
            if op == "messages.get" {
                (mail.body, mail.body_state) = match body {
                    Body::Text(text) => (Some(text), BodyState::Ok),
                    Body::HeaderOnly => (None, BodyState::NotDownloaded),
                    Body::Failed => (None, BodyState::Undecodable),
                };
                Item::MailMessage(mail)
            } else {
                Item::MailSummary(MailSummary {
                    id: mail.id,
                    mailbox: mail.mailbox,
                    date_ms: mail.date_ms,
                    from: mail.from,
                    to: mail.to,
                    cc: mail.cc,
                    subject: mail.subject,
                    read: mail.read,
                    flagged: mail.flagged,
                    truncated: vec![],
                })
            }
        }
        _ => return Err(Refusal::SourceFailed),
    };
    Ok(SourceRecord {
        tagged: TaggedItem::from_item(item),
        reminder_due,
    })
}
