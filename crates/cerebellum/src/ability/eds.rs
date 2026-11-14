//! Host-neutral EDS reads. The native D-Bus adapter supplies a request-local bus.

// No native bus factory is installed yet. Keep the seam available on every host
// so its fake exercises the same filtering and parsers as the eventual adapter.
#![cfg_attr(not(test), allow(dead_code))]

use std::{cell::RefCell, sync::Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use cerebellum_ability::{
    events::parse_occurrence_id,
    filter::TaggedItem,
    ical::{Calendar, ParseError},
    ids::validate_id,
    items::{Container, Group, GroupKind},
    time::SourceTimeZone,
    vcard, BoundScope, Item, Token, ValidatedArgs,
};
use serde_json::Value;

use super::{
    serving::{self, ReadAccess, ReadRequest, SourceRead, SourceRecord},
    Availability, Refusal, StatusSource,
};
use crate::terminal_arbiter::TerminalArbiter;

// EDS build config names Calendar8 and AddressBook10; packaged EDS service
// definitions (Fedora/Azure Linux evolution-data-server.spec) name Sources5.
// Accept only these interface generations, not an arbitrary version suffix.
pub(super) const ACCEPTED_BUS_NAMES: [&str; 3] = [
    "org.gnome.evolution.dataserver.Sources5",
    "org.gnome.evolution.dataserver.Calendar8",
    "org.gnome.evolution.dataserver.AddressBook10",
];
const BUS_PREFIXES: [&str; 3] = [
    "org.gnome.evolution.dataserver.Sources",
    "org.gnome.evolution.dataserver.Calendar",
    "org.gnome.evolution.dataserver.AddressBook",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Calendar,
    TaskList,
    AddressBook,
}

impl Kind {
    fn for_token(token: Token) -> Result<Self, Refusal> {
        match token {
            Token::Calendar => Ok(Self::Calendar),
            Token::Reminders => Ok(Self::TaskList),
            Token::Contacts => Ok(Self::AddressBook),
            _ => Err(Refusal::SourceFailed),
        }
    }
}

#[derive(Clone)]
pub(super) struct Source {
    pub uid: String,
    pub kind: Kind,
    pub label: String,
}

/// No activation operation is exposed. The native implementation must set
/// NO_AUTO_START on every EDS call, even after its owner check succeeds.
pub(super) trait BusFactory: Send + Sync + 'static {
    fn connect(&self) -> Result<Box<dyn Bus>, Refusal>;
}

pub(super) trait Bus {
    /// ListNames/GetNameOwner evidence only, never ListActivatableNames.
    fn owned_names(&self) -> Result<Vec<String>, Refusal>;
    fn system_iana_zone(&self) -> Option<String>;
    fn sources(&mut self) -> Result<Vec<Source>, Refusal>;
    fn open_client(&mut self, source: &Source) -> Result<Box<dyn Client>, Refusal>;
}

/// A client is attached to exactly one EDS source. Its identity comes from that
/// attachment, not from the request scope or from a scope-wide multi-source view.
pub(super) trait Client {
    fn source_uid(&self) -> &str;
    /// Each string is one vCard, or one calendar UID's complete object including
    /// its master, every detached override and referenced VTIMEZONE definitions.
    fn objects(&mut self) -> Result<Vec<String>, Refusal>;
    fn object(&mut self, uid: &str) -> Result<Option<String>, Refusal>;
}

pub(super) struct EdsSource {
    factory: Option<Arc<dyn BusFactory>>,
}

impl EdsSource {
    pub(super) fn new(factory: Option<Arc<dyn BusFactory>>) -> Self {
        Self { factory }
    }

    fn open(&self, gate: Option<Arc<TerminalArbiter>>) -> Result<Access, Refusal> {
        let bus = self
            .factory
            .as_ref()
            .ok_or(Refusal::Unavailable("data_service_missing"))?
            .connect()?;
        Ok(Access {
            bus: RefCell::new(bus),
            gate,
        })
    }
}

impl StatusSource for EdsSource {
    fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
        match self.open(None) {
            Ok(access) => access.status(tokens),
            Err(Refusal::Unavailable(reason)) => Ok(tokens
                .iter()
                .map(|&t| (t, Availability::unavailable(reason)))
                .collect()),
            Err(_) => Err(()),
        }
    }

    fn request(&self, request: ReadRequest) -> Result<Option<Value>, Refusal> {
        let gate = request.gate.clone();
        if gate.gate.stopped() {
            return Ok(None);
        }
        let result = self
            .open(Some(gate.clone()))
            .and_then(|access| serving::read_inner(&access, request));
        if gate.gate.stopped() {
            Ok(None)
        } else {
            result
        }
    }
}

struct Access {
    bus: RefCell<Box<dyn Bus>>,
    gate: Option<Arc<TerminalArbiter>>,
}

impl Access {
    fn check(&self) -> Result<(), Refusal> {
        if self.gate.as_ref().is_some_and(|g| g.gate.stopped()) {
            Err(Refusal::SourceFailed)
        } else {
            Ok(())
        }
    }

    fn sources(&self, token: Token) -> Result<Vec<Source>, Refusal> {
        self.check()?;
        let kind = Kind::for_token(token)?;
        Ok(self
            .bus
            .borrow_mut()
            .sources()?
            .into_iter()
            .filter(|s| s.kind == kind && validate_id("source", &s.uid).is_ok())
            .collect())
    }
}

fn availability(names: &[String], token: Token) -> Availability {
    let factory = if token == Token::Contacts { 2 } else { 1 };
    let required = [0, factory];
    // A missing required owner wins over an unsupported version of the other
    // service: no call to an unowned service is allowed to activate it.
    if required
        .iter()
        .any(|&i| !names.iter().any(|n| n.starts_with(BUS_PREFIXES[i])))
    {
        return Availability::unavailable("data_service_missing");
    }
    if required
        .iter()
        .any(|&i| !names.iter().any(|n| n == ACCEPTED_BUS_NAMES[i]))
    {
        return Availability::unavailable("format_unrecognized");
    }
    Availability {
        unavailable_reason: None,
    }
}

impl ReadAccess for Access {
    fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
        self.check().map_err(|_| ())?;
        let names = self.bus.borrow().owned_names().map_err(|_| ())?;
        Ok(tokens
            .iter()
            .map(|&t| (t, availability(&names, t)))
            .collect())
    }

    fn choices(&self, token: Token) -> Result<Vec<serving::ScopeChoice>, Refusal> {
        Ok(self
            .sources(token)?
            .into_iter()
            .map(|s| serving::ScopeChoice {
                id: s.uid,
                label: s.label,
                kind: (token == Token::Contacts).then_some(GroupKind::Account),
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
        let sources = self.sources(token)?;
        let mut read = SourceRead {
            containers: sources.iter().map(|s| s.uid.clone()).collect(),
            time_zone: None,
            records: vec![],
        };
        if !scope.ids().is_subset(&read.containers) {
            return Err(Refusal::ScopeStale);
        }
        if matches!(op, "calendars.list" | "lists.list" | "groups.list") {
            read.records = sources
                .into_iter()
                .map(|s| {
                    record(if token == Token::Contacts {
                        Item::Group(Group {
                            id: s.uid,
                            title: Some(s.label),
                            kind: GroupKind::Account,
                            ..Default::default()
                        })
                    } else {
                        Item::Container(Container {
                            id: s.uid,
                            title: Some(s.label),
                            ..Default::default()
                        })
                    })
                })
                .collect();
            return Ok(read);
        }
        if token != Token::Contacts {
            self.check()?;
            read.time_zone = self.bus.borrow().system_iana_zone();
            SourceTimeZone::from_iana_name(read.time_zone.as_deref())
                .map_err(|_| Refusal::SourceFailed)?;
        }
        let get = op.ends_with(".get");
        let target = if get {
            decode_id(args.as_json()["id"].as_str().ok_or(Refusal::ArgsInvalid)?)
        } else {
            None
        };
        if get && target.is_none() {
            return Ok(read);
        }
        for source in sources.iter().filter(|s| scope.ids().contains(&s.uid)) {
            if get && target.as_ref().is_some_and(|(s, _)| s != &source.uid) {
                continue;
            }
            self.check()?;
            let mut client = self.bus.borrow_mut().open_client(source)?;
            let actual_source = client.source_uid().to_owned();
            // Filter before parsing, too. A misdirected client must not leak an
            // unbound source's text or malformed-object presence through get.
            if !scope.ids().contains(&actual_source) {
                continue;
            }
            self.check()?;
            let objects = if let Some((_, local)) = &target {
                let uid = if token == Token::Calendar {
                    parse_occurrence_id(local)
                        .map(|(uid, _)| uid)
                        .unwrap_or_else(|_| local.clone())
                } else {
                    local.clone()
                };
                client.object(&uid)?.into_iter().collect()
            } else {
                client.objects()?
            };
            for text in objects {
                read.records.extend(project(
                    token,
                    args,
                    &actual_source,
                    &text,
                    read.time_zone.as_deref(),
                    target.as_ref().map(|(_, id)| id.as_str()),
                )?);
            }
        }
        Ok(read)
    }
}

fn record(item: Item) -> SourceRecord {
    SourceRecord {
        tagged: TaggedItem::from_item(item),
        reminder_due: None,
    }
}

fn project(
    token: Token,
    args: &ValidatedArgs,
    source: &str,
    text: &str,
    zone: Option<&str>,
    target: Option<&str>,
) -> Result<Vec<SourceRecord>, Refusal> {
    let failed = |error| match error {
        ParseError::Unsupported if token == Token::Calendar => Refusal::RecurrenceUnsupported,
        ParseError::Unsupported
        | ParseError::Syntax
        | ParseError::SourceTimeZone
        | ParseError::IdTooLong => Refusal::SourceFailed,
    };
    let items: Vec<Item> = match token {
        Token::Contacts => {
            // EDS returns individual vCards. Silently dropping a malformed card
            // would return an incomplete successful page. Returning partial
            // results with an error disclosure needs a wire-contract change.
            // A get parses only its own card, not malformed siblings.
            let contacts = vcard::parse(text).map_err(|_| Refusal::SourceFailed)?;
            if contacts.len() != 1 {
                return Err(Refusal::SourceFailed);
            }
            contacts
                .into_iter()
                .map(|mut c| {
                    c.groups = vec![source.to_owned()];
                    Item::Contact(c)
                })
                .collect()
        }
        Token::Calendar | Token::Reminders => {
            // Parse one UID at a time, keeping its master and overrides together.
            let calendar = Calendar::parse(text, zone).map_err(failed)?;
            if token == Token::Calendar {
                let events = if let Some(id) = target {
                    calendar
                        .event(source, id)
                        .map_err(failed)?
                        .into_iter()
                        .collect()
                } else {
                    calendar
                        .events(
                            source,
                            args.as_json()["from_ms"]
                                .as_i64()
                                .ok_or(Refusal::ArgsInvalid)?,
                            args.as_json()["to_ms"]
                                .as_i64()
                                .ok_or(Refusal::ArgsInvalid)?,
                        )
                        .map_err(failed)?
                };
                events.into_iter().map(Item::Event).collect()
            } else {
                calendar
                    .reminders(source)
                    .map_err(failed)?
                    .into_iter()
                    .map(Item::Reminder)
                    .collect()
            }
        }
        _ => return Err(Refusal::SourceFailed),
    };
    items
        .into_iter()
        .map(|mut item| {
            let encoded = encode_id(source, item.id())?;
            match &mut item {
                Item::Contact(c) => c.id = encoded,
                Item::Event(e) => e.id = encoded,
                Item::Reminder(r) => r.id = encoded,
                _ => return Err(Refusal::SourceFailed),
            }
            Ok(record(item))
        })
        .collect()
}

/// Include the actual source UID because EDS object UIDs need not be unique
/// across sources. The local event id retains the iCalendar occurrence's identity.
pub(super) fn encode_id(source: &str, local: &str) -> Result<String, Refusal> {
    validate_id("source", source).map_err(|_| Refusal::SourceFailed)?;
    validate_id("id", local).map_err(|_| Refusal::SourceFailed)?;
    let id = format!(
        "eds1.{}.{}",
        URL_SAFE_NO_PAD.encode(source),
        URL_SAFE_NO_PAD.encode(local)
    );
    validate_id("id", &id).map_err(|_| Refusal::SourceFailed)?;
    Ok(id)
}

fn decode_id(id: &str) -> Option<(String, String)> {
    let (source, local) = id.strip_prefix("eds1.")?.split_once('.')?;
    let source = String::from_utf8(URL_SAFE_NO_PAD.decode(source).ok()?).ok()?;
    let local = String::from_utf8(URL_SAFE_NO_PAD.decode(local).ok()?).ok()?;
    (encode_id(&source, &local).ok()?.as_str() == id).then_some((source, local))
}
