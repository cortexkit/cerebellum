//! Reserved, host-neutral reads. Production cannot enter without a journal proof.

use std::{collections::BTreeSet, sync::Arc};

pub(super) use cerebellum_ability::page::ScopeChoice;
use cerebellum_ability::{
    filter::{retain_in_scope, scoped_get, TaggedItem},
    page::{build_choices_page, build_page},
    time::{ReminderDue, SourceTimeZone},
    BoundScope, Item, Token, ValidatedArgs,
};
use serde_json::{Map, Value};

use super::{
    journal::{ReservedRead, Summary},
    AbilityPlane, Refusal, StatusSource,
};
use crate::{
    ability_source::{SourceLease, SourceOutcome},
    terminal_arbiter::TerminalArbiter,
};

pub(super) struct SourceRead {
    /// All currently existing containers, including empty ones. Check every
    /// bound id before inspecting items, so a stale scope cannot yield a partial page.
    pub containers: BTreeSet<String>,
    /// Required for every events/reminders list and get, even an empty read.
    pub time_zone: Option<String>,
    pub records: Vec<SourceRecord>,
}

pub(super) struct SourceRecord {
    pub tagged: TaggedItem,
    /// A source's floating/date-only due value. Already-resolved reminder
    /// instants may instead be carried in the item's due_ms.
    pub reminder_due: Option<ReminderDue>,
}

pub(super) struct ReadRequest {
    pub(super) _reservation: ReservedRead,
    pub(super) token: Token,
    pub(super) operation: ReadOperation,
    pub(super) gate: Arc<TerminalArbiter>,
}

pub(super) enum ReadOperation {
    Setup,
    Choices {
        key: String,
        limit: Option<usize>,
        cursor: Option<String>,
    },
    Call {
        op: String,
        args: ValidatedArgs,
        scope: BoundScope,
    },
}

impl ReadRequest {
    pub(super) fn setup(proof: ReservedRead, token: Token, gate: Arc<TerminalArbiter>) -> Self {
        Self {
            _reservation: proof,
            token,
            gate,
            operation: ReadOperation::Setup,
        }
    }
    pub(super) fn call(
        proof: ReservedRead,
        token: Token,
        op: &str,
        args: ValidatedArgs,
        scope: BoundScope,
        gate: Arc<TerminalArbiter>,
    ) -> Self {
        Self {
            _reservation: proof,
            token,
            gate,
            operation: ReadOperation::Call {
                op: op.into(),
                args,
                scope,
            },
        }
    }

    pub(super) fn choices(
        proof: ReservedRead,
        token: Token,
        params: &Map<String, Value>,
        gate: Arc<TerminalArbiter>,
    ) -> Self {
        Self {
            _reservation: proof,
            token,
            gate,
            operation: ReadOperation::Choices {
                key: params["key"]
                    .as_str()
                    .expect("validated choices key")
                    .into(),
                limit: params
                    .get("limit")
                    .map(|v| v.as_u64().expect("validated limit") as usize),
                cursor: params
                    .get("cursor")
                    .map(|v| v.as_str().expect("validated cursor").into()),
            },
        }
    }
}

impl AbilityPlane {
    /// The journaled handler keeps this lease through reservation, read and
    /// commit; serving does not acquire a second position in the same unit.
    pub(super) async fn serve(
        &self,
        lease: &mut SourceLease,
        request: ReadRequest,
    ) -> Result<Option<Value>, Refusal> {
        if let Some(helpers) = &self.helpers {
            return super::helper::serve(helpers, lease, request).await;
        }
        match lease.request(self.source.clone(), request).await {
            SourceOutcome::Completed(reply) => reply,
            SourceOutcome::Discarded(_) | SourceOutcome::Stopped => Ok(None),
            SourceOutcome::TimedOut => Err(Refusal::SourceTimeout),
            SourceOutcome::WorkerFailed => Err(Refusal::SourceFailed),
        }
    }
}

/// Preflight and data access share one blocking closure and one source deadline.
/// No session or thread-affine source handle crosses back to the async handler.
pub(super) fn read(
    source: &dyn StatusSource,
    request: ReadRequest,
) -> Result<Option<Value>, Refusal> {
    let completion = request._reservation.completion();
    let result = read_inner(source, request);
    *completion.lock().unwrap() = Some(Summary::from_result(&result));
    result
}

fn read_inner(source: &dyn StatusSource, request: ReadRequest) -> Result<Option<Value>, Refusal> {
    if request.gate.gate.stopped() {
        return Ok(None);
    }
    let token = request.token;
    if matches!(request.operation, ReadOperation::Setup) {
        return source.setup(token).map(Some);
    }
    let tokens: &'static [Token] = match token {
        Token::Calendar => &[Token::Calendar],
        Token::Reminders => &[Token::Reminders],
        Token::Contacts => &[Token::Contacts],
        Token::Messages => &[Token::Messages],
        Token::Mail => &[Token::Mail],
    };
    let availability = source
        .status(tokens)
        .map_err(|_| Refusal::SourceFailed)?
        .into_iter()
        .find(|(candidate, _)| *candidate == token)
        .ok_or(Refusal::SourceFailed)?
        .1;
    // Status may block until after cancellation. Do not begin the next source
    // step; SourceLease will discard this stopped closure's empty result.
    if request.gate.gate.stopped() {
        return Ok(None);
    }
    if let Some(reason) = availability.unavailable_reason {
        return Err(if reason == "source_unresponsive" {
            Refusal::SourceTimeout
        } else {
            Refusal::Unavailable(reason)
        });
    }
    read_available(source, token, request.operation).map(Some)
}

fn read_available(
    source: &dyn StatusSource,
    token: Token,
    operation: ReadOperation,
) -> Result<Value, Refusal> {
    match operation {
        ReadOperation::Setup => unreachable!("setup is served without read preflight"),
        ReadOperation::Choices { key, limit, cursor } => {
            let choices = source.choices(token)?;
            let page = build_choices_page(token, &key, limit, cursor.as_deref(), choices)
                .map_err(failed)?;
            serde_json::to_value(page).map_err(failed)
        }
        ReadOperation::Call { op, args, scope } => {
            let read = source.read(token, &op, &args, &scope)?;
            if !scope.ids().is_subset(&read.containers) {
                return Err(Refusal::ScopeStale);
            }
            let zone = if op.starts_with("events.") || op.starts_with("reminders.") {
                Some(SourceTimeZone::from_iana_name(read.time_zone.as_deref()).map_err(failed)?)
            } else {
                None
            };
            let mut items = Vec::with_capacity(read.records.len());
            for mut record in read.records {
                let Some(item) = retain_in_scope(&scope, record.tagged) else {
                    continue;
                };
                // Discard other containers before conversion too: a malformed
                // out-of-scope record must not reveal its presence through get.
                record.tagged = TaggedItem::from_item(item);
                if let Some(zone) = zone {
                    match &mut record.tagged.item {
                        Item::Event(event) => zone.normalize_event(event).map_err(failed)?,
                        Item::Reminder(reminder) => {
                            if let Some(due) = record.reminder_due {
                                reminder.due_ms =
                                    zone.reminder_due_ms(Some(due)).map_err(failed)?;
                            }
                        }
                        _ => {}
                    }
                }
                items.push(record.tagged);
            }
            let operation = token.operation(&op).expect("validated operation");
            if operation.is_list {
                let page = build_page(token, &op, &args, &scope, items).map_err(failed)?;
                serde_json::to_value(page).map_err(failed)
            } else {
                let id = args.as_json()["id"].as_str().expect("validated get id");
                let mut candidates = items.into_iter().filter(|item| item.item.id() == id);
                let candidate = candidates.next();
                if candidates.next().is_some() {
                    return Err(Refusal::SourceFailed);
                }
                let item = scoped_get(&scope, candidate)
                    .map_err(failed)?
                    .ok_or(Refusal::ItemNotFound)?;
                if item.kind() != operation.item_kind {
                    return Err(Refusal::SourceFailed);
                }
                Ok(serde_json::json!({"item": item}))
            }
        }
    }
}

fn failed<E>(_: E) -> Refusal {
    Refusal::SourceFailed
}
