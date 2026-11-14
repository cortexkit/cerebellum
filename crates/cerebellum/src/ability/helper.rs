//! Async helper serving keeps exclusive use of the helper's request queue
//! through prompt teardown and the journal commit, without parking a pool thread.

use std::{io, path::Path, sync::Arc};

use cerebellum_ability::{cursor::CursorContext, filter::check_page_scope, Item, Token};
use serde_json::{json, Value};

use super::{
    journal::Summary,
    serving::{ReadOperation, ReadRequest},
    Availability, Refusal,
};
use crate::{
    ability_helper::{
        Completion, ErrorCode, Failure, HelperFuture, Launcher, Manager, PermissionStatus, Process,
        Reply, Request,
    },
    ability_source::{SourceLease, SourceUnit, UnitKind, UnitStatus},
    terminal_arbiter::TerminalArbiter,
};

pub(super) struct Helpers {
    pim: Arc<Manager>,
    fda: Arc<Manager>,
}

impl Helpers {
    pub(super) fn new(commit: String, launcher: Arc<dyn Launcher>) -> Self {
        Self {
            pim: Arc::new(Manager::new(
                UnitKind::Pim,
                commit.clone(),
                launcher.clone(),
            )),
            fda: Arc::new(Manager::new(UnitKind::Fda, commit, launcher)),
        }
    }

    pub(super) fn unverified() -> Self {
        Self::new(env!("CEREBELLUM_BUILD_REV").into(), Arc::new(Unverified))
    }

    pub(super) fn for_unit(&self, kind: UnitKind) -> Arc<Manager> {
        match kind {
            UnitKind::Pim => self.pim.clone(),
            UnitKind::Fda => self.fda.clone(),
            _ => unreachable!("in-process sources have no helper"),
        }
    }

    fn for_token(&self, token: Token) -> Arc<Manager> {
        self.for_unit(if matches!(token, Token::Messages | Token::Mail) {
            UnitKind::Fda
        } else {
            UnitKind::Pim
        })
    }
}

// The concrete macOS identity-verified launcher is supplied by the platform
// adapter. Until the adapter installs the launcher, both helpers fail closed.
struct Unverified;
impl Launcher for Unverified {
    fn start<'a>(
        &'a self,
        _: UnitKind,
        _: &'a Path,
    ) -> HelperFuture<'a, io::Result<Box<dyn Process>>> {
        Box::pin(async { Err(io::Error::other("helper is not verified")) })
    }
}

fn failure(error: Failure) -> Refusal {
    match error {
        Failure::Unverified => Refusal::Unavailable("helper_unverified"),
        Failure::RevisionMismatch => Refusal::Unavailable("helper_revision_mismatch"),
        Failure::TimedOut => Refusal::SourceTimeout,
        Failure::Failed | Failure::Stopped => Refusal::SourceFailed,
    }
}

fn reply(completion: Completion) -> Result<Reply, Refusal> {
    match completion {
        Completion::Reply(Reply::Error { code }) => Err(match code {
            ErrorCode::AbilityScopeStale => Refusal::ScopeStale,
            ErrorCode::AbilityItemNotFound => Refusal::ItemNotFound,
            ErrorCode::AbilitySourceTimeout => Refusal::SourceTimeout,
            ErrorCode::AbilitySourceFailed => Refusal::SourceFailed,
        }),
        Completion::Reply(reply) => Ok(reply),
        Completion::Unanswered => Err(Refusal::SourceFailed),
    }
}

async fn statuses(
    helper: &Manager,
    tokens: &[Token],
    lease: &SourceLease,
    gate: &TerminalArbiter,
) -> Result<Vec<(Token, Availability)>, Refusal> {
    let result = helper
        .request(
            Request::Status {
                tokens: tokens.to_vec(),
            },
            lease.source_deadline(),
            gate,
        )
        .await
        .map_err(failure)?;
    let Reply::Status { tokens: values } = reply(result)? else {
        return Err(Refusal::SourceFailed);
    };
    if values.len() != tokens.len()
        || tokens
            .iter()
            .any(|token| values.iter().filter(|v| v.token == *token).count() != 1)
    {
        helper.invalidate().await;
        return Err(Refusal::SourceFailed);
    }
    Ok(values
        .into_iter()
        .map(|value| {
            (
                value.token,
                Availability {
                    unavailable_reason: value.status.unavailable_reason(),
                },
            )
        })
        .collect())
}

pub(super) async fn describe(
    unit: &SourceUnit,
    helper: &Manager,
    gate: Arc<TerminalArbiter>,
    tokens: &'static [Token],
) -> UnitStatus<Vec<(Token, Availability)>> {
    let lease = match unit.arrive(gate.clone()) {
        Ok(ticket) => match ticket.wait().await {
            Ok(lease) => lease,
            Err(_) => return UnitStatus::SourceUnresponsive,
        },
        Err(_) => return UnitStatus::SourceUnresponsive,
    };
    match statuses(helper, tokens, &lease, &gate).await {
        Ok(values) => UnitStatus::Responsive(values),
        Err(Refusal::Unavailable(reason @ ("helper_unverified" | "helper_revision_mismatch"))) => {
            UnitStatus::Responsive(
                tokens
                    .iter()
                    .map(|&token| (token, Availability::unavailable(reason)))
                    .collect(),
            )
        }
        _ => UnitStatus::SourceUnresponsive,
    }
}

pub(super) async fn serve(
    helpers: &Helpers,
    lease: &SourceLease,
    request: ReadRequest,
) -> Result<Option<Value>, Refusal> {
    let completion = request._reservation.completion();
    let gate = request.gate.clone();
    let result = serve_inner(helpers, lease, request).await;
    *completion.lock().unwrap() = Some(Summary::from_result(&result));
    if gate.gate.stopped() {
        Ok(None)
    } else {
        result
    }
}

async fn serve_inner(
    helpers: &Helpers,
    lease: &SourceLease,
    request: ReadRequest,
) -> Result<Option<Value>, Refusal> {
    if request.gate.gate.stopped() {
        return Ok(None);
    }
    let token = request.token;
    let helper = helpers.for_token(token);
    let deadline = lease.source_deadline();
    let gate = &request.gate;
    let wire = match &request.operation {
        ReadOperation::Setup => Request::Setup { token },
        operation => {
            let status = statuses(&helper, &[token], lease, gate).await;
            if gate.gate.stopped() {
                return Ok(None);
            }
            if let Some(reason) = status?
                .into_iter()
                .next()
                .expect("one status")
                .1
                .unavailable_reason
            {
                return Err(Refusal::Unavailable(reason));
            }
            match operation {
                ReadOperation::Choices { key, limit, cursor } => Request::Choices {
                    token,
                    key: key.clone(),
                    limit: *limit,
                    cursor: cursor.clone(),
                },
                ReadOperation::Call { op, args, scope } => Request::Call {
                    token,
                    op: op.clone(),
                    args: args.as_json().clone(),
                    scope: json!({token.info().scope_key: scope.ids()}),
                },
                ReadOperation::Setup => unreachable!(),
            }
        }
    };
    let result = match helper.request(wire, deadline, gate).await {
        Err(Failure::Stopped) => return Ok(None),
        result => result.map_err(failure)?,
    };
    if matches!(result, Completion::Unanswered) {
        return Ok(Some(json!({"state":"unanswered"})));
    }
    let result = match (request.operation, reply(result)?) {
        (ReadOperation::Setup, Reply::Setup { status }) => setup_reply(&helper, token, status),
        (operation, Reply::Result { value }) => validate_result(token, operation, value),
        _ => Err(Refusal::SourceFailed),
    };
    if matches!(result, Err(Refusal::SourceFailed)) {
        helper.invalidate().await;
    }
    result.map(Some)
}

fn setup_reply(helper: &Manager, token: Token, status: PermissionStatus) -> Result<Value, Refusal> {
    use PermissionStatus::*;
    match status {
        SourceMissing => Err(Refusal::Unavailable("source_missing")),
        PermissionMissing if matches!(token, Token::Messages | Token::Mail) => {
            let path = helper
                .executable_path()
                .map_err(|_| Refusal::Unavailable("helper_unverified"))?;
            Ok(json!({"state":"needs_person_action", "executable_path":path}))
        }
        Granted => Ok(json!({"state":"granted"})),
        FormatUnrecognized if matches!(token, Token::Messages | Token::Mail) => {
            Ok(json!({"state":"granted"}))
        }
        Denied | Restricted | WriteOnly | PermissionMissing => Ok(json!({"state":"denied"})),
        _ => Err(Refusal::SourceFailed),
    }
}

fn validate_result(
    token: Token,
    operation: ReadOperation,
    mut value: Value,
) -> Result<Value, Refusal> {
    let object = value.as_object().ok_or(Refusal::SourceFailed)?;
    match operation {
        ReadOperation::Call { op, args, scope } => {
            let operation = token.operation(&op).expect("validated operation");
            let (items, cursor) = if operation.is_list {
                if object
                    .keys()
                    .any(|key| key != "items" && key != "next_cursor")
                {
                    return Err(Refusal::SourceFailed);
                }
                (
                    object
                        .get("items")
                        .and_then(Value::as_array)
                        .ok_or(Refusal::SourceFailed)?
                        .clone(),
                    object.get("next_cursor").cloned(),
                )
            } else {
                if object.len() != 1 {
                    return Err(Refusal::SourceFailed);
                }
                (
                    vec![object.get("item").ok_or(Refusal::SourceFailed)?.clone()],
                    None,
                )
            };
            if items.len()
                > args
                    .as_json()
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(100) as usize
            {
                return Err(Refusal::SourceFailed);
            }
            let mut items = items
                .into_iter()
                .map(|item| {
                    Item::from_json(operation.item_kind, item).map_err(|_| Refusal::SourceFailed)
                })
                .collect::<Result<Vec<_>, _>>()?;
            check_page_scope(&scope, &items).map_err(|_| Refusal::SourceFailed)?;
            for item in &mut items {
                item.normalize().map_err(|_| Refusal::SourceFailed)?;
            }
            if let Some(cursor) = cursor {
                if items.is_empty() {
                    return Err(Refusal::SourceFailed);
                }
                let cursor = cursor.as_str().ok_or(Refusal::SourceFailed)?;
                CursorContext::for_call(token, &op, &args, &scope)
                    .and_then(|ctx| ctx.validate(cursor))
                    .map_err(|_| Refusal::SourceFailed)?;
            }
            if serde_json::to_vec(&items)
                .map_err(|_| Refusal::SourceFailed)?
                .len()
                > cerebellum_ability::page::MAX_PAGE_BYTES
            {
                return Err(Refusal::SourceFailed);
            }
            if operation.is_list {
                value["items"] = json!(items);
            } else {
                if items[0].id() != args.as_json()["id"].as_str().expect("validated id") {
                    return Err(Refusal::SourceFailed);
                }
                value["item"] = json!(items[0]);
            }
        }
        ReadOperation::Choices { key, limit, .. } => {
            if object
                .keys()
                .any(|key| key != "choices" && key != "next_cursor")
            {
                return Err(Refusal::SourceFailed);
            }
            let choices = object
                .get("choices")
                .and_then(Value::as_array)
                .ok_or(Refusal::SourceFailed)?;
            if choices.len() > limit.unwrap_or(100)
                || serde_json::to_vec(choices)
                    .map_err(|_| Refusal::SourceFailed)?
                    .len()
                    > cerebellum_ability::page::MAX_PAGE_BYTES
            {
                return Err(Refusal::SourceFailed);
            }
            for choice in choices {
                let id = choice["id"].as_str().ok_or(Refusal::SourceFailed)?;
                if id.is_empty()
                    || id.len() > 2048
                    || choice["label"]
                        .as_str()
                        .is_none_or(|label| label.len() > 1024)
                {
                    return Err(Refusal::SourceFailed);
                }
            }
            if let Some(cursor) = object.get("next_cursor") {
                if choices.is_empty() {
                    return Err(Refusal::SourceFailed);
                }
                let cursor = cursor.as_str().ok_or(Refusal::SourceFailed)?;
                CursorContext::for_choices(token, &key)
                    .and_then(|ctx| ctx.validate(cursor))
                    .map_err(|_| Refusal::SourceFailed)?;
            }
        }
        ReadOperation::Setup => return Err(Refusal::SourceFailed),
    }
    Ok(value)
}
