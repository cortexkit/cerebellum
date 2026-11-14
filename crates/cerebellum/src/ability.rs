//! Management-only personal-data ability admission, bindings and descriptions.

use std::sync::Arc;

use cerebellum_ability::{
    cursor::CursorContext,
    schema::token_schemas,
    tokens::{Platform, Token},
    validate_args, validate_scope, BoundScope, ValidatedArgs,
};
use serde_json::{json, Map, Value};
use subc_protocol::{call_mode::CallMode, scope::ScopeKind, Frame, Principal};

use crate::{
    ability_source::{QueueError, Source, SourceUnit, SourceUnits, UnitStatus},
    terminal_arbiter::TerminalArbiter,
    AcceptedBindFacts, ModuleError, Planes,
};

mod binding;
use binding::{BindingReader, UnavailableBindingReader};

pub(crate) const DESCRIBE: &str = "ability.describe";
pub(crate) const SCOPE_CHOICES: &str = "ability.scope_choices";
pub(crate) const SETUP: &str = "ability.setup";
pub(crate) const CALL: &str = "ability.call";
pub(crate) const OPERATIONS: [&str; 4] = [DESCRIBE, SCOPE_CHOICES, SETUP, CALL];

pub(crate) fn is_operation(method: &str) -> bool {
    OPERATIONS.contains(&method)
}

pub(crate) const fn platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::MacOs
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Linux
    }
}

/// The manifest declares a build's potential, not the person's current access.
/// Catalog tokens and SUBC capability identifiers use different spellings.
pub(crate) fn manifest_capabilities() -> impl Iterator<Item = String> {
    platform().tokens().iter().map(|token| {
        map_capability(token.as_str()).expect("declared ability token has a manifest form")
    })
}

/// Map either catalog-token or manifest spelling to the other. Area and verb
/// contain no hyphens, so the reverse mapping is unambiguous.
fn map_capability(value: &str) -> Option<String> {
    fn part(value: &str) -> bool {
        value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }
    if let Some(value) = value.strip_prefix("cap/") {
        let (name, version) = value.split_once('@')?;
        let mut parts = name.split('.');
        let area = parts.next()?;
        let verb = parts.next();
        if !part(area) || verb.is_some_and(|verb| !part(verb)) || parts.next().is_some() {
            return None;
        }
        let capability = format!("cap-{}/v{version}", name.replace('.', "-"));
        subc_protocol::manifest::is_valid_capability_identifier(&capability).then_some(capability)
    } else {
        if !subc_protocol::manifest::is_valid_capability_identifier(value) {
            return None;
        }
        let (name, version) = value.strip_prefix("cap-")?.split_once("/v")?;
        let mut parts = name.split('-');
        let area = parts.next()?;
        let verb = parts.next();
        if !part(area) || verb.is_some_and(|verb| !part(verb)) || parts.next().is_some() {
            return None;
        }
        Some(format!("cap/{}@{version}", name.replace('-', ".")))
    }
}

/// Status adapters return one availability value per requested token. No adapter
/// is installed until its platform source and non-prompting preflight are ready.
trait StatusSource: Send + Sync + 'static {
    fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()>;
}

#[derive(Clone, Copy)]
struct Availability {
    unavailable_reason: Option<&'static str>,
}

impl Availability {
    fn unavailable(reason: &'static str) -> Self {
        Self {
            unavailable_reason: Some(reason),
        }
    }
}

struct UnavailableSource(Platform);
impl StatusSource for UnavailableSource {
    fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
        let reason = match self.0 {
            Platform::MacOs => "helper_unverified",
            Platform::Windows => "classic_outlook_missing",
            Platform::Linux => "data_service_missing",
        };
        Ok(tokens
            .iter()
            .map(|&token| (token, Availability::unavailable(reason)))
            .collect())
    }
}

struct StatusAdapter(Arc<dyn StatusSource>);
impl Source for StatusAdapter {
    type Request = ();
    type Reply = ();
    type Status = Vec<(Token, Availability)>;
    type Error = ();

    fn request(&self, (): ()) -> Result<(), ()> {
        Err(())
    }

    fn status(&self, tokens: &'static [Token]) -> Result<Self::Status, ()> {
        self.0.status(tokens)
    }
}

pub(crate) struct AbilityPlane {
    platform: Platform,
    units: SourceUnits,
    source: Arc<StatusAdapter>,
    binding: Arc<dyn BindingReader>,
}

impl Default for AbilityPlane {
    fn default() -> Self {
        Self::new(platform(), Arc::new(UnavailableSource(platform())))
    }
}

impl AbilityPlane {
    fn new(platform: Platform, source: Arc<dyn StatusSource>) -> Self {
        Self {
            platform,
            units: SourceUnits::new(platform),
            source: Arc::new(StatusAdapter(source)),
            binding: Arc::new(UnavailableBindingReader),
        }
    }

    async fn describe(&self, gate: Arc<TerminalArbiter>) -> Value {
        let mut checks = tokio::task::JoinSet::new();
        for unit in self.units.iter() {
            let unit: SourceUnit = unit.clone();
            let source = self.source.clone();
            let gate = gate.clone();
            checks.spawn(async move { unit.status(source, gate).await });
        }
        let mut statuses = Vec::new();
        while let Some(result) = checks.join_next().await {
            if let Ok(UnitStatus::Responsive(values)) = result {
                statuses.extend(values);
            }
        }
        let tokens: Vec<_> = token_schemas(self.platform)
            .into_iter()
            .map(|schema| {
                let availability = statuses
                    .iter()
                    .find(|(token, _)| *token == schema.token)
                    .map(|(_, availability)| *availability)
                    .unwrap_or(Availability::unavailable("source_unresponsive"));
                let mut entry =
                    serde_json::to_value(schema).expect("static token schema serializes");
                entry["available"] = json!(availability.unavailable_reason.is_none());
                if let Some(reason) = availability.unavailable_reason {
                    entry["unavailable_reason"] = json!(reason);
                }
                entry
            })
            .collect();
        json!({"tokens": tokens})
    }

    async fn call(
        &self,
        facts: &AcceptedBindFacts,
        params: &Map<String, Value>,
        token: Token,
        gate: Arc<TerminalArbiter>,
    ) -> Result<Option<Value>, Refusal> {
        let op = params["op"].as_str().expect("validated op type");
        if token.operation(op).is_none() {
            return Err(Refusal::OpUnknown);
        }
        let scope = validate_scope(token, &params["scope"]).map_err(|_| Refusal::ScopeInvalid)?;
        let args = validate_args(token, op, &params["args"]).map_err(|_| Refusal::ArgsInvalid)?;
        if let Some(cursor) = args.cursor() {
            CursorContext::for_call(token, op, &args, &scope)
                .and_then(|context| context.validate(cursor))
                .map_err(|_| Refusal::ArgsInvalid)?;
        }
        check_message_scope(token, op, &args, &scope)?;
        let key = params["key"].as_str().expect("validated key type");
        let Some(install) = binding::authorize(
            self.binding.as_ref(),
            facts.flow_id.as_deref().expect("admitted flow"),
            key,
            &scope,
            &gate,
        )
        .await?
        else {
            return Ok(None);
        };
        let unit = self.units.for_token(token).expect("declared token unit");
        let lease = match unit.arrive(gate).map(|ticket| ticket.wait()) {
            Ok(wait) => wait.await,
            Err(error) => Err(error),
        };
        match lease {
            Err(QueueError::Stopped) => Ok(None),
            Err(QueueError::SourceTimeout) => Err(Refusal::SourceTimeout),
            Ok(_lease) => Err(pending_call(install)),
        }
    }
}

fn check_message_scope(
    token: Token,
    op: &str,
    args: &ValidatedArgs,
    scope: &BoundScope,
) -> Result<(), Refusal> {
    if op == "messages.list" && matches!(token, Token::Messages | Token::Mail) {
        let id = args.as_json()[token.info().scope_key]
            .as_str()
            .expect("validated message container");
        if !scope.contains(id) {
            return Err(Refusal::OutOfScope);
        }
    }
    Ok(())
}

fn admitted(facts: &AcceptedBindFacts, method: &str, origin_present: bool) -> bool {
    let stamped_flow = facts
        .scope
        .as_ref()
        .and_then(|stamp| stamp.attributes.flow_id.as_ref());
    let core = matches!(&facts.principal, Some(Principal::Reserved { module_id }) if module_id == "prefrontal-core")
        && facts.flow_id.is_none()
        && stamped_flow.is_none()
        && facts.call_mode == CallMode::Classic
        && facts.codemode_head.is_none()
        && !facts.acts_as_agent
        && facts
            .scope
            .as_ref()
            .is_none_or(|stamp| stamp.attributes.run_id.is_none());
    let flow = facts.flow_id.is_some()
        && matches!(&facts.principal, Some(Principal::Reserved { module_id }) if module_id == "basal");
    match method {
        DESCRIBE => core || flow,
        CALL => flow,
        SCOPE_CHOICES | SETUP => {
            core && !origin_present
                && facts.scope.as_ref().is_none_or(|stamp| {
                    stamp.attributes.agent_id.is_none() && stamp.kind != ScopeKind::Worker
                })
        }
        _ => false,
    }
}

#[derive(Clone, Copy)]
enum Refusal {
    PrincipalDenied,
    ArgsInvalid,
    TokenUnknown,
    OpUnknown,
    ScopeInvalid,
    OutOfScope,
    SourceFailed,
    SourceTimeout,
    BindingUnavailable,
}
impl Refusal {
    fn wire(self) -> (&'static str, &'static str) {
        match self {
            Self::PrincipalDenied => (
                "principal_denied",
                "this route may not call this ability operation",
            ),
            Self::ArgsInvalid => ("ability_args_invalid", "the ability arguments are invalid"),
            Self::TokenUnknown => (
                "ability_token_unknown",
                "the ability token is not declared by this build",
            ),
            Self::OpUnknown => (
                "ability_op_unknown",
                "the ability operation is not declared for this token",
            ),
            Self::ScopeInvalid => ("ability_scope_invalid", "the ability scope is invalid"),
            Self::OutOfScope => (
                "ability_out_of_scope",
                "the ability request is outside the bound scope",
            ),
            Self::SourceFailed => (
                "ability_source_failed",
                "the ability source could not serve the request",
            ),
            Self::BindingUnavailable => (
                "ability_binding_unavailable",
                "the ability binding is unavailable",
            ),
            Self::SourceTimeout => (
                "ability_source_timeout",
                "the ability source did not answer in time",
            ),
        }
    }
}

fn params<'a>(
    method: &str,
    request: &'a Map<String, Value>,
) -> Result<Option<&'a Map<String, Value>>, Refusal> {
    let params = match request.get("params") {
        None if method == DESCRIBE => return Ok(None),
        Some(Value::Object(params)) => params,
        _ => return Err(Refusal::ArgsInvalid),
    };
    let (required, optional): (&[&str], &[&str]) = match method {
        DESCRIBE => (&[], &[]),
        SCOPE_CHOICES => (&["token", "key"], &["limit", "cursor"]),
        SETUP => (&["token"], &[]),
        CALL => (&["key", "token", "op", "args", "scope"], &[]),
        _ => unreachable!(),
    };
    if params
        .keys()
        .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
        || required.iter().any(|key| !params.contains_key(*key))
        || params.iter().any(|(key, value)| match key.as_str() {
            "scope" | "args" => !value.is_object(),
            "limit" => !value.is_i64() && !value.is_u64(),
            _ => !value.is_string(),
        })
        || (method == CALL
            && params
                .get("key")
                .and_then(Value::as_str)
                .is_none_or(|key| key.is_empty() || key.len() > 256))
    {
        return Err(Refusal::ArgsInvalid);
    }
    Ok(Some(params))
}

/// Fail closed until source enumeration can durably record the read's outcome
/// before replying, without recording source labels or ids. It must reserve a
/// journal entry before reading the person's bindable calendars, lists or groups.
fn pending_scope_choices() -> Refusal {
    Refusal::SourceFailed
}
/// Fail closed until setup can durably record its access decision before replying.
/// It must reserve a journal entry first and let a verified macOS helper prompt
/// only after receiving permission to proceed.
fn pending_setup() -> Refusal {
    Refusal::SourceFailed
}
/// No source read may run until its outcome can be reserved and committed. Keep
/// the verified install provenance at this boundary for the journaled handler.
fn pending_call(_install: binding::Install) -> Refusal {
    Refusal::SourceFailed
}

fn validate_choices(token: Token, params: &Map<String, Value>) -> Result<(), Refusal> {
    let context = CursorContext::for_choices(token, params["key"].as_str().expect("validated key"))
        .map_err(|_| Refusal::ArgsInvalid)?;
    if params.get("limit").is_some_and(|limit| {
        limit
            .as_u64()
            .is_none_or(|limit| !(1..=200).contains(&limit))
    }) {
        return Err(Refusal::ArgsInvalid);
    }
    if let Some(cursor) = params.get("cursor").and_then(Value::as_str) {
        context.validate(cursor).map_err(|_| Refusal::ArgsInvalid)?;
    }
    Ok(())
}

async fn dispatch(
    plane: &AbilityPlane,
    facts: &AcceptedBindFacts,
    method: &str,
    request: &Map<String, Value>,
    gate: Arc<TerminalArbiter>,
) -> Result<Option<Value>, Refusal> {
    if !admitted(facts, method, request.contains_key("origin")) {
        return Err(Refusal::PrincipalDenied);
    }
    let params = params(method, request)?;
    if method == DESCRIBE {
        return Ok(Some(plane.describe(gate).await));
    }
    let params = params.expect("non-describe params");
    let token = params["token"]
        .as_str()
        .and_then(Token::parse)
        .filter(|token| plane.platform.tokens().contains(token))
        .ok_or(Refusal::TokenUnknown)?;
    match method {
        SCOPE_CHOICES => {
            validate_choices(token, params)?;
            Err(pending_scope_choices())
        }
        SETUP => Err(pending_setup()),
        CALL => plane.call(facts, params, token, gate).await,
        _ => unreachable!(),
    }
}

pub(crate) async fn handle(
    frame: &Frame,
    writer: &tokio::sync::mpsc::Sender<Frame>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
    method: &str,
    request: &Map<String, Value>,
) -> Result<(), ModuleError> {
    let gate =
        TerminalArbiter::current().unwrap_or_else(|| Arc::new(TerminalArbiter::new(frame.clone())));
    let result = dispatch(
        &planes.management.abilities,
        facts,
        method,
        request,
        gate.clone(),
    )
    .await;
    // A stopped handler leaves the terminal reply to the arbiter, even if its
    // binding future became ready at the same instant as the stop.
    if gate.gate.stopped() {
        return Ok(());
    }
    let (ver, channel, epoch, corr) = (
        frame.header.ver,
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
    );
    match result {
        Ok(Some(reply)) => {
            crate::send_tool_response(writer, ver, channel, epoch, corr, reply).await
        }
        Ok(None) => Ok(()),
        Err(refusal) => {
            let (code, message) = refusal.wire();
            crate::send_route_error(writer, ver, channel, epoch, corr, code, message).await
        }
    }
}

#[cfg(test)]
mod tests;
