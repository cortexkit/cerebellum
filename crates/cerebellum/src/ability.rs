//! Management-only personal-data ability admission and static descriptions.

use std::sync::Arc;

use cerebellum_ability::{
    schema::token_schemas,
    tokens::{Platform, Token},
};
use serde_json::{json, Map, Value};
use subc_protocol::{call_mode::CallMode, scope::ScopeKind, Frame, Principal};

use crate::{
    ability_source::{Source, SourceUnit, SourceUnits, UnitStatus},
    terminal_arbiter::TerminalArbiter,
    AcceptedBindFacts, ModuleError, Planes,
};

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
    SourceFailed,
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
            Self::SourceFailed => (
                "ability_source_failed",
                "the ability source could not serve the request",
            ),
            Self::BindingUnavailable => (
                "ability_binding_unavailable",
                "the ability binding is unavailable",
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
            "limit" => !value.is_u64(),
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
/// Fail closed until core's install record supplies the person's bound source
/// ids for the requested ability key, checked before any queued data read.
fn pending_call() -> Refusal {
    Refusal::BindingUnavailable
}

pub(crate) async fn handle(
    frame: &Frame,
    writer: &tokio::sync::mpsc::Sender<Frame>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
    method: &str,
    request: &Map<String, Value>,
) -> Result<(), ModuleError> {
    let result = if !admitted(facts, method, request.contains_key("origin")) {
        Err(Refusal::PrincipalDenied)
    } else {
        match params(method, request) {
            Err(refusal) => Err(refusal),
            Ok(_) if method == DESCRIBE => {
                let gate = TerminalArbiter::current()
                    .unwrap_or_else(|| Arc::new(TerminalArbiter::new(frame.clone())));
                Ok(planes.management.abilities.describe(gate).await)
            }
            Ok(Some(params)) => {
                let token = params
                    .get("token")
                    .and_then(Value::as_str)
                    .and_then(Token::parse);
                if token.is_none_or(|token| !platform().tokens().contains(&token)) {
                    Err(Refusal::TokenUnknown)
                } else {
                    Err(match method {
                        SCOPE_CHOICES => pending_scope_choices(),
                        SETUP => pending_setup(),
                        CALL => pending_call(),
                        _ => unreachable!(),
                    })
                }
            }
            Ok(None) => unreachable!(),
        }
    };
    let (ver, channel, epoch, corr) = (
        frame.header.ver,
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
    );
    match result {
        Ok(reply) => crate::send_tool_response(writer, ver, channel, epoch, corr, reply).await,
        Err(refusal) => {
            let (code, message) = refusal.wire();
            crate::send_route_error(writer, ver, channel, epoch, corr, code, message).await
        }
    }
}

#[cfg(test)]
mod tests;
