//! Operator inventory is a projection of enforcement's rows, never a second
//! grant store. Revoking a row wakes the work bound to that exact id.

use serde_json::{json, Value};

use crate::agent_grants::{AgentGrant, BrowserTarget, GrantHolder, GrantSubject};
use crate::authorization::{HazardClass, COMPOSE, MUTATE_REVERSIBLE, OBSERVE};
use crate::{management, AcceptedBindFacts, Frame, ModuleError, Planes};

pub(crate) const CAPABILITY: &str = "permissions/v1";
pub(crate) const LIST: &str = "permissions.list";
pub(crate) const REVOKE: &str = "permissions.revoke";

pub(crate) fn is_operation(method: &str) -> bool {
    matches!(method, LIST | REVOKE)
}

pub(crate) fn bind_admitted(
    principal: &Option<subc_protocol::Principal>,
    target: &subc_protocol::RouteTarget,
) -> bool {
    // Cingulate collects permissions and revocations for the operator. Give it
    // a management route without first-party membership, which would also
    // expose unrelated operator operations, tools and sessions.
    is_aggregator(principal)
        && matches!(target, subc_protocol::RouteTarget::ManagementSurface { module_id } if module_id == "cerebellum")
}

fn is_aggregator(principal: &Option<subc_protocol::Principal>) -> bool {
    matches!(principal, Some(subc_protocol::Principal::Reserved { module_id }) if module_id == "cingulate")
}

pub(crate) fn refused_method(frame: &Frame, facts: &AcceptedBindFacts) -> Option<String> {
    if !is_aggregator(&facts.principal) {
        return None;
    }
    // Processing pending consent answers can mint grants before an operation's
    // handler runs. Reject unrelated names before that processing or any other
    // handler's grant lookup, even if the handler would eventually refuse.
    // Anything that isn't plainly one of the two operations is refused,
    // including a body that doesn't parse or names no method, so a request
    // shape this check doesn't recognise can't slip past it.
    let request: Option<Value> = serde_json::from_slice(&frame.body).ok();
    let method = request
        .as_ref()
        .and_then(|request| request.get("method"))
        .and_then(Value::as_str);
    match method {
        Some(method) if is_operation(method) => None,
        Some(method) => Some(method.to_string()),
        None => Some(
            request
                .as_ref()
                .and_then(|request| request.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("<request without a method>")
                .to_string(),
        ),
    }
}

pub(crate) async fn handle(
    frame: &Frame,
    writer: &tokio::sync::mpsc::Sender<Frame>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
    method: &str,
    request: &serde_json::Map<String, Value>,
) -> Result<(), ModuleError> {
    let (ver, channel, epoch, corr) = (
        frame.header.ver,
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
    );
    // A direct route identifies an OS user, not a person: agent shells have
    // that identity too. Only the permissions aggregator may administer rows.
    if !is_aggregator(&facts.principal) {
        return crate::send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "permissions_operator_required",
            "permissions operations need reserved:cingulate",
        )
        .await;
    }
    let empty = serde_json::Map::new();
    let params = match request.get("params") {
        None => &empty,
        Some(Value::Object(params)) => params,
        Some(_) => {
            return crate::send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "params",
                "wrong_type",
            )
            .await
        }
    };
    let field = if method == LIST { "agent_id" } else { "id" };
    let parsed = (|| {
        if let Some(unknown) = params.keys().find(|name| name.as_str() != field) {
            return Err((unknown.as_str(), "unknown_field"));
        }
        match params.get(field) {
            None if method == LIST => Ok(None),
            None => Err((field, "missing_field")),
            Some(Value::String(value)) if value.is_empty() => Err((field, "empty_value")),
            Some(Value::String(value)) => Ok(Some(value.as_str())),
            Some(_) => Err((field, "wrong_type")),
        }
    })();
    let value = match parsed {
        Ok(value) => value,
        Err((field, reason)) => {
            return crate::send_invalid_request_response(
                writer, ver, channel, epoch, corr, field, reason,
            )
            .await
        }
    };
    let store = planes.management.agent_grants();
    let result = if method == LIST {
        store.live_rows(value, store.now_ms()).map(|mut rows| {
            rows.sort_by(|a, b| a.id.cmp(&b.id));
            json!({"grants":rows.iter().map(|row| describe(row, &planes.management)).collect::<Vec<_>>()})
        })
    } else {
        let id = value.expect("revoke requires an id");
        store
            .revoke_with_stopping(id, store.now_ms())
            .map(|(revoked, stopping)| {
                if !revoked {
                    json!({"outcome":"not_found"})
                } else if stopping {
                    json!({"outcome":"revoked","stopping":true})
                } else {
                    json!({"outcome":"revoked"})
                }
            })
    };
    match result {
        Ok(reply) => crate::send_tool_response(writer, ver, channel, epoch, corr, reply).await,
        // An unreadable inventory is not an empty inventory, and a failed
        // durable revoke must never be acknowledged as having removed access.
        Err(error) => {
            crate::send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "permissions_unavailable",
                &format!("the agent grant store is unavailable: {error}"),
            )
            .await
        }
    }
}

fn describe(row: &AgentGrant, management: &management::ManagementPlane) -> Value {
    let holder = match &row.holder {
        GrantHolder::Head { agent_id } => json!({"kind":"agent","agent_id":agent_id}),
        GrantHolder::Worker {
            agent_id,
            scope_ref,
        } => json!({"kind":"worker","agent_id":agent_id,"scope_ref":scope_ref}),
    };
    let browser = if row.browser_target == Some(BrowserTarget::UserBrowser) {
        "the person's Chrome"
    } else {
        "the agent browser"
    };
    let (scope, subject, label) = match &row.subject {
        GrantSubject::App(bundle) => {
            // Grants store the app's public identity, not a display name. Use
            // its running name when available; otherwise keep that identity so
            // stopped or unreadable apps remain recognisable and revocable.
            let name = management
                .resolve_process(bundle)
                .map(|process| management.application_name(&process))
                .unwrap_or_else(|_| bundle.clone());
            ("app", name.clone(), format!("the app {name}"))
        }
        GrantSubject::WholeComputer => (
            "whole_computer",
            "Whole computer".into(),
            "the whole computer, including your mouse and keyboard".into(),
        ),
        GrantSubject::Origin(site) | GrantSubject::Domain(site) => (
            "site",
            format!("{site}: {}", browser_access(row)),
            browser_scope_label(row, format!("the site {site} in {browser}")),
        ),
        GrantSubject::AllSites => (
            "all_sites",
            format!("All sites: {}", browser_access(row)),
            format!("every site in {browser}"),
        ),
    };
    let subject = if row.browser_target == Some(BrowserTarget::UserBrowser) {
        format!("{subject} in {browser}")
    } else {
        subject
    };
    let mut described = json!({"id":row.id,"agent_id":row.holder.agent_id(),"holder":holder,"module":"cerebellum","subject_label":subject,"scope":scope,"scope_label":label,"granted_at_ms":row.granted_at_ms});
    if let Some(expires) = row.expires_at_ms {
        described["expires_at_ms"] = json!(expires);
    }
    if let Some(card) = &row.card_ref {
        described["card_ref"] = json!(card);
    }
    if matches!(
        row.subject,
        GrantSubject::WholeComputer | GrantSubject::AllSites
    ) {
        described["group"] = json!("danger");
    }
    described
}

fn browser_access(row: &AgentGrant) -> &'static str {
    // Browser rows are validated before listing: their ceiling is one through
    // four. Describe that ceiling without exposing internal tier numbers.
    match row.max_level {
        OBSERVE => "read",
        COMPOSE => "read, click and type",
        MUTATE_REVERSIBLE => "read, click, type and make reversible changes",
        _ => "read, click, type and make lasting changes",
    }
}

fn browser_scope_label(row: &AgentGrant, mut label: String) -> String {
    let hazards: Vec<_> = HazardClass::ALL
        .iter()
        .filter(|hazard| row.hazards.contains(hazard))
        .map(|hazard| match hazard {
            HazardClass::CredentialFormSubmit => "sign-in forms",
            HazardClass::FinancialFormSubmit => "payment forms",
            HazardClass::UnverifiedFormContents => "forms with unverified contents",
        })
        .collect();
    if !hazards.is_empty() {
        label.push_str("; consent includes ");
        label.push_str(&hazards.join(", "));
    }
    label
}

#[cfg(test)]
mod tests;
