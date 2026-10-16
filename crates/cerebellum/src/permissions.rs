//! Operator inventory is a projection of enforcement's rows, never a second
//! grant store. Revoking a row wakes the work bound to that exact id.

use serde_json::{json, Value};

use crate::agent_grants::{AgentGrant, BrowserTarget, GrantHolder, GrantSubject};
use crate::{management, AcceptedBindFacts, Frame, ModuleError, Planes};

pub(crate) const CAPABILITY: &str = "permissions/v1";
pub(crate) const LIST: &str = "permissions.list";
pub(crate) const REVOKE: &str = "permissions.revoke";

pub(crate) fn is_operation(method: &str) -> bool {
    matches!(method, LIST | REVOKE)
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
    if !matches!(&facts.principal, Some(subc_protocol::Principal::Reserved { module_id }) if module_id == "cingulate")
    {
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
            site.clone(),
            format!("the site {site} in {browser}"),
        ),
        GrantSubject::AllSites => (
            "all_sites",
            "All sites".into(),
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

#[cfg(test)]
mod tests;
