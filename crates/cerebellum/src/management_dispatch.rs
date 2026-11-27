use super::*;

/// The request fields of the standing-grant operations, checked in one
/// place: `Err` names the field and the reason code of the refusal.
mod standing_grant_params {
    use serde_json::{Map, Value};

    pub(super) type Refusal = (&'static str, &'static str);

    /// Refuse any field outside `allowed`, naming the first in sorted order.
    pub(super) fn only(params: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
        match params
            .keys()
            .filter(|field| !allowed.contains(&field.as_str()))
            .min()
        {
            Some(field) => Err(field.clone()),
            None => Ok(()),
        }
    }

    /// An optional canonical origin a standing row could name.
    pub(super) fn origin(params: &Map<String, Value>) -> Result<Option<String>, Refusal> {
        match params.get("origin") {
            None => Ok(None),
            Some(Value::String(origin)) => {
                if crate::classification::canonical_grant_origin(origin).as_deref()
                    == Some(origin.as_str())
                {
                    Ok(Some(origin.clone()))
                } else {
                    Err(("origin", "invalid_origin"))
                }
            }
            Some(_) => Err(("origin", "wrong_type")),
        }
    }

    pub(super) fn domain(params: &Map<String, Value>) -> Result<Option<String>, Refusal> {
        match params.get("domain") {
            None => Ok(None),
            Some(Value::String(domain))
                if crate::browser_standing_grants::domain_scope(&format!("https://{domain}"))
                    .as_deref()
                    == Some(domain.as_str()) =>
            {
                Ok(Some(domain.clone()))
            }
            Some(Value::String(_)) => Err(("domain", "invalid_domain")),
            Some(_) => Err(("domain", "wrong_type")),
        }
    }

    /// The required, nonempty `agent_id` an operator names.
    pub(super) fn agent_id(params: &Map<String, Value>) -> Result<String, Refusal> {
        match params.get("agent_id") {
            Some(Value::String(agent)) if !agent.is_empty() => Ok(agent.clone()),
            Some(Value::String(_)) => Err(("agent_id", "empty_value")),
            Some(_) => Err(("agent_id", "wrong_type")),
            None => Err(("agent_id", "missing_field")),
        }
    }
}

pub(super) async fn handle_management_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
) -> Result<(), ModuleError> {
    if let Some(terminal) = TerminalArbiter::current() {
        terminal.set_step(CallStep::Queue);
    }
    let _browser_guard = match browser_queue::enter(&frame, planes).await {
        Ok(guard) => guard,
        Err(outcome) => return send_queue_refusal(writer, &frame, planes, outcome).await,
    };
    let mut facts = facts.clone();
    if let Some(terminal) = TerminalArbiter::current() {
        terminal.set_step(CallStep::Preflight);
        facts.identity.witness = terminal.witness.clone();
    }
    handle_management_request_observed(frame, writer, &facts, planes, None).await
}

/// Serve one tool-display pull: the caller check and the record lookup live in
/// `Records::read`; this only frames its answer or refusal.
pub(super) async fn send_display_read(
    writer: &mpsc::Sender<Frame>,
    (ver, channel, epoch, corr): (u8, u16, u32, u64),
    facts: &AcceptedBindFacts,
    planes: &Planes,
    params: Value,
) -> Result<(), ModuleError> {
    match planes
        .routes
        .display
        .read(facts.principal.as_ref(), params)
        .await
    {
        Ok(bytes) => {
            send_tool_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                serde_json::from_slice(&bytes).expect("stored display arguments are JSON"),
            )
            .await
        }
        Err(error) => tool_provider::send_error(error, (ver, channel, epoch, corr), writer).await,
    }
}

pub(super) async fn handle_management_request_observed(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
    call_key: Option<&str>,
) -> Result<(), ModuleError> {
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let corr = frame.header.corr;
    let ver = frame.header.ver;

    let Ok(request) = serde_json::from_slice::<serde_json::Value>(&frame.body) else {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "invalid_request",
            "request body not decodable",
        )
        .await;
    };
    let Some(object) = request.as_object() else {
        return send_invalid_request_response(writer, ver, channel, epoch, corr, "$", "wrong_type")
            .await;
    };
    if let Some(field) = object
        .keys()
        .filter(|field| {
            !matches!(field.as_str(), "method" | "params")
                && !(field.as_str() == "origin"
                    && matches!(
                        object.get("method").and_then(Value::as_str),
                        Some(ability::SCOPE_CHOICES | ability::SETUP)
                    ))
        })
        .min()
    {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            field,
            "unknown_field",
        )
        .await;
    }

    let Some(method) = object.get("method").and_then(serde_json::Value::as_str) else {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "method",
            "missing_field",
        )
        .await;
    };
    if !dispatchable_management_operation(method) {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "unknown_method",
            &format!("unknown method '{method}'"),
        )
        .await;
    }
    if permissions::is_operation(method) {
        return permissions::handle(&frame, writer, facts, planes, method, object).await;
    }
    if ability::is_operation(method) {
        return ability::handle(&frame, writer, facts, planes, method, object).await;
    }
    if method == private_content::QUERY {
        return private_content::handle(&frame, writer, facts, planes, object).await;
    }
    if method == image_handles::RESOLVE {
        return handle_image_resolve(&frame, writer, planes, object).await;
    }
    if method == cortexkit_role_tool_display::DISPLAY_READ {
        let params = object.get("params").cloned().unwrap_or(Value::Null);
        return send_display_read(writer, (ver, channel, epoch, corr), facts, planes, params).await;
    }
    if method == management::SESSION_TURN_ENDED {
        return handle_session_turn_ended(
            writer,
            facts,
            planes,
            object,
            (ver, channel, epoch, corr),
        )
        .await;
    }
    // Operator operations (list or revoke grants, profile-root rebind, and
    // launch-recovery clear) administer machine-wide grants and browser state.
    // A flow route never gets them, even when acting for its owner.
    if (codemode::legacy_run(facts)
        || (facts.call_mode == subc_protocol::call_mode::CallMode::Codemode
            && matches!(
                method,
                management::CLEAR_LAUNCH_RECOVERY | management::REBIND_PROFILE_ROOT
            )))
        && matches!(
            method,
            management::OPEN_GRANT
                | management::IMPORT_LOGIN
                | management::CAPTURE_LOGIN
                | management::PRESENT
                | management::CLEAR_LAUNCH_RECOVERY
                | management::REBIND_PROFILE_ROOT
        )
    {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            agent_run_consent_refusal(),
        )
        .await;
    }
    if facts.flow_id.is_some() && is_operator_operation(method) {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            flow_consent_refusal("unattended_flow"),
        )
        .await;
    }
    if method == management::WOULD_ASK
        && !cerebellum_core::principal::admits_session_calls(&facts.principal)
        && !(facts.flow_id.is_some()
            && facts.acts_as_agent
            && facts.agent_project_id_attested
            && matches!(&facts.principal, Some(subc_protocol::Principal::Reserved { module_id }) if module_id == "basal"))
    {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "principal_denied",
            "grants.would_ask requires the agent's orchestrator or an owner-authorized reserved:basal flow",
        )
        .await;
    }
    // Session admission, before any operation below asks a person, opens or
    // reads a grant, or writes the journal; see `send_session_caller_not_admitted`.
    // A caller not admitted to act in a conversation reaches only the
    // operator's operations, and those see these facts with every trace of
    // the conversation removed.
    let operator_facts;
    let facts = if method == management::WOULD_ASK || facts.admits_session_calls() {
        facts
    } else if is_operator_operation(method) {
        operator_facts = facts.outside_session_scope();
        &operator_facts
    } else {
        if let Some(refusal) = session_flow_refusal(facts) {
            return send_tool_response(writer, ver, channel, epoch, corr, refusal).await;
        }
        return send_session_caller_not_admitted(writer, ver, channel, epoch, corr, facts).await;
    };
    if let Some(refusal) = session_flow_refusal(facts) {
        return send_tool_response(writer, ver, channel, epoch, corr, refusal).await;
    }
    if facts.flow_id.is_some()
        && matches!(
            method,
            management::OPEN_GRANT
                | management::IMPORT_LOGIN
                | management::CAPTURE_LOGIN
                | management::PRESENT
                | management::CLEAR_LAUNCH_RECOVERY
                | management::REBIND_PROFILE_ROOT
        )
    {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            flow_consent_refusal("unattended_flow"),
        )
        .await;
    }
    #[cfg(windows)]
    if planes.enforce_windows_browser_refusals() {
        if let Some(refusal) = windows_withheld::management_refusal(method) {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                refusal.code,
                refusal.message,
            )
            .await;
        }
    }
    let params = object
        .get("params")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let Some(params_object) = params.as_object() else {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "params",
            "wrong_type",
        )
        .await;
    };

    if matches!(method, management::PRESENT | management::IMPORT_LOGIN) {
        if let Some(field) = params_object
            .keys()
            .filter(|field| field.as_str() != "origin")
            .min()
        {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let Some(origin_value) = params_object.get("origin") else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "origin",
                "missing_field",
            )
            .await;
        };
        let Some(origin) = origin_value.as_str() else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "origin",
                "wrong_type",
            )
            .await;
        };
        if crate::classification::canonical_grant_origin(origin).as_deref() != Some(origin) {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "origin",
                "invalid_origin",
            )
            .await;
        }
        let reply = if method == management::IMPORT_LOGIN {
            let reply =
                import_browser_login(planes, facts, writer, channel, epoch, corr, origin).await;
            match planes.browser.finish_reply(method, reply) {
                Ok(reply) => reply,
                Err(error) => return send_route_error(writer, ver, channel, epoch, corr,
                    browser::RESULT_SCHEMA_VIOLATION_CODE,
                    &format!("the import reply violated its declared result schema ({error}); the import may already have completed, so do not retry based on this response"),
                ).await,
            }
        } else {
            let held = call_key.map(|key| {
                let principal = journal::call_records::principal_label(facts.principal.as_ref());
                let scope = facts
                    .scope
                    .as_ref()
                    .map(journal::call_records::ScopeIdentity::from_stamp)
                    .unwrap_or_else(|| journal::call_records::ScopeIdentity {
                        owner: principal.clone(),
                        reference: facts.identity.conversation_key.clone(),
                        scope_epoch: 0,
                    });
                (principal, key.to_owned(), scope)
            });
            present_browser_handoff(planes, &facts.identity, origin, held).await
        };
        let reply = match planes.browser.finish_reply(method, reply) {
            Ok(reply) => reply,
            Err(error) => {
                return send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    browser::RESULT_SCHEMA_VIOLATION_CODE,
                    &format!("the handoff reply violated its result schema: {error}"),
                )
                .await
            }
        };
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    if method == management::WOULD_ASK {
        let request = match management::parse_would_ask(params_object) {
            Ok(request) => request,
            Err(error) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    &error.field,
                    error.reason,
                )
                .await
            }
        };
        if let Some(flow_id) = facts.flow_id.as_deref() {
            let field = if request.agent_id != facts.identity.agent_project_id {
                Some("agent_id")
            } else if request.flow_id != flow_id {
                Some("flow_id")
            } else {
                None
            };
            if let Some(field) = field {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    field,
                    "scope_mismatch",
                )
                .await;
            }
        }
        let reply = planes.management.would_ask(&request);
        let items = reply["items"]
            .as_array()
            .expect("the evaluator returns items");
        let counts = json!({
            "item_count":items.len(),
            "yes":items.iter().filter(|i| i["verdict"] == "yes").count(),
            "no":items.iter().filter(|i| i["verdict"] == "no").count(),
            "would_ask":items.iter().filter(|i| i["verdict"] == "would_ask").count(),
        });
        if planes
            .browser
            .journal_would_ask(
                &facts.identity,
                principal_label(&facts.principal),
                &request.agent_id,
                &request.flow_id,
                counts,
            )
            .await
            .is_err()
        {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "journal_unavailable",
                "permission query could not be audited",
            )
            .await;
        }
        return match planes.browser.finish_reply(method, reply) {
            Ok(reply) => send_tool_response(writer, ver, channel, epoch, corr, reply).await,
            Err(error) => {
                send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    browser::RESULT_SCHEMA_VIOLATION_CODE,
                    &format!("the permission reply violated its declared result schema ({error})"),
                )
                .await
            }
        };
    }

    if method == management::CAPTURE_LOGIN {
        let request = match login_capture::parse_request(params_object) {
            Ok(request) => request,
            Err(error) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    &error.field,
                    error.reason,
                )
                .await
            }
        };
        let Some(call_key) = call_key else {
            return send_tool_response(writer, ver, channel, epoch, corr, json!({
                "outcome":"invalid_request",
                "detail":{
                    "field":"call_key",
                    "reason_code":"required",
                    "remedy":"capture_login needs a keyed call because its result arrives later as a notice; do not poll for it"
                }
            })).await;
        };
        let reply = capture_browser_login(
            planes,
            facts,
            writer,
            (channel, epoch, corr),
            &request,
            call_key,
        )
        .await;
        // A capture cancelled before the handoff sends no reply of its own:
        // the Cancel already chose this call's reply in its terminal arbiter.
        // Its own `{"outcome":"cancelled"}` would otherwise replace that
        // reply whenever it reached the route in time, so the bytes sent
        // would depend on scheduling.
        if reply["outcome"] == "cancelled"
            && TerminalArbiter::current().is_some_and(|terminal| terminal.answered_by_cancel())
        {
            return Ok(());
        }
        return match planes
            .browser
            .finish_reply(management::CAPTURE_LOGIN, reply)
        {
            Ok(reply) => send_tool_response(writer, ver, channel, epoch, corr, reply).await,
            Err(error) => {
                send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    browser::RESULT_SCHEMA_VIOLATION_CODE,
                    &format!(
                        "the capture reply violated its declared result schema ({error}); any \
                         captured file is deleted at its deadline, so capture again rather than \
                         retrying from this response"
                    ),
                )
                .await
            }
        };
    }

    if method == management::RESUME {
        if let Some(field) = params_object.keys().min() {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let reply = resume_browser_handoff(planes, &facts.identity).await;
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    if method == management::OPEN_TARGET {
        if let Some(field) = params_object
            .keys()
            .filter(|field| field.as_str() != "bundle_identity")
            .min()
        {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let Some(bundle_identity) = params_object
            .get("bundle_identity")
            .and_then(serde_json::Value::as_str)
            .filter(|bundle| !bundle.is_empty())
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "bundle_identity",
                "missing_field",
            )
            .await;
        };
        // Waits for the person exactly as a computer action does, so it is
        // interruptible in the same ways.
        let cancel = planes
            .cancellations
            .get((channel, epoch, corr))
            .unwrap_or_else(CancelHandle::pending);
        let consent = consent_context(planes, facts, writer, channel, epoch);
        let reply = planes
            .management
            .open_target(bundle_identity, &consent, &cancel)
            .await;
        // The caller is gone when its route unbound mid-wait; nothing is sent.
        if planes.routes.get(channel, epoch).is_none() {
            return Ok(());
        }
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    if method == management::LIST_APP_GRANTS {
        if let Some(field) = params_object.keys().min() {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let reply = planes.management.computer_grants().list();
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    if method == management::REVOKE_APP_GRANT {
        if let Some(field) = params_object
            .keys()
            .filter(|field| !matches!(field.as_str(), "grantee" | "bundle_identity" | "dry_run"))
            .min()
        {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let mut named = [None, None];
        for (slot, field) in named.iter_mut().zip(["grantee", "bundle_identity"]) {
            match params_object.get(field) {
                Some(serde_json::Value::String(value)) if !value.is_empty() => {
                    *slot = Some(value.clone())
                }
                Some(serde_json::Value::String(_)) => {
                    return send_invalid_request_response(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        field,
                        "empty_value",
                    )
                    .await
                }
                other => {
                    return send_invalid_request_response(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        field,
                        if other.is_some() {
                            "wrong_type"
                        } else {
                            "missing_field"
                        },
                    )
                    .await
                }
            }
        }
        let dry_run = match params_object.get("dry_run") {
            None => false,
            Some(serde_json::Value::Bool(dry_run)) => *dry_run,
            Some(_) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "dry_run",
                    "wrong_type",
                )
                .await
            }
        };
        let [Some(grantee), Some(bundle_identity)] = named else {
            unreachable!("both fields were checked above");
        };
        let reply = planes
            .management
            .computer_grants()
            .revoke(&grantee, &bundle_identity, dry_run);
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    if matches!(
        method,
        management::REVOKE_ACCESS | management::REVOKE_GRANT | management::LIST_GRANTS
    ) {
        let reply = match standing_grant_operation(method, params_object, facts, planes) {
            Ok(reply) => reply,
            Err(StandingGrantOperationRefusal::UnknownField(field)) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    &field,
                    "unknown_field",
                )
                .await
            }
            Err(StandingGrantOperationRefusal::Invalid((field, reason))) => {
                return send_invalid_request_response(
                    writer, ver, channel, epoch, corr, field, reason,
                )
                .await
            }
        };
        // The agent's own revocation is reached from the browser tool, so its
        // reply is held to the result schema the tool declares for it.
        let reply = if method == management::REVOKE_ACCESS {
            match planes.browser.finish_reply(method, reply) {
                Ok(reply) => reply,
                Err(error) => {
                    return send_route_error(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        browser::RESULT_SCHEMA_VIOLATION_CODE,
                        &format!(
                            "the revoke_access reply violated its declared result schema \
                             ({error}); the access may already have been removed, so call \
                             revoke_access again rather than retrying from this response"
                        ),
                    )
                    .await
                }
            }
        } else {
            reply
        };
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    use cingulate_client::card::CardKind;

    let (mut reply, question, settlement) = if method == management::OPEN_GRANT {
        if let Some(field) = params_object
            .keys()
            .filter(|field| !matches!(field.as_str(), "origins" | "hazards" | "severity_tier"))
            .min()
        {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let Some(origin_values) = params_object
            .get("origins")
            .and_then(serde_json::Value::as_array)
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "origins",
                "missing_field",
            )
            .await;
        };
        let Some(origins) = origin_values
            .iter()
            .map(serde_json::Value::as_str)
            .map(|origin| origin.map(str::to_string))
            .collect::<Option<Vec<_>>>()
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "origins",
                "wrong_type",
            )
            .await;
        };
        let Some(hazard_values) = params_object
            .get("hazards")
            .and_then(serde_json::Value::as_array)
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "hazards",
                "missing_field",
            )
            .await;
        };
        let Some(hazards) = hazard_values
            .iter()
            .map(serde_json::Value::as_str)
            .map(|hazard| hazard.and_then(crate::authorization::HazardClass::from_wire))
            .collect::<Option<Vec<_>>>()
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "hazards",
                "unsupported_value",
            )
            .await;
        };
        // Optional: omitted keeps the ceiling the hazards imply. Out-of-range
        // integers are refused by the management plane below.
        let severity_tier = match params_object.get("severity_tier") {
            None => None,
            Some(value) => match value.as_u64() {
                Some(tier) => Some(u8::try_from(tier).unwrap_or(u8::MAX)),
                None => {
                    return send_invalid_request_response(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        "severity_tier",
                        "wrong_type",
                    )
                    .await
                }
            },
        };
        let opened = planes
            .management
            .open_browser_grant_for_holder(
                &facts.identity.conversation_key,
                origins,
                hazards,
                severity_tier,
                true,
                standing_offer_agent(facts),
                permission_scope::authorizing_holder(facts).as_ref(),
            )
            .await;
        let (reply, question) = match opened {
            Ok(opened) => opened,
            Err(management::BrowserGrantRequestError::InvalidOrigins) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "origins",
                    "unsupported_value",
                )
                .await
            }
            Err(management::BrowserGrantRequestError::UngrantableOrigin { value }) => {
                // The value is echoed so a caller holding several origins can
                // see which one was refused, `null` included.
                return send_tool_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    json!({
                        "outcome": "invalid_request",
                        "context": null,
                        "session": null,
                        "detail": {
                            "field": "origins",
                            "reason_code": "unsupported_value",
                            "value": value,
                        },
                    }),
                )
                .await;
            }
            Err(management::BrowserGrantRequestError::InvalidHazards) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "hazards",
                    "unsupported_value",
                )
                .await
            }
            Err(management::BrowserGrantRequestError::InvalidSeverityTier) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "severity_tier",
                    "out_of_range",
                )
                .await
            }
        };
        (reply, question, CardKind::WebsiteAccessInAdvance)
    } else if method == management::CLEAR_LAUNCH_RECOVERY {
        if let Some(field) = params_object
            .keys()
            .filter(|field| !matches!(field.as_str(), "agent_project_id" | "sequence"))
            .min()
        {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        // The project is named explicitly: the operator clears another
        // project's record from their own desk route.
        let Some(agent_project_id) = params_object
            .get("agent_project_id")
            .and_then(serde_json::Value::as_str)
            .filter(|project| !project.is_empty())
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "agent_project_id",
                "missing_field",
            )
            .await;
        };
        let sequence = match params_object.get("sequence") {
            None => None,
            Some(value) => match value.as_u64() {
                Some(sequence) => Some(sequence),
                None => {
                    return send_invalid_request_response(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        "sequence",
                        "wrong_type",
                    )
                    .await
                }
            },
        };
        let (reply, question) = planes
            .management
            .open_launch_recovery_clear(agent_project_id, sequence, true)
            .await;
        (reply, question, CardKind::StuckProfileClearance)
    } else {
        if let Some(field) = params_object.keys().min() {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let (reply, question) = planes
            .management
            .open_profile_root_rebind(&facts.identity.conversation_key, true)
            .await;
        (reply, question, CardKind::ProfileReidentification)
    };

    if let Some(mut question) = question {
        if let Err(error) = question.bind_holder(permission_scope::minting_holder(facts)) {
            error.apply_to_reply(&mut reply);
            return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
        }
        let raised = async {
            let live = browser_consent::live(facts, planes, channel, epoch)?;
            let mut session = planes
                .consent
                .session(&live)
                .await
                .map_err(|error| cingulate_client::desk::Ending::of_refusal(&error))?;
            browser_consent::raise(
                &planes.management,
                &planes.consent,
                &live,
                &mut session,
                settlement,
                &question,
                true,
            )
            .await
        }
        .await;
        match raised {
            Ok((ask_id, _)) => reply["ask_id"] = json!(ask_id),
            Err(ending) => {
                browser_consent::settle_failed(&planes.management, settlement, &question, &ending);
                browser_consent::unavailable(
                    &mut reply,
                    &ending,
                    if settlement == CardKind::StuckProfileClearance {
                        "keep"
                    } else {
                        management::BROWSER_GRANT_DECLINE
                    },
                );
            }
        }
    }

    send_tool_response(writer, ver, channel, epoch, corr, reply).await
}

/// Why a standing-grant operation's request was refused before it ran.
enum StandingGrantOperationRefusal {
    UnknownField(String),
    Invalid(standing_grant_params::Refusal),
}

impl From<standing_grant_params::Refusal> for StandingGrantOperationRefusal {
    fn from(refusal: standing_grant_params::Refusal) -> Self {
        Self::Invalid(refusal)
    }
}

/// Serve `browser.revoke_access`, `browser.revoke_grant` or `grants.list`.
///
/// `browser.revoke_access` acts for the route's own agent, which must be
/// attested, since it names the rows it removes; it asks nobody because it
/// only narrows. The other two name the agent explicitly and are the
/// operator's (see `is_operator_operation`).
fn standing_grant_operation(
    method: &str,
    params: &serde_json::Map<String, Value>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
) -> Result<Value, StandingGrantOperationRefusal> {
    use browser_standing_grants::RevokeTarget;
    let standing = planes.management.standing_browser_grants();
    match method {
        management::REVOKE_ACCESS => {
            standing_grant_params::only(params, &["origin", "domain"])
                .map_err(StandingGrantOperationRefusal::UnknownField)?;
            let origin = standing_grant_params::origin(params)?;
            let holder = permission_scope::authorizing_holder(facts);
            if (planes.management.unified_agent_grants().is_some() && holder.is_none())
                || (planes.management.unified_agent_grants().is_none()
                    && (!facts.agent_project_id_attested || !facts.acts_as_agent))
            {
                return Ok(json!({
                    "outcome": "agent_not_attested",
                    "revoked": 0,
                    "remedy": "this route's agent identity is not attested, so it holds no standing browser access to remove",
                }));
            }
            let domain = standing_grant_params::domain(params)?;
            let target = match (origin, domain) {
                (Some(_), Some(_)) => return Err(("domain", "conflicting_fields").into()),
                (Some(origin), None) => RevokeTarget::Origin(origin),
                (None, Some(domain)) => RevokeTarget::Domain(domain),
                (None, None) => RevokeTarget::Everything,
            };
            if let Some(store) = planes.management.unified_agent_grants() {
                return Ok(management::retained_browser_ops::revoke_rows(
                    store,
                    agent_grants::BrowserTarget::AgentProfile,
                    &target,
                    |row_holder| Some(row_holder) == holder.as_ref(),
                ));
            }
            Ok(standing.revoke(&facts.identity.agent_project_id, &target))
        }
        management::REVOKE_GRANT => {
            standing_grant_params::only(params, &["agent_id", "origin", "domain", "all_sites"])
                .map_err(StandingGrantOperationRefusal::UnknownField)?;
            let agent_id = standing_grant_params::agent_id(params)?;
            let origin = standing_grant_params::origin(params)?;
            let all_sites = match params.get("all_sites") {
                None => false,
                Some(Value::Bool(true)) => true,
                Some(Value::Bool(false)) => {
                    return Err(("all_sites", "unsupported_value").into());
                }
                Some(_) => return Err(("all_sites", "wrong_type").into()),
            };
            let domain = standing_grant_params::domain(params)?;
            if domain.is_some() && (origin.is_some() || all_sites) {
                return Err(("domain", "conflicting_fields").into());
            }
            let target = match (origin, all_sites) {
                (Some(_), true) => return Err(("all_sites", "conflicting_fields").into()),
                (Some(origin), false) => RevokeTarget::Origin(origin),
                (None, true) => RevokeTarget::AllSites,
                (None, false) => domain.map_or(RevokeTarget::Everything, RevokeTarget::Domain),
            };
            if let Some(store) = planes.management.unified_agent_grants() {
                return Ok(management::retained_browser_ops::revoke_rows(
                    store,
                    agent_grants::BrowserTarget::AgentProfile,
                    &target,
                    |holder| holder.agent_id() == agent_id,
                ));
            }
            Ok(standing.revoke(&agent_id, &target))
        }
        _ => {
            standing_grant_params::only(params, &["agent_id"])
                .map_err(StandingGrantOperationRefusal::UnknownField)?;
            let agent_id = standing_grant_params::agent_id(params)?;
            let apps = planes.management.computer_grants().list();
            let app_grants: Vec<Value> = apps["grants"]
                .as_array()
                .map(|grants| {
                    grants
                        .iter()
                        .filter(|grant| grant["grantee"] == agent_id.as_str())
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            Ok(json!({
                "agent_id": agent_id,
                "browser": planes.management.unified_agent_grants().map_or_else(|| json!({
                    "grants": standing
                        .live_rows(&agent_id)
                        .iter()
                        .map(browser_standing_grants::StandingBrowserGrant::describe)
                        .collect::<Vec<_>>(),
                    "store": standing.store_state(),
                }), |store| management::retained_browser_ops::listing(store, &agent_id)),
                "apps": {
                    "grants": app_grants,
                    "store": apps["store"].clone(),
                },
            }))
        }
    }
}

async fn import_browser_login(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    channel: u16,
    epoch: u32,
    corr: u64,
    origin: &str,
) -> Value {
    let durable = facts.identity.profile_disposition == ProfileDisposition::Durable;
    if let Err(result) = login_import::profile_precondition(origin, durable) {
        return journal_login_import_result(planes, &facts.identity, *result).await;
    }
    if !computer_grants::admits_consent(facts) {
        if facts.flow_id.is_some() {
            return flow_consent_refusal("unattended_flow");
        }
        let why = cingulate_client::desk::NoCard::NoAgentSession;
        let result = login_import::ImportResult::refusal(
            origin,
            "consent_unavailable",
            why.remedy().unwrap(),
        );
        let mut reply = journal_login_import_result(planes, &facts.identity, result).await;
        reply["detail"] = json!({"reason":why.reason(),"remedy":why.remedy()});
        return reply;
    }
    let (location, profile_uuid) = match planes
        .management
        .durable_login_profile_identity(&facts.identity.agent_project_id)
    {
        Ok(Some(location)) => location,
        Ok(None) => {
            let result = login_import::ImportResult::refusal(
                origin,
                "profile_not_durable",
                "launch the durable profile once so the profile registry can mint it",
            );
            return journal_login_import_result(planes, &facts.identity, result).await;
        }
        Err(_) => {
            let result = login_import::ImportResult::refusal(
                origin,
                "profile_not_durable",
                "restore access to the durable browser profile registry, then retry",
            );
            return journal_login_import_result(planes, &facts.identity, result).await;
        }
    };
    planes
        .browser
        .register_existing_profile(&facts.identity, &profile_uuid)
        .await;
    let Some(launch_executable) = planes
        .browser_config
        .as_ref()
        .and_then(|config| config.executable_path.as_deref())
    else {
        let result = login_import::ImportResult::refusal(
            origin,
            "launch_binary_unsupported",
            "configure a supported Chromium-family browser executable",
        );
        return journal_login_import_result(planes, &facts.identity, result).await;
    };
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        let result = login_import::ImportResult::refusal(
            origin,
            "launch_binary_unsupported",
            "run the module with a readable user home directory",
        );
        return journal_login_import_result(planes, &facts.identity, result).await;
    };
    let plan = match login_import::prepare_import(
        origin,
        &facts.identity.agent_project_id,
        launch_executable,
        location,
        login_import::ImportSettings::production(&home),
    ) {
        login_import::PreparedImport::Ready(plan) => plan,
        login_import::PreparedImport::Refused(result) => {
            return journal_login_import_result(planes, &facts.identity, result).await
        }
    };

    complete_login_import(
        planes,
        facts,
        writer,
        channel,
        epoch,
        plan,
        planes.cancellations.get((channel, epoch, corr)),
    )
    .await
}

pub(super) async fn complete_login_import(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    channel: u16,
    epoch: u32,
    plan: login_import::LoginImportPlan,
    cancel: Option<CancelHandle>,
) -> Value {
    let request = login_consent_request(
        planes,
        facts,
        writer,
        (channel, epoch),
        computer_grants::LoginCapability::ImportLogin,
        plan.consent_parameters(),
        cancel.clone(),
    );
    let carrier = Arc::clone(&request.carrier);
    let consent = planes
        .management
        .computer_grants()
        .require_login(request, || plan.question(&facts.identity.agent_project_id));
    let consent = consent.await;
    let mut execution = None;
    let answer = match consent {
        computer_grants::LoginConsent::Ended(answer) => {
            if let cingulate_client::desk::Ending::NoCard(why) = answer.ending {
                return json!({"outcome":"consent_unavailable","detail":{"reason":why.reason(),"remedy":why.remedy()}});
            }
            if matches!(&answer.ending, cingulate_client::desk::Ending::Declined { choice_id } if choice_id != "deny")
            {
                return json!({"outcome":"unrecognized_answer","remedy":"The answer could not be read; retry this call to ask again."});
            }
            if answer.ending == cingulate_client::desk::Ending::Withdrawn
                && planes.draining.load(std::sync::atomic::Ordering::Acquire)
            {
                return json!({"outcome":"module_draining"});
            }
            if answer.ending == cingulate_client::desk::Ending::Withdrawn
                && !cancel.as_ref().is_some_and(CancelHandle::is_cancelled)
            {
                return json!({"outcome":"question_withdrawn","remedy":"retry this call to ask again"});
            }
            if answer.taken_approval {
                execution = Some(answer.clone());
            }
            Some(answer.ending)
        }
        computer_grants::LoginConsent::Pending { ask_id } => {
            return journal_login_import_result(planes, &facts.identity, plan.pending(ask_id))
                .await;
        }
    };

    let answer = if cancel.as_ref().is_some_and(CancelHandle::is_cancelled) {
        None
    } else {
        answer
    };
    // Journal or relaunch failures must not hide that the copy already ran.
    let mut execution_result = json!({"outcome":"not_run"});
    let reply = async {
        let decision = match &answer {
            Some(cingulate_client::desk::Ending::Granted { choice_id }) => Some(choice_id.as_str()),
            // None of these permits a transfer, and they are listed rather
            // than wildcarded so a future ending has to be decided about here.
            Some(
                cingulate_client::desk::Ending::Declined { .. }
                | cingulate_client::desk::Ending::NoAnswer
                | cingulate_client::desk::Ending::NotPutToAnyone
                | cingulate_client::desk::Ending::DeliveryFailed
                | cingulate_client::desk::Ending::Withdrawn
                | cingulate_client::desk::Ending::NoCard(_),
            )
            | None => None,
        };
    let mut reopen = None;
    if plan.permits_transfer(decision) {
        let status = planes.sessions.status(
            &facts.identity.conversation_key,
            planes.lease_clock.as_ref(),
            std::time::SystemTime::now(),
        );
        if status.get("outcome").and_then(Value::as_str) == Some("ready") {
            let Some(config) = planes.browser_config.as_ref() else {
                return journal_login_import_result(
                    planes,
                    &facts.identity,
                    plan.refusal("session_open", "close"),
                )
                .await;
            };
            let closed =
                close_idle_for_import_off_task(planes, &facts.identity.conversation_key, config)
                    .await;
            match closed {
                Ok(Ok((closed, url))) if closed["outcome"] == "closed" => {
                    reopen = Some(url);
                    planes.browser.end_context(&facts.identity, false).await;
                }
                _ => {
                    return journal_login_import_result(
                        planes,
                        &facts.identity,
                        plan.refusal("session_open", "close"),
                    )
                    .await
                }
            }
        }
    }
    if plan.permits_transfer(decision) {
        if let Some(id) = execution.as_ref().and_then(|answer| answer.elicitation_id.as_deref()) {
            if planes.consent.begin_execution(id).is_err() {
                execution_result = json!({"outcome":"consent_unavailable", "reason":"grant_store_unavailable"});
                return execution_result.clone();
            }
        }
    }
    let result = match &answer {
        Some(answer) => plan.conclude(answer),
        // A caller stop authorizes no transfer and is not a person's denial.
        None => plan.cancelled(),
    };
    execution_result = result.to_value();
    let mut reply = journal_login_import_result(planes, &facts.identity, result).await;
    if let Some(url) = reopen {
        // Even a failed copy must not leave a session we closed unnecessarily down.
        let launched =
            handle_browser_control(browser_session::BROWSER_LAUNCH, &json!({}), facts, planes)
                .await;
        if launched["outcome"] == "launched" {
            let mut restored_url = None;
            if let Some(url) = url {
                if let Some(origin) = classification::canonical_origin_from_url(&url) {
                    let granted = planes
                        .management
                        .browser_grants()
                        .lock()
                        .await
                        .select_covering_grant(
                            &facts.identity.conversation_key,
                            authorization::Severity::new(1, false, false),
                            &origin,
                        )
                        .is_ok();
                    if granted {
                        let navigation = planes.browser.serve(&facts.identity, browser::BrowserCapability::Navigate,
                            &json!({"url":url,"intent":"Restore the page after importing login","severity":{"tier":1,"credential":false,"financial":false},"wait":"settle"})).await;
                        if let Ok(navigation) = navigation {
                            if matches!(navigation["outcome"].as_str(), Some("ok" | "not_settled"))
                            {
                                restored_url = navigation["url_final"].as_str().map(str::to_string);
                            }
                        }
                    }
                }
            }
            reply["relaunched"] = json!({"browser_session_id":launched["browser_session_id"],"restored_url":restored_url});
        } else {
            reply["relaunched"] = Value::Null;
            reply["detail"] = launched;
        }
    }
    reply
    }.await;
    if let Some(answer) = execution {
        computer_grants::report_login_execution(
            &carrier,
            &answer,
            &execution_result,
            "transferred",
        )
        .await;
    }
    reply
}

pub(super) async fn journal_login_import_result(
    planes: &Planes,
    identity: &RouteIdentity,
    result: login_import::ImportResult,
) -> Value {
    if result.outcome == "transferred"
        && planes
            .browser
            .record_signed_in(&identity.agent_project_id, &result.origin)
            .await
            .is_err()
    {
        return json!({"outcome":"internal_failure","reason":"signed_in_domains_unavailable"});
    }
    if planes
        .browser
        .journal_login_import(
            identity,
            &result.origin,
            &result.outcome,
            result.browser.as_deref(),
            result.rows,
        )
        .await
        .is_err()
    {
        return json!({"outcome":"internal_failure","reason":"journal_unavailable"});
    }
    result.to_value()
}

pub(super) async fn present_browser_handoff(
    planes: &Planes,
    identity: &RouteIdentity,
    origin: &str,
    held: Option<(String, String, journal::call_records::ScopeIdentity)>,
) -> Value {
    let deadline_ms = planes
        .browser_config
        .as_ref()
        .map_or(30_000, |config| config.navigation_settle_deadline_ms);
    // Fronting the window and reading its cookies are blocking CDP commands
    // under the session's driver lock, so they run on the blocking pool, never
    // on this async task. The call took its work permit when it got its turn
    // in the conversation's queue, and keeps it until this job finishes: if
    // the call is answered (by its deadline, a cancel or a drain) before the
    // job returns, its route task is kept alive, holding the permit, until
    // then. So a stuck job keeps counting against the plane's capacity.
    let sessions = planes.sessions.clone();
    let clock = Arc::clone(&planes.lease_clock);
    let route_key = identity.conversation_key.clone();
    let profile = identity.agent_project_id.clone();
    let profile_name = browser_signed_in::SignedInDomains::profile_name(identity);
    let present_origin = origin.to_owned();
    let presented = on_call_blocking_pool(move || {
        sessions.present_for_profile(
            &route_key,
            &profile,
            &profile_name,
            &present_origin,
            deadline_ms,
            clock.as_ref(),
        )
    })
    .await;
    let Ok(presented) = presented else {
        return json!({"outcome":"internal_failure"});
    };
    let presented = match presented {
        Ok(presented) => presented,
        Err(browser_session::PresentRefusal::NoSession) => {
            return json!({"outcome":"no_session","remedy":"launch the browser"})
        }
        Err(browser_session::PresentRefusal::OriginMismatch { current_origin }) => {
            return json!({
                "outcome":"origin_mismatch",
                "current_origin":current_origin,
                "remedy":"call navigate",
            })
        }
        Err(browser_session::PresentRefusal::HandoffOpen) => {
            return json!({"outcome":"handoff_open","remedy":"call resume"})
        }
        Err(browser_session::PresentRefusal::PresentFailed { error_text }) => {
            return json!({
                "outcome":"present_failed",
                "error_text":error_text,
                "remedy":"call present",
            })
        }
    };

    if planes
        .browser
        .journal_handoff_opened(identity, origin)
        .await
        .is_err()
    {
        let _ = planes
            .sessions
            .resume(&identity.conversation_key, planes.lease_clock.as_ref());
        return json!({"outcome":"internal_failure"});
    }

    if let Some((principal, key, scope)) = held.clone() {
        let calls = Arc::clone(&planes.calls);
        let conversation = identity.conversation_key.clone();
        let origin = origin.to_owned();
        let saved = tokio::task::spawn_blocking(move || {
            calls.hold_handoff(
                &principal,
                &key,
                &conversation,
                scope,
                &origin,
                wall_clock_ms(),
            )
        })
        .await;
        if !matches!(saved, Ok(Ok(()))) {
            let _ = planes
                .sessions
                .resume(&identity.conversation_key, planes.lease_clock.as_ref());
            return json!({"outcome":"internal_failure"});
        }
    }

    let settle = held
        .as_ref()
        .map(|(principal, key, _)| {
            let calls = Arc::clone(&planes.calls);
            let (principal, key) = (principal.clone(), key.clone());
            Arc::new(move |ending| {
                calls
                    .finish_handoff(&principal, &key, ending, wall_clock_ms())
                    .is_ok()
            }) as HandoffSettle
        })
        .or_else(tool_display::handoff_settle);
    spawn_handoff_poll(
        planes,
        identity.clone(),
        presented.generation,
        deadline_ms,
        settle,
    );

    if held.is_some() {
        json!({"outcome":"login_pending", "origin":origin, "expires_in_ms":presented.expires_in_ms})
    } else {
        json!({"outcome":"presented", "expires_in_ms":presented.expires_in_ms})
    }
}

pub(super) fn handoff_ending(
    outcome: browser_session::HandoffOutcome,
) -> journal::call_records::HandoffEnding {
    use journal::call_records::HandoffEnding;
    match outcome {
        browser_session::HandoffOutcome::LoginObserved => HandoffEnding::LoginObserved,
        browser_session::HandoffOutcome::Expired => HandoffEnding::HandoffExpired,
        browser_session::HandoffOutcome::ClosedByCaller => HandoffEnding::ClosedByCaller,
    }
}

pub(super) async fn resume_browser_handoff(planes: &Planes, identity: &RouteIdentity) -> Value {
    let calls = Arc::clone(&planes.calls);
    let sessions = planes.sessions.clone();
    let clock = Arc::clone(&planes.lease_clock);
    let conversation = identity.conversation_key.clone();
    let resumed = tokio::task::spawn_blocking(move || {
        calls.resume_handoff(&conversation, wall_clock_ms(), || {
            sessions.resume(&conversation, clock.as_ref())
        })
    })
    .await;
    let close = match resumed {
        Ok(Ok(close)) => close,
        Ok(Err(browser_session::ResumeRefusal::NoHandoff)) => {
            return json!({"outcome":"no_handoff","remedy":"call present"})
        }
        Err(_) => return json!({"outcome":"internal_failure"}),
    };
    if close.should_journal {
        let _ = planes
            .browser
            .journal_handoff_closed(identity, &close)
            .await;
    }
    json!({
        "outcome":"resumed",
        "handoff":close.outcome.as_str(),
        "origin":close.origin,
    })
}

/// Adapter for `session.turn_ended`: admit, parse, hand off, acknowledge.
///
/// Interim: the supervising module calls this directly until the harness
/// publishes a turn-ended event; then this adapter goes, and the
/// subscription calls [`computer_capability::cursor::Coordinator::turn_ended`]
/// the same way.
///
/// Only the agent's orchestrator may call it, by exact reserved principal. A flow
/// carrier or another first-party module is refused like any other caller of
/// a supervisor-only operation. Once admitted and well formed, the reply is
/// always an acknowledgement, even for a session that drew no badge: the
/// caller learns nothing about which sessions used the computer. It writes no
/// journal and touches nothing but the cursor badge: it hides the badge, and
/// an action of that agent still waiting for its badge to arrive will not
/// start. It never touches an action already dispatched.
async fn handle_session_turn_ended(
    writer: &mpsc::Sender<Frame>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
    object: &serde_json::Map<String, Value>,
    (ver, channel, epoch, corr): (u8, u16, u32, u64),
) -> Result<(), ModuleError> {
    if !cerebellum_core::principal::admits_session_calls(&facts.principal) {
        record_turn_ended_refused();
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "principal_denied",
            "session.turn_ended requires the agent's orchestrator",
        )
        .await;
    }
    let params = object.get("params").cloned().unwrap_or(json!({}));
    let Some(params) = params.as_object() else {
        record_turn_ended_refused();
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "params",
            "wrong_type",
        )
        .await;
    };
    let request = match turn_ended::parse(params) {
        Ok(request) => request,
        Err(error) => {
            record_turn_ended_refused();
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                &error.field,
                error.reason,
            )
            .await;
        }
    };
    if let Some(cursor) = planes_cursor(planes) {
        let matched = cursor.turn_ended(
            &request.session_ref,
            Some(&request.scope_ref),
            request.outcome,
        );
        if matched {
            record_turn_ended_matched_badge();
        }
    }
    send_tool_response(
        writer,
        ver,
        channel,
        epoch,
        corr,
        json!({"acknowledged": true}),
    )
    .await?;
    record_turn_ended_received(request.at_ms);
    Ok(())
}

/// `image.resolve`: the bytes a screenshot handle stands for.
///
/// The model-call broker fetches screenshots a codemode program passes by
/// handle, since the bytes are too large for the program result.
/// Only `reserved:broca` on a management surface reaches it, checked by the
/// route dispatcher before this runs.
///
/// A handle that is unknown, expired, or belongs to a scope outside the
/// caller's union all get one identical refusal body, and the store does the
/// same work for each, so the reply never says whether a handle exists.
async fn handle_image_resolve(
    frame: &Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    request: &serde_json::Map<String, Value>,
) -> Result<(), ModuleError> {
    let (ver, channel, epoch, corr) = (
        frame.header.ver,
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
    );
    let params = request.get("params").and_then(Value::as_object);
    let parsed = (|| {
        let params = params.ok_or(("params", "wrong_type"))?;
        // Largest frame first, so a query naming an unusual key is refused for
        // that key rather than for whichever key happened to come first.
        if let Some(field) = params
            .keys()
            .filter(|field| !matches!(field.as_str(), "handle" | "scope_ref" | "parent_scope_ref"))
            .max()
        {
            return Err((field.as_str(), "unknown_field"));
        }
        let text = |field: &'static str| match params.get(field) {
            Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.as_str())),
            Some(Value::String(_)) => Err((field, "empty_value")),
            Some(_) => Err((field, "wrong_type")),
            None => Ok(None),
        };
        let handle = text("handle")?.ok_or(("handle", "missing_field"))?;
        let scope = text("scope_ref")?.ok_or(("scope_ref", "missing_field"))?;
        let parent = text("parent_scope_ref")?;
        Ok((handle, scope, parent))
    })();
    let (handle, scope, parent) = match parsed {
        Ok(parsed) => parsed,
        Err((field, reason)) => {
            return send_invalid_request_response(writer, ver, channel, epoch, corr, field, reason)
                .await
        }
    };
    let scopes = private_content::scope_union(planes, scope, parent);
    let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
    let resolved = planes
        .image_handles
        .resolve(handle, &scopes, wall_clock_ms());
    // Like private_content, refusals use a JSON body in a Response frame.
    // The model-call broker treats a body with `outcome` as a refusal; an
    // Error frame would violate that contract.
    debug_assert!(resolved
        .as_ref()
        .is_none_or(|resolved| resolved.body.len() <= image_handles::MAX_RESOLVE_BODY_BYTES));
    let Some(resolved) = resolved else {
        let refusal = json!({
            "outcome": image_handles::UNAVAILABLE,
            "context": null,
            "session": null,
            "detail": {"field": "handle"},
        });
        return send_tool_response(writer, ver, channel, epoch, corr, refusal).await;
    };
    let flags = Flags::new(resolved.binary, subc_protocol::Priority::Interactive, false);
    let frame = Frame::build_with_version(
        ver,
        FrameType::Response,
        flags,
        channel,
        epoch,
        corr,
        resolved.body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}
