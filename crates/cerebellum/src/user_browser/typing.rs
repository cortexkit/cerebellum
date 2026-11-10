use super::*;

pub(super) fn allows_focus_form_controls(
    dom: &serde_json::Map<String, Value>,
    identity: &BackendNodeIdentity,
    expected: &NonTypeClassificationRecord,
    observed: &NonTypeClassificationRecord,
) -> bool {
    let mut updated = expected.clone();
    updated.associated_form_controls = observed.associated_form_controls.clone();
    if updated != *observed
        || observed.associated_form_controls.iter().any(|control| {
            control.password
                || control.autocomplete_tokens.iter().any(|token| {
                    crate::classification::credential_token(token)
                        || crate::classification::financial_token(token)
                })
        })
        || type_field_refusal(observed).is_some()
    {
        return false;
    }
    // Focus handlers may add clear buttons or hidden search fields. Recompute
    // the same type decision used before dispatch; a form-only change must not
    // hide a newly ineligible or sensitive target, or require a different tier.
    let Ok(target) = crate::browser::navigation::type_target_from_capture(dom, identity, observed)
    else {
        return false;
    };
    let decision = target.classification();
    crate::browser_type::browser_type_dispatch_eligible(&target)
        && !decision.credential
        && !decision.financial
        && decision.required_tier == expected.required_tier
}

pub(super) fn role_name(nodes: &[Value], backend: u64) -> Option<(String, String)> {
    let node = nodes
        .iter()
        .find(|node| node["backendDOMNodeId"] == backend && node["ignored"] == false)?;
    Some((
        node.pointer("/role/value")?.as_str()?.into(),
        node.pointer("/name/value")?.as_str()?.into(),
    ))
}

/// A focus handler may replace its input. Only this one post-focus handoff can
/// change identities; attached targets and all later checks remain strict.
pub(super) async fn after_focus(
    context: &Context<'_>,
    tab: &str,
    snapshot: &Snapshot,
    original: &ShownRef,
) -> Result<Option<ShownRef>, Value> {
    let frame = &original.frame;
    let observed = input_document(context, tab, snapshot, true).await?;
    if let Some(reason) = observed.unreadable_frames.get(&frame.frame_id) {
        return Err(reason.refusal());
    }
    if !observed.frames.iter().any(|live| live.same_document(frame)) {
        return Err(refusal("frame_changed"));
    }
    let mut commands = vec![
        command("Accessibility.enable", json!({})),
        command(
            "Accessibility.getFullAXTree",
            json!({"frameId":frame.frame_id}),
        ),
    ];
    commands.extend(flattened_document());
    let capture = context
        .cdp_frame(tab, Some(snapshot.interaction), frame, commands)
        .await?;
    let dom = capture
        .results
        .last()
        .and_then(Value::as_object)
        .ok_or_else(|| protocol_error("DOM.getFlattenedDocument", None))?;
    let dom_nodes = dom
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| protocol_field_error("DOM.getFlattenedDocument", "nodes"))?;
    if dom_nodes
        .iter()
        .any(|node| node["backendNodeId"] == original.identity.backend_node_id)
    {
        return Ok(None);
    }
    let nodes = capture.results[1]["nodes"]
        .as_array()
        .ok_or_else(|| protocol_field_error("Accessibility.getFullAXTree", "nodes"))?;
    let observation = snapshot_from_capture(
        nodes,
        dom,
        tab,
        &frame.frame_id,
        snapshot.interaction,
        &frame.url,
        &frame.origin,
    )
    .map_err(|_| refusal("classification_unavailable"))?;
    let mut focused = observation.refs.iter().filter(|reference| {
        reference
            .backend_identity
            .as_ref()
            .is_some_and(|identity| identity.frame_id == frame.frame_id)
            && observation
                .facts
                .get(&reference.captured.reference)
                .is_some_and(|facts| facts.states.iter().any(|state| state == "focused"))
    });
    let candidate = focused
        .next()
        .ok_or_else(|| refusal("classification_changed"))?;
    if focused.next().is_some() {
        return Err(refusal("classification_changed"));
    }
    let identity = candidate
        .backend_identity
        .as_ref()
        .expect("filtered identity");
    // Compare the complete computed AX strings, not the renderer's bounded
    // labels: two long accessible names must not match only by a prefix.
    if original.role_name.is_none()
        || role_name(nodes, identity.backend_node_id) != original.role_name
    {
        return Err(refusal("classification_changed"));
    }
    let (_, record) = classify_frame_capture(
        capture.results.last(),
        identity,
        frame,
        snapshot.interaction,
        "type.after_focus.classify_flattened_document",
    )?;
    if let Some(reply) = type_field_refusal(&record) {
        return Err(reply);
    }
    let target = crate::browser::navigation::type_target_from_capture(dom, identity, &record)
        .map_err(|_| refusal("classification_unavailable"))?;
    if !crate::browser_type::browser_type_dispatch_eligible(&target)
        || target.classification().credential
        || target.classification().financial
    {
        return Err(refusal("target_not_interactive"));
    }
    let focus = context
        .cdp_frame(
            tab,
            Some(snapshot.interaction),
            frame,
            runtime_plan(identity, functions::HAS_FOCUS),
        )
        .await?;
    if focus
        .results
        .last()
        .and_then(|result| result.pointer("/result/value"))
        != Some(&json!(true))
    {
        return Err(refusal("type_focus_not_ready"));
    }
    input_document(context, tab, snapshot, true).await?;
    Ok(Some(ShownRef {
        identity: identity.clone(),
        frame: frame.clone(),
        classification: Some(record),
        role_name: original.role_name.clone(),
    }))
}
