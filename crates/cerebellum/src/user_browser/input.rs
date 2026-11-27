use super::*;
use crate::browser::keys::Key;

pub(super) async fn input(
    context: &Context<'_>,
    tab: &str,
    action: &str,
    args: &Value,
    current: &Document,
) -> Result<Value, Value> {
    let mut text_attempted = false;
    let result = input_inner(context, tab, action, args, current, &mut text_attempted).await;
    result.map_err(|mut reply| {
        if action == "type" && !text_attempted && reply["input_dispatched"] == true {
            // Focus and caret events can affect the page, but they do not send
            // the requested text. Do not discourage a retry as if insertion ran.
            reply["outcome"] = json!("outcome_unknown");
            reply["remedy"] = json!("The requested text was not sent. Focus or caret input may have taken effect. Take a fresh read before deciding whether to retry typing.");
        }
        reply
    })
}

async fn input_inner(
    context: &Context<'_>,
    tab: &str,
    action: &str,
    args: &Value,
    current: &Document,
    text_attempted: &mut bool,
) -> Result<Value, Value> {
    let key = context.key;
    let keyboard = action == "type" || key.is_some();
    let snapshot = context
        .target()
        .snapshot(context.route, tab, context.connection, args)?;
    if !current.observer_available || snapshot.observer_continuity != current.observer_continuity {
        return Err(observer_unavailable());
    }
    bind_observer_continuity(snapshot.observer_continuity);
    if snapshot.document != current.committed || snapshot.interaction != current.interaction {
        return Err(read_again(false));
    }
    let (mut identity, frame, position) = if action == "click_point" {
        let image = snapshot
            .image
            .as_ref()
            .ok_or_else(|| refusal("snapshot_kind_mismatch"))?;
        let (width, height) = (image.width, image.height);
        if args["image_width_px"] != width || args["image_height_px"] != height {
            return Err(invalid("image_width_px", "dimension_mismatch"));
        }
        let x = args["point"]["x"].as_i64().unwrap();
        let y = args["point"]["y"].as_i64().unwrap();
        if x < 0 || y < 0 || x as u64 >= width || y as u64 >= height {
            return Err(refusal("point_outside_viewport"));
        }
        let metrics = context
            .cdp(
                tab,
                Some(snapshot.interaction),
                vec![command("Page.getLayoutMetrics", json!({}))],
            )
            .await?;
        if metrics.results[0]["cssVisualViewport"] != image.viewport {
            return Err(refusal("viewport_changed"));
        }
        let mapped = crate::coordinate::map_pixel_center(
            viewport_transform(&image.viewport)?,
            width as u32,
            height as u32,
            x,
            y,
        )
        .map_err(|_| refusal("invalid_coordinates"))?;
        let (x, y) = mapped.tuple();
        let hit = context.cdp(tab, Some(snapshot.interaction), vec![command("DOM.getNodeForLocation", json!({"x":x.round() as i64,"y":y.round() as i64,"includeUserAgentShadowDOM":false}))]).await?;
        let frame_id = hit.results[0]["frameId"].as_str().ok_or_else(|| {
            classification_failure(
                "click_point.hit_frame",
                "",
                None,
                "hit_test_frame_id_missing",
            )
        })?;
        let frame = current
            .frames
            .iter()
            .find(|frame| frame.frame_id == frame_id)
            .ok_or_else(|| refusal("frame_not_authorized"))?
            .clone();
        let backend = hit.results[0]["backendNodeId"].as_u64().ok_or_else(|| {
            classification_failure(
                "click_point.hit_node",
                &frame.url,
                Some(false),
                "hit_test_backend_node_id_missing",
            )
        })?;
        let local = &hit.results[0]["frame_point"];
        let position = if local.is_null() {
            (x, y)
        } else {
            (
                local["x"]
                    .as_f64()
                    .ok_or_else(|| protocol_field_error("DOM.getNodeForLocation", "frame_point"))?,
                local["y"]
                    .as_f64()
                    .ok_or_else(|| protocol_field_error("DOM.getNodeForLocation", "frame_point"))?,
            )
        };
        (
            BackendNodeIdentity::new(tab, frame_id, backend).map_err(|_| {
                classification_failure(
                    "click_point.node_identity",
                    &frame.url,
                    Some(true),
                    "invalid_backend_node_identity",
                )
            })?,
            frame,
            Some(position),
        )
    } else {
        let reference = snapshot
            .refs
            .get(args["ref"].as_str().unwrap())
            .ok_or_else(|| refusal("ref_scope_mismatch"))?;
        (reference.identity.clone(), reference.frame.clone(), None)
    };
    if let Some(reason) = current.unreadable_frames.get(&frame.frame_id) {
        return Err(reason.refusal());
    }
    if !current.frames.iter().any(|live| live.same_document(&frame)) {
        return Err(refusal("frame_changed"));
    }
    // An ungranted frame cannot even be classified for input. A top-level
    // screenshot grant does not authorize acting inside a cross-site frame.
    let input_origin = origin(&frame.origin)?;
    let requested = if keyboard {
        Severity::new(2, false, false)
    } else {
        declared_severity(args)?
    };
    let read_grant = context
        // Classification reads the frame; it does not perform the declared
        // action. Ask for that action only after its hazards are known, so a
        // form submit gets one correctly disclosed higher-risk approval.
        .authorize(
            &input_origin,
            Severity::new(authorization::OBSERVE, false, false),
            BTreeSet::new(),
        )
        .await?;
    let observed = context
        .cdp_frame(
            tab,
            Some(snapshot.interaction),
            &frame,
            flattened_document(),
        )
        .await?;
    let (dom_object, mut classification) = classify_frame_capture(
        observed.results.last(),
        &identity,
        &frame,
        snapshot.interaction,
        "input.classify_flattened_document",
    )?;
    let native_option = action == "click"
        && crate::browser::navigation::native_select::target_from_capture(
            dom_object,
            &identity,
            &classification,
        )
        .map_err(|problem| {
            let mut reply = refusal("target_not_interactive");
            reply["detail"] = json!({"step":"input.native_option","problem":problem});
            reply
        })?;
    let expected = args["ref"]
        .as_str()
        .and_then(|reference| snapshot.refs.get(reference))
        .and_then(|reference| reference.classification.as_ref());
    if key.is_some() && expected.is_none() {
        return Err(refusal("classification_unavailable"));
    }
    if let Some(expected) = expected {
        if *expected != classification {
            return Err(classification_changed(
                expected,
                &classification,
                InputCheck::PreDispatch,
            ));
        }
        if key == Some(Key::Enter) && expected.implicit_submit != classification.implicit_submit {
            return Err(refusal("classification_changed"));
        }
    }
    if key.is_some_and(|key| key.field_refusal(&classification).is_some()) {
        return Err(type_field_refusal(&classification).expect("sensitive field refusal"));
    }
    if action == "type" {
        if let Some(reply) = type_field_refusal(&classification) {
            return Err(reply);
        }
        let target = crate::browser::navigation::type_target_from_capture(
            dom_object,
            &identity,
            &classification,
        )
        .map_err(|cause| {
            classification_failure(
                "input.type_target_from_capture",
                &frame.url,
                Some(true),
                &cause.to_string(),
            )
        })?;
        if !crate::browser_type::browser_type_dispatch_eligible(&target)
            || target.classification().credential
            || target.classification().financial
        {
            return Err(refusal("target_not_interactive"));
        }
    }
    let authorized_action = if action == "click_point" {
        Action::ClickPoint
    } else {
        Action::Click
    };
    let policy_error = |_| {
        classification_failure(
            "input.target_hazards",
            &frame.url,
            Some(true),
            "hazard_projection_failed",
        )
    };
    let (severity, hazards, destinations) = if let Some(key) = key {
        let policy = key.policy(&classification).map_err(policy_error)?;
        (
            policy.severity,
            policy.hazards,
            policy.destinations.map(|origin| origin.map(str::to_owned)),
        )
    } else {
        let (severity, hazards) = if action == "type" {
            (requested, BTreeSet::new())
        } else {
            (
                authorization::effective_severity(
                    authorized_action,
                    requested,
                    Some(&classification),
                )
                .map_err(|_| refusal("severity_below_floor"))?,
                authorization::target_hazards(authorized_action, Some(&classification))
                    .map_err(policy_error)?,
            )
        };
        (
            severity,
            hazards,
            [classification.activation_destination_origin.clone(), None],
        )
    };
    let once = if read_grant.covers(&input_origin, severity, &hazards) {
        read_grant
    } else {
        context
            .authorize(&input_origin, severity, hazards.clone())
            .await?
    };
    let mut destination_grants = BTreeMap::new();
    for destination in destinations.iter().flatten() {
        if destination != &frame.origin && !destination_grants.contains_key(destination) {
            let grant = context
                .authorize(destination, severity, hazards.clone())
                .await?;
            destination_grants.insert(destination.clone(), grant);
        }
    }
    // Resolve explicit new-tab links as a background open instead of letting
    // Chrome activate the page's new target, even briefly.
    if !keyboard {
        if let Some(url) =
            crate::browser::navigation::new_tab_link_from_capture(dom_object, &identity, &frame.url)
        {
            let destination = origin(&url)?;
            if !context.granted(
                &destination,
                severity,
                &hazards,
                destination_grants.get(&destination),
            ) && !context.granted(&destination, severity, &hazards, Some(&once))
            {
                return Err(refusal("grant_revoked"));
            }
            verify_input(
                context,
                tab,
                &snapshot,
                &frame,
                &identity,
                &mut classification,
                InputCheck::PreDispatch,
            )
            .await?;
            let raw = invoke(
                context.bridge(),
                context.route,
                &context.cancel,
                "open_tab",
                json!({"url":url,"opener_tab":tab}),
            )
            .await?;
            let opened: Claimed = decode("tab_reply", raw)?;
            if opened.connection_epoch != context.connection {
                return Err(read_again(false));
            }
            context
                .target()
                .state()
                .claims
                .insert(opened.tab.clone(), context.route);
            return Ok(
                json!({"browser":"user","outcome":"ok","tab":opened.tab,"connection_epoch":context.connection,"interaction_epoch":opened.interaction_epoch,"input_dispatched":false}),
            );
        }
    }
    let position = if keyboard || native_option {
        None
    } else if position.is_some() {
        position
    } else {
        input_document(context, tab, &snapshot, false).await?;
        let quad = context
            .cdp_frame(
                tab,
                Some(snapshot.interaction),
                &frame,
                vec![
                    // The Chrome DevTools Protocol scrolls the node without page-supplied JavaScript or
                    // activating its tab. Measure in the same attachment after
                    // scrolling, not against the snapshot's old page position.
                    command(
                        "DOM.scrollIntoViewIfNeeded",
                        json!({"backendNodeId":identity.backend_node_id}),
                    ),
                    command("Page.getLayoutMetrics", json!({})),
                    command(
                        "DOM.getContentQuads",
                        json!({"backendNodeId":identity.backend_node_id}),
                    ),
                ],
            )
            .await?;
        Some(quad_center(
            &quad.results[2],
            &quad.results[1]["cssVisualViewport"],
        )?)
    };
    let mut steps = Vec::new();
    if native_option {
        steps.push(command(
            "Runtime.callFunctionOn",
            json!({"functionDeclaration":functions::CHOOSE_OPTION,"returnByValue":true}),
        ));
    } else if keyboard {
        steps.push(command(
            "DOM.focus",
            json!({"backendNodeId":identity.backend_node_id}),
        ));
        if let Some(key) = key {
            for down in [true, false] {
                steps.push(command("Input.dispatchKeyEvent", key.event(down)));
            }
        } else {
            let declaration = if args["clear_first"] == true {
                functions::SELECT
            } else {
                functions::APPEND_CARET
            };
            steps.push(command(
                "Runtime.callFunctionOn",
                json!({"functionDeclaration":declaration,"returnByValue":true}),
            ));
            steps.push(command("Input.insertText", json!({"text":args["text"]})));
        }
    } else {
        let (x, y) = position.unwrap();
        for event in ["mousePressed", "mouseReleased"] {
            steps.push(command(
                "Input.dispatchMouseEvent",
                json!({"type":event,"x":x,"y":y,"button":"left","clickCount":1}),
            ));
        }
    }
    let mut dispatched = false;
    let mut popup = false;
    let mut after_focus = false;
    let mut selected = None;
    let mut steps = steps.into_iter();
    while let Some(step) = steps.next() {
        let just_focused = std::mem::take(&mut after_focus);
        if !context.granted(&input_origin, severity, &hazards, Some(&once))
            || destinations.iter().flatten().any(|destination| {
                !context.granted(
                    destination,
                    severity,
                    &hazards,
                    destination_grants.get(destination),
                ) && !context.granted(destination, severity, &hazards, Some(&once))
            })
        {
            let mut reply = refusal("grant_revoked");
            reply["input_dispatched"] = json!(dispatched);
            return Err(reply);
        }
        let verification = verify_input(
            context,
            tab,
            &snapshot,
            &frame,
            &identity,
            &mut classification,
            if just_focused {
                InputCheck::PostFocus
            } else if dispatched {
                InputCheck::PreInsertion
            } else {
                InputCheck::PreDispatch
            },
        )
        .await;
        if let Err(reply) = verification {
            if !just_focused || key.is_some() {
                return Err(prior_input(reply, dispatched));
            }
            let original = snapshot.refs.get(args["ref"].as_str().unwrap()).unwrap();
            let Some(replacement) = typing::after_focus(context, tab, &snapshot, original)
                .await
                .map_err(|reply| prior_input(reply, dispatched))?
            else {
                return Err(prior_input(reply, dispatched));
            };
            identity = replacement.identity;
            classification = replacement.classification.expect("classified replacement");
            verify_input(
                context,
                tab,
                &snapshot,
                &frame,
                &identity,
                &mut classification,
                InputCheck::PostFocus,
            )
            .await
            .map_err(|reply| prior_input(reply, dispatched))?;
        }
        if let Some((x, y)) = position {
            verify_click_position(
                context,
                tab,
                &snapshot,
                &frame,
                &classification,
                (x, y),
                dispatched,
            )
            .await
            .map_err(|reply| prior_input(reply, dispatched))?;
        }
        let commands = if (action == "type" || native_option)
            && step["method"] == "Runtime.callFunctionOn"
        {
            if args["clear_first"] != true
                && matches!(
                    classification.effective_input_type.as_deref(),
                    Some("number" | "email")
                )
            {
                // Choose the caret operation after any focus replacement: number and
                // email inputs reject setSelectionRange, unlike text inputs.
                vec![
                    command(
                        "Emulation.setFocusEmulationEnabled",
                        json!({"enabled":true}),
                    ),
                    command(
                        "Input.dispatchKeyEvent",
                        json!({"type":"keyDown","key":"End","code":"End","windowsVirtualKeyCode":35}),
                    ),
                    command(
                        "Input.dispatchKeyEvent",
                        json!({"type":"keyUp","key":"End","code":"End","windowsVirtualKeyCode":35}),
                    ),
                ]
            } else {
                runtime_plan(
                    &identity,
                    step["params"]["functionDeclaration"]
                        .as_str()
                        .expect("pinned declaration"),
                )
            }
        } else {
            let keypress = key.is_some() && step["method"] == "Input.dispatchKeyEvent";
            if (action == "type" && step["method"] == "Input.insertText") || keypress {
                let focused = context
                    .cdp_frame(
                        tab,
                        Some(snapshot.interaction),
                        &frame,
                        runtime_plan(&identity, functions::HAS_FOCUS),
                    )
                    .await
                    .map_err(|reply| prior_input(reply, dispatched))?;
                if focused
                    .results
                    .last()
                    .and_then(|result| result.pointer("/result/value"))
                    != Some(&json!(true))
                {
                    return Err(prior_input(refusal("type_focus_not_ready"), dispatched));
                }
                verify_input(
                    context,
                    tab,
                    &snapshot,
                    &frame,
                    &identity,
                    &mut classification,
                    InputCheck::PreInsertion,
                )
                .await
                .map_err(|reply| prior_input(reply, dispatched))?;
            }
            // Background pages can acknowledge mouse input without delivering
            // it. Emulate page focus without activating the person's tab or
            // window. Keep each pair in one attachment so the extension can
            // release the press even if the interaction check refuses the release.
            let mut commands = vec![command(
                "Emulation.setFocusEmulationEnabled",
                json!({"enabled":true}),
            )];
            commands.push(step);
            if !keyboard || keypress {
                commands.extend(steps.by_ref());
            }
            commands
        };
        let is_focus = keyboard
            && commands
                .iter()
                .any(|command| command["method"] == "DOM.focus");
        *text_attempted |= commands
            .iter()
            .any(|command| command["method"] == "Input.insertText");
        let outcome = context
            .cdp_frame(tab, Some(snapshot.interaction), &frame, commands)
            .await;
        match outcome {
            Ok(result) => {
                if result
                    .results
                    .iter()
                    .any(|result| result.get("exceptionDetails").is_some())
                {
                    let mut reply = refusal(if native_option {
                        "target_not_interactive"
                    } else {
                        "runtime_exception"
                    });
                    if native_option {
                        reply["detail"] = json!({"step":"input.native_option","problem":"option or select is disabled or unavailable"});
                    }
                    return Err(prior_input(reply, true));
                }
                if native_option {
                    selected = result
                        .results
                        .last()
                        .and_then(crate::browser::navigation::native_select::selected_value);
                    if selected.is_none() {
                        return Err(prior_input(refusal("runtime_exception"), true));
                    }
                }
                dispatched = true;
                after_focus = is_focus;
                popup |= result.popup;
            }
            Err(mut reply) => {
                if dispatched {
                    reply["input_dispatched"] = json!(true);
                }
                return Err(reply);
            }
        }
    }
    let landed = context.document(tab).await.map_err(|mut reply| {
        if dispatched {
            reply["input_dispatched"] = json!(true);
        }
        reply
    })?;
    if !landed.observer_available {
        return Err(prior_input(observer_unavailable(), dispatched));
    }
    let landing_origin = landed
        .frames
        .iter()
        .find(|live| live.frame_id == frame.frame_id)
        .map(|live| live.origin.clone())
        .unwrap_or_else(|| "null".into());
    let landing_allowed = |origin: &str| {
        context.granted(
            origin,
            Severity::new(1, false, false),
            &BTreeSet::new(),
            Some(&once),
        ) || context.granted(
            origin,
            Severity::new(1, false, false),
            &BTreeSet::new(),
            destination_grants.get(origin),
        )
    };
    // Acting inside a child does not revisit the unchanged top page. A real
    // top-page navigation, or a child redirect, still needs its landing grant.
    if !landing_allowed(&landing_origin)
        || (landed.committed != current.committed
            && !landing_allowed(&origin(&landed.committed.url)?))
    {
        let mut reply = refusal("landing_site_not_authorized");
        reply["input_dispatched"] = json!(dispatched);
        return Err(reply);
    }
    let mut reply = json!({"browser":"user","outcome":"ok","tab":tab,"input_dispatched":dispatched,"connection_epoch":context.connection,"interaction_epoch":landed.interaction});
    if key.is_some() {
        let changed = landed.committed != current.committed
            || landed.frames.len() != current.frames.len()
            || !current
                .frames
                .iter()
                .all(|frame| landed.frames.iter().any(|live| live.same_document(frame)));
        reply["page_changed"] = json!(changed);
    }
    if let Some((value, selected_index)) = selected {
        reply["value"] = json!(value);
        reply["selectedIndex"] = json!(selected_index);
    }
    if popup {
        reply["popup_activated_briefly"] = json!(true);
    }
    Ok(reply)
}
