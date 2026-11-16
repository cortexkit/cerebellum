//! Native options have no layout box while their select is collapsed. Both
//! browser adapters use the same bounded DOM operation instead of mouse input.

use super::*;

pub(crate) fn target_from_capture(
    capture: &Map<String, Value>,
    identity: &BackendNodeIdentity,
    classification: &NonTypeClassificationRecord,
) -> Result<bool, &'static str> {
    let nodes = parse_flattened_dom_nodes(capture).map_err(|_| "option document is unavailable")?;
    target(&nodes, identity, classification)
}

pub(super) fn target(
    nodes: &[RawDomNode],
    identity: &BackendNodeIdentity,
    classification: &NonTypeClassificationRecord,
) -> Result<bool, &'static str> {
    let Some(option) = nodes.iter().find(|node| {
        node.backend_node_id == identity.backend_node_id && node.local_name == "option"
    }) else {
        return Ok(false);
    };
    let parent = |node: &RawDomNode| {
        node.parent_id
            .and_then(|id| nodes.iter().find(|node| node.node_id == id))
    };
    let mut select = parent(option).ok_or("option has no select")?;
    let group = (select.local_name == "optgroup").then_some(select);
    if group.is_some() {
        select = parent(select).ok_or("option has no select")?;
    }
    if select.local_name != "select" {
        return Err("option has no select");
    }
    if option.attributes.contains_key("disabled")
        || select.attributes.contains_key("disabled")
        || group.is_some_and(|group| group.attributes.contains_key("disabled"))
    {
        return Err("option, optgroup or select is disabled");
    }
    // Changing a select does not submit its form, but it still writes a value
    // into that form. Do not let option refs bypass sensitive-form refusal.
    if classification.credential
        || classification.financial
        || classification
            .associated_form_controls
            .iter()
            .any(|control| {
                control.password
                    || control.autocomplete_tokens.iter().any(|token| {
                        classification::credential_token(token)
                            || classification::financial_token(token)
                    })
            })
    {
        return Err("native options in credential or payment forms cannot be changed");
    }
    Ok(true)
}

pub(crate) fn selected_value(result: &Value) -> Option<(String, i64)> {
    if result.get("exceptionDetails").is_some() {
        return None;
    }
    let value = result.pointer("/result/value")?;
    let selected_index = value["selectedIndex"]
        .as_i64()
        .filter(|index| *index >= -1)?;
    Some((value["value"].as_str()?.to_owned(), selected_index))
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn choose_native_option<C: NavigationClock>(
        &mut self,
        context_key: &str,
        identity: &BackendNodeIdentity,
        attachment: &AttachedTarget,
        expected: (u64, &str, &NonTypeClassificationRecord),
        deadline: Instant,
        deadline_ms: u64,
        clock: &mut C,
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let session = Some(attachment.session_id.clone());
        for method in ["Page.enable", "Network.enable"] {
            self.command(method, None, session.clone(), deadline, None, clock)
                .map_err(ClickDriveError::Navigation)?;
        }
        let resolved = self
            .command_response(
                "DOM.resolveNode",
                Some(
                    serde_json::json!({"backendNodeId":identity.backend_node_id})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
                session.clone(),
                deadline,
                None,
                None,
                clock,
            )
            .map_err(ClickDriveError::Navigation)?;
        let object = resolved
            .result
            .as_ref()
            .and_then(|result| result.get("object"))
            .and_then(|object| object.get("objectId"))
            .and_then(Value::as_str)
            .ok_or(ClickDriveError::ClassificationChanged)?;
        let nodes = self
            .flattened_dom_nodes_before(attachment, deadline, clock)
            .map_err(ClickDriveError::Navigation)?
            .map_err(|_| ClickDriveError::ClassificationChanged)?;
        let actual = build_non_type_classification(&nodes, identity, expected.0, expected.1)
            .map_err(|_| ClickDriveError::ClassificationChanged)?;
        if actual != *expected.2 {
            return Err(ClickDriveError::ClassificationChanged);
        }
        if target(&nodes, identity, &actual) != Ok(true) {
            return Err(ClickDriveError::Intercepted(
                serde_json::json!({"reason_code":"target_not_interactive","problem":"option or select is disabled, sensitive, or unavailable"}),
            ));
        }
        let mut tracker = Tracker::default();
        if self.continuously_serviced {
            self.enable_lifecycle_events(deadline, clock)
                .map_err(ClickDriveError::Navigation)?;
            tracker.begin_loader_fence(self.frame_generation);
        }
        let mut dialogs = Vec::new();
        let response = self.command_response_handling_javascript_dialogs("Runtime.callFunctionOn", Some(serde_json::json!({"objectId":object,"functionDeclaration":crate::user_browser::functions::CHOOSE_OPTION,"returnByValue":true}).as_object().unwrap().clone()), session, deadline, None, &mut dialogs, (context_key, &mut tracker), clock)
            .map_err(ClickDriveError::Navigation)?;
        let (value, selected_index) = response.result.as_ref()
            .and_then(|result| selected_value(&Value::Object(result.clone())))
            .ok_or_else(|| ClickDriveError::Intercepted(serde_json::json!({"reason_code":"target_not_interactive","problem":"option or select is disabled or unavailable; selection could not be verified"})))?;
        let navigation = self
            .observe_click_navigation(context_key, tracker, deadline_ms, clock)
            .map_err(ClickDriveError::Navigation)?;
        Ok(BrowserClickOutcome::OptionSelected {
            value,
            selected_index,
            navigation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn closed_native_option_uses_the_production_click_driver_without_layout() {
        let dom = json!({"nodes":[
            {"nodeId":1,"backendNodeId":1,"nodeType":9,"nodeName":"#document","localName":""},
            {"nodeId":2,"parentId":1,"backendNodeId":2,"nodeType":1,"nodeName":"SELECT","localName":"select","attributes":[]},
            {"nodeId":3,"parentId":2,"backendNodeId":3,"nodeType":1,"nodeName":"OPTION","localName":"option","attributes":["value","mac"]}
        ]});
        let identity = BackendNodeIdentity::new("target-own", "main", 3).unwrap();
        let expected = classify_flattened_document(
            dom.as_object().unwrap(),
            &identity,
            1,
            "https://example.test",
        )
        .unwrap();
        let results = [
            json!({}),
            dom.clone(),
            json!({}),
            json!({}),
            json!({"object":{"objectId":"option-object"}}),
            json!({}),
            dom,
            json!({"result":{"value":{"value":"mac","selectedIndex":1}}}),
        ];
        let mut driver = super::super::tests::attached_driver(results.into_iter().enumerate().map(
            |(index, result)| json!({"id":index+1,"sessionId":"session-own","result":result}),
        ));
        let result = driver
            .click_with_clock(
                "route-own",
                &identity,
                1000,
                &mut |_| {},
                Some((1, "https://example.test", Some(&expected))),
                &mut super::super::tests::FakeClock::new(),
            )
            .unwrap();
        assert!(
            matches!(result, BrowserClickOutcome::OptionSelected { ref value, selected_index:1, .. } if value == "mac"),
            "{result:?}"
        );
        let methods: Vec<_> = driver
            .pipe
            .writes
            .iter()
            .map(|command| command["method"].as_str().unwrap())
            .collect();
        assert_eq!(
            methods,
            [
                "DOM.enable",
                "DOM.getFlattenedDocument",
                "Page.enable",
                "Network.enable",
                "DOM.resolveNode",
                "DOM.enable",
                "DOM.getFlattenedDocument",
                "Runtime.callFunctionOn"
            ]
        );
        assert_eq!(
            driver.pipe.writes.last().unwrap()["params"]["functionDeclaration"],
            crate::user_browser::functions::CHOOSE_OPTION
        );
    }

    #[test]
    fn native_option_runtime_is_a_mutation_at_the_terminal_dispatch_gate() {
        let params = json!({"functionDeclaration":crate::user_browser::functions::CHOOSE_OPTION});
        assert_eq!(
            command_effect(
                "Runtime.callFunctionOn",
                params.as_object(),
                Some("session-own")
            ),
            CommandEffect::Mutation
        );
    }
}
