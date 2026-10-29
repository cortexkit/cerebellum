use super::*;
use crate::browser_type::{
    BrowserTypeDriver, BrowserTypeExecutor, BrowserTypeRequest, BrowserTypeResult,
    RecordingAuthorizer, RecordingJournal, TypeDispatch, TypeDriverError, TypeGeometry, TypeTarget,
};

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub fn type_classified(
        &mut self,
        context_key: &str,
        target: &TypeDispatch,
        text: &str,
        clear_first: bool,
        deadline_ms: u64,
    ) -> Result<BrowserTypeResult, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        if self
            .ensure_attached(context_key, deadline, &mut clock)
            .is_err()
        {
            return Ok(BrowserTypeResult::NotReady {
                reason_code: "type_attachment_not_ready".into(),
            });
        }
        let mut adapter = TypeAdapter {
            driver: self,
            context_key,
            target,
            deadline_ms,
            deadline,
            clock,
            selected: false,
            runtime_enabled: false,
        };
        let snapshot = match adapter.observe_type_target() {
            Ok(snapshot) => snapshot,
            Err(error) => return Ok(crate::browser_type::observation_failure(&error)),
        };
        let mut request = BrowserTypeRequest::new("ref", "snapshot", text);
        request.replace = clear_first;
        // The caller authorized and journaled this dispatch before it reached
        // the driver. The executor runs here only to re-check the target
        // before and after focus, so it gets throwaway in-memory journal and
        // authorizer stand-ins: no second journal record, no stored text.
        Ok(BrowserTypeExecutor::execute(
            &mut adapter,
            &mut RecordingJournal::default(),
            &mut RecordingAuthorizer::allowing(),
            &snapshot,
            &request,
        ))
    }
}

struct TypeAdapter<'a, IO: CdpPipeIo> {
    driver: &'a mut CdpNavigationDriver<IO>,
    context_key: &'a str,
    target: &'a TypeDispatch,
    deadline_ms: u64,
    deadline: Instant,
    clock: SystemNavigationClock,
    selected: bool,
    runtime_enabled: bool,
}

impl<IO: CdpPipeIo> TypeAdapter<'_, IO> {
    fn verify_focus(&mut self, object_id: &str) -> Result<(), TypeDriverError> {
        let focused = self.command("Runtime.callFunctionOn", serde_json::json!({"objectId":object_id,"functionDeclaration":"function() { return this.ownerDocument.hasFocus() && this.getRootNode().activeElement === this; }","returnByValue":true}))?;
        if focused
            .get("result")
            .and_then(|result| result.get("value"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(TypeDriverError::new("type_focus_not_ready"));
        }
        Ok(())
    }

    fn command(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Map<String, Value>, TypeDriverError> {
        // Initialize Runtime before asking a cold renderer for a remote DOM object.
        // Its acknowledgement establishes the execution-context domain on this session.
        if method == "DOM.resolveNode" && !self.runtime_enabled {
            self.command("Runtime.enable", serde_json::json!({}))?;
            self.runtime_enabled = true;
        }
        let attachment = self
            .driver
            .frame_attachment(&self.target.identity)
            .map_err(|_| TypeDriverError::new("type_frame_not_ready"))?;
        if self.clock.now() >= self.deadline {
            return Err(TypeDriverError::new("type_deadline_expired"));
        }
        let not_ready = match method {
            "DOM.focus" => "type_focus_not_ready",
            "DOM.resolveNode" => "type_context_not_ready",
            "Runtime.enable" => "type_runtime_not_ready",
            "Input.dispatchKeyEvent" if params["key"] == "End" => "type_caret_not_ready",
            "Input.dispatchKeyEvent" => "type_clear_not_ready",
            "Input.insertText" => "type_insert_not_ready",
            "Runtime.callFunctionOn"
                if params["functionDeclaration"]
                    .as_str()
                    .is_some_and(|function| function.contains("this.select()")) =>
            {
                "type_selection_not_ready"
            }
            "Runtime.callFunctionOn"
                if params["functionDeclaration"]
                    .as_str()
                    .is_some_and(|function| function.contains("length === 0")) =>
            {
                "type_clear_not_ready"
            }
            "Runtime.callFunctionOn"
                if params["functionDeclaration"]
                    .as_str()
                    .is_some_and(|function| function.contains("collapse(false)")) =>
            {
                "type_caret_not_ready"
            }
            _ => "type_focus_not_ready",
        };
        let response = self
            .driver
            .command_response(
                method,
                params.as_object().cloned(),
                Some(attachment.session_id),
                self.deadline,
                None,
                None,
                &mut self.clock,
            )
            .map_err(|_| {
                TypeDriverError::new(if self.clock.now() >= self.deadline {
                    "type_deadline_expired"
                } else {
                    not_ready
                })
            })?;
        if response.error.is_some() {
            return Err(TypeDriverError::new(not_ready));
        }
        response
            .result
            .ok_or_else(|| TypeDriverError::new("cdp_failure"))
    }
}

impl<IO: CdpPipeIo> BrowserTypeDriver for TypeAdapter<'_, IO> {
    fn observe_type_target(&mut self) -> Result<TypeTarget, TypeDriverError> {
        let live = self
            .driver
            .committed_document(self.context_key, self.deadline_ms)
            .map_err(|_| TypeDriverError::new("type_document_not_ready"))?;
        super::super::typing::check_type_document(self.target.document.as_ref(), Ok(live))
            .map_err(|_| TypeDriverError::new("document_changed"))?;
        if let Some(frame) = &self.target.frame {
            if !self
                .driver
                .prepare_frame(self.context_key, frame, self.deadline_ms)
                .map_err(|_| TypeDriverError::new("type_frame_not_ready"))?
            {
                return Err(TypeDriverError::new("frame_changed"));
            }
        }
        let attachment = self
            .driver
            .frame_attachment(&self.target.identity)
            .map_err(|_| TypeDriverError::new("type_frame_not_ready"))?;
        let nodes = self
            .driver
            .flattened_dom_nodes_before(&attachment, self.deadline, &mut self.clock)
            .map_err(|_| TypeDriverError::new("cdp_failure"))?
            .map_err(|_| TypeDriverError::new("classification_unavailable"))?;
        let expected = &self.target.classification;
        let actual = build_non_type_classification(
            &nodes,
            &self.target.identity,
            expected.document_epoch,
            &expected.current_top_level_origin,
        )
        .map_err(|_| TypeDriverError::new("classification_unavailable"))?;
        // Name/id hints are deliberately excluded from the stored fingerprint.
        // Recheck their typing verdict so a focus handler cannot turn an
        // ordinary field into a sensitive one between observations.
        if &actual != expected
            || crate::classification::type_field_reason(&actual)
                != crate::classification::type_field_reason(expected)
        {
            return Err(TypeDriverError::new("classification_changed"));
        }
        let node = nodes
            .iter()
            .find(|node| node.backend_node_id == self.target.identity.backend_node_id)
            .ok_or_else(|| TypeDriverError::new("node_changed"))?;
        let attrs = &node.attributes;
        let input_type = attrs
            .get("type")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| "text".into());
        let writable = node.local_name == "textarea"
            || (node.local_name == "input"
                && crate::classification::type_input_supported(&input_type));
        let mut inert = attrs.contains_key("inert");
        let mut editable = attrs.get("contenteditable").map(|value| value != "false");
        let mut parent_id = node.parent_id;
        while let Some(parent) =
            parent_id.and_then(|id| nodes.iter().find(|node| node.node_id == id))
        {
            inert |= parent.attributes.contains_key("inert");
            if editable.is_none() {
                editable = parent
                    .attributes
                    .get("contenteditable")
                    .map(|value| value != "false");
            }
            parent_id = parent.parent_id;
        }
        self.driver
            .content_quad_position(
                node.backend_node_id,
                &attachment.session_id,
                self.deadline,
                &mut self.clock,
            )
            .map_err(|_| TypeDriverError::new("no_geometry"))?;
        Ok(TypeTarget {
            node_identity: actual.node_identity,
            document_epoch: actual.document_epoch,
            form_owner: actual.form_owner,
            autocomplete_tokens: actual.target_autocomplete_tokens,
            password: actual.target_password,
            writable_text_control: writable,
            editable_region: editable.unwrap_or(false),
            disabled: attrs.contains_key("disabled"),
            readonly: attrs.contains_key("readonly"),
            inert,
            form_descendants: Vec::new(),
            geometry: TypeGeometry::default(),
        })
    }

    fn focus_type_target(&mut self, _: &str) -> Result<(), TypeDriverError> {
        // Emulate document focus without activating Chrome or raising its window.
        // Separate frame targets have their own sessions and need their own setting.
        let session = self
            .driver
            .frame_attachment(&self.target.identity)
            .map_err(|_| TypeDriverError::new("type_frame_not_ready"))?
            .session_id;
        if !self.driver.focus_emulated_sessions.contains(&session) {
            self.command(
                "Emulation.setFocusEmulationEnabled",
                serde_json::json!({"enabled":true}),
            )?;
            self.driver.focus_emulated_sessions.insert(session);
        }
        self.command(
            "DOM.focus",
            serde_json::json!({"backendNodeId":self.target.identity.backend_node_id}),
        )?;
        Ok(())
    }

    fn select_type_target_contents(&mut self, _: &str) -> Result<(), TypeDriverError> {
        let resolved = self.command(
            "DOM.resolveNode",
            serde_json::json!({"backendNodeId":self.target.identity.backend_node_id}),
        )?;
        let object_id = resolved
            .get("object")
            .and_then(|object| object.get("objectId"))
            .and_then(Value::as_str)
            .ok_or_else(|| TypeDriverError::new("cdp_failure"))?;
        let selected = self.command("Runtime.callFunctionOn", serde_json::json!({"objectId":object_id,"functionDeclaration":"function() { if (typeof this.select === 'function') { this.select(); } else { const range = this.ownerDocument.createRange(); range.selectNodeContents(this); const selection = this.ownerDocument.getSelection(); selection.removeAllRanges(); selection.addRange(range); } }","returnByValue":true}))?;
        if selected.contains_key("exceptionDetails") {
            return Err(TypeDriverError::new("selection_failed"));
        }
        self.selected = true;
        Ok(())
    }

    fn insert_type_text(&mut self, _: &str, text: &str) -> Result<(), TypeDriverError> {
        // The executor has rechecked the page document and target classification
        // after selecting. Only now may deleting the selection change the value.
        let resolved = self.command(
            "DOM.resolveNode",
            serde_json::json!({"backendNodeId":self.target.identity.backend_node_id}),
        )?;
        let object_id = resolved
            .get("object")
            .and_then(|object| object.get("objectId"))
            .and_then(Value::as_str)
            .ok_or_else(|| TypeDriverError::new("cdp_failure"))?;
        self.verify_focus(object_id)?;
        if self.selected {
            self.command("Input.dispatchKeyEvent", serde_json::json!({"type":"keyDown","key":"Backspace","code":"Backspace","windowsVirtualKeyCode":8}))?;
            self.command("Input.dispatchKeyEvent", serde_json::json!({"type":"keyUp","key":"Backspace","code":"Backspace","windowsVirtualKeyCode":8}))?;
            let empty = self.command("Runtime.callFunctionOn", serde_json::json!({"objectId":object_id,"functionDeclaration":"function() { return (typeof this.value === 'string' ? this.value : this.textContent).length === 0; }","returnByValue":true}))?;
            if empty
                .get("result")
                .and_then(|result| result.get("value"))
                .and_then(Value::as_bool)
                != Some(true)
            {
                return Err(TypeDriverError::new("type_clear_not_ready"));
            }
        } else if matches!(
            self.target.classification.effective_input_type.as_deref(),
            Some("number" | "email")
        ) {
            // Number and email inputs reject setSelectionRange; a native End
            // key moves their caret without changing the value.
            for event in ["keyDown", "keyUp"] {
                self.command("Input.dispatchKeyEvent", serde_json::json!({"type":event,"key":"End","code":"End","windowsVirtualKeyCode":35}))?;
            }
            // Key handlers can change the field or move focus. Revalidate both
            // before any text follows the caret movement.
            let live = self.observe_type_target()?;
            if !crate::browser_type::browser_type_dispatch_eligible(&live) {
                return Err(TypeDriverError::new("classification_changed"));
            }
            self.verify_focus(object_id)?;
        } else {
            // Focus does not establish an append caret. Move it only after the
            // executor's live-document and classification rechecks, just before insertion.
            let moved = self.command("Runtime.callFunctionOn", serde_json::json!({"objectId":object_id,"functionDeclaration":"function() { if (typeof this.setSelectionRange === 'function') { const end = this.value.length; this.setSelectionRange(end, end); } else { const range = this.ownerDocument.createRange(); range.selectNodeContents(this); range.collapse(false); const selection = this.ownerDocument.getSelection(); selection.removeAllRanges(); selection.addRange(range); } return true; }","returnByValue":true}))?;
            if moved.contains_key("exceptionDetails")
                || moved
                    .get("result")
                    .and_then(|result| result.get("value"))
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                return Err(TypeDriverError::new("type_caret_not_ready"));
            }
        }
        self.command("Input.insertText", serde_json::json!({"text":text}))?;
        Ok(())
    }
}
