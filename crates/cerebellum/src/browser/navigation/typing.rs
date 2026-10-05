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
        self.ensure_attached(context_key, deadline, &mut clock)?;
        let mut adapter = TypeAdapter {
            driver: self,
            context_key,
            target,
            deadline_ms,
            deadline,
            clock,
            selected: false,
        };
        let snapshot = match adapter.observe_type_target() {
            Ok(snapshot) => snapshot,
            Err(_) => {
                return Ok(BrowserTypeResult::StaleSnapshot {
                    reason: crate::browser_type::StaleReason::ResolvedNodeChanged,
                })
            }
        };
        let mut request = BrowserTypeRequest::new("ref", "snapshot", text);
        request.replace = clear_first;
        // BrowserPlane has authorized and journaled this dispatch. These local
        // adapters let the executor check the target again before and after
        // focus without duplicating durable records or storing typed text.
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
}

impl<IO: CdpPipeIo> TypeAdapter<'_, IO> {
    fn command(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Map<String, Value>, TypeDriverError> {
        let attachment = self
            .driver
            .frame_attachment(&self.target.identity)
            .map_err(|_| TypeDriverError::new("frame_unavailable"))?;
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
            .map_err(|_| TypeDriverError::new("cdp_failure"))?;
        if response.error.is_some() {
            return Err(TypeDriverError::new("cdp_failure"));
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
            .committed_document(self.context_key, self.deadline_ms);
        super::super::typing::check_type_document(self.target.document.as_ref(), live)
            .map_err(|_| TypeDriverError::new("document_changed"))?;
        if let Some(frame) = &self.target.frame {
            if !self
                .driver
                .prepare_frame(self.context_key, frame, self.deadline_ms)
                .map_err(|_| TypeDriverError::new("frame_changed"))?
            {
                return Err(TypeDriverError::new("frame_changed"));
            }
        }
        let attachment = self
            .driver
            .frame_attachment(&self.target.identity)
            .map_err(|_| TypeDriverError::new("frame_changed"))?;
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
        if &actual != expected {
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
                && matches!(
                    input_type.as_str(),
                    "text" | "search" | "email" | "url" | "tel" | "password"
                ));
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
        let focused = self.command("Runtime.callFunctionOn", serde_json::json!({"objectId":object_id,"functionDeclaration":"function() { return this.getRootNode().activeElement === this; }","returnByValue":true}))?;
        if focused
            .get("result")
            .and_then(|result| result.get("value"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(TypeDriverError::new("focus_changed"));
        }
        if self.selected {
            self.command("Input.dispatchKeyEvent", serde_json::json!({"type":"keyDown","key":"Backspace","code":"Backspace","windowsVirtualKeyCode":8}))?;
            self.command("Input.dispatchKeyEvent", serde_json::json!({"type":"keyUp","key":"Backspace","code":"Backspace","windowsVirtualKeyCode":8}))?;
        }
        self.command("Input.insertText", serde_json::json!({"text":text}))?;
        Ok(())
    }
}
