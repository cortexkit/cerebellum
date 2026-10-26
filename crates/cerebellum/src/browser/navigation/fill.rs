//! The CDP half of `browser.fill_login`: check each login field again on the
//! live page, then insert its value, and clear what was filled when anything
//! changed in between.
//!
//! Every check runs on the same CDP connection and in the same driver call as
//! the insertion it guards, so nothing this module issues can sit between the
//! last check and the value reaching the field.

use super::*;
use crate::browser::fill::{FillDispatch, FillOutcome, FillTarget, FilledField, FilledFieldsState};

/// Focus the field and select its contents, so the insertion replaces what
/// is there. Answers whether the field is now the focused element.
const SELECT_FOR_FILL: &str = "function() { this.focus(); if (typeof this.select === 'function') { this.select(); } return this.ownerDocument.hasFocus() && this.getRootNode().activeElement === this; }";
/// The length of the field's value in UTF-16 code units. The value itself
/// never leaves the page.
const FILLED_LENGTH: &str =
    "function() { return typeof this.value === 'string' ? this.value.length : -1; }";
/// Empty the field and tell the page it changed.
const CLEAR_FILLED: &str = "function() { if (typeof this.value === 'string') { this.value = ''; this.dispatchEvent(new Event('input', {bubbles: true})); this.dispatchEvent(new Event('change', {bubbles: true})); } return true; }";
/// Whether the field is still in its document and holds a value.
const STILL_FILLED: &str = "function() { return this.isConnected && typeof this.value === 'string' && this.value.length > 0; }";

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub fn fill_login(
        &mut self,
        context_key: &str,
        dispatch: &FillDispatch,
        deadline_ms: u64,
    ) -> Result<FillOutcome, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, &mut clock)?;
        let mut runtime = HashSet::new();
        // Every field is checked before any is filled, so a page that changed
        // since the snapshot receives nothing at all.
        for target in &dispatch.targets {
            if let Err(reason_code) =
                self.verify_fill_target(context_key, dispatch, target, deadline, &mut clock)
            {
                return Ok(FillOutcome::Aborted { reason_code });
            }
        }
        let mut filled: Vec<FilledField> = Vec::new();
        for target in &dispatch.targets {
            // Checked again right before this field's insertion: an earlier
            // insertion can run page script that navigates or swaps the form.
            let step = self
                .verify_fill_target(context_key, dispatch, target, deadline, &mut clock)
                .and_then(|()| {
                    filled.push(FilledField {
                        identity: target.identity.clone(),
                        frame: target.frame.clone(),
                    });
                    self.insert_fill_value(target, &mut runtime, deadline, &mut clock)
                });
            if let Err(reason_code) = step {
                self.clear_fields(context_key, &filled, &mut runtime, deadline, &mut clock);
                return Ok(FillOutcome::Aborted { reason_code });
            }
        }
        Ok(FillOutcome::Filled)
    }

    pub fn clear_filled(
        &mut self,
        context_key: &str,
        fields: &[FilledField],
        deadline_ms: u64,
    ) -> Result<(), NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, &mut clock)?;
        self.clear_fields(
            context_key,
            fields,
            &mut HashSet::new(),
            deadline,
            &mut clock,
        );
        Ok(())
    }

    pub fn filled_fields_state(
        &mut self,
        context_key: &str,
        fields: &[FilledField],
        deadline_ms: u64,
    ) -> Result<FilledFieldsState, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, &mut clock)?;
        let mut runtime = HashSet::new();
        for field in fields {
            if let Some(frame) = &field.frame {
                // A frame that navigated or went away took its field with it.
                if !self.prepare_frame(context_key, frame, deadline_ms)? {
                    continue;
                }
            } else {
                self.active_frame = None;
            }
            let Some(object_id) =
                self.resolve_fill_node(&field.identity, &mut runtime, deadline, &mut clock)?
            else {
                continue;
            };
            let answer = self.call_on_fill_node(
                &field.identity,
                &object_id,
                STILL_FILLED,
                deadline,
                &mut clock,
            )?;
            if answer.and_then(|value| value.as_bool()) != Some(false) {
                // Anything but a plain "no" keeps the field counted as filled.
                return Ok(FilledFieldsState::SomeFilled);
            }
        }
        Ok(FilledFieldsState::AllEmptyOrGone)
    }

    /// The page still shows the snapshot's document, the field's frame still
    /// holds the same document from the same origin, and the field classifies
    /// exactly as it did in the snapshot.
    fn verify_fill_target(
        &mut self,
        context_key: &str,
        dispatch: &FillDispatch,
        target: &FillTarget,
        deadline: Instant,
        clock: &mut SystemNavigationClock,
    ) -> Result<(), &'static str> {
        let remaining = deadline.saturating_duration_since(clock.now());
        let remaining_ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
        if remaining_ms == 0 {
            return Err("fill_deadline_expired");
        }
        let live = self.committed_document(context_key, remaining_ms);
        super::super::typing::check_type_document(dispatch.document.as_ref(), live)
            .map_err(|_| "document_changed")?;
        match &target.frame {
            Some(frame) => {
                if !self
                    .prepare_frame(context_key, frame, remaining_ms)
                    .map_err(|_| "fill_frame_not_ready")?
                {
                    return Err("frame_changed");
                }
            }
            None => self.active_frame = None,
        }
        let attachment = self
            .frame_attachment(&target.identity)
            .map_err(|_| "fill_frame_not_ready")?;
        let nodes = self
            .flattened_dom_nodes_before(&attachment, deadline, clock)
            .map_err(|_| "fill_observation_not_ready")?
            .map_err(|_| "classification_unavailable")?;
        let expected = &target.classification;
        let actual = build_non_type_classification(
            &nodes,
            &target.identity,
            expected.document_epoch,
            &expected.current_top_level_origin,
        )
        .map_err(|_| "classification_unavailable")?;
        if &actual != expected {
            return Err("classification_changed");
        }
        let node = nodes
            .iter()
            .find(|node| node.backend_node_id == target.identity.backend_node_id)
            .ok_or("node_changed")?;
        if node.local_name != "input"
            || node.attributes.contains_key("disabled")
            || node.attributes.contains_key("readonly")
        {
            return Err("target_not_interactive");
        }
        Ok(())
    }

    fn insert_fill_value(
        &mut self,
        target: &FillTarget,
        runtime: &mut HashSet<String>,
        deadline: Instant,
        clock: &mut SystemNavigationClock,
    ) -> Result<(), &'static str> {
        let attachment = self
            .frame_attachment(&target.identity)
            .map_err(|_| "fill_frame_not_ready")?;
        // Emulate document focus without activating Chrome or raising its
        // window, as typing does.
        if !self
            .focus_emulated_sessions
            .contains(&attachment.session_id)
        {
            self.fill_command(
                &attachment.session_id,
                "Emulation.setFocusEmulationEnabled",
                serde_json::json!({"enabled": true}),
                deadline,
                clock,
            )
            .ok_or("fill_focus_not_ready")?;
            self.focus_emulated_sessions
                .insert(attachment.session_id.clone());
        }
        self.fill_command(
            &attachment.session_id,
            "DOM.focus",
            serde_json::json!({"backendNodeId": target.identity.backend_node_id}),
            deadline,
            clock,
        )
        .ok_or("fill_focus_not_ready")?;
        let object_id = self
            .resolve_fill_node(&target.identity, runtime, deadline, clock)
            .map_err(|_| "fill_context_not_ready")?
            .ok_or("node_changed")?;
        let focused = self
            .call_on_fill_node(
                &target.identity,
                &object_id,
                SELECT_FOR_FILL,
                deadline,
                clock,
            )
            .map_err(|_| "fill_focus_not_ready")?;
        if focused.and_then(|value| value.as_bool()) != Some(true) {
            return Err("fill_focus_not_ready");
        }
        // CDP takes the value as JSON text, so this copy and the serialized
        // command are ordinary heap buffers, dropped once the command is sent
        // and answered. They live inside this one driver call.
        let mut params = Map::new();
        params.insert(
            "text".into(),
            Value::String(target.value.as_str().to_owned()),
        );
        let inserted = self.command_response(
            "Input.insertText",
            Some(params),
            Some(attachment.session_id.clone()),
            deadline,
            None,
            None,
            clock,
        );
        if !inserted.is_ok_and(|response| response.error.is_none()) {
            return Err("fill_insert_not_ready");
        }
        // The page must hold exactly what was inserted: a handler that kept
        // old text or dropped characters leaves a login that would fail.
        let length = self
            .call_on_fill_node(&target.identity, &object_id, FILLED_LENGTH, deadline, clock)
            .map_err(|_| "fill_insert_not_ready")?;
        let expected = target.value.encode_utf16().count() as u64;
        if length.and_then(|value| value.as_u64()) != Some(expected) {
            return Err("fill_insert_not_ready");
        }
        Ok(())
    }

    fn clear_fields(
        &mut self,
        context_key: &str,
        fields: &[FilledField],
        runtime: &mut HashSet<String>,
        deadline: Instant,
        clock: &mut SystemNavigationClock,
    ) {
        let remaining_ms = |clock: &mut SystemNavigationClock| {
            u64::try_from(deadline.saturating_duration_since(clock.now()).as_millis())
                .unwrap_or(u64::MAX)
        };
        for field in fields {
            if let Some(frame) = &field.frame {
                let ms = remaining_ms(clock);
                if !self.prepare_frame(context_key, frame, ms).unwrap_or(false) {
                    continue;
                }
            } else {
                self.active_frame = None;
            }
            let Ok(Some(object_id)) =
                self.resolve_fill_node(&field.identity, runtime, deadline, clock)
            else {
                continue;
            };
            let _ =
                self.call_on_fill_node(&field.identity, &object_id, CLEAR_FILLED, deadline, clock);
        }
    }

    /// One command on `session`; `None` when it failed or Chrome refused it.
    fn fill_command(
        &mut self,
        session: &str,
        method: &str,
        params: Value,
        deadline: Instant,
        clock: &mut SystemNavigationClock,
    ) -> Option<Map<String, Value>> {
        let response = self
            .command_response(
                method,
                params.as_object().cloned(),
                Some(session.to_owned()),
                deadline,
                None,
                None,
                clock,
            )
            .ok()?;
        if response.error.is_some() {
            return None;
        }
        response.result
    }

    /// The field's remote object id, or `None` when the node is gone.
    fn resolve_fill_node(
        &mut self,
        identity: &BackendNodeIdentity,
        runtime: &mut HashSet<String>,
        deadline: Instant,
        clock: &mut SystemNavigationClock,
    ) -> Result<Option<String>, NavigationDriveError> {
        let session = self.frame_attachment(identity)?.session_id;
        // A cold renderer answers DOM.resolveNode only once Runtime is enabled
        // on that session.
        if !runtime.contains(&session) {
            self.fill_command(
                &session,
                "Runtime.enable",
                serde_json::json!({}),
                deadline,
                clock,
            )
            .ok_or(NavigationDriveError::CdpFailure)?;
            runtime.insert(session.clone());
        }
        Ok(self
            .fill_command(
                &session,
                "DOM.resolveNode",
                serde_json::json!({"backendNodeId": identity.backend_node_id}),
                deadline,
                clock,
            )
            .and_then(|resolved| {
                resolved
                    .get("object")
                    .and_then(|object| object.get("objectId"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }))
    }

    /// Call `function` on the field; the plain value it returned, if any.
    fn call_on_fill_node(
        &mut self,
        identity: &BackendNodeIdentity,
        object_id: &str,
        function: &str,
        deadline: Instant,
        clock: &mut SystemNavigationClock,
    ) -> Result<Option<Value>, NavigationDriveError> {
        let session = self.frame_attachment(identity)?.session_id;
        let result = self
            .fill_command(
                &session,
                "Runtime.callFunctionOn",
                serde_json::json!({
                    "objectId": object_id,
                    "functionDeclaration": function,
                    "returnByValue": true,
                }),
                deadline,
                clock,
            )
            .ok_or(NavigationDriveError::CdpFailure)?;
        if result.contains_key("exceptionDetails") {
            return Ok(None);
        }
        Ok(result
            .get("result")
            .and_then(|result| result.get("value"))
            .cloned())
    }
}
