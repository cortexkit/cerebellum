//! The CDP half of `browser.fill_login`: check each login field again on the
//! live page, then insert its value, and clear what was filled when anything
//! changed in between.
//!
//! The final validation and native value setter run synchronously on the
//! resolved element, bound to its independently resolved owner document.

use super::*;
use crate::browser::fill::{
    FillDispatch, FillOutcome, FillTarget, FilledField, FilledFieldsState, LoginField,
};

// No focus events or focus-directed CDP insertion: the page cannot redirect
// this value to a different element between validation and the setter.
const INSERT_FILLED: &str = r#"function(doc, expectedType, autocomplete, origin, value, isUsername, password, checkOnly) {
    const win = doc.defaultView;
    if (!this.isConnected || this.ownerDocument !== doc || !win || win.document !== doc ||
        win.origin !== origin || doc.location.protocol !== 'https:' ||
        !(this instanceof win.HTMLInputElement) || this.localName !== 'input' ||
        this.type !== expectedType || this.disabled || this.readOnly) return false;
    const tokens = (this.getAttribute('autocomplete') || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (JSON.stringify(tokens) !== JSON.stringify(autocomplete)) return false;
    if (isUsername) {
        const roles = (this.getAttribute('role') || '').toLowerCase().split(/\s+/);
        if (this.hidden || roles.some(role => role === 'search' || role === 'searchbox')) return false;
        if (expectedType !== 'email' && !tokens.includes('username') && !tokens.includes('email')) {
            const follows = (a, b) => {
                const position = a.compareDocumentPosition(b);
                return !(position & 1) && !!(position & 4);
            };
            const form = this.form;
            if (!form || !(password instanceof win.HTMLInputElement) || !password.isConnected ||
                password.ownerDocument !== doc || password.type !== 'password' ||
                password.form !== form || !follows(this, password)) return false;
            const usernameLike = value => value.toLowerCase().split(/\s+/).some(part =>
                part === 'e-mail' || part === 'user_id' || part.split(/[_\-.]/).some(token =>
                    ['username','user','login','email','mail','userid','account'].includes(token)));
            const hinted = [this.name, this.id, ...tokens].some(usernameLike);
            if (!hinted) {
                const preceding = Array.from(doc.querySelectorAll('input')).filter(input =>
                    input.form === form && ['text','email'].includes(input.type) &&
                    follows(form, input) && follows(input, password));
                if (preceding.length !== 1 || preceding[0] !== this) return false;
            }
        }
    }
    if (checkOnly) return true;
    const set = Object.getOwnPropertyDescriptor(win.HTMLInputElement.prototype, 'value').set;
    set.call(this, value);
    this.dispatchEvent(new win.Event('input', {bubbles:true}));
    this.dispatchEvent(new win.Event('change', {bubbles:true}));
    return this.value === value;
}"#;
/// Empty the field and tell the page it changed.
const CLEAR_FILLED: &str = "function() { if (typeof this.value === 'string') { this.value = ''; this.dispatchEvent(new Event('input', {bubbles: true})); this.dispatchEvent(new Event('change', {bubbles: true})); } return true; }";
/// Whether the field is still in its document and holds a value.
const STILL_FILLED: &str = "function() { return this.isConnected && typeof this.value === 'string' && this.value.length > 0; }";

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    /// All live field/frame checks, without sending values or changing fields.
    /// A reason is a refusal; None means the page is ready to ask the vault.
    pub fn check_fill_login(
        &mut self,
        context_key: &str,
        dispatch: &FillDispatch,
        deadline_ms: u64,
    ) -> Result<Option<&'static str>, NavigationDriveError> {
        let mut clock = SystemNavigationClock;
        let deadline = clock
            .now()
            .checked_add(Duration::from_millis(deadline_ms))
            .ok_or(NavigationDriveError::CdpFailure)?;
        self.ensure_attached(context_key, deadline, &mut clock)?;
        let mut runtime = HashSet::new();
        let mut filled = Vec::new();
        for target in &dispatch.targets {
            let check = self
                .verify_fill_target(context_key, dispatch, target, deadline, &mut clock)
                .and_then(|()| {
                    self.check_or_insert_fill_target(
                        context_key,
                        dispatch,
                        target,
                        &mut runtime,
                        &mut filled,
                        true,
                        deadline,
                        &mut clock,
                    )
                });
            if let Err(reason_code) = check {
                return Ok(Some(reason_code));
            }
        }
        Ok(None)
    }

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
                    self.check_or_insert_fill_target(
                        context_key,
                        dispatch,
                        target,
                        &mut runtime,
                        &mut filled,
                        false,
                        deadline,
                        &mut clock,
                    )
                });
            if let Err(reason_code) = step {
                let cleanup_deadline = clock.now() + Duration::from_millis(1_000);
                self.clear_fields(
                    context_key,
                    &filled,
                    &mut runtime,
                    cleanup_deadline,
                    &mut clock,
                );
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
        let live = live.map_err(|_| "document_changed")?;
        crate::browser::fill::field_origin(target.frame.as_ref(), &live)
            .map_err(|_| "origin_opaque")?;
        super::super::typing::check_type_document(dispatch.document.as_ref(), Ok(live))
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
        if target.field == LoginField::Username {
            if crate::browser::fill::username_uses_form_heuristic(expected)
                && actual.login_field != expected.login_field
            {
                return Err("classification_changed");
            }
            let password = dispatch
                .targets
                .iter()
                .find(|field| field.field == LoginField::Password)
                .ok_or("not_a_password_field")?;
            let actual_password = build_non_type_classification(
                &nodes,
                &password.identity,
                expected.document_epoch,
                &expected.current_top_level_origin,
            )
            .map_err(|_| "classification_unavailable")?;
            crate::browser::fill::check_username_field(&actual, &actual_password)?;
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

    #[allow(clippy::too_many_arguments)]
    fn check_or_insert_fill_target(
        &mut self,
        context_key: &str,
        dispatch: &FillDispatch,
        target: &FillTarget,
        runtime: &mut HashSet<String>,
        filled: &mut Vec<FilledField>,
        check_only: bool,
        deadline: Instant,
        clock: &mut SystemNavigationClock,
    ) -> Result<(), &'static str> {
        let attachment = self
            .frame_attachment(&target.identity)
            .map_err(|_| "fill_frame_not_ready")?;
        let object_id = self
            .resolve_fill_node(&target.identity, runtime, deadline, clock)
            .map_err(|_| "fill_context_not_ready")?
            .ok_or("node_changed")?;
        // resolve_fill_node creates this wrapper in the exact captured frame's
        // isolated world. Compare its owner with that world's document, not
        // DOM.Node.frameId, which Chrome omits when describing a Document.
        // A same-session, same-origin adoption must still fail this check.
        if self
            .call_on_fill_node(
                &target.identity,
                &object_id,
                "function() { return this.ownerDocument === document; }",
                deadline,
                clock,
            )
            .map_err(|_| "owner_document_unavailable")?
            != Some(Value::Bool(true))
        {
            return Err("owner_frame_changed");
        }
        let owner = self.fill_command(&attachment.session_id, "Runtime.callFunctionOn",
            serde_json::json!({"objectId":object_id,"functionDeclaration":"function() { return this.ownerDocument; }","returnByValue":false}), deadline, clock)
            .ok_or("owner_document_unavailable")?;
        let owner_id = owner
            .get("result")
            .and_then(|result| result.get("objectId"))
            .and_then(Value::as_str)
            .ok_or("owner_document_unavailable")?;
        let described = self
            .fill_command(
                &attachment.session_id,
                "DOM.describeNode",
                serde_json::json!({"objectId":owner_id}),
                deadline,
                clock,
            )
            .ok_or("owner_document_unavailable")?;
        let node = described.get("node").ok_or("owner_document_unavailable")?;
        let expected_origin = target
            .frame
            .as_ref()
            .map_or(&target.classification.current_top_level_origin, |frame| {
                &frame.origin
            });
        // The owner document's URL must itself be https; inherited origins of
        // about:blank/srcdoc are not a destination authorized for a saved login.
        let url = node
            .get("documentURL")
            .and_then(Value::as_str)
            .ok_or("owner_document_unavailable")?;
        if !url.starts_with("https:")
            || crate::classification::canonical_origin_from_url(url).as_ref()
                != Some(expected_origin)
        {
            return Err("owner_origin_changed");
        }
        // Bind the resolved document to the authorized loader after resolving
        // ownership. A later navigation detaches this document and the atomic
        // function below refuses it rather than inserting in its replacement.
        self.verify_fill_target(context_key, dispatch, target, deadline, clock)?;
        let password_argument = if target.field == LoginField::Username {
            let password = dispatch
                .targets
                .iter()
                .find(|field| field.field == LoginField::Password)
                .ok_or("not_a_password_field")?;
            let password_id = self
                .resolve_fill_node(&password.identity, runtime, deadline, clock)
                .map_err(|_| "fill_context_not_ready")?
                .ok_or("node_changed")?;
            serde_json::json!({"objectId": password_id})
        } else {
            serde_json::json!({"value": null})
        };
        if !check_only {
            dispatch.mark_insertion_attempted();
            filled.push(FilledField {
                identity: target.identity.clone(),
                frame: target.frame.clone(),
            });
        }
        let result = self.fill_command(&attachment.session_id, "Runtime.callFunctionOn", serde_json::json!({
            "objectId":object_id, "functionDeclaration":INSERT_FILLED, "returnByValue":true,
            "arguments":[{"objectId":owner_id},
                {"value":target.classification.effective_input_type.as_deref().unwrap_or("text")},
                {"value":target.classification.target_autocomplete_tokens},
                {"value":expected_origin}, {"value":if check_only { None } else { Some(target.value.as_str()) }},
                {"value":target.field == LoginField::Username}, password_argument, {"value":check_only}]
        }), deadline, clock).ok_or("fill_insert_not_ready")?;
        if result.contains_key("exceptionDetails")
            || result
                .get("result")
                .and_then(|result| result.get("value"))
                .and_then(Value::as_bool)
                != Some(true)
        {
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
        // A dedicated isolated world supplies pristine DOM intrinsics rather
        // than page-overridden setters, getters or event constructors.
        let world = self
            .fill_command(
                &session,
                "Page.createIsolatedWorld",
                serde_json::json!({"frameId":identity.frame_id,"worldName":"cortexkit-login-fill"}),
                deadline,
                clock,
            )
            .ok_or(NavigationDriveError::CdpFailure)?;
        let context_id = world
            .get("executionContextId")
            .and_then(Value::as_i64)
            .ok_or(NavigationDriveError::CdpFailure)?;
        let resolved = self
            .fill_command(
                &session,
                "DOM.resolveNode",
                serde_json::json!({"backendNodeId": identity.backend_node_id, "executionContextId":context_id}),
                deadline,
                clock,
            ).ok_or(NavigationDriveError::CdpFailure)?;
        let id = resolved
            .get("object")
            .and_then(|object| object.get("objectId"))
            .and_then(Value::as_str)
            .ok_or(NavigationDriveError::CdpFailure)?;
        Ok(Some(id.to_owned()))
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
