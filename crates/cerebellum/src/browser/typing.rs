use super::*;
use crate::browser_type::{BrowserTypeResult, TypeDispatch};

pub(super) fn check_type_document(
    expected: Option<&CommittedDocument>,
    live: Result<CommittedDocument, crate::browser_session::NavigationDriveError>,
) -> Result<(), BrowserError> {
    let live = live.map_err(|_| BrowserError::TypeNotReady {
        reason_code: "type_document_not_ready",
    })?;
    check_snapshot_document(expected, Ok(live))
}

impl BrowserPlane {
    pub(super) async fn type_text(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(args, &["ref", "snapshot_id", "text", "clear_first"])
            .await?;
        let reference = required_string(object, "ref", 2, 21)?;
        if !snapshot_store::valid_ref(reference) {
            return Err(BrowserError::InvalidRequest {
                field: "ref".into(),
                reason_code: "unsupported_value",
            });
        }
        let text = object
            .get("text")
            .ok_or_else(|| BrowserError::InvalidRequest {
                field: "text".into(),
                reason_code: "missing_field",
            })?
            .as_str()
            .ok_or_else(|| BrowserError::InvalidRequest {
                field: "text".into(),
                reason_code: "wrong_type",
            })?;
        if text.chars().count() > 10_000 {
            return Err(BrowserError::InvalidRequest {
                field: "text".into(),
                reason_code: "out_of_range",
            });
        }
        let clear_first = match object.get("clear_first") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => {
                return Err(BrowserError::InvalidRequest {
                    field: "clear_first".into(),
                    reason_code: "wrong_type",
                })
            }
        };
        let (snapshot_id, dispatch, origin) = {
            let mut state = self.state.lock().await;
            let context = state
                .contexts
                .get_mut(&identity.conversation_key)
                .filter(|context| !context.ended)
                .ok_or(BrowserError::NoSession)?;
            let snapshot_id = match object.get("snapshot_id") {
                Some(_) => {
                    let id = required_string(object, "snapshot_id", 32, 32)?;
                    if !snapshot_store::valid_snapshot_id(id) {
                        return Err(BrowserError::InvalidRequest {
                            field: "snapshot_id".into(),
                            reason_code: "unsupported_value",
                        });
                    }
                    id.to_string()
                }
                None => context
                    .refs
                    .shown(reference)
                    .map(|shown| shown.snapshot_id.clone())
                    .ok_or(BrowserError::StaleSnapshot {
                        reason_code: "not_retained",
                    })?,
            };
            let snapshot = context
                .snapshots
                .pin_text(&snapshot_id, context.epoch.value())
                .map_err(map_snapshot_error)?;
            let resolved = (|| {
                let record = snapshot
                    .refs
                    .iter()
                    .find(|record| record.captured.reference == reference)
                    .ok_or_else(|| BrowserError::RefNotFound {
                        reference: reference.into(),
                    })?;
                let classification = record
                    .classification
                    .as_ref()
                    .map_err(|reason| BrowserError::ClassificationUnavailable(reason.clone()))?
                    .as_ref()
                    .clone();
                // Sensitive and unsupported controls are rejected before consuming
                // any grant or committing input.
                if let Some(reason_code) = crate::classification::type_field_reason(&classification)
                {
                    return Err(BrowserError::TypeField {
                        reason_code,
                        input_type: classification
                            .effective_input_type
                            .clone()
                            .unwrap_or_else(|| "none".into()),
                    });
                }
                let origin = record
                    .frame_document
                    .as_ref()
                    .map(|frame| frame.origin.clone())
                    .unwrap_or_else(|| snapshot.source_origin.clone());
                Ok((
                    TypeDispatch {
                        identity: record
                            .backend_identity
                            .clone()
                            .ok_or(BrowserError::ElementIntercepted)?,
                        classification,
                        frame: record.frame_document.clone(),
                        document: snapshot.source_document.clone(),
                    },
                    origin,
                ))
            })();
            if resolved.is_err() {
                context.snapshots.unpin(&snapshot_id);
            }
            let (dispatch, origin) = resolved?;
            (snapshot_id, dispatch, origin)
        };
        let result = self
            .type_pinned(identity, &snapshot_id, dispatch, origin, text, clear_first)
            .await;
        self.unpin_snapshot(identity, &snapshot_id).await;
        result
    }

    async fn type_pinned(
        &self,
        identity: &RouteIdentity,
        snapshot_id: &str,
        dispatch: TypeDispatch,
        origin: String,
        text: &str,
        clear_first: bool,
    ) -> Result<Value, BrowserError> {
        let profile_name = crate::browser_signed_in::SignedInDomains::profile_name(identity);
        {
            let grants = self.grants.lock().await;
            // Typing changes page state, so it needs at least tier 2, the same
            // floor a click on a form control gets; a field the classifier
            // ranks higher keeps its higher tier.
            let severity = crate::authorization::Severity::new(
                dispatch.classification.required_tier.max(2),
                false,
                false,
            );
            let mut request = AuthorizationRequest::click(
                &identity.conversation_key,
                severity,
                snapshot_id,
                &identity.agent_project_id,
                &dispatch.classification,
            );
            request.action = crate::authorization::Action::Type;
            request.signed_in_profile = &profile_name;
            let decision = grants
                .authorize(request, &origin_from_url(&origin))
                .map_err(map_authorization_error)?;
            self.remember_authorization(identity, &decision).await;
            grants.commit(&decision).map_err(|_| {
                map_authorization_error(crate::authorization::AuthorizationError::NoGrant)
            })?;
        }
        let mut operation = self
            .reserve(identity, BrowserCapability::Type)
            .await?
            .ok_or(BrowserError::NoSession)?;
        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline)| *deadline)
            .ok_or(BrowserError::NoSession)?;
        // Check the live document before the durable dispatch commit as well as inside the driver.
        let route_key = identity.conversation_key.clone();
        let document = dispatch.document.clone();
        let (returned, live) = tokio::task::spawn_blocking(move || {
            let live = operation.committed_document(&route_key, deadline_ms);
            (operation, live)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        operation = returned;
        if let Err(error) = check_type_document(document.as_ref(), live) {
            operation.finish();
            return Err(error);
        }
        self.commit(identity, BrowserCapability::Type).await?;
        let route_key = identity.conversation_key.clone();
        let text = text.to_owned();
        let characters = text.chars().count();
        let (operation, result) = tokio::task::spawn_blocking(move || {
            let result =
                operation.type_classified(&route_key, &dispatch, &text, clear_first, deadline_ms);
            (operation, result)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        operation.finish();
        let result = result.map_err(|_| BrowserError::TypeNotReady {
            reason_code: "type_attachment_not_ready",
        })?;
        let response = result.to_value();
        if let BrowserTypeResult::Ok = result {
            let response = json!({"outcome":"ok","characters_dispatched":characters});
            self.finalize(
                identity,
                BrowserCapability::Type,
                Outcome::Success,
                response.clone(),
            )
            .await?;
            return Ok(response);
        }
        let outcome = if matches!(result, BrowserTypeResult::NotReady { .. }) {
            Outcome::Denied
        } else {
            Outcome::StaleSnapshot
        };
        self.finalize(identity, BrowserCapability::Type, outcome, response)
            .await?;
        Err(match result {
            BrowserTypeResult::InvalidRequest { field, reason_code } => {
                BrowserError::InvalidRequest {
                    field,
                    reason_code: if reason_code == "credential_input_unsupported" {
                        "credential_input_unsupported"
                    } else {
                        "target_not_interactive"
                    },
                }
            }
            BrowserTypeResult::StaleSnapshot { .. } => BrowserError::StaleSnapshot {
                reason_code: "document_or_target_changed",
            },
            BrowserTypeResult::NotReady { reason_code } => BrowserError::TypeNotReady {
                reason_code: match reason_code.as_str() {
                    "type_runtime_not_ready" => "type_runtime_not_ready",
                    "type_context_not_ready" => "type_context_not_ready",
                    "type_deadline_expired" => "type_deadline_expired",
                    "type_frame_not_ready" => "type_frame_not_ready",
                    "type_document_not_ready" => "type_document_not_ready",
                    "type_clear_not_ready" => "type_clear_not_ready",
                    "type_caret_not_ready" => "type_caret_not_ready",
                    "type_focus_not_ready" => "type_focus_not_ready",
                    "type_selection_not_ready" => "type_selection_not_ready",
                    "type_insert_not_ready" => "type_insert_not_ready",
                    "type_attachment_not_ready" => "type_attachment_not_ready",
                    _ => "type_observation_not_ready",
                },
            },
            BrowserTypeResult::AuthorizationDenied => {
                map_authorization_error(crate::authorization::AuthorizationError::NoGrant)
            }
            _ => BrowserError::Internal {
                reason_code: JournalReasonCode::InternalFailure,
            },
        })
    }
}
