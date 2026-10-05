use super::*;
use crate::browser_type::{BrowserTypeResult, TypeDispatch};

pub(super) fn check_type_document(
    expected: Option<&CommittedDocument>,
    live: Result<CommittedDocument, crate::browser_session::NavigationDriveError>,
) -> Result<(), BrowserError> {
    check_snapshot_document(expected, live)
}

impl BrowserPlane {
    pub(super) async fn type_text(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(args, &["ref", "text", "clear_first"])
            .await?;
        let reference = required_string(object, "ref", 2, 5)?;
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
            let snapshot_id =
                context
                    .last_text_snapshot
                    .clone()
                    .ok_or(BrowserError::StaleSnapshot {
                        reason_code: "not_retained",
                    })?;
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
                // Sensitive fields are rejected before consuming any grant or committing input.
                if classification.is_credential_field()
                    || classification
                        .target_autocomplete_tokens
                        .iter()
                        .any(|token| crate::classification::financial_token(token))
                {
                    return Err(BrowserError::InvalidRequest {
                        field: "text".into(),
                        reason_code: "credential_input_unsupported",
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
        {
            let grants = self.grants.lock().await;
            // Typing changes page state, so it needs at least tier 2, the same floor a click on a form control gets; a field the
            // classifier ranks higher keeps its higher tier.
            let severity = crate::authorization::Severity::new(
                dispatch.classification.required_tier.max(2),
                false,
                false,
            );
            let request = AuthorizationRequest::click(
                &identity.conversation_key,
                severity,
                snapshot_id,
                &identity.agent_project_id,
                &dispatch.classification,
            );
            let decision = grants
                .authorize(request, &origin_from_url(&origin))
                .map_err(map_authorization_error)?;
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
        let result = result.map_err(map_navigation_drive_error)?;
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
        self.finalize(
            identity,
            BrowserCapability::Type,
            Outcome::StaleSnapshot,
            response,
        )
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
            BrowserTypeResult::AuthorizationDenied => {
                map_authorization_error(crate::authorization::AuthorizationError::NoGrant)
            }
            _ => BrowserError::Internal {
                reason_code: JournalReasonCode::InternalFailure,
            },
        })
    }
}
