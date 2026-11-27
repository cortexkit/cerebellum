use super::*;

impl BrowserPlane {
    /// Build a click's reply from what the driver measured, and record a
    /// navigation the click caused as the conversation's current page.
    ///
    /// Recording it keeps the tracked page, and the `url_final` later replies
    /// report, in step with the browser. Reads do not rely on it: a snapshot
    /// or screenshot asks the browser for its committed URL and authorizes
    /// against that.
    pub(super) async fn click_reply(
        &self,
        identity: &RouteIdentity,
        outcome: crate::browser_session::BrowserClickOutcome,
    ) -> Value {
        use crate::browser_session::{BrowserClickOutcome, ClickNavigation};
        let selected = match &outcome {
            BrowserClickOutcome::OptionSelected {
                value,
                selected_index,
                ..
            } => Some((value.clone(), *selected_index)),
            _ => None,
        };
        let (dialogs, navigation) = match outcome {
            BrowserClickOutcome::OptionSelected { navigation, .. } => (Vec::new(), navigation),
            BrowserClickOutcome::Clicked { navigation, .. } => (Vec::new(), navigation),
            BrowserClickOutcome::KeyPressed {
                navigation,
                dialogs,
            } => (dialogs, navigation),
            BrowserClickOutcome::JavaScriptDialogDismissed {
                dialogs,
                navigation,
                ..
            } => (dialogs, navigation),
        };
        let mut response = match navigation {
            ClickNavigation::NoneObserved { window_ms } => json!({
                "outcome":"ok",
                "navigation":"none_observed",
                "navigation_window_ms":window_ms,
            }),
            ClickNavigation::SameDocument { url } => {
                // A same-document change cannot leave the origin, so the
                // document epoch and its snapshots stay valid.
                if let Some(context) = self
                    .state
                    .lock()
                    .await
                    .contexts
                    .get_mut(&identity.conversation_key)
                {
                    context.tracker.url_final = Some(url.clone());
                }
                json!({"outcome":"ok","navigation":"same_document","url_final":url})
            }
            ClickNavigation::MainFrame(tracker) if tracker.download_blocked => {
                let mut response = navigate_reply(&tracker, false);
                response["navigation"] = json!("not_committed");
                response
            }
            ClickNavigation::MainFrame(tracker) if tracker.navigation_ended_without_commit() => {
                // The page the click started from is still the one shown.
                json!({
                    "outcome":"ok",
                    "navigation":"not_committed",
                    "lifecycle":{"events":[],"loaded":false,"settled":false},
                })
            }
            ClickNavigation::MainFrame(tracker) => {
                if let Some(context) = self
                    .state
                    .lock()
                    .await
                    .contexts
                    .get_mut(&identity.conversation_key)
                {
                    let _ = context
                        .epoch
                        .replace(DocumentTransition::TopLevelDocumentReplaced);
                    context.tracker = (*tracker).clone();
                }
                let mut response = navigate_reply(&tracker, true);
                let object = response
                    .as_object_mut()
                    .expect("navigation response is an object");
                object.insert("navigation".into(), json!("main_frame"));
                if let Some(error_text) = tracker.main_frame_failure() {
                    let failed = BrowserError::NavigationFailed {
                        error_text: error_text.to_string(),
                    };
                    object.insert("outcome".into(), json!(failed.outcome()));
                    object.insert("remedy".into(), json!(failed.remedy()));
                    object.insert("detail".into(), failed.detail().unwrap_or(Value::Null));
                }
                if let Some(url_final) = tracker.url_final.as_deref() {
                    // The same check the next snapshot runs, made without
                    // committing, so the caller learns before reading whether
                    // that read will be refused and which origin to request.
                    let landing_origin = origin_from_url(url_final);
                    let granted = self
                        .grants
                        .lock()
                        .await
                        .authorize_document(
                            AuthorizationRequest::snapshot(
                                &identity.conversation_key,
                                url_final,
                                &identity.agent_project_id,
                            ),
                            &landing_origin,
                            tracker.main_frame_network.is_public(&landing_origin),
                        )
                        .is_ok();
                    object.insert("landing_origin".into(), json!(landing_origin));
                    object.insert("landing_origin_granted".into(), json!(granted));
                }
                response
            }
        };
        if let Some((value, selected_index)) = selected {
            response["value"] = json!(value);
            response["selectedIndex"] = json!(selected_index);
        }
        if !dialogs.is_empty() {
            let object = response
                .as_object_mut()
                .expect("click response is an object");
            if object.get("outcome") == Some(&json!("ok")) {
                object.insert("outcome".into(), json!("javascript_dialog_dismissed"));
            }
            // Dialog details have their own field. Lifecycle describes document
            // navigation consistently, even when a dialog opened without one.
            object
                .entry("lifecycle")
                .or_insert_with(|| json!({"events":[],"loaded":false,"settled":false}));
            object.insert(
                "dialogs".into(),
                dialogs
                    .into_iter()
                    .map(|dialog| {
                        json!({
                            "dialog_type": dialog.dialog_type,
                            "response": dialog.response.as_str(),
                        })
                    })
                    .collect(),
            );
        }
        response
    }

    pub(super) async fn click(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let key = keys::PRESS_KEY.try_with(|key| *key).ok();
        let fields: &[&str] = if key.is_some() {
            &["ref", "snapshot_id"]
        } else {
            &["ref", "snapshot_id", "intent", "severity"]
        };
        let object = self.validate_request(args, fields).await?;
        let reference = required_string(object, "ref", 2, 21)?;
        let snapshot_id = required_string(object, "snapshot_id", 32, 32)?;
        if !snapshot_store::valid_snapshot_id(snapshot_id) {
            return Err(BrowserError::InvalidRequest {
                field: "snapshot_id".into(),
                reason_code: "unsupported_value",
            });
        }
        if !snapshot_store::valid_ref(reference) {
            return Err(BrowserError::InvalidRequest {
                field: "ref".into(),
                reason_code: "unsupported_value",
            });
        }
        // The floor is enforced by authorization below, which is also where the
        // target's required severity is computed; refusing there lets the
        // refusal carry that exact value instead of a second estimate.
        let requested_severity = if key.is_some() {
            crate::authorization::Action::Click.floor()
        } else {
            bounded_string(object, "intent", 0, 512)?;
            parse_severity(object)?
        };
        let (
            backend_identity,
            classification,
            document_epoch,
            source_origin,
            source_document,
            frame_document,
        ) = {
            let mut state = self.state.lock().await;
            let context = state
                .contexts
                .get_mut(&identity.conversation_key)
                .ok_or(BrowserError::NoSession)?;
            if context.ended {
                return Err(BrowserError::NoSession);
            }
            let snapshot = context
                .snapshots
                .pin_text(snapshot_id, context.epoch.value())
                .map_err(map_snapshot_error)?;
            let Some(record) = snapshot
                .refs
                .iter()
                .find(|record| record.captured.reference == reference)
            else {
                context.snapshots.unpin(snapshot_id);
                return Err(BrowserError::RefNotFound {
                    reference: reference.to_string(),
                });
            };
            let Some(backend_identity) = record.backend_identity.clone() else {
                context.snapshots.unpin(snapshot_id);
                return Err(BrowserError::ElementIntercepted);
            };
            (
                backend_identity,
                record.classification.clone().map(|record| *record),
                snapshot.document_epoch,
                record
                    .frame_document
                    .as_ref()
                    .map(|frame| frame.origin.clone())
                    .unwrap_or_else(|| snapshot.source_origin.clone()),
                snapshot.source_document.clone(),
                record.frame_document.clone(),
            )
        };

        if let Err(reason) = &classification {
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(BrowserError::ClassificationUnavailable(reason.clone()));
        }
        if let Some((reason_code, input_type)) =
            key.zip(classification.as_ref().ok())
                .and_then(|(key, record)| {
                    key.field_refusal(record).map(|reason| {
                        (
                            reason,
                            record
                                .effective_input_type
                                .clone()
                                .unwrap_or_else(|| "none".into()),
                        )
                    })
                })
        {
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(BrowserError::TypeField {
                reason_code,
                input_type,
            });
        }
        let activated_element = classification
            .as_ref()
            .ok()
            .filter(|_| key.is_none())
            .map(|record| json!({"identity":record.activation_target_identity,"kind":record.target_kind}));
        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline_ms)| *deadline_ms);
        // Before input, recompute the snapshot classification so a changed
        // target cannot inherit authorization from the earlier observation.

        let authorization = {
            let grants = self.grants.lock().await;
            let request = match classification.as_ref() {
                Ok(classification) => AuthorizationRequest::click(
                    &identity.conversation_key,
                    requested_severity,
                    snapshot_id,
                    &identity.agent_project_id,
                    classification,
                ),
                Err(_) => AuthorizationRequest::click_unverified(
                    &identity.conversation_key,
                    requested_severity,
                    snapshot_id,
                    &identity.agent_project_id,
                ),
            };
            let origin = origin_from_url(&source_origin);
            let network = frame_document
                .as_ref()
                .map(|frame| frame.network)
                .or_else(|| source_document.as_ref().map(|document| document.network))
                .unwrap_or_default();
            grants
                .authorize_document_input(request, &origin, network.is_public(&origin), key)
                .and_then(|decision| {
                    grants
                        .commit(&decision)
                        .map_err(|_| crate::authorization::AuthorizationError::NoGrant)?;
                    Ok(decision)
                })
        };
        if let Err(error) = authorization {
            self.unpin_snapshot(identity, snapshot_id).await;
            let mut error = map_authorization_error(error);
            if let (
                BrowserError::HazardNotDisclosed {
                    classification_unavailable,
                    ..
                }
                | BrowserError::SeverityBelowFloor {
                    classification_unavailable,
                    ..
                },
                Err(reason),
            ) = (&mut error, &classification)
            {
                *classification_unavailable = Some(reason.clone());
            }
            return Err(error);
        }

        self.remember_authorization(
            identity,
            authorization.as_ref().expect("authorization succeeded"),
        )
        .await;

        let reservation = self.reserve(identity, BrowserCapability::Click).await;
        let mut session_operation = match reservation {
            Ok(Some(operation)) => operation,
            Ok(None) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(BrowserError::NoSession);
            }
            Err(error) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(error);
            }
        };
        if let Err(error) = self.commit(identity, BrowserCapability::Click).await {
            session_operation.finish();
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(error);
        }
        {
            let mut state = self.state.lock().await;
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpObserve,
            );
        }

        let Some(deadline_ms) = deadline_ms else {
            session_operation.finish();
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(BrowserError::NoSession);
        };
        let state = Arc::clone(&self.state);
        let route_key = identity.conversation_key.clone();
        let expected_classification = classification.ok();
        let origin = source_origin;
        let driven = tokio::task::spawn_blocking(move || {
            // Lock order: this callback runs inside the driver call, while the
            // session's driver lock is held, and it takes the browser state
            // lock. So nothing may call into the browser sessions (status,
            // admission, driver calls, close or teardown) while holding the
            // browser state lock; that would take the two in the other order.
            let mut key_attempted = false;
            let mut input_dispatched = |event| {
                let operation = match event {
                    crate::browser_session::BrowserInputEvent::KeyPress => {
                        key_attempted = true;
                        Operation::CdpInputPress
                    }
                    crate::browser_session::BrowserInputEvent::Press(_) => Operation::CdpInputPress,
                    crate::browser_session::BrowserInputEvent::Release(_)
                    | crate::browser_session::BrowserInputEvent::KeyRelease => {
                        Operation::CdpInputRelease
                    }
                };
                let mut state = state.blocking_lock();
                Self::op(&mut state, &route_key, operation);
            };
            // Checked on this operation immediately before input, so the
            // document the click lands in is the one the snapshot read.
            let live = session_operation.committed_document(&route_key, deadline_ms);
            if let Err(error) = check_snapshot_document(source_document.as_ref(), live) {
                return (session_operation, Err(error));
            }
            if let Some(frame) = &frame_document {
                match session_operation.prepare_frame(&route_key, frame, deadline_ms) {
                    Ok(true) => {}
                    _ => {
                        return (
                            session_operation,
                            Err(BrowserError::StaleSnapshot {
                                reason_code: "frame_document_changed",
                            }),
                        )
                    }
                }
            }
            let result = if let Some(key) = key {
                let target = keys::KeyTarget {
                    key,
                    node: backend_identity,
                    origin,
                    expected: expected_classification.expect("a key needs a classified target"),
                };
                session_operation.press_key_classified(
                    &route_key,
                    &target,
                    deadline_ms,
                    &mut input_dispatched,
                )
            } else {
                session_operation.click_classified(
                    &route_key,
                    &backend_identity,
                    document_epoch,
                    &origin,
                    expected_classification.as_ref(),
                    deadline_ms,
                    &mut input_dispatched,
                )
            };
            (session_operation, Ok((result, key_attempted)))
        })
        .await;
        let (session_operation, drive_result) = match driven {
            Ok(result) => result,
            Err(_) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(BrowserError::Internal {
                    reason_code: JournalReasonCode::InternalFailure,
                });
            }
        };
        session_operation.finish();
        self.unpin_snapshot(identity, snapshot_id).await;
        let (drive_result, key_attempted) = self
            .refuse_moved_page(identity, BrowserCapability::Click, drive_result)
            .await?;

        let mut response = match drive_result {
            Ok(outcome) => self.click_reply(identity, outcome).await,
            Err(_) if key_attempted => json!({
                "outcome":"dispatch_outcome_unknown",
                "detail":{"dispatched":true,"step":"dispatch"},
                "effect_status":"effect_indeterminate",
                "remedy":"Read the page again before repeating; the key press may have taken effect."
            }),
            Err(crate::browser_session::ClickDriveError::Intercepted(detail)) => {
                return Err(BrowserError::Intercepted(detail));
            }
            Err(crate::browser_session::ClickDriveError::NoPosition) => {
                return Err(BrowserError::ElementIntercepted);
            }
            Err(crate::browser_session::ClickDriveError::ClassificationChanged) => {
                return Err(BrowserError::StaleSnapshot {
                    reason_code: "classification_changed",
                });
            }
            Err(crate::browser_session::ClickDriveError::OutsideViewportAfterScroll(refusal)) => {
                return Err(BrowserError::OutsideViewportAfterScroll { refusal });
            }
            Err(crate::browser_session::ClickDriveError::Navigation(error)) => {
                return Err(map_navigation_drive_error(error));
            }
        };
        if key.is_none() {
            response["activated_element"] = activated_element.unwrap_or(Value::Null);
        }
        self.finalize(
            identity,
            BrowserCapability::Click,
            if response["outcome"] == "dispatch_outcome_unknown" {
                Outcome::InternalError
            } else if response["outcome"] == "unsupported_download" {
                Outcome::Denied
            } else {
                Outcome::Success
            },
            response.clone(),
        )
        .await?;
        Ok(response)
    }
}
