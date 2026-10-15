use super::*;
use crate::browser_session::BrowserScrollTarget;

fn page_target(object: &Map<String, Value>) -> Result<BrowserScrollTarget, BrowserError> {
    let direction = required_string(object, "direction", 1, 5)?;
    let amount = optional_integer(object, "amount", 1, 10_000)?.unwrap_or(600) as i32;
    let (x, y) = match direction {
        "up" => (0, -amount),
        "down" => (0, amount),
        "left" => (-amount, 0),
        "right" => (amount, 0),
        _ => {
            return Err(BrowserError::InvalidRequest {
                field: "direction".into(),
                reason_code: "unsupported_value",
            })
        }
    };
    Ok(BrowserScrollTarget::Page { x, y })
}

impl BrowserPlane {
    pub(super) async fn scroll(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(args, &["ref", "direction", "amount"])
            .await?;
        let requested = match object.get("ref") {
            None => None,
            Some(_) => {
                let reference = required_string(object, "ref", 2, 21)?;
                if !snapshot_store::valid_ref(reference) {
                    return Err(BrowserError::InvalidRequest {
                        field: "ref".into(),
                        reason_code: "unsupported_value",
                    });
                }
                if object.contains_key("direction") || object.contains_key("amount") {
                    return Err(BrowserError::InvalidRequest {
                        field: "direction".into(),
                        reason_code: "unsupported_value",
                    });
                }
                Some(reference)
            }
        };
        let page = if requested.is_none() {
            Some(page_target(object)?)
        } else {
            None
        };
        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, ms)| *ms)
            .ok_or(BrowserError::NoSession)?;
        let operation = self
            .admit_operation(identity, BrowserCapability::Scroll)?
            .ok_or(BrowserError::NoSession)?;
        let (operation, source) = self
            .read_live_document(identity, operation, deadline_ms)
            .await?;
        self.authorize_read(identity, BrowserCapability::Scroll, &source.url)
            .await?;
        let (target, frame) = if let Some(requested) = requested {
            let state = self.state.lock().await;
            let context = state
                .contexts
                .get(&identity.conversation_key)
                .ok_or(BrowserError::NoSession)?;
            zoom_target(context, requested, &[], Some(&source))?;
            let shown = context
                .refs
                .shown(requested)
                .ok_or_else(|| BrowserError::RefNotFound {
                    reference: requested.into(),
                })?;
            let identity =
                shown
                    .record
                    .backend_identity
                    .clone()
                    .ok_or(BrowserError::StaleSnapshot {
                        reason_code: "ref_from_older_snapshot",
                    })?;
            (
                BrowserScrollTarget::Element(identity),
                shown.record.frame_document.clone(),
            )
        } else {
            (page.expect("page target parsed"), None)
        };
        self.reserve_journal(identity, BrowserCapability::Scroll, true)
            .await?;
        self.commit(identity, BrowserCapability::Scroll).await?;
        let route = identity.conversation_key.clone();
        let (operation, driven, after) = tokio::task::spawn_blocking(move || {
            let mut operation = operation;
            let driven = (|| {
                // A printed element reference belongs to one document. Check its
                // frame before scrolling; moving the viewport does not activate
                // the referenced control, so the page's read grant is sufficient.
                if let Some(frame) = frame {
                    if !operation
                        .prepare_frame(&route, &frame, deadline_ms)
                        .map_err(map_navigation_drive_error)?
                    {
                        return Err(BrowserError::StaleSnapshot {
                            reason_code: "frame_document_changed",
                        });
                    }
                }
                operation
                    .scroll(&route, &target, deadline_ms)
                    .map_err(map_navigation_drive_error)
            })();
            let after = operation.committed_document(&route, deadline_ms);
            (operation, driven, after)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        operation.finish();
        driven?;
        self.confirm_read_document(identity, BrowserCapability::Scroll, &source, after)
            .await?;
        self.finalize(
            identity,
            BrowserCapability::Scroll,
            Outcome::Success,
            json!({"outcome":"ok","scroll_dispatched":true}),
        )
        .await?;
        Ok(json!({"outcome":"ok","scroll_dispatched":true}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scroll_page_direction_and_amount_are_bounded() {
        assert_eq!(
            page_target(json!({"direction":"down"}).as_object().unwrap()).unwrap(),
            BrowserScrollTarget::Page { x: 0, y: 600 }
        );
        assert_eq!(
            page_target(
                json!({"direction":"left","amount":900})
                    .as_object()
                    .unwrap()
            )
            .unwrap(),
            BrowserScrollTarget::Page { x: -900, y: 0 }
        );
        for args in [
            json!({"direction":"down","amount":0}),
            json!({"direction":"down","amount":10001}),
            json!({"direction":"other"}),
        ] {
            assert!(page_target(args.as_object().unwrap()).is_err());
        }
    }
}
