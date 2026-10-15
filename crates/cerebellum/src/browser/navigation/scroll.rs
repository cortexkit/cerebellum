use super::*;
use crate::browser_session::BrowserScrollTarget;

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    /// Scroll without focusing the page or activating its browser window.
    pub fn scroll(
        &mut self,
        context_key: &str,
        target: &BrowserScrollTarget,
        deadline_ms: u64,
    ) -> Result<(), NavigationDriveError> {
        self.scroll_with_clock(context_key, target, deadline_ms, &mut SystemNavigationClock)
    }

    fn scroll_with_clock<C: NavigationClock>(
        &mut self,
        context_key: &str,
        target: &BrowserScrollTarget,
        deadline_ms: u64,
        clock: &mut C,
    ) -> Result<(), NavigationDriveError> {
        let deadline = clock.now() + Duration::from_millis(deadline_ms);
        self.ensure_attached(context_key, deadline, clock)?;
        let attachment = self
            .attachment
            .clone()
            .ok_or(NavigationDriveError::Unavailable)?;
        let (method, params, session) = match target {
            BrowserScrollTarget::Element(identity) => {
                if identity.target_id != attachment.target_id
                    || self
                        .active_frame
                        .as_ref()
                        .is_some_and(|frame| frame.frame_id != identity.frame_id)
                {
                    return Err(NavigationDriveError::CdpFailure);
                }
                (
                    "DOM.scrollIntoViewIfNeeded",
                    serde_json::json!({"backendNodeId": identity.backend_node_id}),
                    self.active_frame
                        .as_ref()
                        .map(|frame| frame.session_id.clone())
                        .unwrap_or(attachment.session_id),
                )
            }
            BrowserScrollTarget::Page { x, y } => {
                let tree = self.command(
                    "Page.getFrameTree",
                    None,
                    Some(attachment.session_id.clone()),
                    snapshot_step_deadline(deadline, true, clock.now()),
                    None,
                    clock,
                )?;
                let frame = tree
                    .get("frameTree")
                    .and_then(|tree| tree.get("frame"))
                    .and_then(|frame| frame.get("id"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| NavigationDriveError::CdpFailure.at_step("Page.getFrameTree"))?;
                // Native scrolling in an isolated world works on background
                // pages and cannot be replaced by page-authored scrollBy code.
                let world = self.command(
                    "Page.createIsolatedWorld",
                    Some(
                        serde_json::json!({"frameId":frame,"worldName":"cerebellum-scroll"})
                            .as_object()
                            .unwrap()
                            .clone(),
                    ),
                    Some(attachment.session_id.clone()),
                    snapshot_step_deadline(deadline, true, clock.now()),
                    None,
                    clock,
                )?;
                let context = world
                    .get("executionContextId")
                    .and_then(Value::as_u64)
                    .filter(|id| *id > 0)
                    .ok_or_else(|| {
                        NavigationDriveError::CdpFailure.at_step("Page.createIsolatedWorld")
                    })?;
                (
                    "Runtime.callFunctionOn",
                    serde_json::json!({
                        "executionContextId":context,
                        "functionDeclaration":"function(x, y) { window.scrollBy({left:x, top:y, behavior:'instant'}); }",
                        "arguments":[{"value":x},{"value":y}], "returnByValue":true,
                    }),
                    attachment.session_id,
                )
            }
        };
        let result = self.command(
            method,
            params.as_object().cloned(),
            Some(session),
            snapshot_step_deadline(deadline, true, clock.now()),
            None,
            clock,
        )?;
        if result.contains_key("exceptionDetails") {
            return Err(NavigationDriveError::CdpFailure.at_step(method));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{attached_driver, FakeClock};
    use super::*;
    use serde_json::json;

    #[test]
    fn scroll_ref_dispatches_backend_identity_without_fronting() {
        let mut driver = attached_driver([json!({"id":1,"sessionId":"session-own","result":{}})]);
        let target = BrowserScrollTarget::Element(
            BackendNodeIdentity::new("target-own", "frame-own", 91).unwrap(),
        );
        driver
            .scroll_with_clock("route-own", &target, 1000, &mut FakeClock::new())
            .unwrap();
        assert_eq!(driver.pipe.writes.len(), 1);
        assert_eq!(
            driver.pipe.writes[0]["method"],
            "DOM.scrollIntoViewIfNeeded"
        );
        assert_eq!(driver.pipe.writes[0]["params"], json!({"backendNodeId":91}));
    }

    #[test]
    fn scroll_page_uses_native_isolated_world_without_fronting() {
        let mut driver = attached_driver([
            json!({"id":1,"sessionId":"session-own","result":{"frameTree":{"frame":{"id":"frame-own"}}}}),
            json!({"id":2,"sessionId":"session-own","result":{"executionContextId":7}}),
            json!({"id":3,"sessionId":"session-own","result":{"result":{"type":"undefined"}}}),
        ]);
        driver
            .scroll_with_clock(
                "route-own",
                &BrowserScrollTarget::Page { x: 0, y: 600 },
                1000,
                &mut FakeClock::new(),
            )
            .unwrap();
        assert_eq!(
            driver
                .pipe
                .writes
                .iter()
                .map(|command| command["method"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "Page.getFrameTree",
                "Page.createIsolatedWorld",
                "Runtime.callFunctionOn"
            ]
        );
        assert_eq!(driver.pipe.writes[1]["params"]["frameId"], "frame-own");
        let params = &driver.pipe.writes[2]["params"];
        assert_eq!(params["executionContextId"], 7);
        assert_eq!(params["arguments"], json!([{"value":0},{"value":600}]));
        assert!(params["functionDeclaration"]
            .as_str()
            .unwrap()
            .contains("window.scrollBy"));
        assert_eq!(
            command_effect("Runtime.callFunctionOn", params.as_object(), None),
            CommandEffect::Mutation
        );
        assert_eq!(
            command_effect("DOM.scrollIntoViewIfNeeded", None, None),
            CommandEffect::Mutation
        );
    }

    #[test]
    fn scroll_page_refuses_a_runtime_exception() {
        let mut driver = attached_driver([
            json!({"id":1,"sessionId":"session-own","result":{"frameTree":{"frame":{"id":"frame-own"}}}}),
            json!({"id":2,"sessionId":"session-own","result":{"executionContextId":7}}),
            json!({"id":3,"sessionId":"session-own","result":{"exceptionDetails":{}}}),
        ]);
        assert_eq!(
            driver.scroll_with_clock(
                "route-own",
                &BrowserScrollTarget::Page { x: 0, y: 600 },
                1000,
                &mut FakeClock::new()
            ),
            Err(NavigationDriveError::CdpFailure.at_step("Runtime.callFunctionOn"))
        );
    }

    #[test]
    fn scroll_deadline_does_not_dispatch_late_input() {
        let mut driver = attached_driver([]);
        assert!(driver
            .scroll_with_clock(
                "route-own",
                &BrowserScrollTarget::Page { x: 0, y: 600 },
                0,
                &mut FakeClock::new()
            )
            .is_err());
        assert!(driver.pipe.writes.is_empty());
    }
}
