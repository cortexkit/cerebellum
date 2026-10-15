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
                let metrics = self.command(
                    "Page.getLayoutMetrics",
                    None,
                    Some(attachment.session_id.clone()),
                    snapshot_step_deadline(deadline, true, clock.now()),
                    None,
                    clock,
                )?;
                let viewport = metrics
                    .get("cssVisualViewport")
                    .and_then(Value::as_object)
                    .ok_or(NavigationDriveError::CdpFailure)?;
                let width = viewport
                    .get("clientWidth")
                    .and_then(Value::as_f64)
                    .filter(|n| n.is_finite() && *n > 0.0)
                    .ok_or(NavigationDriveError::CdpFailure)?;
                let height = viewport
                    .get("clientHeight")
                    .and_then(Value::as_f64)
                    .filter(|n| n.is_finite() && *n > 0.0)
                    .ok_or(NavigationDriveError::CdpFailure)?;
                // CDP gesture distances describe the finger's movement, opposite
                // to the content offset requested by the caller.
                (
                    "Input.synthesizeScrollGesture",
                    serde_json::json!({
                        "x": width / 2.0, "y": height / 2.0,
                        "xDistance": -i64::from(*x), "yDistance": -i64::from(*y), "speed": 10000,
                        "gestureSourceType": "mouse", "preventFling": true,
                    }),
                    attachment.session_id,
                )
            }
        };
        self.command(
            method,
            params.as_object().cloned(),
            Some(session),
            snapshot_step_deadline(deadline, true, clock.now()),
            None,
            clock,
        )?;
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
    fn scroll_page_uses_css_viewport_and_signed_distance() {
        let mut driver = attached_driver([
            json!({"id":1,"sessionId":"session-own","result":{"cssVisualViewport":{"clientWidth":800,"clientHeight":600}}}),
            json!({"id":2,"sessionId":"session-own","result":{}}),
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
            driver.pipe.writes[1]["method"],
            "Input.synthesizeScrollGesture"
        );
        assert_eq!(driver.pipe.writes[1]["params"]["yDistance"], -600);
        assert_eq!(driver.pipe.writes[1]["params"]["y"], 300.0);
        assert_eq!(
            command_effect("DOM.scrollIntoViewIfNeeded", None, None),
            CommandEffect::Mutation
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
