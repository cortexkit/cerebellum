//! Windows refuses unsupported actions before entering either browser backend.

use crate::{browser, flat_tools, management, Value};

pub(super) struct Refusal {
    pub code: &'static str,
    pub message: &'static str,
}

const USER_BROWSER: Refusal = Refusal {
    code: "user_browser_not_supported",
    message: "This build cannot control the person's browser yet. Call browser_use with browser:\"own\" and action:\"status\" to check the agent's browser instead.",
};

const ACTION_WITHHELD: Refusal = Refusal {
    code: "browser_action_not_supported",
    message: "This browser action is not available in this build yet. Call browser_use with browser:\"own\" and action:\"status\" to check the agent's browser; do not retry the unavailable action.",
};

// Keep flat and legacy calls behind the same row, so a withheld action cannot
// reach its backend by switching API surfaces.
const OWN_ACTIONS: &[(&str, &str, Refusal)] = &[
    ("present", management::PRESENT, ACTION_WITHHELD),
    ("resume", management::RESUME, ACTION_WITHHELD),
    ("capture_login", management::CAPTURE_LOGIN, ACTION_WITHHELD),
    ("fill_login", browser::fill::FILL_LOGIN, ACTION_WITHHELD),
    ("import_login", management::IMPORT_LOGIN, ACTION_WITHHELD),
];

pub(super) fn tool_refusal(name: &str, arguments: &Value) -> Option<&'static Refusal> {
    if name != flat_tools::BROWSER_USE {
        return legacy_tool_refusal(name);
    }
    match arguments.get("browser") {
        Some(target) if target == "user" => return Some(&USER_BROWSER),
        Some(target) if target != "own" => return None,
        _ => {}
    }
    let action = arguments.get("action")?.as_str()?;
    OWN_ACTIONS
        .iter()
        .find_map(|(flat, _, refusal)| (*flat == action).then_some(refusal))
}

pub(super) fn legacy_tool_refusal(name: &str) -> Option<&'static Refusal> {
    if name == browser::fill::FILL_LOGIN {
        return legacy_refusal(name);
    }
    None
}

pub(super) fn management_refusal(method: &str) -> Option<&'static Refusal> {
    if method == browser::fill::FILL_LOGIN {
        return None;
    }
    legacy_refusal(method)
}

fn legacy_refusal(name: &str) -> Option<&'static Refusal> {
    OWN_ACTIONS
        .iter()
        .find_map(|(_, legacy, refusal)| (*legacy == name).then_some(refusal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{json, Arc, Flags, Frame, FrameType, HealthState, Planes, Priority};

    async fn tool(planes: &Planes, corr: u64, name: &str, args: Value) -> (FrameType, Value) {
        let frame = Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            10,
            1,
            corr,
            serde_json::to_vec(&json!({"name":name, "arguments":args})).unwrap(),
        )
        .unwrap();
        crate::install_test_bind(&planes.routes, &frame);
        assert!(
            crate::browser_queue::arrive(&frame, planes).is_none(),
            "a withheld call must not enter browser queue or bridge preflight"
        );
        let (writer, mut replies) = tokio::sync::mpsc::channel(8);
        let call = crate::CallObservation::new();
        crate::handle_tool_request(frame, &writer, planes, &call)
            .await
            .unwrap();
        assert!(!call.commit_point.load(std::sync::atomic::Ordering::SeqCst));
        let reply = replies.try_recv().expect("one terminal admission refusal");
        assert!(replies.try_recv().is_err());
        (
            reply.header.ty,
            serde_json::from_slice(&reply.body).unwrap(),
        )
    }

    #[cfg(not(feature = "windows-browser-release"))]
    #[tokio::test]
    async fn windows_browser_unbound_direct_calls_stay_out_of_backend() {
        let planes = Planes::new(Arc::new(HealthState::new()));
        assert!(planes.browser_config.is_some());
        assert!(!planes.browser_admitted());
        for (corr, target) in [(1, "own"), (2, "user")] {
            let (kind, reply) = tool(
                &planes,
                corr,
                flat_tools::BROWSER_USE,
                json!({"action":"launch","browser":target}),
            )
            .await;
            assert_eq!(kind, FrameType::Error);
            assert_eq!(reply["code"], "tool_disabled", "{reply}");
        }
    }

    #[cfg(feature = "windows-browser-release")]
    fn assert_refused(kind: FrameType, reply: &Value, code: &str) {
        assert_eq!(kind, FrameType::Error, "{reply}");
        assert_eq!(reply["code"], code, "{reply}");
        assert!(
            reply["message"]
                .as_str()
                .unwrap()
                .contains("Call browser_use with browser:\"own\" and action:\"status\""),
            "{reply}"
        );
    }

    #[cfg(feature = "windows-browser-release")]
    #[tokio::test]
    async fn windows_browser_bound_refuses_user_before_the_bridge() {
        let planes = Planes::new(Arc::new(HealthState::new()));
        assert!(crate::browser_build_admits());
        assert!(planes.browser_admitted());
        let (kind, reply) = tool(
            &planes,
            1,
            flat_tools::BROWSER_USE,
            json!({"action":"status","browser":"user"}),
        )
        .await;
        assert_refused(kind, &reply, "user_browser_not_supported");
        assert_eq!(reply["browser"], "user", "{reply}");
    }

    #[cfg(feature = "windows-browser-release")]
    #[tokio::test]
    async fn windows_browser_bound_withheld_table_never_dispatches() {
        let planes = Planes::new(Arc::new(HealthState::new()));
        let expected = [
            "present",
            "resume",
            "capture_login",
            "fill_login",
            "import_login",
        ];
        assert_eq!(
            OWN_ACTIONS
                .iter()
                .map(|(action, _, _)| *action)
                .collect::<Vec<_>>(),
            expected
        );
        for (index, action) in expected.into_iter().enumerate() {
            let (kind, reply) = tool(
                &planes,
                index as u64 + 1,
                flat_tools::BROWSER_USE,
                json!({"action":action,"browser":"own"}),
            )
            .await;
            assert_refused(kind, &reply, "browser_action_not_supported");
        }
        let (kind, reply) = tool(
            &planes,
            6,
            browser::fill::FILL_LOGIN,
            json!({"secret":"fixture"}),
        )
        .await;
        assert_refused(kind, &reply, "browser_action_not_supported");

        for (index, (_, method, _)) in OWN_ACTIONS
            .iter()
            .filter(|(_, method, _)| *method != browser::fill::FILL_LOGIN)
            .enumerate()
        {
            let frame = Frame::build(
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                10,
                1,
                index as u64 + 7,
                serde_json::to_vec(&json!({"method":method,"params":{}})).unwrap(),
            )
            .unwrap();
            crate::install_test_bind(&planes.routes, &frame);
            let facts = planes.routes.get(10, 1).unwrap();
            let (writer, mut replies) = tokio::sync::mpsc::channel(8);
            crate::handle_management_request_observed(frame, &writer, &facts, &planes, None)
                .await
                .unwrap();
            let reply = replies.try_recv().expect("management alias must refuse");
            assert_refused(
                reply.header.ty,
                &serde_json::from_slice(&reply.body).unwrap(),
                "browser_action_not_supported",
            );
        }
    }
}
