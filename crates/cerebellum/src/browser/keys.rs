use serde_json::{json, Value};
use std::collections::BTreeSet;

use crate::authorization::{self, Action, AuthorizationError, HazardClass, Severity};
use crate::classification::NonTypeClassificationRecord;

tokio::task_local! {
    // Set only by the flat-tool boundary after it validates the key. A
    // granular browser.click call cannot send keyboard input.
    pub(crate) static PRESS_KEY: Key;
}

macro_rules! browser_keys {
    ($($variant:ident => ($name:literal, $key:literal, $code:literal, $vk:literal)),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Key { $($variant),+ }

        impl Key {
            pub(crate) const NAMES: &'static [&'static str] = &[$($name),+];

            pub(crate) fn parse(name: &str) -> Option<Self> {
                match name { $($name => Some(Self::$variant),)+ _ => None }
            }

            pub(crate) const fn name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }

            fn cdp_fields(self) -> (&'static str, &'static str, u32) {
                match self { $(Self::$variant => ($key, $code, $vk)),+ }
            }
        }
    };
}

browser_keys! {
    Enter => ("enter", "Enter", "Enter", 13),
    Escape => ("escape", "Escape", "Escape", 27),
    Tab => ("tab", "Tab", "Tab", 9),
    ShiftTab => ("shift_tab", "Tab", "Tab", 9),
    Up => ("up", "ArrowUp", "ArrowUp", 38),
    Down => ("down", "ArrowDown", "ArrowDown", 40),
    Left => ("left", "ArrowLeft", "ArrowLeft", 37),
    Right => ("right", "ArrowRight", "ArrowRight", 39),
    Home => ("home", "Home", "Home", 36),
    End => ("end", "End", "End", 35),
    PageUp => ("page_up", "PageUp", "PageUp", 33),
    PageDown => ("page_down", "PageDown", "PageDown", 34),
    Backspace => ("backspace", "Backspace", "Backspace", 8),
    Delete => ("delete", "Delete", "Delete", 46),
}

impl Key {
    pub(crate) fn schema() -> Value {
        json!({"type":"string","enum":Self::NAMES,"description":"Key to press."})
    }

    pub(crate) const fn deletes(self) -> bool {
        matches!(self, Self::Backspace | Self::Delete)
    }

    pub(crate) fn field_refusal(
        self,
        record: &NonTypeClassificationRecord,
    ) -> Option<&'static str> {
        if self.deletes() {
            crate::classification::type_field_reason(record)
                .filter(|reason| matches!(*reason, "credential_field" | "payment_field"))
        } else {
            None
        }
    }

    pub(crate) fn policy(
        self,
        record: &NonTypeClassificationRecord,
    ) -> Result<KeyPolicy<'_>, AuthorizationError> {
        let mut policy = KeyPolicy {
            severity: Action::Click.floor(),
            hazards: BTreeSet::new(),
            destinations: [None; 2],
        };
        if self != Self::Enter {
            return Ok(policy);
        }
        for (index, record) in [
            Some(record),
            record
                .implicit_submit
                .as_ref()
                .map(|submit| submit.as_ref().map(|submit| submit.activation.as_ref()))
                .transpose()
                .map_err(|_| AuthorizationError::SeverityUnclassifiable)?,
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(record) = record {
                let (severity, _) =
                    authorization::computed_required_severity(Action::Click, Some(record))?;
                policy.severity = if index == 0 && severity.tier == authorization::OBSERVE {
                    severity
                } else {
                    policy.severity.maximum(severity)
                };
                policy
                    .hazards
                    .extend(authorization::target_hazards(Action::Click, Some(record))?);
                policy.destinations[index] = record.activation_destination_origin.as_deref();
            }
        }
        Ok(policy)
    }

    pub(crate) fn matches_classification(
        self,
        expected: &NonTypeClassificationRecord,
        live: &NonTypeClassificationRecord,
    ) -> bool {
        expected == live
            && (self != Self::Enter || expected.implicit_submit == live.implicit_submit)
            && self.field_refusal(live).is_none()
    }

    pub(crate) fn event(self, down: bool) -> Value {
        let (key, code, vk) = self.cdp_fields();
        let mut params = json!({
            "type": if down { "keyDown" } else { "keyUp" },
            "key":key,"code":code,"windowsVirtualKeyCode":vk,
        });
        if self == Self::ShiftTab {
            params["modifiers"] = json!(8); // The Shift bit in the Chrome DevTools Protocol's modifier mask.
        }
        if down && self == Self::Enter {
            // A Return character triggers the browser's native Enter default action.
            params["text"] = json!("\r");
        }
        params
    }
}

pub(crate) struct KeyPolicy<'a> {
    pub(crate) severity: Severity,
    pub(crate) hazards: BTreeSet<HazardClass>,
    pub(crate) destinations: [Option<&'a str>; 2],
}

#[derive(Clone)]
pub struct KeyTarget {
    pub(crate) key: Key,
    pub(crate) node: crate::snapshot_store::BackendNodeIdentity,
    pub(crate) origin: String,
    pub(crate) expected: NonTypeClassificationRecord,
}
