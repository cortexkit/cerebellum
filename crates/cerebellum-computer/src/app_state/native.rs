//! The macOS reader behind the application-state seam.

use std::any::Any;
use std::sync::Arc;

use cerebellum_macos::{
    read_app_state, AxAppStateBounds, AxAppStateError, AxRetainedElement, AxStateElement,
    AxStateValue,
};

use super::source::{
    AppStateReadError, AppStateSource, ElementHandle, ElementToken, ElementValue, RawAppState,
    RawElement, ReadBounds,
};
use crate::platform::native::{verify_grant, GrantVerification};
use crate::platform::ProcessGrant;

/// A retained macOS accessibility element as an element token.
#[derive(Debug)]
struct MacElementToken(AxRetainedElement);

impl ElementToken for MacElementToken {
    fn same_element(&self, other: &dyn ElementToken) -> bool {
        other
            .as_any()
            .downcast_ref::<Self>()
            .is_some_and(|other| self.0.same_element(&other.0))
    }

    fn identity_hash(&self) -> u64 {
        self.0.identity_hash()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn handle(element: AxRetainedElement) -> ElementHandle {
    Arc::new(MacElementToken(element))
}

fn convert(element: AxStateElement) -> RawElement {
    RawElement {
        handle: handle(element.element),
        role: element.role,
        subrole: element.subrole,
        title: element.title,
        description: element.description,
        value_description: element.value_description,
        value: match element.value {
            AxStateValue::Absent => ElementValue::Absent,
            AxStateValue::Text(text) => ElementValue::Text(text),
            AxStateValue::Boolean(flag) => ElementValue::Boolean(flag),
            AxStateValue::Number(number) => ElementValue::Number(number),
            AxStateValue::Other => ElementValue::Other,
        },
        value_settable: element.value_settable,
        selected: element.selected,
        enabled: element.enabled,
        focused: element.focused,
        expanded: element.expanded,
        children: element.children.into_iter().map(convert).collect(),
        unreadable_children: element.unreadable_children,
    }
}

/// Reads applications through the macOS accessibility API.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacAppStateSource;

impl AppStateSource for MacAppStateSource {
    /// Read the granted process, and only while it is still the granted
    /// process: a pid reused by another program after the grant was made is
    /// refused rather than read under the old grant.
    fn read_app_state(
        &self,
        target: &ProcessGrant,
        bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        match verify_grant(target.pid, target) {
            GrantVerification::Current => {}
            GrantVerification::TargetGone | GrantVerification::TargetReplaced => {
                return Err(AppStateReadError::TargetGone)
            }
            GrantVerification::TargetUnreadable | GrantVerification::DifferentProcess => {
                return Err(AppStateReadError::Unreadable)
            }
        }
        let state = read_app_state(
            target.pid,
            AxAppStateBounds {
                max_elements: bounds.max_elements,
                max_depth: bounds.max_depth,
                timeout: bounds.timeout,
            },
        )
        .map_err(|error| match error {
            AxAppStateError::NotPermitted => AppStateReadError::AccessibilityNotPermitted,
            AxAppStateError::ProcessGone => AppStateReadError::TargetGone,
            AxAppStateError::Unreadable { .. } => AppStateReadError::Unreadable,
        })?;
        Ok(RawAppState {
            roots: state.roots.into_iter().map(convert).collect(),
            focused: state.focused.map(handle),
            unreadable_subtrees: state.unreadable_subtrees,
            read_bound_reached: state.bound_reached,
        })
    }
}
