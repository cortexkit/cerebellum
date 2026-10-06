//! The macOS reader behind the application-state seam.

use std::any::Any;
use std::sync::Arc;

use cerebellum_macos::{
    read_app_state, AxAppStateBounds, AxAppStateError, AxElementActionError, AxHitScope,
    AxRetainedElement, AxStateElement, AxStateValue, AxTextAttribute,
};

use super::source::{
    AppStateReadError, AppStateSource, ElementActionError, ElementFacts, ElementHandle,
    ElementToken, ElementValue, HitScope, RawAppState, RawElement, ReadBounds, RunningApp,
    TextAttribute, WindowMark,
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

/// The retained element behind a token, when the token is this reader's.
fn retained(element: &ElementHandle) -> Result<&AxRetainedElement, ElementActionError> {
    element
        .as_any()
        .downcast_ref::<MacElementToken>()
        .map(|token| &token.0)
        .ok_or(ElementActionError::Gone)
}

fn action_error(error: AxElementActionError) -> ElementActionError {
    match error {
        AxElementActionError::NotPermitted => ElementActionError::NotPermitted,
        AxElementActionError::ElementGone => ElementActionError::Gone,
        AxElementActionError::Unsupported => ElementActionError::Unsupported,
        AxElementActionError::Failed { .. } => ElementActionError::Failed,
    }
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
        url: element.url,
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

    fn element_facts(&self, element: &ElementHandle) -> Result<ElementFacts, ElementActionError> {
        let facts = cerebellum_macos::element_facts(retained(element)?).map_err(action_error)?;
        Ok(ElementFacts {
            pid: facts.pid,
            role: facts.role,
            subrole: facts.subrole,
            title: facts.title,
            actions: facts.actions,
            value_settable: facts.value_settable,
            selected_text_settable: facts.selected_text_settable,
        })
    }

    fn press(&self, element: &ElementHandle) -> Result<(), ElementActionError> {
        cerebellum_macos::press_element(retained(element)?).map_err(action_error)
    }

    fn text_value(&self, element: &ElementHandle) -> Result<Option<String>, ElementActionError> {
        cerebellum_macos::element_text_value(retained(element)?).map_err(action_error)
    }

    fn selected_range(
        &self,
        element: &ElementHandle,
    ) -> Result<Option<(usize, usize)>, ElementActionError> {
        cerebellum_macos::element_selected_range(retained(element)?).map_err(action_error)
    }

    fn write_text(
        &self,
        element: &ElementHandle,
        attribute: TextAttribute,
        text: &str,
    ) -> Result<(), ElementActionError> {
        let attribute = match attribute {
            TextAttribute::Value => AxTextAttribute::Value,
            TextAttribute::SelectedText => AxTextAttribute::SelectedText,
        };
        cerebellum_macos::write_element_text(retained(element)?, attribute, text)
            .map_err(action_error)
    }

    fn element_at(
        &self,
        scope: HitScope,
        point: (f64, f64),
    ) -> Result<Option<(ElementHandle, Option<u32>)>, ElementActionError> {
        let scope = match scope {
            HitScope::Application { pid } => AxHitScope::Application(pid),
            HitScope::SystemWide => AxHitScope::SystemWide,
        };
        Ok(
            cerebellum_macos::element_at_position(scope, point.0, point.1)
                .map_err(action_error)?
                .map(|(element, pid)| (handle(element), pid)),
        )
    }

    /// Read only while the process is still the granted one, for the same
    /// reason a state read is.
    fn focused_element(
        &self,
        target: &ProcessGrant,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        match verify_grant(target.pid, target) {
            GrantVerification::Current => {}
            GrantVerification::TargetGone | GrantVerification::TargetReplaced => {
                return Err(ElementActionError::Gone)
            }
            GrantVerification::TargetUnreadable | GrantVerification::DifferentProcess => {
                return Err(ElementActionError::Failed)
            }
        }
        Ok(cerebellum_macos::focused_element(target.pid)
            .map_err(action_error)?
            .map(handle))
    }

    fn frontmost_pid(&self) -> Option<u32> {
        cerebellum_macos::frontmost_process_id().and_then(|pid| u32::try_from(pid).ok())
    }

    /// Read only while the process is still the granted one, for the same
    /// reason a state read is.
    fn focused_window(
        &self,
        target: &ProcessGrant,
    ) -> Result<Option<WindowMark>, ElementActionError> {
        match verify_grant(target.pid, target) {
            GrantVerification::Current => {}
            GrantVerification::TargetGone | GrantVerification::TargetReplaced => {
                return Err(ElementActionError::Gone)
            }
            GrantVerification::TargetUnreadable | GrantVerification::DifferentProcess => {
                return Err(ElementActionError::Failed)
            }
        }
        Ok(cerebellum_macos::focused_window(target.pid)
            .map_err(action_error)?
            .map(|(window, title)| WindowMark {
                handle: handle(window),
                title,
            }))
    }

    fn hardware_input(
        &self,
        _target: &ProcessGrant,
    ) -> Result<(std::time::Instant, Option<std::time::Instant>), ElementActionError> {
        cerebellum_macos::SessionEventTap::hardware_input_snapshot()
            .ok_or(ElementActionError::Failed)
    }

    /// Sender-blind HID age, retained for posting bookkeeping. It cannot
    /// identify the person because other processes' synthetic events count too.
    fn time_since_last_input(&self) -> Option<std::time::Duration> {
        let seconds = cerebellum_macos::seconds_since_last_deliberate_input(
            cerebellum_macos::EventSourceStateTable::HidSystem,
        );
        std::time::Duration::try_from_secs_f64(seconds).ok()
    }

    /// Regular applications only: an application whose policy could not be
    /// read is left out rather than guessed at, because the list is what a
    /// name given as a target is matched against.
    fn running_apps(&self) -> Result<Vec<RunningApp>, AppStateReadError> {
        let applications = cerebellum_macos::running_applications(RUNNING_APPS_TIMEOUT)
            .map_err(|_| AppStateReadError::Unreadable)?;
        let frontmost = self.frontmost_pid();
        let mut apps: Vec<RunningApp> = applications
            .into_iter()
            .filter(|application| {
                application.regular == Some(true) && !application.bundle_identifier.is_empty()
            })
            .map(|application| RunningApp {
                frontmost: frontmost == Some(application.pid),
                name: application.name,
                bundle_identity: application.bundle_identifier,
                pid: application.pid,
            })
            .collect();
        apps.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then(left.pid.cmp(&right.pid))
        });
        Ok(apps)
    }
}

/// How long the window server may take to list the running applications:
/// the `computer.list_apps` row declares the same 1000 ms deadline.
const RUNNING_APPS_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(1000);
