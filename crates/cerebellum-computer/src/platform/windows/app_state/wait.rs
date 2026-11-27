use super::*;
use crate::{
    dispatch::{
        post_condition::{ObservedElement, PostCondition},
        PredicatePoller,
    },
    platform::{AccessibilityElementName, AccessibilityReadbackAttribute},
};

/// Polls predicates across eligible windows; only a unique, non-sensitive
/// match may expose its value. Legacy Windows calls use their original reader.
pub struct WindowsAppStatePoller {
    source: WindowsAppStateSource,
    grant: ProcessGrant,
    started: Instant,
}

impl WindowsAppStatePoller {
    pub fn new(source: WindowsAppStateSource, grant: ProcessGrant) -> Self {
        Self {
            source,
            grant,
            started: Instant::now(),
        }
    }
}

impl PredicatePoller for WindowsAppStatePoller {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    fn read(
        &mut self,
        predicate: &PostCondition,
        deadline_ms: u32,
    ) -> Result<ObservedElement, String> {
        let timeout = Duration::from_millis(u64::from(deadline_ms));
        let end = Instant::now() + timeout;
        let bounds = ReadBounds {
            timeout,
            ..ReadBounds::default()
        };
        // Search reads only naming and structural facts. Even when the predicate
        // is about a value, only the unique matching element may reach its getter.
        let raw = self
            .source
            .read_forest(&self.grant, bounds, end, false)
            .map_err(read_reason)?;
        let key = predicate.element();
        let attribute = predicate.readback_attribute();
        let mut matches = Vec::new();
        for root in &raw.roots {
            collect_matches(root, key, &mut matches);
        }
        let mut observed = ObservedElement {
            present: !matches.is_empty(),
            focused: None,
            enabled: None,
            value: None,
            unreadable_subtrees: raw.unreadable_subtrees as u64 + u64::from(raw.read_bound_reached),
        };
        if attribute == AccessibilityReadbackAttribute::Presence
            || observed.unreadable_subtrees != 0
        {
            return Ok(observed);
        }
        let matching = match matches.as_slice() {
            [] => return Ok(observed),
            [matching] => *matching,
            _ => return Err("element_name_ambiguous".into()),
        };
        let key = key.clone();
        let (enabled, value) = self
            .source
            .with_element(&matching.handle, end, move |ui, element| {
                let node = ui.node(element)?;
                if !name_matches(&key, &node.token, Some(&node.role)) {
                    return Err(ReadError::Gone);
                }
                match attribute {
                    AccessibilityReadbackAttribute::Enabled => {
                        Ok((Some(ui.enabled(element)?), None))
                    }
                    AccessibilityReadbackAttribute::Value => Ok((
                        None,
                        Some(ui.value(element)?.ok_or(ReadError::Unsupported)?),
                    )),
                    _ => Ok((None, None)),
                }
            })
            .map_err(read_reason)?;
        observed.enabled = enabled;
        observed.value = value;
        if attribute == AccessibilityReadbackAttribute::Focused {
            let focus = focused_mark(&self.grant, true, end).map_err(read_reason)?;
            observed.focused = Some(
                focus
                    .and_then(|(_, element)| element)
                    .is_some_and(|focused| focused.same_element(matching.handle.as_ref())),
            );
        }
        Ok(observed)
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

fn name_matches(key: &AccessibilityElementName, element: &Element, role: Option<&str>) -> bool {
    match key {
        AccessibilityElementName::Identifier(id) => &element.key.fingerprint.automation_id == id,
        AccessibilityElementName::RoleAndTitle {
            role: wanted,
            title,
        } => {
            (role == Some(wanted.as_str())
                || wanted
                    .strip_prefix("uia_control_type:")
                    .and_then(|kind| kind.parse::<i32>().ok())
                    == Some(element.key.fingerprint.control_type))
                && &element.name == title
        }
    }
}

fn collect_matches<'a>(
    root: &'a RawElement,
    wanted: &AccessibilityElementName,
    result: &mut Vec<&'a RawElement>,
) {
    if element_token(&root.handle)
        .is_ok_and(|element| name_matches(wanted, element, root.role.as_deref()))
    {
        result.push(root);
    }
    for child in &root.children {
        collect_matches(child, wanted, result);
    }
}

fn read_reason(error: ReadError) -> String {
    match error {
        ReadError::Gone => "target_gone",
        ReadError::Replaced => "target_replaced",
        ReadError::Permission => "accessibility_permission_required",
        ReadError::NotInspectable => "target_not_inspectable",
        ReadError::Deadline => "read_deadline_exceeded",
        ReadError::Bound => "search_bound_exceeded",
        ReadError::Unsupported => "scoped_read_unsupported",
        ReadError::Unreadable => "accessibility_read_failed",
    }
    .into()
}
