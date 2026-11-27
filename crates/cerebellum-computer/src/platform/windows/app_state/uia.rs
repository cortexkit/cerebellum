use super::{
    contains, same_binding, BoundWindow, Element, ElementKey, Fingerprint, ReadError, ReadResult,
};
use crate::app_state::source::{ElementFacts, ElementHandle, ElementValue, RawElement};
use cerebellum_windows::{
    root_window_number, window_owner, RetainedProcessHandle, ScopedUia, UiaElementRef, UiaPatterns,
};
use std::sync::Arc;

const MAX_PATH: usize = 64;
const MENU_BAR: i32 = 50010;
const MENU_ITEM: i32 = 50011;

pub(super) fn role(control: i32, password: bool, root: bool, menu_bar_item: bool) -> String {
    if password {
        return "AXSecureTextField".into();
    }
    if root {
        return "AXWindow".into();
    }
    match control {
        50000 => "AXButton",
        50002 => "AXCheckBox",
        50003 => "AXComboBox",
        50004 => "AXTextField",
        50009 => "AXMenu",
        MENU_BAR => "AXMenuBar",
        MENU_ITEM if menu_bar_item => "AXMenuBarItem",
        MENU_ITEM => "AXMenuItem",
        50013 => "AXRadioButton",
        50030 => "AXTextArea",
        50032 => "AXWindow",
        _ => return format!("uia_control_type:{control}"),
    }
    .into()
}

fn can_press(patterns: UiaPatterns) -> bool {
    patterns.invoke || patterns.toggle || patterns.selection_item || patterns.expand_collapse
}

#[derive(Debug)]
pub(super) struct Node {
    pub token: Element,
    pub role: String,
}

impl Node {
    fn hazard(&self) -> bool {
        crate::app_state::pointer_sensitivity::hazardous_role_title(
            Some(&self.role),
            Some(&self.token.name),
            true,
        )
    }
    pub fn handle(self) -> ElementHandle {
        Arc::new(self.token)
    }
}

pub(super) struct UiWindow<'a> {
    uia: &'a ScopedUia,
    process: &'a RetainedProcessHandle,
    pid: u32,
    generation: u64,
    window: &'a BoundWindow,
    root: UiaElementRef,
}

impl<'a> UiWindow<'a> {
    pub fn new(
        uia: &'a ScopedUia,
        process: &'a RetainedProcessHandle,
        pid: u32,
        generation: u64,
        window: &'a BoundWindow,
    ) -> ReadResult<Self> {
        same_binding(process, pid, window)?;
        let root = uia.at_window(window.content())?;
        let scope = Self {
            uia,
            process,
            pid,
            generation,
            window,
            root,
        };
        scope.contained(&scope.root)?;
        Ok(scope)
    }

    pub fn root(&self) -> &UiaElementRef {
        &self.root
    }

    pub fn confirm(&self) -> ReadResult<()> {
        same_binding(self.process, self.pid, self.window)
    }

    fn contained(&self, element: &UiaElementRef) -> ReadResult<()> {
        if self.uia.pid(element)? != self.pid {
            return Err(ReadError::Unreadable);
        }
        if let Some(hwnd) = self.uia.native_window(element)? {
            if root_window_number(hwnd) != Some(self.window.root.number)
                || !window_owner(hwnd).is_ok_and(|(pid, _)| pid == self.pid)
            {
                return Err(ReadError::Unreadable);
            }
        }
        Ok(())
    }

    fn fingerprint(&self, element: &UiaElementRef) -> ReadResult<Fingerprint> {
        let control_type = self.uia.control_type(element)?;
        if control_type <= 0 {
            return Err(ReadError::Unreadable);
        }
        Ok(Fingerprint {
            control_type,
            automation_id: self.uia.automation_id(element)?,
            class_name: self.uia.class_name(element)?,
        })
    }

    pub fn node(&self, element: &UiaElementRef) -> ReadResult<Node> {
        self.contained(element)?;
        let runtime_id = self.uia.runtime_id(element)?.ok_or(ReadError::Gone)?;
        let fingerprint = self.fingerprint(element)?;
        let is_root = self.uia.same(&self.root, element)?;
        let menu_bar_item = if !is_root && fingerprint.control_type == MENU_ITEM {
            let parent = self.uia.parent(element)?.ok_or(ReadError::Unreadable)?;
            self.contained(&parent)?;
            self.uia.control_type(&parent)? == MENU_BAR
        } else {
            false
        };
        let role = role(
            fingerprint.control_type,
            self.uia.password(element)?,
            is_root,
            menu_bar_item,
        );
        Ok(Node {
            role,
            token: Element {
                key: ElementKey {
                    pid: self.pid,
                    generation: self.generation,
                    hwnd: self.window.root.number,
                    runtime_id,
                    fingerprint,
                },
                proof: self.window.proof.clone(),
                name: self.uia.name(element)?,
            },
        })
    }

    pub fn facts(&self, element: &UiaElementRef) -> ReadResult<ElementFacts> {
        let node = self.node(element)?;
        let patterns = self.uia.patterns(element)?;
        Ok(ElementFacts {
            pid: Some(self.pid),
            role: Some(node.role),
            title: Some(node.token.name),
            actions: if can_press(patterns) {
                vec!["AXPress".into()]
            } else {
                Vec::new()
            },
            value_settable: patterns.value_read_only == Some(false),
            ..Default::default()
        })
    }

    pub fn enabled(&self, element: &UiaElementRef) -> ReadResult<bool> {
        Ok(self.uia.enabled(element)?)
    }

    pub fn parent(&self, element: &UiaElementRef) -> ReadResult<Option<ElementHandle>> {
        if self.uia.same(element, &self.root)? {
            return Ok(None);
        }
        let parent = self.uia.parent(element)?.ok_or(ReadError::Unreadable)?;
        Ok(Some(self.node(&parent)?.handle()))
    }

    fn safe_path(&self, element: &UiaElementRef) -> ReadResult<bool> {
        if self.node(element)?.hazard() {
            return Ok(false);
        }
        if self.uia.same(element, &self.root)? {
            return Ok(true);
        }
        let mut current = self.uia.parent(element)?;
        for _ in 0..MAX_PATH {
            let parent = current.ok_or(ReadError::Unreadable)?;
            if self.node(&parent)?.hazard() {
                return Ok(false);
            }
            if self.uia.same(&parent, &self.root)? {
                return Ok(true);
            }
            current = self.uia.parent(&parent)?;
        }
        Err(ReadError::Bound)
    }

    pub fn value(&self, element: &UiaElementRef) -> ReadResult<Option<String>> {
        self.confirm()?;
        if !self.safe_path(element)? {
            return Err(ReadError::Unsupported);
        }
        Ok(self.uia.current_value(element)?)
    }

    pub fn selected_range(&self, element: &UiaElementRef) -> ReadResult<Option<(usize, usize)>> {
        self.confirm()?;
        if !self.safe_path(element)? {
            return Err(ReadError::Unsupported);
        }
        Ok(self.uia.text_selection(element)?)
    }

    pub fn focused(&self, native: Option<u32>) -> ReadResult<Option<ElementHandle>> {
        let Some(hwnd) = native else { return Ok(None) };
        if !window_owner(hwnd).is_ok_and(|(pid, _)| pid == self.pid)
            || root_window_number(hwnd) != Some(self.window.root.number)
        {
            return Err(ReadError::Unreadable);
        }
        let found = match self.uia.focused()? {
            Some(focused) if self.uia.native_window(&focused)? == Some(hwnd) => focused,
            _ => self.uia.at_window(hwnd)?,
        };
        if self.uia.native_window(&found)? != Some(hwnd) {
            return Err(ReadError::Unreadable);
        }
        let node = self.node(&found)?;
        self.find(&node.token.key)?;
        let thread = self.window.proof.content_window_and_thread().1;
        let now =
            cerebellum_windows::gui_thread_windows(thread).map_err(|_| ReadError::Unreadable)?;
        if now.focus != native
            || !now.active.is_some_and(|active| {
                active == self.window.root.number || active == self.window.content()
            })
        {
            return Err(ReadError::Unreadable);
        }
        Ok(Some(node.handle()))
    }

    pub fn find(&self, key: &ElementKey) -> ReadResult<UiaElementRef> {
        let mut budget = crate::app_state::source::READ_BOUND_ELEMENTS;
        self.search(
            self.uia.at_window(self.window.content())?,
            &key.runtime_id,
            MAX_PATH - 1,
            &mut budget,
        )?
        .ok_or(ReadError::Gone)
        .and_then(|element| {
            if self.fingerprint(&element)? != key.fingerprint {
                return Err(ReadError::Gone);
            }
            Ok(element)
        })
    }

    fn search(
        &self,
        element: UiaElementRef,
        wanted: &[i32],
        depth: usize,
        budget: &mut usize,
    ) -> ReadResult<Option<UiaElementRef>> {
        *budget = budget.checked_sub(1).ok_or(ReadError::Bound)?;
        self.contained(&element)?;
        if self
            .uia
            .runtime_id(&element)?
            .ok_or(ReadError::Unreadable)?
            == wanted
        {
            return Ok(Some(element));
        }
        let mut next = self.uia.child(&element)?;
        while let Some(child) = next {
            next = self.uia.sibling(&child)?;
            if let Some(found) = self.search(
                child,
                wanted,
                depth.checked_sub(1).ok_or(ReadError::Bound)?,
                budget,
            )? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    pub fn tree(
        &self,
        root: &UiaElementRef,
        depth: usize,
        count: &mut usize,
        values: bool,
    ) -> ReadResult<RawElement> {
        self.tree_inner(root, depth.min(MAX_PATH - 1), count, values)
    }

    fn tree_inner(
        &self,
        element: &UiaElementRef,
        depth: usize,
        count: &mut usize,
        values: bool,
    ) -> ReadResult<RawElement> {
        *count = count.checked_sub(1).ok_or(ReadError::Bound)?;
        let node = self.node(element)?;
        let enabled = self.enabled(element)?;
        let mut children = Vec::new();
        let mut unreadable_children = 0;
        let mut next = self.uia.child(element).or_else(|e| {
            recoverable(e.into()).map(|()| {
                unreadable_children += 1;
                None
            })
        })?;
        while let Some(child) = next {
            if depth == 0 || *count == 0 {
                unreadable_children += 1;
                break;
            }
            match self.tree_inner(&child, depth - 1, count, values) {
                Ok(child) => children.push(child),
                Err(error) => {
                    recoverable(error)?;
                    unreadable_children += 1;
                }
            }
            next = self.uia.sibling(&child).or_else(|e| {
                recoverable(e.into()).map(|()| {
                    unreadable_children += 1;
                    None
                })
            })?;
        }
        let candidate_value = values
            && matches!(
                node.role.as_str(),
                "AXTextField" | "AXTextArea" | "AXComboBox"
            );
        let value = if candidate_value {
            self.value(element)
                .ok()
                .flatten()
                .map_or(ElementValue::Absent, ElementValue::Text)
        } else {
            ElementValue::Absent
        };
        let value_settable = candidate_value
            && self
                .uia
                .patterns(element)
                .is_ok_and(|p| p.value_read_only == Some(false));
        let menu_visible =
            matches!(node.role.as_str(), "AXMenu" | "AXMenuBar") && !self.uia.offscreen(element)?;
        let title = (!node.token.name.is_empty()).then(|| node.token.name.clone());
        let role = Some(node.role.clone());
        Ok(RawElement {
            handle: node.handle(),
            role,
            title,
            value,
            value_settable,
            enabled,
            children,
            unreadable_children,
            menu_visible,
            subrole: None,
            description: None,
            value_description: None,
            selected: false,
            focused: false,
            main_window: false,
            focused_window: false,
            expanded: None,
            closed_menu_children: 0,
            url: None,
        })
    }

    pub fn hit(&self, point: (f64, f64)) -> ReadResult<Option<ElementHandle>> {
        let mut budget = crate::app_state::source::READ_BOUND_ELEMENTS;
        let Some(mut hit) = self.deepest(
            self.uia.at_window(self.window.content())?,
            point,
            MAX_PATH - 1,
            &mut budget,
        )?
        else {
            return Ok(None);
        };
        let deepest = self.node(&hit)?;
        for _ in 0..MAX_PATH {
            let node = self.node(&hit)?;
            if node.hazard() || can_press(self.uia.patterns(&hit)?) {
                return Ok(Some(node.handle()));
            }
            if self.uia.same(&hit, &self.root)? {
                return Ok(Some(deepest.handle()));
            }
            hit = self.uia.parent(&hit)?.ok_or(ReadError::Unreadable)?;
        }
        Err(ReadError::Bound)
    }

    fn deepest(
        &self,
        element: UiaElementRef,
        point: (f64, f64),
        depth: usize,
        budget: &mut usize,
    ) -> ReadResult<Option<UiaElementRef>> {
        *budget = budget.checked_sub(1).ok_or(ReadError::Bound)?;
        self.contained(&element)?;
        let at_point =
            !self.uia.offscreen(&element)? && contains(self.uia.rectangle(&element)?, point);
        let mut next = self.uia.child(&element)?;
        let mut hit = None;
        // A provider's parent bounding rectangle need not enclose its children.
        // Inspect each branch rather than pruning away a possible deeper hit.
        while let Some(child) = next {
            next = self.uia.sibling(&child)?;
            if let Some(found) = self.deepest(
                child,
                point,
                depth.checked_sub(1).ok_or(ReadError::Bound)?,
                budget,
            )? {
                if hit.replace(found).is_some() {
                    return Err(ReadError::Unreadable);
                }
            }
        }
        Ok(hit.or_else(|| at_point.then_some(element)))
    }
}

fn recoverable(error: ReadError) -> ReadResult<()> {
    match error {
        ReadError::Replaced | ReadError::Deadline | ReadError::Permission => Err(error),
        _ => Ok(()),
    }
}
