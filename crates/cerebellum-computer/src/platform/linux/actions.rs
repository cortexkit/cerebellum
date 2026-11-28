use crate::app_state::source::{
    AppStateReadError, AppStateSource, ElementActionError, ElementFacts, ElementReadError,
    RunningApp, TextAttribute, WindowMark,
};

use super::*;

fn action_error(reason: &'static str) -> ElementActionError {
    ElementActionError::PlatformRefused(reason)
}

fn post_result(result: Result<bool, Error>) -> Result<(), ElementActionError> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(ElementActionError::Failed),
        Err(Error::Timeout | Error::Unreadable) => Err(ElementActionError::Indeterminate),
        Err(Error::Stale) => Err(action_error(STALE)),
    }
}

fn byte_offset(text: &str, character: i32) -> Option<usize> {
    let offset = usize::try_from(character).ok()?;
    text.char_indices()
        .map(|(index, _)| index)
        .chain([text.len()])
        .nth(offset)
}

fn press_index(actions: &[(String, String, String)]) -> Option<i32> {
    let mut choices = actions.iter().enumerate().filter(|(_, (name, _, _))| {
        matches!(name.as_str(), "click" | "press" | "activate" | "toggle")
    });
    let (index, _) = choices.next()?;
    if choices.next().is_some() {
        return None;
    }
    i32::try_from(index).ok()
}

impl Source {
    pub fn action_floor(&self, element: &ElementHandle, writing: bool) -> Result<(), &'static str> {
        let deadline = Instant::now() + QUERY_LIMIT;
        let (token, open) = self.resolve_token(element, deadline)?;
        // Keep refusing an element already read as a password or payment
        // field. A previously ordinary role or attribute set must be re-read.
        if token.raw_role.as_ref().is_some_and(tree::password)
            || token.attributes.as_ref().is_some_and(tree::payment)
        {
            return Err("secure_field_focused");
        }
        atspi::bounded(deadline, async {
            Ok(tree::floor(&open, &token.object, writing).await)
        })
        .map_err(|error| {
            if error == Error::Stale {
                STALE
            } else {
                "focus_unreadable"
            }
        })??;
        self.same_epoch(open.live.epoch)
    }

    fn get<T>(
        &self,
        element: &ElementHandle,
        read: impl for<'a> FnOnce(
            &'a Open,
            &'a Object,
        ) -> Pin<Box<dyn Future<Output = Result<T, Error>> + 'a>>,
    ) -> Result<T, ElementActionError> {
        let deadline = Instant::now() + QUERY_LIMIT;
        let (token, open) = self
            .resolve_token(element, deadline)
            .map_err(action_error)?;
        let value = atspi::bounded(deadline, read(&open, &token.object))
            .map_err(|error| action_error(reason(error)))?;
        self.same_epoch(open.live.epoch).map_err(action_error)?;
        Ok(value)
    }
}

impl AppStateSource for Source {
    fn semantic_action_floor(
        &self,
        element: &ElementHandle,
        writing: bool,
    ) -> Result<(), &'static str> {
        self.action_floor(element, writing)
    }

    fn running_apps(&self) -> Result<Vec<RunningApp>, AppStateReadError> {
        let apps = self
            .inventory()
            .map_err(|_| AppStateReadError::Unreadable)?;
        Ok(apps
            .into_iter()
            .filter_map(|app| {
                let grant = app.grant?;
                Some(RunningApp {
                    name: app.name,
                    bundle_identity: grant.bundle_identity,
                    pid: grant.pid,
                    frontmost: false,
                })
            })
            .collect())
    }

    fn read_app_state(
        &self,
        target: &ProcessGrant,
        bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        self.read_tree(target, None, bounds)
            .map_err(|reason| match reason {
                STALE => AppStateReadError::TargetGone,
                _ => AppStateReadError::Unreadable,
            })
    }

    fn read_element_state(
        &self,
        target: &ProcessGrant,
        element: &ElementHandle,
        bounds: ReadBounds,
        _expand_menus: bool,
    ) -> Result<RawAppState, ElementReadError> {
        self.read_tree(target, Some(element), bounds)
            .map_err(|reason| match reason {
                STALE => ElementReadError::Gone,
                _ => ElementReadError::Unreadable,
            })
    }

    fn element_facts(&self, element: &ElementHandle) -> Result<ElementFacts, ElementActionError> {
        let pid = Self::token_grant(element).ok_or(action_error(STALE))?.pid;
        self.get(element, |open, object| {
            Box::pin(async move {
                let bus = &open.live.bus;
                let raw = bus.role(object).await?;
                let interfaces = bus.interfaces(object).await?;
                let bits = bus.state(object).await?;
                let editable = tree::editable(&bits, &interfaces);
                let actionable = tree::has(&interfaces, "Action")
                    && press_index(&bus.actions(object).await?).is_some();
                Ok(ElementFacts {
                    pid: Some(pid),
                    role: Some(
                        if *object == open.root {
                            "AXApplication"
                        } else {
                            tree::role(&raw)
                        }
                        .to_owned(),
                    ),
                    title: bus.name(object).await.ok(),
                    actions: if actionable {
                        vec!["AXPress".into()]
                    } else {
                        Vec::new()
                    },
                    value_settable: editable,
                    selected_text_settable: editable && tree::has(&interfaces, "Text"),
                    subrole: None,
                })
            })
        })
    }

    fn element_parent(
        &self,
        element: &ElementHandle,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        let grant = Self::token_grant(element)
            .ok_or(action_error(STALE))?
            .clone();
        self.get(element, |open, object| {
            Box::pin(async move {
                if *object == open.root {
                    return Ok(None);
                }
                let Some(parent) = open.live.bus.parent(object).await? else {
                    return Ok(None);
                };
                if parent.peer != open.root.peer {
                    return Err(Error::Unreadable);
                }
                let raw_role = open.live.bus.role(&parent).await.ok();
                let attributes = open.live.bus.attributes(&parent).await.ok();
                Ok(Some(Arc::new(Token {
                    object: parent,
                    grant,
                    raw_role,
                    attributes,
                }) as ElementHandle))
            })
        })
    }

    fn element_enabled(&self, element: &ElementHandle) -> Option<bool> {
        self.get(element, |open, object| {
            Box::pin(async move { Ok(tree::enabled(&open.live.bus.state(object).await?)) })
        })
        .ok()
        .flatten()
    }

    fn press(&self, element: &ElementHandle) -> Result<(), ElementActionError> {
        let deadline = Instant::now() + QUERY_LIMIT;
        let (token, open) = self
            .resolve_token(element, deadline)
            .map_err(action_error)?;
        let actions = atspi::bounded(deadline, open.live.bus.actions(&token.object))
            .map_err(|e| action_error(reason(e)))?;
        let index = press_index(&actions).ok_or(ElementActionError::Unsupported)?;
        self.action_floor(element, false).map_err(action_error)?;
        self.verify(&token.grant).map_err(action_error)?;
        post_result(atspi::bounded(
            Instant::now() + QUERY_LIMIT,
            open.live.bus.action(&token.object, index),
        ))
    }

    fn text_value(&self, element: &ElementHandle) -> Result<Option<String>, ElementActionError> {
        self.action_floor(element, false).map_err(action_error)?;
        self.get(element, |open, object| {
            Box::pin(async move { open.live.bus.text(object).await.map(Some) })
        })
    }

    fn selected_range(
        &self,
        element: &ElementHandle,
    ) -> Result<Option<(usize, usize)>, ElementActionError> {
        self.action_floor(element, false).map_err(action_error)?;
        self.get(element, |open, object| {
            Box::pin(async move {
                let (start, end) = open.live.bus.selection(object).await?;
                let text = open.live.bus.text(object).await?;
                Ok(byte_offset(&text, start)
                    .zip(byte_offset(&text, end))
                    .and_then(|(start, end)| {
                        let selected = text.get(start..end)?;
                        Some((
                            text[..start].encode_utf16().count(),
                            selected.encode_utf16().count(),
                        ))
                    }))
            })
        })
    }

    fn write_text(
        &self,
        element: &ElementHandle,
        attribute: TextAttribute,
        text: &str,
    ) -> Result<(), ElementActionError> {
        self.action_floor(element, true).map_err(action_error)?;
        let deadline = Instant::now() + QUERY_LIMIT;
        let (token, open) = self
            .resolve_token(element, deadline)
            .map_err(action_error)?;
        let text = if attribute == TextAttribute::SelectedText {
            // Replace the selected characters in one setter. Separate delete
            // and insert calls could leave the field truncated on refusal.
            atspi::bounded(deadline, async {
                let (start, end) = open.live.bus.selection(&token.object).await?;
                let mut previous = open.live.bus.text(&token.object).await?;
                let (start, end) = byte_offset(&previous, start)
                    .zip(byte_offset(&previous, end))
                    .filter(|(a, b)| a <= b)
                    .ok_or(Error::Unreadable)?;
                previous.replace_range(start..end, text);
                Ok(previous)
            })
            .map_err(|error| action_error(reason(error)))?
        } else {
            text.to_owned()
        };
        self.action_floor(element, true).map_err(action_error)?;
        self.verify(&token.grant).map_err(action_error)?;
        post_result(atspi::bounded(
            Instant::now() + QUERY_LIMIT,
            open.live.bus.set_text(&token.object, &text),
        ))
    }

    fn focused_element(
        &self,
        target: &ProcessGrant,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        let state = self
            .read_tree(target, None, focus_bounds())
            .map_err(action_error)?;
        if !state.is_complete() {
            return Err(action_error("focus_unreadable"));
        }
        Ok(state.focused)
    }

    fn focused_window(
        &self,
        target: &ProcessGrant,
    ) -> Result<Option<WindowMark>, ElementActionError> {
        let state = self
            .read_tree(target, None, focus_bounds())
            .map_err(action_error)?;
        if !state.is_complete() || state.roots.iter().any(|node| node.role.is_none()) {
            return Err(action_error("focus_unreadable"));
        }
        let mut windows = state
            .roots
            .into_iter()
            .filter(|node| node.role.as_deref() == Some("AXWindow"));
        let first = windows.next();
        let chosen = match (first, windows.next()) {
            (Some(window), None) => Some(window),
            (Some(first), Some(second)) => {
                let mut active = [first, second]
                    .into_iter()
                    .chain(windows)
                    .filter(|node| node.focused_window);
                let current = active.next();
                if current.is_none() || active.next().is_some() {
                    return Err(action_error("focus_unreadable"));
                }
                current
            }
            (None, _) => None,
        };
        Ok(chosen.map(|node| WindowMark {
            handle: node.handle,
            title: node.title,
        }))
    }
}

fn focus_bounds() -> ReadBounds {
    ReadBounds {
        timeout: QUERY_LIMIT,
        ..ReadBounds::default()
    }
}
