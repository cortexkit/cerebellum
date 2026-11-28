use crate::app_state::source::ElementValue;

use super::*;

const ACTIVE: usize = 1;
const CHECKED: usize = 4;
const DEFUNCT: usize = 6;
const EDITABLE: usize = 7;
pub(super) const ENABLED: usize = 8;
const EXPANDABLE: usize = 9;
const EXPANDED: usize = 10;
pub(super) const FOCUSED: usize = 12;
const SENSITIVE: usize = 24;
const SELECTED: usize = 23;
const SHOWING: usize = 25;

pub(super) fn state(bits: &[u32], index: usize) -> Option<bool> {
    bits.get(index / 32)
        .map(|word| (word & (1 << (index % 32))) != 0)
}

pub(super) fn enabled(bits: &[u32]) -> Option<bool> {
    Some(state(bits, ENABLED)? && state(bits, SENSITIVE)?)
}

pub(super) fn editable(bits: &[u32], interfaces: &[String]) -> bool {
    state(bits, EDITABLE) == Some(true) && has(interfaces, "EditableText")
}

pub(super) fn has(interfaces: &[String], name: &str) -> bool {
    interfaces
        .iter()
        .any(|i| i.strip_prefix("org.a11y.atspi.") == Some(name))
}

pub(super) fn role(raw: &(u32, String)) -> &str {
    if password(raw) {
        return "AXSecureTextField";
    }
    // GTK4's GetRoleName returns a toolkit role name (for example "button"
    // or "text box"). GetRole carries the AT-SPI enum even in that case.
    match raw.0 {
        2 | 16 | 19 | 23 | 69 => return "AXWindow", // alert, dialog, file chooser, frame, window
        43 | 62 => return "AXButton",               // push button, toggle button
        61 | 79 => return "AXTextField",            // text, entry
        35 => return "AXMenuItem",
        7 => return "AXCheckBox",
        44 => return "AXRadioButton",
        _ => {}
    }
    match raw.1.as_str() {
        "frame" | "dialog" | "window" | "file chooser" | "alert" => "AXWindow",
        "push button" | "toggle button" => "AXButton",
        "text" | "entry" => "AXTextField",
        "menu item" => "AXMenuItem",
        "check box" => "AXCheckBox",
        "radio button" => "AXRadioButton",
        other => other,
    }
}

pub(super) fn password(raw: &(u32, String)) -> bool {
    // ATSPI_ROLE_PASSWORD_TEXT is independent of the toolkit's role string.
    raw.0 == 40 || raw.1 == "password text"
}

pub(super) fn payment(attributes: &Attributes) -> bool {
    attributes.get("autocomplete").is_some_and(|value| {
        value.split_whitespace().any(|token| {
            token
                .get(..3)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("cc-"))
                && token.len() > 3
        })
    })
}

pub(super) async fn floor(open: &Open, object: &Object, writing: bool) -> Result<(), &'static str> {
    let bus = &open.live.bus;
    let mut current = object.clone();
    let mut visited = HashSet::new();
    let mut web = false;
    for _ in 0..64 {
        if current.peer != open.root.peer || !visited.insert(current.clone()) {
            return Err("focus_unreadable");
        }
        let raw = bus.role(&current).await.map_err(floor_error)?;
        if password(&raw) {
            return Err("secure_field_focused");
        }
        if payment(&bus.attributes(&current).await.map_err(floor_error)?) {
            return Err("secure_field_focused");
        }
        web |= raw.1 == "document web";
        if current == open.root {
            return if writing && web {
                Err("web_content_needs_type")
            } else {
                Ok(())
            };
        }
        current = bus
            .parent(&current)
            .await
            .map_err(floor_error)?
            .ok_or("focus_unreadable")?;
    }
    Err("focus_unreadable")
}

fn floor_error(error: Error) -> &'static str {
    match error {
        Error::Stale => STALE,
        _ => "focus_unreadable",
    }
}

pub(super) async fn read(
    open: &Open,
    grant: &ProcessGrant,
    object: &Object,
    zoomed: bool,
    bounds: ReadBounds,
) -> Result<RawAppState, Error> {
    let roots = if zoomed {
        vec![Some(object.clone())]
    } else {
        open.live.bus.children(object).await?
    };
    let mut read = Reader {
        open,
        grant,
        bounds,
        visited: HashSet::new(),
        state: RawAppState {
            roots: Vec::new(),
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        },
    };
    for root in roots {
        if let Some(root) = read.node(root, 0).await? {
            read.state.roots.push(root);
        }
        if read.state.read_bound_reached {
            break;
        }
    }
    Ok(read.state)
}

struct Reader<'a> {
    open: &'a Open,
    grant: &'a ProcessGrant,
    bounds: ReadBounds,
    visited: HashSet<Object>,
    state: RawAppState,
}

impl Reader<'_> {
    fn node(&mut self, object: Option<Object>, depth: usize) -> NodeFuture<'_> {
        Box::pin(async move {
            if depth > self.bounds.max_depth || self.visited.len() >= self.bounds.max_elements {
                self.state.read_bound_reached = true;
                return Ok(None);
            }
            let Some(object) = object.filter(|object| {
                object.peer == self.open.root.peer && self.visited.insert(object.clone())
            }) else {
                self.state.unreadable_subtrees += 1;
                return Ok(None);
            };
            let bus = &self.open.live.bus;
            let bits = match bus.state(&object).await {
                Ok(bits) if state(&bits, DEFUNCT) == Some(false) => bits,
                _ if depth == 0 => return Err(Error::Unreadable),
                _ => {
                    self.state.unreadable_subtrees += 1;
                    return Ok(None);
                }
            };
            let raw_role = bus.role(&object).await.ok();
            let attributes = bus.attributes(&object).await.ok();
            let translated = raw_role.as_ref().map(role);
            let title = bus.name(&object).await.ok().filter(|name| !name.is_empty());
            let interfaces = bus.interfaces(&object).await.unwrap_or_default();
            let focused = state(&bits, FOCUSED) == Some(true);
            let window = translated == Some("AXWindow");
            let active = state(&bits, ACTIVE) == Some(true);
            let value =
                if has(&interfaces, "Text") && floor(self.open, &object, false).await.is_ok() {
                    bus.text(&object)
                        .await
                        .map_or(ElementValue::Absent, ElementValue::Text)
                } else if matches!(translated, Some("AXCheckBox" | "AXRadioButton")) {
                    state(&bits, CHECKED).map_or(ElementValue::Absent, ElementValue::Boolean)
                } else {
                    ElementValue::Absent
                };
            let role = translated.map(str::to_owned);
            let handle: ElementHandle = Arc::new(Token {
                object: object.clone(),
                grant: self.grant.clone(),
                raw_role,
                attributes,
            });
            if focused && self.state.focused.is_none() {
                self.state.focused = Some(handle.clone());
            }
            let mut children = Vec::new();
            let before = self.state.unreadable_subtrees;
            match bus.children(&object).await {
                Ok(references) => {
                    for child in references {
                        if let Some(child) = self.node(child, depth + 1).await? {
                            children.push(child);
                        }
                        if self.state.read_bound_reached {
                            break;
                        }
                    }
                }
                Err(_) => self.state.unreadable_subtrees += 1,
            }
            Ok(Some(RawElement {
                handle,
                role,
                title,
                subrole: None,
                description: None,
                value_description: None,
                value,
                value_settable: editable(&bits, &interfaces),
                selected: state(&bits, SELECTED) == Some(true),
                enabled: enabled(&bits).unwrap_or(true),
                focused,
                main_window: window && active,
                focused_window: window && active,
                expanded: (state(&bits, EXPANDABLE) == Some(true))
                    .then(|| state(&bits, EXPANDED))
                    .flatten(),
                menu_visible: state(&bits, SHOWING) == Some(true),
                closed_menu_children: 0,
                url: None,
                children,
                unreadable_children: self.state.unreadable_subtrees - before,
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atspi_roles_and_payment_tokens() {
        for (raw, translated) in [
            ("dialog", "AXWindow"),
            ("push button", "AXButton"),
            ("entry", "AXTextField"),
            ("password text", "AXSecureTextField"),
            ("menu item", "AXMenuItem"),
            ("check box", "AXCheckBox"),
            ("radio button", "AXRadioButton"),
            ("custom", "custom"),
        ] {
            assert_eq!(role(&(1, raw.into())), translated);
        }
        assert_eq!(role(&(40, "entry".into())), "AXSecureTextField");
        assert_eq!(role(&(43, "button".into())), "AXButton");
        assert_eq!(role(&(61, "text box".into())), "AXTextField");
        for (value, blocked) in [
            ("SECTION-A shipping CC-number", true),
            ("cc-csc\tusername", true),
            ("x-cc-number", false),
            ("cc", false),
        ] {
            assert_eq!(
                payment(&Attributes::from([("autocomplete".into(), value.into())])),
                blocked
            );
        }
    }
}
