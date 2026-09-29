//! How one element becomes one line of the state tree, and how a tree is
//! narrowed and bounded for a reply.
//!
//! The line grammar is fixed because two readers depend on it: an agent that
//! parses the tree, and the diff, which decides "changed" by comparing exactly
//! what a line says. Everything an application supplies appears only inside
//! the quoted label, escaped, so no title can forge a line, an id or a marker.

use super::source::{ElementValue, RawElement};

/// The longest label rendered, in characters. Labels are application text of
/// any length, and one long document value must not crowd every other
/// element out of the reply.
pub const MAX_LABEL_CHARS: usize = 200;

/// The largest `tree` rendered, in bytes. A reply carries more than the tree,
/// and every reply stays within 64 KiB; this leaves room for the rest.
pub const MAX_TREE_BYTES: usize = 56 * 1024;

/// What the literal in a secure field's value position says instead of the
/// value.
pub const VALUE_WITHHELD: &str = "[value withheld]";

/// What one element renders as, before an id is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementDescription {
    /// The raw accessibility role, for role filters that name it.
    pub role: Option<String>,
    /// The role in plain words, such as `text field`.
    pub role_words: String,
    /// The merged label, unescaped and untruncated.
    pub label: String,
    /// The markers that are true, in the fixed order.
    pub markers: Vec<&'static str>,
    /// A non-text value shown after the markers, such as a slider's position.
    pub value: Option<String>,
    /// Whether the element carries the secure-text subrole, so its value is
    /// never shown and the value position says [`VALUE_WITHHELD`].
    pub secure: bool,
}

impl ElementDescription {
    /// Everything a line says about the element apart from its id. Two reads
    /// whose signatures differ show a change; geometry is never part of it,
    /// so an element that only moved is unchanged.
    pub fn signature(&self) -> String {
        format!(
            "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
            self.role_words,
            self.label,
            self.markers.join(" "),
            self.value.as_deref().unwrap_or(""),
            self.secure
        )
    }
}

/// Whether the element is a secure text field, whose value is never shown.
///
/// The subrole is trustworthy when present and says nothing when absent: an
/// application can draw a password box without it, so its absence is no
/// guarantee that a field is not secret.
pub fn is_secure(element: &RawElement) -> bool {
    element.subrole.as_deref() == Some("AXSecureTextField")
        || element.role.as_deref() == Some("AXSecureTextField")
}

/// Describe one element.
pub fn describe(element: &RawElement) -> ElementDescription {
    let secure = is_secure(element);
    let string_value = match &element.value {
        ElementValue::Text(text) => Some(text.as_str()),
        _ => None,
    };
    // A secure field's value reaches the tree through neither attribute: an
    // application may mirror the typed secret into its value description as
    // readily as into its value.
    let candidates = if secure {
        [
            element.title.as_deref(),
            element.description.as_deref(),
            None,
            None,
        ]
    } else {
        [
            element.title.as_deref(),
            element.description.as_deref(),
            element.value_description.as_deref(),
            string_value,
        ]
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in candidates.into_iter().flatten().map(str::trim) {
        if !part.is_empty() && !parts.contains(&part) {
            parts.push(part);
        }
    }
    let label = parts.join(" | ");

    let toggle = is_toggle(element);
    let (checked, mixed, value) = if secure {
        (false, false, None)
    } else {
        match &element.value {
            ElementValue::Number(number) if toggle => (*number == 1.0, *number == 2.0, None),
            ElementValue::Boolean(on) if toggle => (*on, false, None),
            ElementValue::Number(number) => (false, false, Some(format_number(*number))),
            ElementValue::Boolean(on) => (false, false, Some(on.to_string())),
            ElementValue::Absent | ElementValue::Text(_) | ElementValue::Other => {
                (false, false, None)
            }
        }
    };

    let mut markers = Vec::new();
    if element.value_settable {
        markers.push("settable");
    }
    if element.selected {
        markers.push("selected");
    }
    if !element.enabled {
        markers.push("disabled");
    }
    if element.focused {
        markers.push("focused");
    }
    if element.expanded == Some(true) {
        markers.push("expanded");
    }
    if checked {
        markers.push("checked");
    }
    if mixed {
        markers.push("mixed");
    }

    ElementDescription {
        role: element.role.clone(),
        role_words: role_words(element),
        label,
        markers,
        value,
        secure,
    }
}

/// Whether the element is an on/off control, whose numeric value is a state
/// rather than a quantity.
fn is_toggle(element: &RawElement) -> bool {
    matches!(
        element.role.as_deref(),
        Some("AXCheckBox" | "AXRadioButton" | "AXToggle" | "AXSwitch")
    ) || matches!(element.subrole.as_deref(), Some("AXSwitch" | "AXToggle"))
}

fn format_number(number: f64) -> String {
    if !number.is_finite() {
        return "unknown".to_string();
    }
    if number.fract() == 0.0 && number.abs() < 1e15 {
        format!("{}", number as i64)
    } else {
        let text = format!("{number:.3}");
        text.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

/// The role in plain lower-case words: `AXTextField` reads `text field`.
///
/// A role is a string the application supplies, so only ASCII letters and
/// digits survive: a role carrying a quote, a newline or a plausible element
/// id would otherwise sit outside the quoted label, where escaping does not
/// reach.
fn role_words(element: &RawElement) -> String {
    let named = match element.subrole.as_deref() {
        Some("AXSecureTextField") => Some("AXSecureTextField"),
        Some("AXSearchField") => Some("AXSearchField"),
        Some("AXDialog" | "AXSystemDialog") => Some("AXDialog"),
        // A window's own controls carry no title or description; only the
        // subrole tells the close button from minimize and zoom, so without
        // it all three read as a bare `button` and none can be chosen.
        Some(
            subrole
            @ ("AXCloseButton" | "AXMinimizeButton" | "AXZoomButton" | "AXFullScreenButton"),
        ) => Some(subrole),
        _ => None,
    };
    let Some(role) = named.or(element.role.as_deref()) else {
        return "element".to_string();
    };
    let role = role.strip_prefix("AX").unwrap_or(role);
    let mut words = String::new();
    let mut previous_lower = false;
    for character in role.chars().filter(char::is_ascii_alphanumeric) {
        if character.is_ascii_uppercase() && previous_lower {
            words.push(' ');
        }
        previous_lower = character.is_ascii_lowercase() || character.is_ascii_digit();
        words.push(character.to_ascii_lowercase());
    }
    if words.is_empty() {
        "element".to_string()
    } else {
        words
    }
}

/// Escape label text so it cannot leave its quotes or its line.
///
/// Backslash and quote are escaped so the closing quote is always the real
/// one; newline, carriage return and tab by name; every other control
/// character, and the Unicode line and paragraph separators, as `\u{..}`.
/// A hostile title carrying a newline and something shaped like an element
/// id therefore stays inside one element's label.
pub fn escape_label(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') => {
                escaped.push_str(&format!("\\u{{{:x}}}", u32::from(character)));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

/// The label as a line shows it: at most [`MAX_LABEL_CHARS`] characters of
/// the original, then escaped. Truncated before escaping, so a cut can never
/// split an escape and leave a backslash against the closing quote.
fn rendered_label(label: &str) -> (String, bool) {
    if label.chars().count() > MAX_LABEL_CHARS {
        let cut: String = label.chars().take(MAX_LABEL_CHARS).collect();
        (format!("{}…", escape_label(&cut)), true)
    } else {
        (escape_label(label), false)
    }
}

/// The session-ending menu titles, normalised. Prefixes, so "Log Out Jane
/// Appleseed…" and "Force Quit Safari" match.
const SESSION_ENDING_PREFIXES: [&str; 7] = [
    "log out",
    "restart",
    "shut down",
    "force quit",
    "lock screen",
    "sleep",
    "empty trash",
];

/// Whether a menu title names an item that ends or suspends the person's
/// session, or empties the Trash.
///
/// The title is trimmed, runs of whitespace become one space, a trailing
/// ellipsis (`…` or `...`) goes, and ASCII letters are folded to lower case.
/// The Kelvin sign is folded to `k` because canonical normalisation maps it
/// to that letter, so "Loc\u{212A} Screen" is the same title to a reader and
/// must be to this check. Only English titles match; the Apple menu, where
/// most of these live, is matched by position instead, so its items are
/// caught whatever language names them.
pub fn is_session_ending_title(title: &str) -> bool {
    let mut normalised = String::with_capacity(title.len());
    let mut pending_space = false;
    for character in title.trim().chars() {
        if character.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !normalised.is_empty() {
            normalised.push(' ');
        }
        pending_space = false;
        let character = if character == '\u{212A}' {
            'k'
        } else {
            character
        };
        normalised.push(character.to_ascii_lowercase());
    }
    let normalised = normalised
        .strip_suffix('…')
        .or_else(|| normalised.strip_suffix("..."))
        .unwrap_or(&normalised)
        .trim_end();
    SESSION_ENDING_PREFIXES
        .iter()
        .any(|prefix| normalised.starts_with(prefix))
}

/// Whether an element's own title makes it a session-ending menu item.
pub fn is_session_ending_item(element: &RawElement) -> bool {
    matches!(
        element.role.as_deref(),
        Some("AXMenuItem" | "AXMenuBarItem")
    ) && element
        .title
        .as_deref()
        .is_some_and(is_session_ending_title)
}

/// One element of a read, as the element map numbered it.
#[derive(Debug, Clone)]
pub struct ObservedNode {
    /// `None` when the element map was full and the element went unnumbered.
    pub element_id: Option<String>,
    pub description: ElementDescription,
    /// Session-ending menu items, and everything beneath them. Never
    /// rendered.
    pub hazard: bool,
    pub children: Vec<ObservedNode>,
}

/// Why a reply's tree is shorter than the application's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncationReason {
    ElementCapReached,
    LabelTruncated,
}

impl TruncationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ElementCapReached => "element_cap_reached",
            Self::LabelTruncated => "label_truncated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncation {
    pub reason: TruncationReason,
    pub omitted_elements: usize,
}

/// What a read asks to see.
#[derive(Debug, Clone, Copy, Default)]
pub struct RenderFilter<'a> {
    /// Keep elements with any of these roles, named as the raw role
    /// (`AXButton`), without its prefix (`Button`) or in words (`button`),
    /// in any case.
    pub roles: &'a [String],
    /// Keep elements whose rendered text contains this, in any case.
    pub text: Option<&'a str>,
    /// Keep only this element and what lies beneath it.
    pub subtree: Option<&'a str>,
}

impl RenderFilter<'_> {
    fn narrows(&self) -> bool {
        !self.roles.is_empty() || self.text.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedTree {
    pub tree: String,
    pub truncation: Option<Truncation>,
    /// Whether the requested subtree element was in the read.
    pub subtree_found: bool,
}

fn role_matches(description: &ElementDescription, roles: &[String]) -> bool {
    if roles.is_empty() {
        return true;
    }
    let raw = description.role.as_deref().unwrap_or("");
    let bare = raw.strip_prefix("AX").unwrap_or(raw);
    roles.iter().any(|wanted| {
        let wanted = wanted.trim();
        wanted.eq_ignore_ascii_case(raw)
            || wanted.eq_ignore_ascii_case(bare)
            || wanted.eq_ignore_ascii_case(&description.role_words)
            || wanted
                .replace(' ', "")
                .eq_ignore_ascii_case(&description.role_words.replace(' ', ""))
    })
}

/// A text filter matches only what the tree shows: the label as rendered and,
/// for a secure field, the withheld marker. Never a secure field's value, so
/// a filter cannot confirm a secret the tree withholds.
fn text_matches(description: &ElementDescription, text: Option<&str>) -> bool {
    let Some(text) = text else {
        return true;
    };
    let wanted = text.to_lowercase();
    let (label, _) = rendered_label(&description.label);
    label.to_lowercase().contains(&wanted)
        || (description.secure && VALUE_WITHHELD.contains(&wanted))
}

fn line(depth: usize, element_id: &str, description: &ElementDescription) -> (String, bool) {
    let (label, truncated) = rendered_label(&description.label);
    let mut line = format!(
        "{}{} {} \"{}\"",
        "  ".repeat(depth),
        element_id,
        description.role_words,
        label
    );
    if !description.markers.is_empty() {
        line.push_str(&format!(" [{}]", description.markers.join(" ")));
    }
    if description.secure {
        line.push_str(&format!(" value={VALUE_WITHHELD}"));
    } else if let Some(value) = &description.value {
        line.push_str(&format!(" value={value}"));
    }
    (line, truncated)
}

/// Decide, for every node, whether its line is shown. A node is shown when it
/// matches inside the requested scope, or when something beneath it is shown,
/// so a filtered tree keeps each match's ancestor path and still reads as a
/// tree.
fn mark_shown(
    node: &ObservedNode,
    filter: &RenderFilter<'_>,
    in_scope: bool,
    shown: &mut Vec<bool>,
    subtree_found: &mut bool,
) -> bool {
    let index = shown.len();
    shown.push(false);
    if node.hazard || node.element_id.is_none() {
        return false;
    }
    let is_subtree_root = filter.subtree.is_some() && node.element_id.as_deref() == filter.subtree;
    if is_subtree_root {
        *subtree_found = true;
    }
    let in_scope = in_scope || is_subtree_root;
    let mut any_child = false;
    for child in &node.children {
        any_child |= mark_shown(child, filter, in_scope, shown, subtree_found);
    }
    let matches = in_scope
        && (!filter.narrows()
            || (role_matches(&node.description, filter.roles)
                && text_matches(&node.description, filter.text)));
    let visible = matches || any_child;
    shown[index] = visible;
    visible
}

fn count_unnumbered(node: &ObservedNode) -> usize {
    if node.hazard {
        return 0;
    }
    usize::from(node.element_id.is_none())
        + node.children.iter().map(count_unnumbered).sum::<usize>()
}

struct Emitter {
    tree: String,
    omitted: usize,
    labels_truncated: bool,
}

fn emit(node: &ObservedNode, depth: usize, shown: &[bool], cursor: &mut usize, out: &mut Emitter) {
    let index = *cursor;
    *cursor += 1;
    if !shown[index] {
        skip(node, cursor);
        return;
    }
    let element_id = node
        .element_id
        .as_deref()
        .expect("only numbered elements are shown");
    let (text, truncated) = line(depth, element_id, &node.description);
    if out.tree.len() + text.len() + 1 > MAX_TREE_BYTES {
        out.omitted += 1;
    } else {
        out.tree.push_str(&text);
        out.tree.push('\n');
        out.labels_truncated |= truncated;
    }
    for child in &node.children {
        emit(child, depth + 1, shown, cursor, out);
    }
}

/// Advance past a subtree that is not shown, keeping the cursor aligned with
/// the order `mark_shown` visited nodes in.
fn skip(node: &ObservedNode, cursor: &mut usize) {
    if node.hazard || node.element_id.is_none() {
        return;
    }
    for child in &node.children {
        *cursor += 1;
        skip(child, cursor);
    }
}

/// Render an observed tree under a filter, within the reply's bounds.
pub fn render(roots: &[ObservedNode], filter: &RenderFilter<'_>) -> RenderedTree {
    let mut shown = Vec::new();
    let mut subtree_found = false;
    let whole_tree_in_scope = filter.subtree.is_none();
    for root in roots {
        mark_shown(
            root,
            filter,
            whole_tree_in_scope,
            &mut shown,
            &mut subtree_found,
        );
    }
    let mut out = Emitter {
        tree: String::new(),
        omitted: 0,
        labels_truncated: false,
    };
    let mut cursor = 0;
    for root in roots {
        emit(root, 0, &shown, &mut cursor, &mut out);
    }
    let unnumbered: usize = roots.iter().map(count_unnumbered).sum();
    let omitted = out.omitted + unnumbered;
    let truncation = if omitted > 0 {
        Some(Truncation {
            reason: TruncationReason::ElementCapReached,
            omitted_elements: omitted,
        })
    } else if out.labels_truncated {
        Some(Truncation {
            reason: TruncationReason::LabelTruncated,
            omitted_elements: 0,
        })
    } else {
        None
    };
    RenderedTree {
        tree: out.tree,
        truncation,
        subtree_found,
    }
}
