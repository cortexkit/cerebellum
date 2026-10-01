//! How a read of an application becomes the plain text a caller reads.
//!
//! One element is one line, indented two spaces per depth:
//!
//! ```text
//! <id> <role words>[ (<states>)] <label>[, Value: <value>]
//! ```
//!
//! for example `389 tab (selected) AI Developer Tools, Value: 1` or
//! `558 link 17 seconds ago, Value: x.com/polygres/status/2105766657956446225`.
//!
//! Application text never leaves its line: every line break in a label or a
//! value becomes " · " and every other control character a space, so no
//! title can start a line of its own and pass itself off as another element.
//!
//! The same grammar serves four views of one read, so a caller learns it once:
//! an outline of the window (the default), one subtree in full (`zoom`), the
//! matches of a filter with the labelled ancestors that place them, and the
//! diff an action left behind. Every view leaves out unlabelled wrapper
//! groups and text that repeats its parent's label (see [`build`]), and
//! never an element a caller could press, type into or set.

use std::collections::HashSet;

use super::session::StateDiff;
use super::source::{ElementValue, RawElement};

/// The longest label or value rendered, in characters. Labels are
/// application text of any length, and one long document value must not
/// crowd every other element out of the reply.
pub const MAX_LABEL_CHARS: usize = 200;

/// The largest rendered state, in bytes. A reply carries more than the state,
/// and every reply stays within 64 KiB; this leaves room for the rest.
pub const MAX_STATE_TEXT_BYTES: usize = 56 * 1024;

/// A region of the outline whose full rendering is at most this many bytes is
/// printed in full instead of as one summary line.
///
/// 600 bytes is about eight lines, or 150 tokens: a dialog's buttons, a
/// toolbar, a short navigation bar or a settings group fits, so the caller
/// can act on it without a second read, while a list of dozens of rows (some
/// kilobytes) is summarised and costs one line until it is zoomed.
pub const INLINE_REGION_BYTES: usize = 600;

/// The most bytes an outline prints before it stops and points at `zoom`
/// and the filters. An application with no landmarks at all could otherwise
/// put its whole window into the outline.
pub const MAX_OUTLINE_BYTES: usize = 6 * 1024;

/// The largest diff text an action reply carries, in bytes. Past it the diff
/// says how much it left out, and the caller reads the state for the rest.
/// One tab switch once added 1,492 elements; listing them all would bury the
/// few lines that say what the action did, while a read's outline shows the
/// new state in a fraction of the size.
pub const MAX_DIFF_BYTES: usize = 4 * 1024;

/// Siblings that repeat the same role and label shape are listed one by one
/// up to this many; a longer run is one line, `<count> <role>s, like "…"`.
pub const REPEAT_RUN_LIMIT: usize = 3;

/// What `zoom` names to print the menu bar, which the outline leaves out.
pub const MENU_BAR_ZOOM: &str = "menubar";

/// What the literal in a secure field's value position says instead of the
/// value.
pub const VALUE_WITHHELD: &str = "[value withheld]";

/// What a line break inside application text becomes.
const LINE_BREAK: &str = " · ";

/// A region summary lists its members' labels when it has at most this many.
const SUMMARY_LABELS_LISTED: usize = 8;

/// How much of each label a region summary quotes.
const SUMMARY_LABEL_CHARS: usize = 40;

/// How many levels of summarised regions the outline nests. Deeper regions
/// are reached by zooming into the innermost one shown. Two levels show a
/// timeline's posts under the timeline, without each post's parts as well.
const OUTLINE_NESTING: usize = 2;

/// What one element renders as, before an id is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementDescription {
    /// The raw accessibility role, for role filters that name it.
    pub role: Option<String>,
    /// The raw accessibility subrole, which tells landmarks and dialogs from
    /// plain groups.
    pub subrole: Option<String>,
    /// The role in plain words, such as `text field`.
    pub role_words: String,
    /// The merged label, as the application wrote it: not yet made one line
    /// or cut.
    pub label: String,
    /// The states that are true, in the fixed order.
    pub markers: Vec<&'static str>,
    /// What follows `, Value:`: a text input's text, a link's URL, a
    /// slider's position.
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

/// Whether the element takes typed text, so its string value is what was
/// typed rather than part of its name.
fn is_text_input(element: &RawElement) -> bool {
    matches!(
        element.role.as_deref(),
        Some("AXTextField" | "AXTextArea" | "AXComboBox" | "AXSecureTextField")
    ) || matches!(
        element.subrole.as_deref(),
        Some("AXSearchField" | "AXSecureTextField")
    )
}

/// Whether the element is a control whose value is set rather than typed.
fn is_value_control(element: &RawElement) -> bool {
    matches!(
        element.role.as_deref(),
        Some(
            "AXSlider"
                | "AXIncrementor"
                | "AXStepper"
                | "AXScrollBar"
                | "AXColorWell"
                | "AXDateField"
                | "AXTimeField"
                | "AXLevelIndicator"
                | "AXValueIndicator"
        )
    )
}

/// Describe one element.
pub fn describe(element: &RawElement) -> ElementDescription {
    let secure = is_secure(element);
    let text_input = is_text_input(element);
    let string_value = match &element.value {
        ElementValue::Text(text) => Some(text.as_str()),
        _ => None,
    };
    // A secure field's value reaches the line through neither attribute: an
    // application may mirror the typed secret into its value description as
    // readily as into its value. A text input's own text is its value, not
    // part of its name, so it goes after `Value:` like a link's URL.
    let candidates = [
        element.title.as_deref(),
        element.description.as_deref(),
        (!secure)
            .then_some(element.value_description.as_deref())
            .flatten(),
        (!secure && !text_input).then_some(string_value).flatten(),
    ];
    let mut parts: Vec<&str> = Vec::new();
    for part in candidates.into_iter().flatten().map(str::trim) {
        if !part.is_empty() && !parts.contains(&part) {
            parts.push(part);
        }
    }
    let label = parts.join(" | ");

    let toggle = is_toggle(element);
    let (checked, mixed, number) = if secure {
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
    let value = if secure {
        None
    } else if text_input {
        string_value
            .filter(|text| !text.trim().is_empty())
            .map(str::to_string)
    } else {
        // A link's or a web page's URL is its value, so a caller listing
        // links gets their targets from the same read.
        element.url.clone().or(number)
    };

    let mut markers = Vec::new();
    // Only an input or a value control is worth saying is settable: a group
    // or a row that reports a settable value cannot be typed into or slid,
    // and the marker on them is noise a caller learns to skip.
    if element.value_settable && (text_input || is_value_control(element)) {
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
        subrole: element.subrole.clone(),
        role_words: role_words(element),
        label,
        markers,
        value,
        secure,
    }
}

/// Whether the element is an on/off control, whose numeric value is a state
/// rather than a quantity.
///
/// A tab is a radio button to accessibility, but its on state is already
/// `selected`, so its number is shown as its value rather than as a second
/// state saying the same thing.
fn is_toggle(element: &RawElement) -> bool {
    if element.subrole.as_deref() == Some("AXTabButton") {
        return false;
    }
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
/// digits survive: a role carrying a newline or something shaped like an
/// element id would otherwise sit at the front of a line, where nothing
/// else marks where application text begins.
fn role_words(element: &RawElement) -> String {
    let named = match element.subrole.as_deref() {
        Some("AXSecureTextField") => Some("AXSecureTextField"),
        Some("AXSearchField") => Some("AXSearchField"),
        Some("AXDialog" | "AXSystemDialog" | "AXApplicationDialog") => Some("AXDialog"),
        // A window's own controls carry no title or description; only the
        // subrole tells the close button from minimize and zoom, so without
        // it all three read as a bare `button` and none can be chosen.
        Some(
            subrole
            @ ("AXCloseButton" | "AXMinimizeButton" | "AXZoomButton" | "AXFullScreenButton"),
        ) => Some(subrole),
        Some("AXTabButton") => Some("AXTab"),
        // Accessibility reports every web landmark with the group role; only
        // its subrole says which part of the page it is.
        Some("AXLandmarkNavigation") => Some("AXNavigation"),
        Some("AXLandmarkMain") => Some("AXMain"),
        Some("AXLandmarkRegion") => Some("AXRegion"),
        Some("AXLandmarkBanner") => Some("AXBanner"),
        Some("AXLandmarkSearch") => Some("AXSearch"),
        Some("AXLandmarkComplementary") => Some("AXComplementary"),
        Some("AXLandmarkContentInfo") => Some("AXContentInfo"),
        _ => None,
    };
    let role = match (named, element.role.as_deref()) {
        (Some(named), _) => named,
        // Static text is what most lines are; one short word keeps them short.
        (None, Some("AXStaticText")) => "AXText",
        (None, Some(role)) => role,
        (None, None) => return "element".to_string(),
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

/// Application text made into one line: every line break (newline, carriage
/// return, the Unicode line and paragraph separators) becomes " · ", every
/// other control character and run of whitespace one space, and the ends are
/// trimmed.
///
/// This is what keeps a hostile title from forging a line: whatever a label
/// carries, it cannot start a new line, so it cannot put an id at the front
/// of one.
pub fn one_line(text: &str) -> String {
    let mut line = String::with_capacity(text.len());
    let mut pending_break = false;
    let mut pending_space = false;
    for character in text.chars() {
        if matches!(
            character,
            '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        ) {
            pending_break = true;
            continue;
        }
        if character.is_whitespace() || character.is_control() {
            pending_space = true;
            continue;
        }
        if !line.is_empty() {
            if pending_break {
                line.push_str(LINE_BREAK);
            } else if pending_space {
                line.push(' ');
            }
        }
        pending_break = false;
        pending_space = false;
        line.push(character);
    }
    line
}

/// Application text as a line shows it: one line, at most `max` characters,
/// with `…` where it was cut. Says whether it was cut.
fn clipped(text: &str, max: usize) -> (String, bool) {
    let line = one_line(text);
    if line.chars().count() > max {
        let cut: String = line.chars().take(max).collect();
        (format!("{}…", cut.trim_end()), true)
    } else {
        (line, false)
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

/// Why a reply's state is shorter than the application's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncationReason {
    ElementCapReached,
    LabelTruncated,
    /// An action's diff passed [`MAX_DIFF_BYTES`]; a read shows the rest.
    DiffCapReached,
}

impl TruncationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ElementCapReached => "element_cap_reached",
            Self::LabelTruncated => "label_truncated",
            Self::DiffCapReached => "diff_cap_reached",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncation {
    pub reason: TruncationReason,
    pub omitted_elements: usize,
}

// ---------------------------------------------------------------------------
// The collapsed view of a read
// ---------------------------------------------------------------------------

/// One element as the text shows it, with the descendants collapse kept.
#[derive(Debug)]
struct View<'a> {
    node: &'a ObservedNode,
    id: &'a str,
    children: Vec<View<'a>>,
    /// The bytes this subtree takes printed in full at depth zero, with long
    /// runs of repeated siblings summarised: the cost the outline weighs
    /// against [`INLINE_REGION_BYTES`].
    bytes: usize,
    /// How many lines the same printing takes.
    lines: usize,
}

fn raw_role(node: &ObservedNode) -> &str {
    node.description.role.as_deref().unwrap_or("")
}

fn raw_subrole(node: &ObservedNode) -> &str {
    node.description.subrole.as_deref().unwrap_or("")
}

/// A group, container or generic element that only arranges others: no
/// landmark or dialog subrole, no state, no value. Whether one carries
/// anything is then decided by its label and children alone.
fn is_plain_container(node: &ObservedNode) -> bool {
    let description = &node.description;
    matches!(
        raw_role(node),
        "AXGroup" | "AXGenericElement" | "AXUnknown" | "AXLayoutArea" | "AXLayoutItem"
    ) && !raw_subrole(node).starts_with("AXLandmark")
        && !matches!(
            raw_subrole(node),
            "AXDialog" | "AXSystemDialog" | "AXApplicationDialog"
        )
        && description.markers.is_empty()
        && description.value.is_none()
        && !description.secure
}

/// Whether the outline treats the element as a region: a landmark, a
/// container of many like things, a dialog, or a group the application
/// named.
fn is_region(node: &ObservedNode) -> bool {
    matches!(
        raw_role(node),
        "AXWebArea"
            | "AXList"
            | "AXTable"
            | "AXOutline"
            | "AXGrid"
            | "AXBrowser"
            | "AXSheet"
            | "AXDrawer"
            | "AXToolbar"
            | "AXTabGroup"
            | "AXWindow"
    ) || raw_subrole(node).starts_with("AXLandmark")
        || matches!(
            raw_subrole(node),
            "AXDialog" | "AXSystemDialog" | "AXApplicationDialog"
        )
        || (raw_role(node) == "AXGroup" && !one_line(&node.description.label).is_empty())
}

fn is_menu_bar(node: &ObservedNode) -> bool {
    raw_role(node) == "AXMenuBar"
}

/// The collapsed view of one element: zero elements when it carries nothing,
/// its children in its place when it only wraps them, or itself.
///
/// What collapse drops, and why none of it can be acted on:
///
/// * an unlabelled plain container with one child or none, whose child is
///   printed at the container's depth: it names nothing and arranges
///   nothing;
/// * a static text whose label equals the label of the nearest labelled
///   element above it: it is that element's own text a second time;
/// * an unlabelled plain container that is the only thing its parent holds,
///   whose children are printed in its place: it adds a level and nothing
///   else.
///
/// `inherited_label` is the one-line label of the nearest labelled ancestor.
/// `keep_root` keeps the element itself whatever it is, for the element a
/// caller zoomed into and for the top-level windows.
fn build<'a>(node: &'a ObservedNode, inherited_label: &str, keep_root: bool) -> Vec<View<'a>> {
    let Some(id) = node.element_id.as_deref() else {
        return Vec::new();
    };
    if node.hazard {
        return Vec::new();
    }
    let label = one_line(&node.description.label);
    let passed_label = if label.is_empty() {
        inherited_label
    } else {
        &label
    };
    let mut children: Vec<View<'a>> = node
        .children
        .iter()
        .flat_map(|child| build(child, passed_label, false))
        .collect();
    if children.len() == 1
        && is_plain_container(children[0].node)
        && one_line(&children[0].node.description.label).is_empty()
    {
        children = children.pop().map(|only| only.children).unwrap_or_default();
    }
    if !keep_root {
        if raw_role(node) == "AXStaticText" && !label.is_empty() && label == inherited_label {
            return children;
        }
        if is_plain_container(node) && label.is_empty() && children.len() <= 1 {
            return children;
        }
    }
    let (own, _) = line(id, &node.description);
    let mut bytes = own.len() + 1;
    let mut lines = 1;
    for run in runs(&children) {
        let members = &children[run.clone()];
        if members.len() > REPEAT_RUN_LIMIT {
            bytes += 2 + repeat_summary(members, id).len() + 1;
            lines += 1;
        } else {
            for member in members {
                bytes += member.bytes + 2 * member.lines;
                lines += member.lines;
            }
        }
    }
    vec![View {
        node,
        id,
        children,
        bytes,
        lines,
    }]
}

/// A label's shape: its one-line form with the digits taken out, so "Sep 30
/// 02:01" and "Sep 30 02:15" are the same shape and "Inbox" and "Sent" are
/// not.
fn label_shape(label: &str) -> String {
    one_line(label)
        .chars()
        .filter(|character| !character.is_ascii_digit())
        .collect()
}

/// The runs of consecutive siblings sharing a role and a label shape, in
/// order, as index ranges into `views`.
fn runs(views: &[View<'_>]) -> Vec<std::ops::Range<usize>> {
    let mut runs = Vec::new();
    let mut start = 0;
    let key = |view: &View<'_>| {
        (
            view.node.description.role_words.clone(),
            label_shape(&view.node.description.label),
        )
    };
    for index in 1..=views.len() {
        if index == views.len() || key(&views[index]) != key(&views[start]) {
            if start < views.len() {
                runs.push(start..index);
            }
            start = index;
        }
    }
    runs
}

/// Role words in the plural: `buttons`, `check boxes`.
fn plural(words: &str) -> String {
    if words.ends_with('s') || words.ends_with('x') || words.ends_with("ch") {
        format!("{words}es")
    } else {
        format!("{words}s")
    }
}

/// The one line a long run of repeated siblings becomes.
fn repeat_summary(members: &[View<'_>], parent_id: &str) -> String {
    let first = &members[0].node.description;
    let (label, _) = clipped(&first.label, SUMMARY_LABEL_CHARS);
    let like = if label.is_empty() {
        String::new()
    } else {
        format!(", like \"{label}\"")
    };
    format!(
        "{} {}{like} (zoom: {parent_id})",
        members.len(),
        plural(&first.role_words)
    )
}

/// One element's line, without indentation. Says whether a label or value
/// was cut.
fn line(id: &str, description: &ElementDescription) -> (String, bool) {
    let mut text = format!("{id} {}", description.role_words);
    if !description.markers.is_empty() {
        text.push_str(&format!(" ({})", description.markers.join(", ")));
    }
    let (label, mut truncated) = clipped(&description.label, MAX_LABEL_CHARS);
    if !label.is_empty() {
        text.push(' ');
        text.push_str(&label);
    }
    if description.secure {
        text.push_str(&format!(", Value: {VALUE_WITHHELD}"));
    } else if let Some(value) = &description.value {
        let (value, cut) = clipped(value, MAX_LABEL_CHARS);
        truncated |= cut;
        if !value.is_empty() {
            text.push_str(", Value: ");
            text.push_str(&value);
        }
    }
    (text, truncated)
}

/// Where rendered lines collect, held to a byte bound.
struct Emitter {
    text: String,
    limit: usize,
    omitted: usize,
    labels_truncated: bool,
}

impl Emitter {
    fn new(limit: usize) -> Self {
        Self {
            text: String::new(),
            limit,
            omitted: 0,
            labels_truncated: false,
        }
    }

    /// Add one line at `depth`; a line that does not fit is counted instead.
    fn push(&mut self, depth: usize, text: &str) -> bool {
        let indent = 2 * depth;
        if self.text.len() + indent + text.len() + 1 > self.limit {
            self.omitted += 1;
            return false;
        }
        self.text.push_str(&" ".repeat(indent));
        self.text.push_str(text);
        self.text.push('\n');
        true
    }

    fn element(&mut self, depth: usize, view: &View<'_>) {
        let (text, truncated) = line(view.id, &view.node.description);
        if self.push(depth, &text) {
            self.labels_truncated |= truncated;
        }
    }
}

/// Which long runs of repeated siblings a full printing lists one by one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expand {
    /// None: every long run is one line.
    Nothing,
    /// The children of the element printed first, which a caller zoomed
    /// into to see them.
    Children,
    /// Every run, for the menu bar, whose menus are each a run of items.
    Everything,
}

/// Print a view and everything beneath it, summarising long runs of
/// repeated siblings except where `expand` says.
fn print_full(view: &View<'_>, depth: usize, expand: Expand, out: &mut Emitter) {
    out.element(depth, view);
    let below = if expand == Expand::Everything {
        Expand::Everything
    } else {
        Expand::Nothing
    };
    for run in runs(&view.children) {
        let members = &view.children[run];
        if members.len() > REPEAT_RUN_LIMIT && expand == Expand::Nothing {
            out.push(depth + 1, &repeat_summary(members, view.id));
        } else {
            for member in members {
                print_full(member, depth + 1, below, out);
            }
        }
    }
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("~{bytes} B")
    } else {
        format!("~{:.1} KB", bytes as f64 / 1024.0)
    }
}

/// What a summarised region holds: how many of what, a taste of their
/// labels, and what printing it in full would cost.
fn region_summary(view: &View<'_>) -> String {
    let members = &view.children;
    let size = format_size(view.bytes);
    if members.is_empty() {
        return size;
    }
    let first_role = &members[0].node.description.role_words;
    let head = if members
        .iter()
        .all(|member| &member.node.description.role_words == first_role)
    {
        if members.len() == 1 {
            format!("1 {first_role}")
        } else {
            format!("{} {}", members.len(), plural(first_role))
        }
    } else {
        format!("{} elements", members.len())
    };
    let labels: Vec<String> = members
        .iter()
        .map(|member| clipped(&member.node.description.label, SUMMARY_LABEL_CHARS).0)
        .filter(|label| !label.is_empty())
        .collect();
    let taste = if members.len() <= SUMMARY_LABELS_LISTED && !labels.is_empty() {
        format!(": {}", labels.join(", "))
    } else if let Some(first) = labels.first() {
        format!(", like \"{first}\"")
    } else {
        String::new()
    };
    format!("{head}{taste}, {size}")
}

fn emit_region(view: &View<'_>, depth: usize, out: &mut Emitter) {
    let (text, truncated) = line(view.id, &view.node.description);
    if out.push(depth, &format!("{text}  [{}]", region_summary(view))) {
        out.labels_truncated |= truncated;
    }
}

/// Whether the outline looks through an element rather than naming it: an
/// unnamed element that is no region, or the web page itself, whose title and
/// address the header already gives.
fn is_transparent(view: &View<'_>) -> bool {
    raw_role(view.node) == "AXWebArea"
        || (one_line(&view.node.description.label).is_empty() && !is_region(view.node))
}

/// The outline of the top level of a window: a small element in full, a
/// large region or named element as one line followed by the regions inside
/// it, and a large unnamed wrapper looked through.
fn outline(views: &[View<'_>], parent_id: &str, depth: usize, out: &mut Emitter) {
    for run in runs(views) {
        let members = &views[run];
        if members.len() > REPEAT_RUN_LIMIT {
            out.push(depth, &repeat_summary(members, parent_id));
            continue;
        }
        for view in members {
            if out.text.len() > MAX_OUTLINE_BYTES {
                out.omitted += 1;
            } else if is_menu_bar(view.node) {
                out.push(depth, &format!("menu bar (zoom: {MENU_BAR_ZOOM})"));
            } else if view.bytes <= INLINE_REGION_BYTES {
                print_full(view, depth, Expand::Nothing, out);
            } else if is_transparent(view) {
                outline(&view.children, view.id, depth, out);
            } else {
                emit_region(view, depth, out);
                outline_regions(&view.children, view.id, depth + 1, 1, out);
            }
        }
    }
}

/// Inside a summarised region, only the regions it holds are named, one line
/// each, and only the large ones are opened further. The rest of a region's
/// content is what zooming into it shows.
fn outline_regions(
    views: &[View<'_>],
    parent_id: &str,
    depth: usize,
    nesting: usize,
    out: &mut Emitter,
) {
    for run in runs(views) {
        let members = &views[run];
        if members.len() > REPEAT_RUN_LIMIT {
            if members.iter().any(|view| is_region(view.node)) {
                out.push(depth, &repeat_summary(members, parent_id));
            }
            continue;
        }
        for view in members {
            if out.text.len() > MAX_OUTLINE_BYTES {
                out.omitted += 1;
            } else if is_region(view.node) {
                emit_region(view, depth, out);
                if view.bytes > INLINE_REGION_BYTES && nesting < OUTLINE_NESTING {
                    outline_regions(&view.children, view.id, depth + 1, nesting + 1, out);
                }
            } else {
                outline_regions(&view.children, view.id, depth, nesting, out);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// Which part of a read to print in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zoom<'a> {
    /// The menu bar, which the outline leaves out.
    MenuBar,
    /// One element and everything beneath it.
    Element(&'a str),
}

impl<'a> Zoom<'a> {
    /// What a request's `zoom` value names.
    pub fn parse(value: &'a str) -> Self {
        if value.trim().eq_ignore_ascii_case(MENU_BAR_ZOOM) {
            Self::MenuBar
        } else {
            Self::Element(value.trim())
        }
    }
}

/// What a read asks to see. With no zoom and no filter it is the outline.
#[derive(Debug, Clone, Copy, Default)]
pub struct StateRequest<'a> {
    pub zoom: Option<Zoom<'a>>,
    /// Keep elements with any of these roles, named as the raw role
    /// (`AXButton`), without its prefix (`Button`) or in words (`button`),
    /// in any case.
    pub roles: &'a [String],
    /// Keep elements whose rendered label or value contains this, in any
    /// case.
    pub text: Option<&'a str>,
}

impl StateRequest<'_> {
    fn narrows(&self) -> bool {
        !self.roles.is_empty() || self.text.is_some()
    }
}

/// Who the read is of, for the header line.
#[derive(Debug, Clone, Copy)]
pub struct StateHeader<'a> {
    /// The application's name as the person sees it.
    pub app_name: &'a str,
    pub focused_element_id: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedState {
    pub text: String,
    pub truncation: Option<Truncation>,
    /// Whether the element or menu bar `zoom` named was in the read.
    pub zoom_found: bool,
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

/// A text filter matches only what a line shows: the label and value as
/// rendered and, for a secure field, the withheld marker. Never a secure
/// field's value, so a filter cannot confirm a secret the line withholds.
fn text_matches(description: &ElementDescription, text: Option<&str>) -> bool {
    let Some(text) = text else {
        return true;
    };
    let wanted = text.to_lowercase();
    let (label, _) = clipped(&description.label, MAX_LABEL_CHARS);
    let value = if description.secure {
        VALUE_WITHHELD.to_string()
    } else {
        description
            .value
            .as_deref()
            .map(|value| clipped(value, MAX_LABEL_CHARS).0)
            .unwrap_or_default()
    };
    label.to_lowercase().contains(&wanted) || value.to_lowercase().contains(&wanted)
}

/// Collect, in order, every match of the filter with each labelled ancestor
/// that places it, as `(depth, view)` pairs. Returns whether anything
/// beneath or at `view` matched.
fn collect_matches<'v, 'a>(
    view: &'v View<'a>,
    depth: usize,
    request: &StateRequest<'_>,
    found: &mut Vec<(usize, &'v View<'a>)>,
) -> bool {
    let description = &view.node.description;
    let is_match =
        role_matches(description, request.roles) && text_matches(description, request.text);
    let labelled = !one_line(&description.label).is_empty();
    let start = found.len();
    let shown = is_match || labelled;
    if shown {
        found.push((depth, view));
    }
    let child_depth = if shown { depth + 1 } else { depth };
    let mut below = false;
    for child in &view.children {
        below |= collect_matches(child, child_depth, request, found);
    }
    if !is_match && !below {
        found.truncate(start);
        return false;
    }
    true
}

fn count_unnumbered(node: &ObservedNode) -> usize {
    if node.hazard {
        return 0;
    }
    usize::from(node.element_id.is_none())
        + node.children.iter().map(count_unnumbered).sum::<usize>()
}

fn find_node<'a>(nodes: &'a [ObservedNode], id: &str) -> Option<&'a ObservedNode> {
    nodes.iter().find_map(|node| {
        if node.hazard {
            None
        } else if node.element_id.as_deref() == Some(id) {
            Some(node)
        } else {
            find_node(&node.children, id)
        }
    })
}

fn find_role<'a>(nodes: &'a [ObservedNode], role: &str) -> Option<&'a ObservedNode> {
    nodes.iter().find_map(|node| {
        if node.hazard {
            None
        } else if raw_role(node) == role {
            Some(node)
        } else {
            find_role(&node.children, role)
        }
    })
}

/// The first line of every read: whose state it is, which window, the page a
/// browser shows, and what has focus.
fn header(header: &StateHeader<'_>, roots: &[ObservedNode]) -> String {
    let mut parts = vec![one_line(header.app_name)];
    if let Some(window) = roots.iter().find(|root| raw_role(root) == "AXWindow") {
        let (title, _) = clipped(&window.description.label, MAX_LABEL_CHARS);
        parts.push(format!("window \"{title}\""));
        if let Some(url) = find_role(std::slice::from_ref(window), "AXWebArea")
            .and_then(|web| web.description.value.as_deref())
        {
            parts.push(clipped(url, MAX_LABEL_CHARS).0);
        }
    }
    if let Some(focused) = header.focused_element_id {
        parts.push(format!("focused {focused}"));
    }
    parts.join(" · ")
}

/// Render a read: the header line, then the outline, the zoomed subtree, or
/// the filter's matches.
pub fn render_state(
    head: &StateHeader<'_>,
    roots: &[ObservedNode],
    request: &StateRequest<'_>,
) -> RenderedState {
    let mut out = Emitter::new(MAX_STATE_TEXT_BYTES);
    out.push(0, &header(head, roots));

    let target: Option<&ObservedNode> = match request.zoom {
        None => None,
        Some(Zoom::MenuBar) => roots.iter().find(|root| is_menu_bar(root)),
        Some(Zoom::Element(id)) => find_node(roots, id),
    };
    let zoom_found = request.zoom.is_none() || target.is_some();
    let scope: Vec<View<'_>> = match (request.zoom, target) {
        (Some(_), Some(target)) => build(target, "", true),
        (Some(_), None) => Vec::new(),
        (None, _) => roots
            .iter()
            .flat_map(|root| build(root, "", true))
            .collect(),
    };

    if request.narrows() {
        let mut found = Vec::new();
        for view in &scope {
            collect_matches(view, 0, request, &mut found);
        }
        for (depth, view) in found {
            out.element(depth, view);
        }
    } else if let Some(zoom) = request.zoom {
        let expand = match zoom {
            Zoom::MenuBar => Expand::Everything,
            Zoom::Element(_) => Expand::Children,
        };
        for view in &scope {
            print_full(view, 0, expand, &mut out);
        }
    } else {
        // The first window is named by the header, so its own line would say
        // nothing more; its content starts the outline. Any other window or
        // sheet is a region of its own.
        let mut header_window_seen = false;
        for view in &scope {
            if raw_role(view.node) == "AXWindow" && !header_window_seen {
                header_window_seen = true;
                if view.bytes <= INLINE_REGION_BYTES {
                    print_full(view, 0, Expand::Nothing, &mut out);
                } else {
                    outline(&view.children, view.id, 0, &mut out);
                }
            } else {
                outline(std::slice::from_ref(view), view.id, 0, &mut out);
            }
        }
        if out.omitted > 0 {
            out.text.push_str(&format!(
                "… the outline stops at {} KB; zoom into an id above, or use text_filter or role_filter\n",
                MAX_OUTLINE_BYTES / 1024
            ));
            // The outline's own stop is a choice of view, not a loss: every
            // element it leaves out is one zoom or filter away.
            out.omitted = 0;
        }
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
    RenderedState {
        text: out.text,
        truncation,
        zoom_found,
    }
}

// ---------------------------------------------------------------------------
// Diffs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedDiff {
    pub text: String,
    /// Present when the diff passed [`MAX_DIFF_BYTES`] and left lines out.
    pub truncation: Option<Truncation>,
}

/// Ids as the shortest list of numbers and ranges: `4, 7-9, 12`. Ids that are
/// not numbers are listed as they are, after the numbers.
pub fn id_ranges(ids: &[String]) -> String {
    let mut numbers: Vec<u64> = ids.iter().filter_map(|id| id.parse().ok()).collect();
    numbers.sort_unstable();
    numbers.dedup();
    let mut parts: Vec<String> = Vec::new();
    let mut index = 0;
    while index < numbers.len() {
        let start = numbers[index];
        let mut end = start;
        while index + 1 < numbers.len() && numbers[index + 1] == end + 1 {
            index += 1;
            end = numbers[index];
        }
        parts.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        index += 1;
    }
    parts.extend(ids.iter().filter(|id| id.parse::<u64>().is_err()).cloned());
    parts.join(", ")
}

/// Walk the collapsed view in order, collecting the changed and added
/// elements with their depth.
fn collect_changes<'v, 'a>(
    view: &'v View<'a>,
    depth: usize,
    changed: &HashSet<&str>,
    added: &HashSet<&str>,
    found: &mut Vec<(char, usize, &'v View<'a>)>,
) {
    // An unnamed container says nothing but its role, and what it holds is
    // listed beneath it anyway, so a diff leaves its line out.
    let silent = is_plain_container(view.node) && one_line(&view.node.description.label).is_empty();
    if !silent && added.contains(view.id) {
        found.push(('+', depth, view));
    } else if !silent && changed.contains(view.id) {
        found.push(('~', depth, view));
    }
    for child in &view.children {
        collect_changes(child, depth + 1, changed, added, found);
    }
}

/// The text an action reply carries for what the action changed: `+` for an
/// element that appeared, `~` for one whose line changed, each in the read
/// grammar at its depth; then the removed ids as ranges; then the focused
/// element, last.
///
/// Every element is named by its whole line, never by a bare id: an id alone
/// tells a caller nothing it can act on without another read. Past
/// [`MAX_DIFF_BYTES`] the lines stop and the counts of what was left out
/// are given instead.
pub fn render_diff(
    roots: &[ObservedNode],
    diff: &StateDiff,
    focused_element_id: Option<&str>,
) -> RenderedDiff {
    let changed: HashSet<&str> = diff.changed.iter().map(String::as_str).collect();
    let added: HashSet<&str> = diff.added.iter().map(String::as_str).collect();
    let views: Vec<View<'_>> = roots
        .iter()
        .flat_map(|root| build(root, "", true))
        .collect();
    let mut found = Vec::new();
    for view in &views {
        collect_changes(view, 0, &changed, &added, &mut found);
    }

    let removed = if diff.removed.is_empty() {
        None
    } else {
        let ranges = id_ranges(&diff.removed);
        let (ranges, _) = clipped(&ranges, MAX_DIFF_BYTES / 4);
        Some(format!("Removed element IDs: {ranges}"))
    };
    let focused = focused_element_id.and_then(|id| {
        find_node(roots, id).map(|node| format!("focused: {}", line(id, &node.description).0))
    });
    // The removed ranges, the focused line and the line saying what was left
    // out always fit; the changed and added lines share the rest.
    let reserved = removed.as_ref().map_or(0, |text| text.len() + 1)
        + focused.as_ref().map_or(0, |text| text.len() + 1)
        + 160;
    let mut body = Emitter::new(MAX_DIFF_BYTES.saturating_sub(reserved));
    let mut left_changed = 0;
    let mut left_added = 0;
    for (prefix, depth, view) in &found {
        let (text, truncated) = line(view.id, &view.node.description);
        let text = format!("{prefix} {}{text}", "  ".repeat(*depth));
        if body.push(0, &text) {
            body.labels_truncated |= truncated;
        } else if *prefix == '+' {
            left_added += 1;
        } else {
            left_changed += 1;
        }
    }

    let mut text = body.text;
    let left_out = left_changed + left_added;
    if left_out > 0 {
        text.push_str(&format!(
            "… {left_changed} more changed and {left_added} more added elements are not shown: \
             the diff stops at {} KB; read_state to see the rest\n",
            MAX_DIFF_BYTES / 1024
        ));
    }
    if let Some(removed) = removed {
        text.push_str(&removed);
        text.push('\n');
    }
    if text.is_empty() {
        text.push_str("No change seen since the last read.\n");
    }
    if let Some(focused) = focused {
        text.push_str(&focused);
        text.push('\n');
    }
    RenderedDiff {
        text,
        truncation: (left_out > 0).then_some(Truncation {
            reason: TruncationReason::DiffCapReached,
            omitted_elements: left_out,
        }),
    }
}
