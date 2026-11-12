//! The page as plain text: what a browser snapshot returns to the model.
//!
//! Every element is one line, indented two spaces per level:
//!
//! ```text
//! <ref> <role> [(<states>)] <name>[, Value: <value>][, Placeholder: <text>]
//! ```
//!
//! The first line names the page: `<title> · <url> · snapshot <id>`.
//!
//! A plain snapshot returns an outline: one line per landmark (main, a feed,
//! an article, navigation, a sidebar, a form, a dialog, a list, ...) with its
//! size, small landmarks printed in full, and the page's main content before
//! its navigation chrome. `zoom` names one ref and prints that element's whole
//! subtree. This is the same reading order as outlining a file before reading
//! one function of it, and it keeps a feed page's first reply to a few
//! kilobytes instead of tens.
//!
//! Before anything is printed the tree loses what carries nothing: an
//! unlabelled wrapper with one child is replaced by that child, and a text
//! node repeating its parent's name is dropped. Neither rule can remove an
//! element a caller could act on, because neither ever applies to a control.

use std::collections::{BTreeSet, HashMap};

use crate::snapshot_store::{truncate_ax_field, AxRecord, MAX_NAME_BYTES};

/// The reply field that carries the rendered page. Prefrontal lifts a
/// top-level string of this name into a native text part, so the page reaches
/// the model as text rather than as an escaped JSON string.
pub const STATE_TEXT_FIELD: &str = "state_text";

/// Names longer than this are cut with an ellipsis. Chrome names a container
/// with the text of everything inside it (an X post's article is named with
/// the author, the whole post and its counts), so an uncapped name repeats the
/// subtree it heads.
pub const NAME_CHARS: usize = 200;

/// A text node is the page's content itself rather than a summary of it, so
/// it gets more room than a name: a full-length post (280 characters) and a
/// typical paragraph survive one zoom intact.
pub const TEXT_CHARS: usize = 600;

/// An outline line only has to tell landmarks apart; zoom shows the rest.
/// Half the name cap keeps an X timeline's outline, about a dozen posts plus
/// the page's chrome, under 3 KB.
pub const OUTLINE_NAME_CHARS: usize = 100;

/// A landmark whose printed subtree fits in this many bytes is printed in
/// full inside the outline instead of as one summary line. 600 bytes is
/// roughly eight element lines: a tab list, a search form or a short menu.
/// Zooming into one of those would cost a second call plus another header for
/// about the same text, while anything larger (a feed, a long list) is the
/// kind of region the outline exists to keep folded. Three or four inlined
/// regions still fit an outline in the 3 KB the X timeline targets.
pub const INLINE_BYTES: usize = 600;

/// How much content outside any landmark the outline prints at the top level
/// before folding the rest into one "more" line. Pages without landmarks
/// (many simple sites) have everything here, so it gets more room than the
/// per-landmark allowance below.
pub const TOP_LOOSE_BYTES: usize = 1_500;

/// How much loose content (elements that are not themselves landmarks) the
/// outline prints under one large landmark before folding the rest.
pub const NESTED_LOOSE_BYTES: usize = INLINE_BYTES;

/// Siblings sharing a role and a name shape are printed as one example and a
/// count once there are more than this many of them, outside a zoom.
pub const REPEAT_THRESHOLD: usize = 3;

/// The most leaf nodes, empty or not, a subtree may contain to print as one
/// filtered row (see `Tree::leaf_row`). Leaves count across nested wrappers: a
/// property line may wrap its key and value separately, and table cells may
/// wrap their text. The match prints with the smallest such subtree that holds
/// another leaf with a letter or digit. Eight leaves cover both shapes, while
/// a wider subtree is more likely a layout container whose other texts are
/// unrelated to the match.
pub const ROW_LEAVES: usize = 8;

/// The most bytes a subtree's leaf texts, allowing a space per leaf, may
/// have to print as one filtered row: about four lines of a terminal, enough
/// for a key with a JSON string value or a row of short cells. A larger
/// subtree keeps the matching text or smaller row, so one long cell cannot
/// flood a filtered reply.
pub const ROW_BYTES: usize = 300;

// A filtered match on a page that lists repeated items without a table (an
// app list with an icon, a name and a `Configure` link per item, all inside
// unlabelled containers) prints with its "row block": the nearest enclosing
// element that holds a control and a label outside any control (a name with a
// letter or digit), so a name prints with the link that acts on it and the
// link with the name it belongs to. The block uses the same limits as a joined
// row, [`ROW_LEAVES`] leaves and [`ROW_BYTES`] bytes of leaf text. They bound
// the leaves, not every printed element or container name, and they do not
// prove the block is one item, since an unlabelled container holding two
// small items can still qualify. The search stops at landmarks (a list, a
// region) and table parts, so a block is never a whole list or table. See
// `Tree::row_block`.

/// Facts about one element the accessibility record alone does not carry,
/// keyed by the element's ref.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeFacts {
    /// Accessibility states worth printing, in a fixed order (focused,
    /// disabled, checked, ...).
    pub states: Vec<String>,
    /// The absolute URL a link points to.
    pub url: Option<String>,
    /// Whether the element's DOM node is a credential or payment field.
    /// `None` means the DOM was not read for it, which withholds any value
    /// just as `Some(true)` does: a value is printed only when the page's own
    /// markup shows the field is neither.
    pub credential: Option<bool>,
    /// Why the ref has no captured input classification. Shared failures print
    /// once; a different failure prints beside its ref so a filtered match does
    /// not imply that input classification was captured.
    pub classification_unavailable: Option<&'static str>,
    /// The field's placeholder text, which is a hint and never the value.
    pub placeholder: Option<String>,
    /// The element's own serialized markup (its outerHTML). Only a
    /// `dom_full` capture reads it, and only for the outermost content and
    /// chrome landmarks (see [`landmark_class`]), so markup larger than the
    /// caller's `max_bytes` can be laid out main content first.
    pub dom_markup: Option<String>,
    /// The accessibility node ids of the element's ignored ancestors,
    /// innermost first, up to its nearest ancestor that has a record of its
    /// own, at most [`MAX_IGNORED_ANCESTORS`] of them. Chrome ignores a
    /// plain `<div>` or `<span>` with nothing to announce, so a line a page
    /// draws from such wrappers (a JSON viewer's key and value) has no record
    /// grouping its texts; these ids still say which texts share a wrapper.
    /// Only a text filter's row search reads them (see
    /// `Tree::ignored_group_row`).
    pub ignored_ancestors: Vec<String>,
}

/// The most ignored ancestors [`NodeFacts::ignored_ancestors`] keeps for one
/// element. A row is a few texts in a few wrappers, so the innermost sixteen
/// hold any row a filter can print; a longer chain is cut at this many.
pub const MAX_IGNORED_ANCESTORS: usize = 16;

pub(crate) fn append_classification_notice(
    text: &mut String,
    reference: &str,
    facts: &HashMap<String, NodeFacts>,
) {
    if let Some(reason) = facts
        .get(reference)
        .and_then(|facts| facts.classification_unavailable)
    {
        text.push_str(&format!(
            " [{reference} classification unavailable: {reason}]"
        ));
    }
}

/// A repeated failure is capture metadata, not part of every element's label.
/// Count captured identities, not occurrences in joined rows or zoom headers.
#[derive(Default)]
pub(crate) struct ClassificationNotices {
    shared: Option<(&'static str, usize)>,
}

impl ClassificationNotices {
    pub(crate) fn new(records: &[AxRecord], facts: &HashMap<String, NodeFacts>) -> Self {
        let mut counts = std::collections::BTreeMap::new();
        let references = records
            .iter()
            .filter_map(|r| r.reference.as_deref())
            .collect::<BTreeSet<_>>();
        for reference in references {
            if let Some(reason) = facts
                .get(reference)
                .and_then(|f| f.classification_unavailable)
            {
                *counts.entry(reason).or_insert(0) += 1;
            }
        }
        Self {
            shared: counts
                .into_iter()
                .filter(|(_, count)| *count > 1)
                .max_by_key(|(_, count)| *count),
        }
    }

    pub(crate) fn append_summary(&self, text: &mut String) {
        if let Some((reason, count)) = self.shared {
            text.push_str(&format!("\nClassification unavailable for {count} captured refs: {reason}; clicks and typing on them will refuse until a snapshot captures their classification."));
        }
    }

    pub(crate) fn append_inline(
        &self,
        text: &mut String,
        reference: &str,
        facts: &HashMap<String, NodeFacts>,
    ) {
        let reason = facts
            .get(reference)
            .and_then(|f| f.classification_unavailable);
        if reason.is_some() && reason != self.shared.map(|(reason, _)| reason) {
            append_classification_notice(text, reference, facts);
        }
    }
}

pub(crate) const BYTE_CUT_NOTICE: &str = "This snapshot is partial: max_bytes cut the rendered text. Zoom into a container ref or raise max_bytes before assuming absent controls are unavailable.";

pub(crate) fn capture_cut_notice(filters: &Filters) -> String {
    let unsearched = if filters.narrows() {
        "; matches beyond the captured portion were not searched"
    } else {
        ""
    };
    format!("This snapshot is partial. Capture stopped early; some content or refs were not captured{unsearched}. Zoom into a container ref to search or read that subtree.")
}

/// Which element a zoom asked for and which element of this capture it is.
#[derive(Debug, Clone, Copy)]
pub struct Zoom<'a> {
    /// The ref the caller named.
    pub requested: &'a str,
    /// The ref the same element has in this capture, or `None` when it is no
    /// longer on the page.
    pub target: Option<&'a str>,
}

pub struct RenderInput<'a> {
    /// The accessibility tree in document order, each record carrying its
    /// depth.
    pub records: &'a [AxRecord],
    pub facts: &'a HashMap<String, NodeFacts>,
    /// The URL of the document the records were read from.
    pub page_url: &'a str,
    pub snapshot_id: &'a str,
    pub zoom: Option<Zoom<'a>>,
    pub filters: &'a Filters,
    /// The most bytes the rendered text may have.
    pub max_bytes: usize,
}

// Capture-only records carry omission notices without refs. Keep them in the
// header so a zoom or text/role filter cannot hide an unread embedded document.
pub(crate) const UNREAD_FRAME_ROLE: &str = "ck-unread-frame";

#[derive(Debug, Default)]
pub struct Filters {
    pub text: Option<String>,
    pub roles: Vec<String>,
}

impl Filters {
    pub(super) fn parse(
        object: &serde_json::Map<String, serde_json::Value>,
        kind: crate::snapshot_store::SnapshotKind,
    ) -> Result<Self, super::BrowserError> {
        let invalid = |field: &str, reason_code| super::BrowserError::InvalidRequest {
            field: field.into(),
            reason_code,
        };
        if kind != crate::snapshot_store::SnapshotKind::Actionable {
            for field in ["text_filter", "role_filter"] {
                if object.contains_key(field) {
                    return Err(invalid(field, "unsupported_value"));
                }
            }
        }
        let text = match object.get("text_filter") {
            None => None,
            Some(serde_json::Value::String(text)) if text.chars().count() <= 4096 => {
                Some(text.clone())
            }
            Some(serde_json::Value::String(_)) => {
                return Err(invalid("text_filter", "out_of_range"))
            }
            Some(_) => return Err(invalid("text_filter", "wrong_type")),
        };
        let roles = match object.get("role_filter") {
            None => Vec::new(),
            Some(serde_json::Value::Array(roles)) if !roles.is_empty() && roles.len() <= 16 => {
                roles
                    .iter()
                    .map(|role| {
                        role.as_str()
                            .filter(|role| !role.is_empty() && role.len() <= 128)
                            .map(str::to_string)
                            .ok_or_else(|| invalid("role_filter", "wrong_type"))
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
            Some(serde_json::Value::Array(_)) => {
                return Err(invalid("role_filter", "out_of_range"))
            }
            Some(_) => return Err(invalid("role_filter", "wrong_type")),
        };
        Ok(Self { text, roles })
    }

    fn narrows(&self) -> bool {
        self.text.is_some() || !self.roles.is_empty()
    }

    fn no_match_notice(&self) -> String {
        let mut filters = Vec::new();
        if let Some(text) = &self.text {
            let text = cap_chars(one_line(text), 80);
            filters.push(format!(
                "text_filter {text:?} (a literal, case-insensitive substring)"
            ));
        }
        if !self.roles.is_empty() {
            let roles = cap_chars(one_line(&format!("{:?}", self.roles)), 80);
            filters.push(format!("role_filter {roles} (case-insensitive roles)"));
        }
        format!("No element matched {}", filters.join(" and "))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedState {
    pub text: String,
    /// Every ref the text names. These, and only these, stay usable for a
    /// click or a zoom on this snapshot.
    pub printed_refs: BTreeSet<String>,
    /// Bytes and lines the `max_bytes` cut removed; zero when nothing was cut.
    pub cut_bytes: usize,
    pub cut_lines: usize,
}

/// Render a captured page as plain text, as an outline or as one zoomed
/// subtree, within `max_bytes`.
pub fn render(input: &RenderInput<'_>) -> RenderedState {
    render_with_capture_status(input, false)
}

/// Capture bounds apply before filtering. A renderer cannot infer missing
/// subtrees from the records it received, so adapters must pass that status.
pub fn render_with_capture_status(
    input: &RenderInput<'_>,
    capture_incomplete: bool,
) -> RenderedState {
    let tree = Tree::build(input.records, input.facts);
    let mut header = String::new();
    let title = cap_chars(one_line(&tree.names[0]), NAME_CHARS);
    if tree.records[0].is_some_and(|record| record.role == "RootWebArea") && !title.is_empty() {
        header.push_str(&title);
        header.push_str(" · ");
    }
    header.push_str(&short_url(input.page_url).unwrap_or_else(|| input.page_url.to_string()));
    header.push_str(" · snapshot ");
    header.push_str(input.snapshot_id);

    let mut header_refs = Vec::new();
    let lines = match input.zoom {
        Some(zoom) => match zoom.target.and_then(|reference| tree.by_ref.get(reference)) {
            Some(&target) => {
                // An element inside a text field (Chrome's inner editor and
                // its text) is the field's value by another route, so a zoom
                // into one shows the field itself, which withholds it.
                let target = tree.text_field_ancestor(target).unwrap_or(target);
                header.push_str(" · zoom ");
                match tree.reference(target) {
                    Some(reference) => {
                        header.push_str(reference);
                        tree.notices
                            .append_inline(&mut header, reference, input.facts);
                        header_refs.push(reference.to_string());
                    }
                    None => header.push_str(zoom.requested),
                }
                let mut lines = Vec::new();
                if input.filters.narrows() {
                    tree.filtered_lines(target, 0, input.filters, &mut lines);
                } else {
                    tree.full_lines(target, 0, &mut lines);
                    // The target's line may hold its whole name in what the
                    // header and its text children leave of `max_bytes`.
                    let others: usize = lines[1..].iter().map(Line::bytes).sum();
                    let room = input
                        .max_bytes
                        .saturating_sub(header.len() + 1 + others + 1);
                    if let Some(text) = tree.full_name_text(target, room) {
                        lines[0].text = text;
                    }
                }
                lines
            }
            None => {
                header = missing_zoom(zoom.requested, input.records.iter());
                Vec::new()
            }
        },
        None if input.filters.narrows() => {
            let mut lines = Vec::new();
            tree.filtered_lines(0, 0, input.filters, &mut lines);
            lines
        }
        None => tree.outline_lines(),
    };
    tree.notices.append_summary(&mut header);
    if capture_incomplete {
        header.push('\n');
        header.push_str(&capture_cut_notice(input.filters));
    }
    if input.filters.narrows() && lines.is_empty() {
        header.push('\n');
        header.push_str(&input.filters.no_match_notice());
    }
    // The person's browser places frame markers at their owners. Filtering or
    // zooming can remove those lines, but must not hide the unread document.
    for notice in input.records.iter().filter(|record| {
        record.role == UNREAD_FRAME_ROLE
            || (record.role == "StaticText"
                && record.reference.is_none()
                && record.name.starts_with("[embedded frame not readable:")
                && !lines.iter().any(|line| line.text.contains(&record.name)))
    }) {
        header.push('\n');
        header.push_str(&one_line(&notice.name));
    }
    if input.zoom.is_none() && !input.filters.narrows() {
        fit_outline(header, lines, &tree, input.max_bytes)
    } else {
        fit(header, header_refs, lines, &tree, input.max_bytes)
    }
}

/// Neighbours are numeric ref neighbours, not DOM siblings. Callers pass only
/// live records whose refs were printed in an earlier snapshot.
pub(crate) fn missing_zoom<'a>(
    requested: &str,
    records: impl Iterator<Item = &'a AxRecord>,
) -> String {
    let number = |reference: &str| reference.strip_prefix('e')?.parse::<u64>().ok();
    let wanted = number(requested);
    let mut before = None;
    let mut after = None;
    for record in records {
        let Some(id) = record.reference.as_deref().and_then(number) else {
            continue;
        };
        if wanted.is_some_and(|wanted| id < wanted)
            && before.is_none_or(|(previous, _)| id > previous)
        {
            before = Some((id, record));
        }
        if wanted.is_some_and(|wanted| id > wanted)
            && after.is_none_or(|(previous, _)| id < previous)
        {
            after = Some((id, record));
        }
    }
    let label = |candidate: Option<(u64, &AxRecord)>| match candidate {
        Some((id, record)) => format!(
            "e{id} {} {}",
            cap_chars(one_line(&record.role), 40),
            cap_chars(one_line(&record.name), 40)
        ),
        None => "none".into(),
    };
    format!(
        "zoom {}: no such element on the page now.\nBefore: {}\nAfter: {}\nTake a fresh snapshot if the page changed.",
        cap_chars(one_line(requested), 16), label(before), label(after)
    )
}

/// The role word a line prints: `StaticText` reads as `text` and the root
/// `RootWebArea` as `page`; every other accessibility role prints as is.
fn display_role(role: &str) -> &str {
    match role {
        "StaticText" => "text",
        "RootWebArea" => "page",
        other => other,
    }
}

/// Chrome's per-line text boxes and line breaks repeat what their text node
/// already says.
fn skipped(role: &str) -> bool {
    matches!(role, "InlineTextBox" | "LineBreak")
}

fn is_wrapper(role: &str) -> bool {
    matches!(
        role,
        "generic" | "group" | "none" | "presentation" | "GenericContainer" | "Section"
    )
}

fn is_actionable(role: &str) -> bool {
    matches!(
        role,
        "link"
            | "button"
            | "textbox"
            | "searchbox"
            | "combobox"
            | "listbox"
            | "option"
            | "checkbox"
            | "radio"
            | "slider"
            | "spinbutton"
            | "switch"
            | "tab"
            | "menuitem"
            | "menuitemcheckbox"
            | "menuitemradio"
            | "treeitem"
            | "PopUpButton"
            | "ToggleButton"
            | "MenuListOption"
            | "ListBoxOption"
    )
}

/// Text-entry fields (`textbox`, `searchbox`, `combobox`): their value is
/// what a person typed, so it prints only for a field known not to hold a
/// credential or payment detail.
fn is_text_field(role: &str) -> bool {
    matches!(role, "textbox" | "searchbox" | "combobox")
}

/// The parts of a table. A filtered match inside a table keeps the existing
/// table behaviour (a joined row where `Tree::leaf_row` accepts one), so the
/// search for a row block stops at any of them.
fn is_table_part(role: &str) -> bool {
    matches!(
        role,
        "table"
            | "grid"
            | "treegrid"
            | "rowgroup"
            | "row"
            | "cell"
            | "gridcell"
            | "columnheader"
            | "rowheader"
    )
}

/// Controls whose value is a number or a position (a slider's level, a
/// progress bar's percentage); their value always prints.
fn is_value_control(role: &str) -> bool {
    matches!(
        role,
        "slider" | "spinbutton" | "progressbar" | "meter" | "scrollbar"
    )
}

pub(super) const CONTENT: u8 = 0;
pub(super) const NEUTRAL: u8 = 1;
pub(super) const CHROME: u8 = 2;

/// Which landmarks hold the page's content and which its chrome (navigation,
/// header, sidebar, footer). When `max_bytes` forces lines out, content lines
/// are kept first, and the outline lists content first.
pub(super) fn landmark_class(role: &str) -> u8 {
    match role {
        "main" | "feed" | "article" | "dialog" | "alertdialog" => CONTENT,
        "banner" | "navigation" | "complementary" | "contentinfo" | "search" => CHROME,
        _ => NEUTRAL,
    }
}

/// Collapse runs of whitespace (newlines included) to one space, so every
/// element stays on one line.
pub fn one_line(value: &str) -> String {
    value
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn cap_chars(value: String, max: usize) -> String {
    if value.chars().count() <= max {
        return value;
    }
    let mut capped: String = value.chars().take(max.saturating_sub(1)).collect();
    capped.push('…');
    capped
}

/// A URL as host plus path: the scheme, credentials, query and fragment are
/// dropped. `None` for a URL that names no place worth printing (script and
/// data URLs, which can also be arbitrarily long).
pub fn short_url(url: &str) -> Option<String> {
    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("javascript:") || lower.starts_with("data:") || lower.starts_with("blob:")
    {
        return None;
    }
    let rest = ["https://", "http://"]
        .iter()
        .find(|scheme| lower.starts_with(*scheme))
        .map(|scheme| &url[scheme.len()..]);
    let Some(rest) = rest else {
        let end = url.find(['?', '#']).unwrap_or(url.len());
        return Some(cap_chars(one_line(&url[..end]), NAME_CHARS)).filter(|url| !url.is_empty());
    };
    let rest = &rest[..rest.find(['?', '#']).unwrap_or(rest.len())];
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let path = if path == "/" { "" } else { path };
    Some(cap_chars(one_line(&format!("{host}{path}")), NAME_CHARS))
}

/// Resolve a link's `href` attribute against the page it is on. Only used
/// when Chrome did not report the link's absolute URL itself.
pub fn resolve_href(href: &str, page_url: &str) -> String {
    let href = href.trim();
    let scheme_end = href.find(':');
    if scheme_end.is_some_and(|end| !href[..end].contains(['/', '?', '#'])) {
        return href.to_string();
    }
    let (scheme, rest) = page_url.split_once("://").unwrap_or(("https", page_url));
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if let Some(network_path) = href.strip_prefix("//") {
        return format!("{scheme}://{network_path}");
    }
    if href.starts_with('/') {
        return format!("{scheme}://{authority}{href}");
    }
    let page = &page_url[..page_url.find(['?', '#']).unwrap_or(page_url.len())];
    if href.is_empty() || href.starts_with(['?', '#']) {
        return format!("{page}{href}");
    }
    let directory = page
        .rfind('/')
        .filter(|slash| *slash > scheme.len() + 2)
        .map_or(format!("{page}/"), |slash| page[..=slash].to_string());
    format!("{directory}{href}")
}

pub(crate) fn size_text(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    }
}

/// The name with its digits removed: "3 Likes" and "12 Likes" have one shape.
fn shape(name: &str) -> String {
    name.chars().filter(|c| !c.is_ascii_digit()).collect()
}

/// The letters and digits of `text`: what it says, without the quotes,
/// colons and other punctuation a viewer wraps around it.
fn content_chars(text: &str) -> String {
    text.chars().filter(|c| c.is_alphanumeric()).collect()
}

#[derive(Debug, Clone)]
struct Line {
    depth: usize,
    text: String,
    /// When `max_bytes` forces lines out, content (0) is kept before neutral
    /// (1) before chrome (2).
    class: u8,
    refs: Vec<String>,
    /// The outermost landmark the line belongs to, so the closing line that
    /// reports what `max_bytes` removed can name it.
    section: Option<usize>,
    /// Nodes represented by this row, including descendants hidden behind a
    /// summary or a sibling-fold disclosure. Expanded landmark headers count
    /// only themselves, not the children printed after them.
    covered: usize,
    covered_bytes: Option<usize>,
}

impl Line {
    fn bytes(&self) -> usize {
        self.depth * 2 + self.text.len() + 1
    }
}

/// What a filtered reply prints for a node that holds a match.
enum FilterRow {
    /// The node's leaf texts joined on one line (see `Tree::leaf_row`).
    Joined(String),
    /// The node's printed subtree, one element per line, each with the ref it
    /// has (see `Tree::row_block`).
    Block,
    /// These sibling subtrees, printed one element per line in the place of
    /// the node: an ignored wrapper's row holding a key chip, whose ref a
    /// joined line would drop (see `Tree::ignored_group_row`).
    Members(Vec<usize>),
    /// Nothing: the node is part of a row an earlier sibling prints (see
    /// `Tree::ignored_group_row`).
    Covered,
}

enum Item {
    Node(usize),
    /// Siblings folded behind the example printed just before this item.
    More(Vec<usize>),
}

struct Tree<'a> {
    /// Node 0 is the page: the root record when the tree has one, otherwise
    /// a placeholder holding every top-level record.
    records: Vec<Option<&'a AxRecord>>,
    names: Vec<String>,
    children: Vec<Vec<usize>>,
    parent: Vec<Option<usize>>,
    /// Children after collapsing.
    kids: Vec<Vec<usize>>,
    by_ref: HashMap<&'a str, usize>,
    facts: &'a HashMap<String, NodeFacts>,
    notices: ClassificationNotices,
    class: Vec<u8>,
    has_landmark_below: Vec<bool>,
    section: Vec<Option<usize>>,
    /// See `Tree::wrapper_kids`.
    wrapper_kids: std::cell::OnceCell<HashMap<(usize, &'a str), Vec<usize>>>,
}

impl<'a> Tree<'a> {
    fn build(records: &'a [AxRecord], facts: &'a HashMap<String, NodeFacts>) -> Self {
        let mut nodes: Vec<Option<&AxRecord>> = vec![None];
        let mut children = vec![Vec::new()];
        let mut parent = vec![None];
        let mut rest = records
            .iter()
            .filter(|record| !skipped(&record.role))
            .peekable();
        if rest
            .peek()
            .is_some_and(|record| record.role == "RootWebArea")
        {
            nodes[0] = rest.next();
        }
        // Records arrive in document order with their depth, so a record's
        // parent is the nearest earlier record that is shallower.
        let mut stack: Vec<(i64, usize)> = vec![(i64::MIN, 0)];
        for record in rest {
            while stack.len() > 1
                && stack
                    .last()
                    .is_some_and(|(depth, _)| *depth >= record.depth)
            {
                stack.pop();
            }
            let owner = stack.last().expect("the page is never popped").1;
            let index = nodes.len();
            nodes.push(Some(record));
            children.push(Vec::new());
            parent.push(Some(owner));
            children[owner].push(index);
            stack.push((record.depth, index));
        }
        let names = nodes
            .iter()
            .map(|record| {
                record
                    .map(|record| one_line(&record.name))
                    .unwrap_or_default()
            })
            .collect();
        let by_ref = nodes
            .iter()
            .enumerate()
            .filter_map(|(index, record)| Some((record.as_ref()?.reference.as_deref()?, index)))
            .collect();
        let mut tree = Self {
            records: nodes,
            names,
            children,
            parent,
            kids: Vec::new(),
            by_ref,
            facts,
            notices: ClassificationNotices::new(records, facts),
            class: Vec::new(),
            has_landmark_below: Vec::new(),
            section: Vec::new(),
            wrapper_kids: std::cell::OnceCell::new(),
        };
        tree.collapse();
        tree.classify();
        tree
    }

    fn role(&self, node: usize) -> &str {
        self.records[node].map_or("page", |record| record.role.as_str())
    }

    fn reference(&self, node: usize) -> Option<&'a str> {
        self.records[node]?.reference.as_deref()
    }

    fn facts(&self, node: usize) -> Option<&'a NodeFacts> {
        self.facts.get(self.reference(node)?)
    }

    fn is_landmark(&self, node: usize) -> bool {
        let role = self.role(node);
        matches!(
            role,
            "banner"
                | "navigation"
                | "main"
                | "complementary"
                | "contentinfo"
                | "region"
                | "form"
                | "search"
                | "dialog"
                | "alertdialog"
                | "feed"
                | "list"
                | "article"
                | "tablist"
                | "table"
                | "grid"
                | "tree"
                | "menubar"
        ) || (role == "group" && !self.names[node].is_empty())
    }

    /// Compute every node's printed children: an unlabelled wrapper with one
    /// child is replaced by that child (and dropped when it has none), a text
    /// node empty or equal to its parent's name is dropped, and below a text
    /// field only controls remain. Records are in document order, so walking
    /// them backwards visits each node's descendants before the node itself.
    fn collapse(&mut self) {
        let count = self.records.len();
        let mut replacement: Vec<Vec<usize>> = vec![Vec::new(); count];
        let mut kids: Vec<Vec<usize>> = vec![Vec::new(); count];
        for node in (0..count).rev() {
            let role = self.role(node).to_string();
            let mut collapsed: Vec<usize> = if is_text_field(&role) {
                // Below a text field is only Chrome's inner editor holding
                // the value again, which must not print for a credential
                // field. A control inside one (rare, but a rich editor can
                // hold a link) stays reachable.
                let mut found = Vec::new();
                let mut pending: Vec<usize> = self.children[node].iter().rev().copied().collect();
                while let Some(child) = pending.pop() {
                    if is_actionable(self.role(child)) {
                        found.extend(replacement[child].iter().copied());
                    } else {
                        pending.extend(self.children[child].iter().rev().copied());
                    }
                }
                found
            } else {
                self.children[node]
                    .iter()
                    .flat_map(|child| replacement[*child].iter().copied())
                    .collect()
            };
            let own_name = &self.names[node];
            collapsed = collapsed
                .into_iter()
                .flat_map(|child| {
                    if self.role(child) == "StaticText"
                        && (self.names[child].is_empty()
                            || (!own_name.is_empty() && &self.names[child] == own_name))
                    {
                        // Only the redundant text disappears. A captured text
                        // node can still own controls or labelled descendants.
                        kids[child].clone()
                    } else {
                        vec![child]
                    }
                })
                .collect();
            replacement[node] = if node != 0 && is_wrapper(&role) && own_name.is_empty() {
                match collapsed.len() {
                    0 => Vec::new(),
                    1 => collapsed.clone(),
                    _ => vec![node],
                }
            } else {
                vec![node]
            };
            kids[node] = collapsed;
        }
        self.kids = kids;
    }

    fn classify(&mut self) {
        let count = self.records.len();
        let mut inherited = vec![NEUTRAL; count];
        let mut section = vec![None; count];
        for node in 1..count {
            let parent = self.parent[node].expect("only the page has no parent");
            let own = if self.is_landmark(node) {
                landmark_class(self.role(node))
            } else {
                NEUTRAL
            };
            inherited[node] = if own == NEUTRAL {
                inherited[parent]
            } else {
                own
            };
            section[node] = section[parent].or(self.is_landmark(node).then_some(node));
        }
        // A wrapper holding the main content gets the main content's rank,
        // so trimming to `max_bytes` never keeps a child line while dropping
        // the parent line it is indented under.
        let mut class = inherited;
        let mut below = vec![false; count];
        for node in (0..count).rev() {
            for &kid in &self.kids[node] {
                class[node] = class[node].min(class[kid]);
                below[node] |= self.is_landmark(kid) || below[kid];
            }
        }
        self.class = class;
        self.has_landmark_below = below;
        self.section = section;
    }

    /// The nearest text field containing `node`, if any.
    fn text_field_ancestor(&self, node: usize) -> Option<usize> {
        let mut current = self.parent[node];
        let mut found = None;
        while let Some(ancestor) = current {
            if is_text_field(self.role(ancestor)) {
                found = Some(ancestor);
            }
            current = self.parent[ancestor];
        }
        found
    }

    fn element_text(&self, node: usize, name_chars: usize) -> String {
        self.element_text_named(node, cap_chars(self.names[node].clone(), name_chars))
    }

    /// The element's line with `name` printed as its name.
    fn element_text_named(&self, node: usize, name: String) -> String {
        let role = self.role(node);
        let facts = self.facts(node);
        let mut text = String::new();
        if let Some(reference) = self.reference(node) {
            text.push_str(reference);
            text.push(' ');
        }
        text.push_str(display_role(role));
        let credential = facts.and_then(|facts| facts.credential);
        let mut states: Vec<&str> = facts
            .map(|facts| facts.states.iter().map(String::as_str).collect())
            .unwrap_or_default();
        if is_text_field(role) && credential == Some(true) {
            states.push("credential field");
        }
        if !states.is_empty() {
            text.push_str(" (");
            text.push_str(&states.join(", "));
            text.push(')');
        }
        if !name.is_empty() {
            text.push(' ');
            text.push_str(&name);
        }
        let shown_value = self.shown_value(node);
        if let Some(value) = shown_value.filter(|value| !value.is_empty()) {
            text.push_str(", Value: ");
            text.push_str(&cap_chars(value, NAME_CHARS));
        }
        if is_text_field(role) {
            if let Some(placeholder) = facts
                .and_then(|facts| facts.placeholder.as_deref())
                .map(one_line)
                .filter(|placeholder| !placeholder.is_empty() && placeholder != &self.names[node])
            {
                text.push_str(", Placeholder: ");
                text.push_str(&cap_chars(placeholder, NAME_CHARS));
            }
        }
        text
    }

    fn shown_value(&self, node: usize) -> Option<String> {
        let role = self.role(node);
        let facts = self.facts(node);
        let value = self.records[node].and_then(|record| record.value.as_deref());
        if role == "link" {
            facts
                .and_then(|facts| facts.url.as_deref())
                .and_then(short_url)
        } else if is_text_field(role) {
            // Reveal a field's value only when its DOM facts establish that it
            // is neither a credential nor a payment field. Text filtering uses
            // the same redaction so it cannot confirm a hidden value.
            value
                .filter(|_| facts.and_then(|facts| facts.credential) == Some(false))
                .map(one_line)
        } else if is_value_control(role) {
            value.map(one_line)
        } else {
            None
        }
    }

    fn name_chars(&self, node: usize) -> usize {
        if self.role(node) == "StaticText" {
            TEXT_CHARS
        } else {
            NAME_CHARS
        }
    }

    /// The line a zoom prints for `node` when it is a single element (any
    /// children it has are text leaves) whose usual cap cut its name: the
    /// whole stored name, up to [`MAX_NAME_BYTES`], in a line of at most
    /// `room` bytes. A row's Copy button can carry a whole JSON event in its
    /// name, and a zoom on it is how an agent reads that. A name still cut,
    /// by `room` or because the capture stored it at its byte limit, ends
    /// with a marker saying so.
    ///
    /// `None` when the cap cut nothing, when `node` holds other elements (a
    /// container's name repeats the subtree it heads, see [`NAME_CHARS`]), or
    /// when `room` holds no more of the name than the capped line does.
    fn full_name_text(&self, node: usize, room: usize) -> Option<String> {
        let name = &self.names[node];
        if name.chars().count() <= self.name_chars(node)
            || self.kids[node]
                .iter()
                .any(|&kid| self.role(kid) != "StaticText" || !self.kids[kid].is_empty())
        {
            return None;
        }
        // The capture cuts a longer name to `MAX_NAME_BYTES` on a character
        // boundary, so a stored name within one character (at most four
        // bytes) of that limit may have been cut there.
        let stored = self.records[node].map_or(0, |record| record.name.len());
        let mut cut = stored + 4 > MAX_NAME_BYTES;
        let mut shown = truncate_ax_field(name, MAX_NAME_BYTES);
        cut |= shown.len() < name.len();
        let capped = self.element_text(node, self.name_chars(node));
        loop {
            let printed = if cut {
                format!("{shown}… [name cut at {} bytes]", shown.len())
            } else {
                shown.clone()
            };
            let text = self.element_text_named(node, printed);
            if text.len() <= room {
                return (text.len() > capped.len()).then_some(text);
            }
            let over = text.len() - room;
            if over >= shown.len() {
                return None;
            }
            shown = truncate_ax_field(&shown, shown.len() - over);
            cut = true;
        }
    }

    fn line(&self, node: usize, depth: usize, mut text: String) -> Line {
        if let Some(reference) = self.reference(node) {
            self.notices.append_inline(&mut text, reference, self.facts);
        }
        Line {
            depth,
            text,
            class: self.class[node],
            refs: self
                .reference(node)
                .map(str::to_string)
                .into_iter()
                .collect(),
            section: self.section[node],
            covered: 1,
            covered_bytes: None,
        }
    }

    /// The element and everything below it, nothing folded: a zoom.
    fn full_lines(&self, node: usize, depth: usize, out: &mut Vec<Line>) {
        out.push(self.line(node, depth, self.element_text(node, self.name_chars(node))));
        for &kid in &self.kids[node] {
            self.full_lines(kid, depth + 1, out);
        }
    }

    /// Whether `node` itself satisfies the filters. Only the label and the
    /// value the line can reveal are matched.
    fn matches(&self, node: usize, filters: &Filters) -> bool {
        let role = self.role(node);
        let role_match = filters.roles.is_empty()
            || filters.roles.iter().any(|wanted| {
                let wanted = wanted.trim();
                wanted
                    .strip_prefix("AX")
                    .unwrap_or(wanted)
                    .eq_ignore_ascii_case(role)
                    || wanted.eq_ignore_ascii_case(display_role(role))
            });
        let text_match = filters.text.as_ref().is_none_or(|wanted| {
            let wanted = wanted.to_lowercase();
            self.names[node].to_lowercase().contains(&wanted)
                || self
                    .shown_value(node)
                    .is_some_and(|value| value.to_lowercase().contains(&wanted))
        });
        role_match && text_match
    }

    /// The leaf nodes and their texts when `node`'s subtree is small and plain
    /// text only. Nested wrappers are allowed so a property line can wrap its
    /// key and value separately, and table cells can wrap their text.
    ///
    /// `None` when the subtree contains a control or a text field (whose ref
    /// or withheld value a joined line would lose), the page or a landmark
    /// (a list or a table is a region, not a row), or more than [`ROW_LEAVES`]
    /// leaves or [`ROW_BYTES`] bytes. A subtree of a single leaf is accepted,
    /// though it never holds a second leaf for a match to print with.
    ///
    /// A key chip of the match `matched` (see `is_key_chip`) is part of the
    /// key, not a control that refuses the row; the returned flag says the
    /// row holds one, so the caller prints it with its refs rather than as
    /// one joined line that would drop the chip's ref.
    fn leaf_row(&self, node: usize, matched: usize) -> Option<(Vec<(usize, String)>, bool)> {
        if node == 0 || self.is_landmark(node) {
            return None;
        }
        self.leaf_row_of(&[node], matched)
    }

    /// `leaf_row` over several sibling subtrees taken together, as one row:
    /// the leaves of `roots`, in order, under the same refusals and bounds.
    fn leaf_row_of(&self, roots: &[usize], matched: usize) -> Option<(Vec<(usize, String)>, bool)> {
        // Keep sibling iterators rather than enqueueing entire wide containers:
        // the row limits usually reject them after only a few leaves.
        let mut pending = vec![roots.iter()];
        let mut texts = Vec::new();
        let mut bytes = 0;
        let mut leaves = 0;
        let mut holds_chip = false;
        while let Some(siblings) = pending.last_mut() {
            let Some(&kid) = siblings.next() else {
                pending.pop();
                continue;
            };
            let role = self.role(kid);
            let chip = self.is_key_chip(kid, matched);
            holds_chip |= chip;
            if self.is_landmark(kid)
                || (is_actionable(role) && !chip)
                || is_text_field(role)
                || is_value_control(role)
            {
                return None;
            }
            if !self.kids[kid].is_empty() {
                pending.push(self.kids[kid].iter());
                continue;
            }
            leaves += 1;
            if leaves > ROW_LEAVES {
                return None;
            }
            let mut text = self.names[kid].clone();
            if let Some(value) = self.shown_value(kid).filter(|value| !value.is_empty()) {
                if !text.is_empty() {
                    text.push(' ');
                }
                text.push_str(&value);
            }
            if text.is_empty() {
                continue;
            }
            bytes += text.len() + 1;
            if bytes > ROW_BYTES {
                return None;
            }
            texts.push((kid, text));
        }
        Some((texts, holds_chip))
    }

    /// Whether `node` is a control that is only the match's own key: the
    /// match lies strictly inside it, and the letters and digits of all the
    /// text below it are exactly the match's. A JSON viewer renders each key
    /// as a click-to-filter chip holding `'event':` (the key between quotes
    /// and a colon), and a filter on `event` matches the text inside it; the
    /// chip belongs to that key rather than being a separate control beside
    /// it. A control that is itself the match is never a key chip; a row block
    /// around it may still print it with a label beside it. Text fields and
    /// value controls are never key chips, even when their values are shown.
    fn is_key_chip(&self, node: usize, matched: usize) -> bool {
        let role = self.role(node);
        if node == matched || !is_actionable(role) || is_text_field(role) || is_value_control(role)
        {
            return false;
        }
        let key = content_chars(&self.names[matched]);
        if key.is_empty() {
            return false;
        }
        let mut inside = false;
        let mut current = self.parent[matched];
        while let Some(ancestor) = current {
            if ancestor == node {
                inside = true;
                break;
            }
            current = self.parent[ancestor];
        }
        if !inside {
            return false;
        }
        let mut text = String::new();
        let mut leaves = 0;
        let mut pending = vec![node];
        while let Some(kid) = pending.pop() {
            if self.kids[kid].is_empty() {
                // A chip holds one key, so a larger subtree is never one;
                // stopping early keeps the check cheap on large controls.
                leaves += 1;
                text.push_str(&content_chars(&self.names[kid]));
                if leaves > ROW_LEAVES || text.len() > key.len() {
                    return false;
                }
            } else {
                pending.extend(self.kids[kid].iter().rev().copied());
            }
        }
        text == key
    }

    /// The row block a match prints with: its nearest ancestor (in the
    /// printed tree, `ancestors` running from the outermost) that holds at
    /// least one control and at least one text or label, at least one of
    /// which lies outside the match itself. A name matched inside an app's
    /// row then prints with the row's `Configure` link, and a matched
    /// `Configure` link prints with the app's name.
    ///
    /// `None` when no ancestor qualifies before the climb reaches the page, a
    /// landmark (a list or a region is not one item of it), a table part (a
    /// table keeps its joined rows, see `leaf_row`), or an ancestor larger
    /// than [`ROW_LEAVES`] leaves or [`ROW_BYTES`] bytes of leaf text. Every
    /// further ancestor is at least as large, so the climb stops there.
    fn row_block(&self, matched: usize, ancestors: &[usize]) -> Option<usize> {
        for &ancestor in ancestors.iter().rev() {
            if ancestor == 0 || self.is_landmark(ancestor) || is_table_part(self.role(ancestor)) {
                return None;
            }
            if self.is_row_block(ancestor, matched)? {
                return Some(ancestor);
            }
        }
        None
    }

    /// Whether `node`'s subtree is a row block for the match `matched` (see
    /// `row_block`), or `None` when it is too large or holds a landmark or a
    /// table part. For qualifying, a text inside a control is that control's
    /// label, not a separate label; it still counts toward the leaf and byte
    /// limits. A key chip (see `is_key_chip`) counts as part of the match, and
    /// its text as a label: the key is the label its value prints with.
    fn is_row_block(&self, node: usize, matched: usize) -> Option<bool> {
        // Each frame walks siblings lazily in capture order, with their
        // inherited match/control state. Oversized containers need not enqueue
        // every child before the leaf and byte limits can reject them.
        let root = [node];
        let mut pending = vec![(root.iter(), false, false)];
        let (mut control, mut label, mut beside_match) = (false, false, false);
        let (mut leaves, mut bytes) = (0, 0);
        while let Some((siblings, in_match, in_control)) = pending.last_mut() {
            let Some(&kid) = siblings.next() else {
                pending.pop();
                continue;
            };
            let (in_match, in_control) = (*in_match, *in_control);
            let role = self.role(kid);
            if kid != node && (self.is_landmark(kid) || is_table_part(role)) {
                return None;
            }
            let chip = self.is_key_chip(kid, matched);
            let in_match = in_match || kid == matched || chip;
            let actionable = is_actionable(role);
            let labelled = (!actionable || chip)
                && !in_control
                && self.names[kid].chars().any(char::is_alphanumeric);
            control |= actionable;
            label |= labelled;
            beside_match |= (actionable || labelled) && !in_match;
            if !self.kids[kid].is_empty() {
                pending.push((
                    self.kids[kid].iter(),
                    in_match,
                    in_control || (actionable && !chip),
                ));
                continue;
            }
            leaves += 1;
            if leaves > ROW_LEAVES {
                return None;
            }
            // Measured as `leaf_row` measures a leaf: its name and shown
            // value joined by a space, plus one separating space.
            let name = self.names[kid].len();
            let value = self.shown_value(kid).map_or(0, |value| value.len());
            let text = name + value + usize::from(name > 0 && value > 0);
            if text > 0 {
                bytes += text + 1;
                if bytes > ROW_BYTES {
                    return None;
                }
            }
        }
        Some(control && label && beside_match)
    }

    /// The ignored ancestors the capture recorded for `node` (see
    /// `NodeFacts::ignored_ancestors`); empty for a node without a ref.
    fn ignored_ancestors(&self, node: usize) -> &'a [String] {
        self.facts(node)
            .map_or(&[][..], |facts| facts.ignored_ancestors.as_slice())
    }

    /// The child of `owner` (in the record tree) that holds `node`, or `node`
    /// itself when it is one.
    fn child_holding(&self, owner: usize, node: usize) -> Option<usize> {
        let mut current = node;
        loop {
            let parent = self.parent[current]?;
            if parent == owner {
                return Some(current);
            }
            current = parent;
        }
    }

    /// For each printed node and ignored wrapper id, the node's printed
    /// children that the capture recorded inside that wrapper, in order: a
    /// printed child belongs when the record-tree child of the node holding
    /// it lists the wrapper among its ignored ancestors. Built once, on a
    /// filter's first use, in
    /// one pass over the printed tree, so finding a wrapper's members costs
    /// the wrapper's size rather than a scan of every sibling: a log page can
    /// hold thousands of texts under one container, and a broad filter
    /// matches most of them.
    fn wrapper_kids(&self) -> &HashMap<(usize, &'a str), Vec<usize>> {
        self.wrapper_kids.get_or_init(|| {
            let mut index: HashMap<(usize, &'a str), Vec<usize>> = HashMap::new();
            for (owner, kids) in self.kids.iter().enumerate() {
                for &kid in kids {
                    let Some(child) = self.child_holding(owner, kid) else {
                        continue;
                    };
                    for wrapper in self.ignored_ancestors(child) {
                        let members = index.entry((owner, wrapper.as_str())).or_default();
                        // A wrapper listed twice in one chain still holds
                        // the node once.
                        if members.last() != Some(&kid) {
                            members.push(kid);
                        }
                    }
                }
            }
            index
        })
    }

    /// The row a matching leaf `matched` prints with when no ancestor in the
    /// printed tree makes one: the smallest ignored wrapper around it whose
    /// leaves include another leaf with a letter or digit, within
    /// [`ROW_LEAVES`] and [`ROW_BYTES`]. Chrome ignores the plain `<div>` and
    /// `<span>` elements a JSON viewer draws each property line from, so the
    /// texts of every line (`"`, `event`, `":`, `"boat_start_timeout"`) hang
    /// off the viewer's one container, which is far too large to be a row.
    /// The ignored ancestors the capture keeps for each element (see
    /// `NodeFacts::ignored_ancestors`) still say which of those texts one
    /// line's wrapper held.
    ///
    /// Returns the printed node the row prints in place of (the one holding
    /// the match, so a matched key keeps its ref), every printed node the
    /// wrapper holds, and the row. A wrapper holding a key chip (see
    /// `is_key_chip`) prints element by element so the chip keeps its ref.
    ///
    /// The search goes outward one wrapper at a time, from the match's own
    /// wrappers to those of each recorded ancestor, and stops at the first
    /// wrapper or ancestor `leaf_row` refuses (every further one is at least
    /// as large), at a landmark, and at the page.
    fn ignored_group_row(&self, matched: usize) -> Option<(usize, Vec<usize>, FilterRow)> {
        let mut node = matched;
        loop {
            if node == 0 {
                return None;
            }
            if self.is_landmark(node) {
                return None;
            }
            let owner = self.parent[node]?;
            for wrapper in self.ignored_ancestors(node) {
                // The wrapper's printed nodes: those of the owner's children
                // that the capture recorded inside it.
                let roots: &[usize] = self
                    .wrapper_kids()
                    .get(&(owner, wrapper.as_str()))
                    .map_or(&[], Vec::as_slice);
                let (texts, holds_chip) = self.leaf_row_of(roots, matched)?;
                if !texts
                    .iter()
                    .any(|(leaf, text)| *leaf != matched && text.chars().any(char::is_alphanumeric))
                {
                    continue;
                }
                let anchor = roots
                    .iter()
                    .copied()
                    .find(|&root| root == matched || self.child_holding(root, matched).is_some())?;
                let row = if holds_chip {
                    FilterRow::Members(roots.to_vec())
                } else {
                    FilterRow::Joined(
                        texts
                            .into_iter()
                            .map(|(_, text)| text)
                            .collect::<Vec<_>>()
                            .join(" "),
                    )
                };
                return Some((anchor, roots.to_vec(), row));
            }
            self.leaf_row(owner, matched)?;
            node = owner;
        }
    }

    /// Give each match a row to print with. A match inside a row block (see
    /// `row_block`) prints that whole block. Otherwise a matching leaf gets its
    /// nearest ancestor that `leaf_row` accepts and
    /// that holds another leaf with a letter or digit, so a key prints with its
    /// value. Quotes and separators alone do not count. The climb stops at the
    /// first ancestor `leaf_row` rejects, and never goes past the nearest
    /// accepted one, because a larger ancestor can pull in neighbouring
    /// properties. A row holding the key's chip prints element by element, so
    /// the chip keeps its ref and can still be clicked. A leaf that finds no
    /// such ancestor may still print with the texts sharing an ignored wrapper
    /// with it (see `ignored_group_row`).
    fn collect_filter_rows(
        &self,
        node: usize,
        filters: &Filters,
        ancestors: &mut Vec<usize>,
        rows: &mut HashMap<usize, FilterRow>,
    ) {
        let matched = self.matches(node, filters);
        if matches!(rows.get(&node), Some(FilterRow::Covered)) {
            // An earlier match's row already prints this subtree.
            return;
        }
        if let Some(block) = matched.then(|| self.row_block(node, ancestors)).flatten() {
            rows.insert(block, FilterRow::Block);
        } else if self.kids[node].is_empty() && matched {
            let mut found = false;
            for &ancestor in ancestors.iter().rev() {
                let Some((texts, holds_chip)) = self.leaf_row(ancestor, node) else {
                    break;
                };
                if texts
                    .iter()
                    .any(|(leaf, text)| *leaf != node && text.chars().any(char::is_alphanumeric))
                {
                    let row = if holds_chip {
                        FilterRow::Block
                    } else {
                        FilterRow::Joined(
                            texts
                                .into_iter()
                                .map(|(_, text)| text)
                                .collect::<Vec<_>>()
                                .join(" "),
                        )
                    };
                    rows.insert(ancestor, row);
                    found = true;
                    break;
                }
            }
            if !found {
                if let Some((anchor, roots, row)) = self.ignored_group_row(node) {
                    for root in roots {
                        if root != anchor {
                            rows.insert(root, FilterRow::Covered);
                        }
                    }
                    rows.insert(anchor, row);
                }
            }
        }
        ancestors.push(node);
        for &kid in &self.kids[node] {
            self.collect_filter_rows(kid, filters, ancestors, rows);
        }
        ancestors.pop();
    }

    /// Match only the label and the value the line can reveal. Walking the
    /// collapsed tree keeps inner editors from becoming a secret-value oracle.
    fn filtered_lines(
        &self,
        node: usize,
        depth: usize,
        filters: &Filters,
        out: &mut Vec<Line>,
    ) -> bool {
        let mut rows = HashMap::new();
        if filters.text.is_some() {
            self.collect_filter_rows(node, filters, &mut Vec::new(), &mut rows);
        }
        self.filtered_lines_with_rows(node, depth, filters, &rows, out)
    }

    fn filtered_lines_with_rows(
        &self,
        node: usize,
        depth: usize,
        filters: &Filters,
        rows: &HashMap<usize, FilterRow>,
        out: &mut Vec<Line>,
    ) -> bool {
        match rows.get(&node) {
            Some(FilterRow::Joined(texts)) => {
                let mut text = self
                    .reference(node)
                    .map(|reference| format!("{reference} "))
                    .unwrap_or_default();
                text.push_str(texts);
                out.push(self.line(node, depth, text));
                return true;
            }
            Some(FilterRow::Block) => {
                self.full_lines(node, depth, out);
                return true;
            }
            Some(FilterRow::Members(roots)) => {
                for &root in roots {
                    self.full_lines(root, depth, out);
                }
                return true;
            }
            Some(FilterRow::Covered) => return false,
            None => {}
        }
        let line = self.element_text(node, self.name_chars(node));
        let matched = self.matches(node, filters);
        let labelled = !self.names[node].is_empty();
        let start = out.len();
        if matched || labelled {
            out.push(self.line(node, depth, line));
        }
        let mut below = false;
        for &kid in &self.kids[node] {
            below |= self.filtered_lines_with_rows(
                kid,
                depth + usize::from(matched || labelled),
                filters,
                rows,
                out,
            );
        }
        if !matched && !below {
            out.truncate(start);
        }
        matched || below
    }

    /// The element and everything below it with repeated siblings folded:
    /// how the outline prints a small region.
    fn folded_lines(&self, node: usize, depth: usize, out: &mut Vec<Line>) {
        // The outline keeps every article to its one line even inside a
        // region small enough to print in full; see `emit_landmark`.
        if self.role(node) == "article" {
            out.push(self.summary_line(node, depth));
            return;
        }
        out.push(self.line(node, depth, self.element_text(node, self.name_chars(node))));
        for item in self.fold(&self.kids[node]) {
            match item {
                Item::Node(kid) => self.folded_lines(kid, depth + 1, out),
                Item::More(members) => out.push(self.more_line(&members, node, depth + 1)),
            }
        }
    }

    /// Group siblings by role and name shape; a group larger than the
    /// threshold keeps its first member and folds the rest behind it.
    fn fold(&self, siblings: &[usize]) -> Vec<Item> {
        let key = |node: usize| (display_role(self.role(node)), shape(&self.names[node]));
        let mut groups: HashMap<_, Vec<usize>> = HashMap::new();
        for &node in siblings {
            groups.entry(key(node)).or_default().push(node);
        }
        let mut items = Vec::new();
        for &node in siblings {
            let members = &groups[&key(node)];
            if members.len() <= REPEAT_THRESHOLD {
                items.push(Item::Node(node));
            } else if members[0] == node {
                items.push(Item::Node(node));
                items.push(Item::More(members[1..].to_vec()));
            }
        }
        items
    }

    fn more_line(&self, members: &[usize], owner: usize, depth: usize) -> Line {
        let mut text = format!(
            "+{} more {} like this",
            members.len(),
            display_role(self.role(members[0]))
        );
        let mut refs = Vec::new();
        if let Some(reference) = self.reference(owner) {
            text.push_str("; zoom ");
            text.push_str(reference);
            self.notices.append_inline(&mut text, reference, self.facts);
            refs.push(reference.to_string());
        }
        let sizes: Vec<_> = members
            .iter()
            .map(|member| self.zoom_size(*member))
            .collect();
        Line {
            depth,
            text,
            class: self.class[members[0]],
            refs,
            section: self.section[members[0]],
            covered: sizes.iter().map(|size| size.0).sum(),
            covered_bytes: Some(sizes.iter().map(|size| size.1).sum()),
        }
    }

    /// Bytes and lines a zoom on `node` would print.
    fn zoom_size(&self, node: usize) -> (usize, usize) {
        let mut lines = Vec::new();
        self.full_lines(node, 0, &mut lines);
        (lines.len(), lines.iter().map(Line::bytes).sum())
    }

    fn summary_line(&self, node: usize, depth: usize) -> Line {
        let (lines, bytes) = self.zoom_size(node);
        let text = format!(
            "{} · {} lines, {}",
            self.element_text(node, OUTLINE_NAME_CHARS),
            lines,
            size_text(bytes)
        );
        let mut line = self.line(node, depth, text);
        line.covered = lines;
        line.covered_bytes = Some(bytes);
        line
    }

    /// Look through unlabelled layout wrappers to find landmarks. Named or
    /// semantic containers keep their own row, even when they hold a landmark.
    fn entries(&self, nodes: &[usize]) -> Vec<usize> {
        let mut entries = Vec::new();
        for &node in nodes {
            if self.is_landmark(node)
                || !self.has_landmark_below[node]
                || !is_wrapper(self.role(node))
                || !self.names[node].is_empty()
            {
                entries.push(node);
            } else {
                entries.extend(self.entries(&self.kids[node]));
            }
        }
        entries
    }

    fn outline_lines(&self) -> Vec<Line> {
        let mut entries = self.entries(&self.kids[0]);
        // Main content first, chrome last; document order within each.
        entries.sort_by_key(|entry| self.class[*entry]);
        let mut out = Vec::new();
        self.emit_level(&entries, 0, 0, TOP_LOOSE_BYTES, &mut out);
        out
    }

    fn emit_level(
        &self,
        entries: &[usize],
        depth: usize,
        owner: usize,
        loose_budget: usize,
        out: &mut Vec<Line>,
    ) {
        let mut loose_used = 0;
        let mut hidden: Option<(usize, usize)> = None;
        let mut previous_hidden = false;
        for item in self.fold(entries) {
            match item {
                Item::Node(node) if self.is_landmark(node) => {
                    previous_hidden = false;
                    self.emit_landmark(node, depth, out);
                }
                Item::Node(node) if self.has_landmark_below[node] => {
                    previous_hidden = false;
                    out.push(self.line(node, depth, self.element_text(node, OUTLINE_NAME_CHARS)));
                    let mut entries = self.entries(&self.kids[node]);
                    entries.sort_by_key(|entry| self.class[*entry]);
                    self.emit_level(&entries, depth + 1, node, loose_budget, out);
                }
                Item::Node(node) => {
                    let mut lines = Vec::new();
                    self.folded_lines(node, depth, &mut lines);
                    let bytes: usize = lines.iter().map(Line::bytes).sum();
                    if hidden.is_none() && loose_used + bytes <= loose_budget {
                        loose_used += bytes;
                        out.extend(lines);
                        previous_hidden = false;
                    } else {
                        // Once one loose element (content outside any nested
                        // landmark) does not fit its allowance, the later ones
                        // stay hidden too, so nothing prints after a hidden one.
                        let (lines, bytes) = self.zoom_size(node);
                        let total = hidden.get_or_insert((0, 0));
                        total.0 += lines;
                        total.1 += bytes;
                        previous_hidden = true;
                    }
                }
                Item::More(members) => {
                    if previous_hidden {
                        let total = hidden.get_or_insert((0, 0));
                        for member in members {
                            let (lines, bytes) = self.zoom_size(member);
                            total.0 += lines;
                            total.1 += bytes;
                        }
                    } else {
                        out.push(self.more_line(&members, owner, depth));
                    }
                }
            }
        }
        if let Some((lines, bytes)) = hidden {
            let mut text = format!("… {lines} more lines, {} not shown", size_text(bytes));
            let mut refs = Vec::new();
            if let Some(reference) = self.reference(owner) {
                text.push_str("; zoom ");
                text.push_str(reference);
                self.notices.append_inline(&mut text, reference, self.facts);
                refs.push(reference.to_string());
            }
            out.push(Line {
                depth,
                text,
                class: if owner == 0 {
                    NEUTRAL
                } else {
                    self.class[owner]
                },
                refs,
                section: self.section[owner],
                covered: lines,
                covered_bytes: Some(bytes),
            });
        }
    }

    fn emit_landmark(&self, node: usize, depth: usize, out: &mut Vec<Line>) {
        // An article is one post or story; Chrome names it with its whole
        // text, so its one line already reads it and a zoom shows the rest.
        if self.role(node) == "article" {
            out.push(self.summary_line(node, depth));
            return;
        }
        let mut lines = Vec::new();
        self.folded_lines(node, depth, &mut lines);
        if lines.iter().map(Line::bytes).sum::<usize>() <= INLINE_BYTES {
            out.extend(lines);
            return;
        }
        let mut summary = self.summary_line(node, depth);
        summary.covered = 1;
        summary.covered_bytes = None;
        out.push(summary);
        let entries = self.entries(&self.kids[node]);
        self.emit_level(&entries, depth + 1, node, NESTED_LOOSE_BYTES, out);
    }
}

/// An outline row may stand for a whole subtree. If the final byte budget
/// removes that row, carry its hidden nodes into a new disclosure under the
/// nearest surviving parent with a reference, rather than counting only the
/// removed row.
fn fit_outline(
    header: String,
    mut lines: Vec<Line>,
    tree: &Tree<'_>,
    max_bytes: usize,
) -> RenderedState {
    if lines.iter().any(|line| line.covered_bytes.is_some()) {
        // Per-container rows account for the folded nodes. A final reminder
        // keeps that disclosure visible even when a later landmark is expanded.
        lines.push(Line {
            depth: 0,
            text: "[outline: content is folded into the summaries above; use zoom on a container ref to read it]".into(),
            class: CHROME,
            refs: Vec::new(),
            section: None,
            covered: 0,
            covered_bytes: Some(0),
        });
    }
    if header.len() + 1 + lines.iter().map(Line::bytes).sum::<usize>() <= max_bytes {
        return fit(header, Vec::new(), lines, tree, max_bytes);
    }

    let mut parents = vec![None; lines.len()];
    let mut ends = vec![lines.len(); lines.len()];
    let mut stack: Vec<usize> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        while stack
            .last()
            .is_some_and(|&parent| lines[parent].depth >= line.depth)
        {
            ends[stack.pop().expect("a parent was present")] = index;
        }
        parents[index] = stack.last().copied();
        stack.push(index);
    }

    let mut order: Vec<usize> = (0..lines.len()).collect();
    order.sort_by_key(|&index| (lines[index].class, index));
    let (mut keep, mut header_kept, _) = select_lines(header.len() + 1, &lines, tree, max_bytes);
    order.retain(|&index| keep[index]);
    loop {
        // Slot zero holds cuts outside a surviving, referenced parent. Other
        // slots belong to that parent's row and are printed before it closes.
        let mut cuts = vec![(0_usize, 0_usize); lines.len() + 1];
        for (index, line) in lines.iter().enumerate().filter(|(index, _)| !keep[*index]) {
            let mut parent = parents[index];
            while let Some(owner) = parent {
                if keep[owner] && !lines[owner].refs.is_empty() {
                    break;
                }
                parent = parents[owner];
            }
            let cut = &mut cuts[parent.map_or(0, |owner| owner + 1)];
            cut.0 += line.covered;
            cut.1 += line.covered_bytes.unwrap_or_else(|| line.bytes());
        }
        if !header_kept {
            cuts[0].0 += 1;
            cuts[0].1 += header.len() + 1;
        }
        let mut disclosures = Vec::new();
        for (slot, &(count, bytes)) in cuts.iter().enumerate().rev().filter(|(_, cut)| cut.0 > 0) {
            let (at, depth, reference) = if slot == 0 {
                (lines.len(), 0, tree.reference(0))
            } else {
                let owner = slot - 1;
                (
                    ends[owner],
                    lines[owner].depth + 1,
                    Some(lines[owner].refs[0].as_str()),
                )
            };
            let mut text = format!(
                "{}… {count} more lines, {} not shown",
                "  ".repeat(depth),
                size_text(bytes)
            );
            if let Some(reference) = reference {
                text.push_str("; zoom ");
                text.push_str(reference);
            }
            disclosures.push((at, text, reference));
        }
        // Inner parents close before outer parents at the same position.
        disclosures.sort_by_key(|(at, _, _)| *at);
        let mut text = String::new();
        let mut printed_refs = BTreeSet::new();
        if header_kept {
            text.push_str(&header);
            text.push('\n');
        }
        let mut disclosures = disclosures.into_iter().peekable();
        let mut ended_with_disclosure = false;
        for index in 0..=lines.len() {
            while disclosures.peek().is_some_and(|(at, _, _)| *at == index) {
                let (_, disclosure, reference) =
                    disclosures.next().expect("a disclosure was present");
                text.push_str(&disclosure);
                text.push('\n');
                ended_with_disclosure = true;
                if let Some(reference) = reference {
                    printed_refs.insert(reference.to_string());
                }
            }
            if index < lines.len() && keep[index] {
                let line = &lines[index];
                text.push_str(&"  ".repeat(line.depth));
                text.push_str(&line.text);
                text.push('\n');
                printed_refs.extend(line.refs.iter().cloned());
                ended_with_disclosure = line.covered == 0;
            }
        }
        if !ended_with_disclosure {
            text.push_str(&cut_report(&lines, &keep, tree, max_bytes));
            text.push('\n');
        }
        if text.len() <= max_bytes || (!header_kept && order.is_empty()) {
            // No readable disclosure fits a cap smaller than the disclosure
            // itself. The reply's omitted counters still describe that case.
            if text.len() > max_bytes {
                text = compact_cut_report(lines.len() + 1, max_bytes);
                printed_refs.clear();
            }
            return RenderedState {
                text,
                printed_refs,
                cut_bytes: lines
                    .iter()
                    .zip(&keep)
                    .filter(|(_, kept)| !**kept)
                    .map(|(line, _)| line.bytes())
                    .sum::<usize>()
                    + if header_kept { 0 } else { header.len() + 1 },
                cut_lines: keep.iter().filter(|kept| !**kept).count() + usize::from(!header_kept),
            };
        }
        // Drop the lowest-priority suffix, never content to admit chrome.
        // Recompute disclosures after each batch: removing a parent coalesces
        // all its children's cuts into the parent's own surviving ancestor.
        let mut removed = 0;
        let overflow = text.len() - max_bytes;
        while removed < overflow {
            if let Some(index) = order.pop() {
                keep[index] = false;
                removed += lines[index].bytes();
            } else {
                header_kept = false;
                break;
            }
        }
    }
}

/// Keep the text within `max_bytes`. The header goes first, then lines by
/// class (content, then neutral, then chrome) in display order, so the page's
/// main content survives a small budget and the navigation goes first. A
/// line's class is never better than its parent's, so a kept line's parent is
/// always kept too. The final line says what was cut.
fn fit(
    header: String,
    header_refs: Vec<String>,
    lines: Vec<Line>,
    tree: &Tree<'_>,
    max_bytes: usize,
) -> RenderedState {
    let header_bytes = header.len() + 1;
    let (keep, header_kept, trailer) = select_lines(header_bytes, &lines, tree, max_bytes);

    let mut text = String::new();
    let mut printed_refs = BTreeSet::new();
    if header_kept {
        text.push_str(&header);
        text.push('\n');
        printed_refs.extend(header_refs);
    }
    let mut cut_bytes = 0;
    let mut cut_lines = 0;
    for (line, kept) in lines.iter().zip(&keep) {
        if *kept {
            for _ in 0..line.depth {
                text.push_str("  ");
            }
            text.push_str(&line.text);
            text.push('\n');
            printed_refs.extend(line.refs.iter().cloned());
        } else {
            cut_bytes += line.bytes();
            cut_lines += 1;
        }
    }
    if !header_kept {
        cut_bytes += header_bytes;
        cut_lines += 1;
    }
    // A budget too small for the report leaves it out whole rather than
    // printing half a sentence; the reply's `omitted` counts still say it.
    if cut_lines > 0 && text.len() + trailer.len() < max_bytes {
        text.push_str(&trailer);
        text.push('\n');
    } else if cut_lines > 0 {
        // Tiny budgets cannot hold the section list. Never spend the remaining
        // space on undisclosed content; keep a short whole disclosure instead.
        text = compact_cut_report(lines.len() + 1, max_bytes);
        printed_refs.clear();
        cut_lines = lines.len() + 1;
        cut_bytes = header_bytes + lines.iter().map(Line::bytes).sum::<usize>();
    }
    RenderedState {
        text,
        printed_refs,
        cut_bytes,
        cut_lines,
    }
}

fn compact_cut_report(lines: usize, max_bytes: usize) -> String {
    let text = format!("[cut {lines} lines; zoom or raise max_bytes]\n");
    if text.len() <= max_bytes {
        text
    } else {
        String::new()
    }
}

fn select_lines(
    header_bytes: usize,
    lines: &[Line],
    tree: &Tree<'_>,
    max_bytes: usize,
) -> (Vec<bool>, bool, String) {
    let total = header_bytes + lines.iter().map(Line::bytes).sum::<usize>();
    let mut order: Vec<usize> = (0..lines.len()).collect();
    order.sort_by_key(|index| (lines[*index].class, *index));

    let mut keep = vec![true; lines.len()];
    let mut trailer = String::new();
    let mut header_kept = total <= max_bytes || header_bytes <= max_bytes;
    if total > max_bytes {
        let mut reserve = 0;
        loop {
            let budget = max_bytes.saturating_sub(reserve);
            keep = vec![false; lines.len()];
            header_kept = header_bytes <= budget;
            let mut used = if header_kept { header_bytes } else { 0 };
            if header_kept {
                for &index in &order {
                    let bytes = lines[index].bytes();
                    if used + bytes > budget {
                        break;
                    }
                    used += bytes;
                    keep[index] = true;
                }
            }
            trailer = cut_report(lines, &keep, tree, max_bytes);
            if trailer.len() < reserve {
                break;
            }
            // Reserving monotonically avoids both a fixed retry limit and
            // oscillation when the omitted-section names change at a boundary.
            reserve = reserve.max(trailer.len() + 1);
        }
    }

    (keep, header_kept, trailer)
}

/// One line naming what the budget removed, by the landmark it belonged to.
fn cut_report(lines: &[Line], keep: &[bool], tree: &Tree<'_>, max_bytes: usize) -> String {
    const LISTED: usize = 6;
    let mut sections: Vec<(Option<usize>, bool)> = Vec::new();
    let mut cut_lines = 0;
    let mut cut_bytes = 0;
    for (line, kept) in lines.iter().zip(keep) {
        if *kept {
            continue;
        }
        cut_lines += 1;
        cut_bytes += line.bytes();
        if !sections.iter().any(|(section, _)| *section == line.section) {
            let whole = lines
                .iter()
                .zip(keep)
                .filter(|(other, _)| other.section == line.section)
                .all(|(_, kept)| !kept);
            sections.push((line.section, whole));
        }
    }
    let mut names: Vec<String> = sections
        .iter()
        .take(LISTED)
        .map(|(section, whole)| {
            let label = match section {
                Some(node) => match tree.reference(*node) {
                    Some(reference) => format!("{} {reference}", display_role(tree.role(*node))),
                    None => display_role(tree.role(*node)).to_string(),
                },
                None => "other content".to_string(),
            };
            format!("{label} ({})", if *whole { "all" } else { "partly" })
        })
        .collect();
    if sections.len() > LISTED {
        names.push(format!("{} more", sections.len() - LISTED));
    }
    format!(
        "[cut {cut_lines} lines, {} to fit max_bytes {max_bytes}: {}; zoom one of them or raise max_bytes]",
        size_text(cut_bytes),
        names.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmatched_filters_are_disclosed_even_when_capture_stopped_early() {
        let records = vec![
            record(0, "RootWebArea", "Settings", Some("e1")),
            record(1, "heading", "Versioning", Some("e2")),
            record(1, "button", "Save", Some("e3")),
        ];
        for (filters, expected) in [
            (
                Filters {
                    text: Some("ersion|ifecycle|ncryption|ock".into()),
                    roles: Vec::new(),
                },
                "No element matched text_filter \"ersion|ifecycle|ncryption|ock\" (a literal, case-insensitive substring)",
            ),
            (
                Filters {
                    text: None,
                    roles: vec!["checkbox".into()],
                },
                "No element matched role_filter [\"checkbox\"] (case-insensitive roles)",
            ),
            (
                Filters {
                    text: Some("Versioning".into()),
                    roles: vec!["button".into()],
                },
                "No element matched text_filter \"Versioning\" (a literal, case-insensitive substring) and role_filter [\"button\"] (case-insensitive roles)",
            ),
        ] {
            for incomplete in [false, true] {
                let rendered = render_with_capture_status(
                    &RenderInput {
                        records: &records,
                        facts: &HashMap::new(),
                        page_url: "https://example.com/",
                        snapshot_id: "s1",
                        zoom: None,
                        filters: &filters,
                        max_bytes: 4_000,
                    },
                    incomplete,
                );
                assert!(rendered.text.lines().any(|line| line == expected), "{}", rendered.text);
                assert_eq!(rendered.text.contains("Capture stopped early"), incomplete);
                assert_eq!(rendered.cut_lines, 0);
            }
        }
    }

    #[test]
    fn unmatched_filter_echo_is_one_line_and_bounded() {
        let records = vec![record(0, "RootWebArea", "Page", Some("e1"))];
        let rendered = filtered(&records, &format!("missing\n{}", "秘密".repeat(100)));
        let notice = rendered
            .text
            .lines()
            .find(|line| line.starts_with("No element matched"))
            .expect("missing no-match notice");
        assert!(notice.contains("missing "));
        assert!(notice.chars().count() < 180, "{notice}");
        assert!(!notice.contains(&"秘密".repeat(100)));
    }

    #[test]
    fn repeated_classification_failures_print_once_and_keep_exceptions() {
        let records = vec![
            record(0, "RootWebArea", "Thread", Some("e1")),
            record(1, "region", "Comments", Some("e2")),
            record(2, "button", "13 more replies", Some("e3")),
            record(2, "textbox", "Reply", Some("e4")),
            record(2, "button", "Other frame", Some("e5")),
        ];
        let facts = records
            .iter()
            .map(|record| {
                (
                    record.reference.clone().unwrap(),
                    NodeFacts {
                        classification_unavailable: Some(
                            if record.reference.as_deref() == Some("e5") {
                                "target_not_in_document"
                            } else {
                                "dom_read_failed"
                            },
                        ),
                        ..NodeFacts::default()
                    },
                )
            })
            .collect();
        let rendered = render(&RenderInput {
            records: &records,
            facts: &facts,
            page_url: "https://example.com/",
            snapshot_id: "s1",
            zoom: Some(Zoom {
                requested: "e2",
                target: Some("e2"),
            }),
            filters: &Filters::default(),
            max_bytes: 30_000,
        });
        assert_eq!(
            rendered.text.matches("dom_read_failed").count(),
            1,
            "{}",
            rendered.text
        );
        assert!(
            rendered.text.contains("Classification unavailable for"),
            "{}",
            rendered.text
        );
        assert!(
            rendered.text.contains("clicks and typing"),
            "{}",
            rendered.text
        );
        assert!(
            rendered
                .text
                .contains("[e5 classification unavailable: target_not_in_document]"),
            "{}",
            rendered.text
        );
        assert!(rendered.printed_refs.contains("e3") && rendered.printed_refs.contains("e4"));
    }

    #[test]
    fn every_rendered_byte_cut_ends_with_a_disclosure() {
        let mut records = vec![record(0, "RootWebArea", "Page", Some("e1"))];
        for section in 0..8 {
            records.push(record(
                1,
                "region",
                &format!("Section {section}"),
                Some(&format!("e{}", 2 + section * 10)),
            ));
            for row in 1..10 {
                records.push(record(
                    2,
                    "button",
                    &format!("{section} {row} {}", "comment ".repeat(12)),
                    Some(&format!("e{}", 2 + section * 10 + row)),
                ));
            }
        }
        for zoom in [
            None,
            Some(Zoom {
                requested: "e1",
                target: Some("e1"),
            }),
        ] {
            for max_bytes in 64..4_000 {
                let rendered = render(&RenderInput {
                    records: &records,
                    facts: &HashMap::new(),
                    page_url: "https://example.com/",
                    snapshot_id: "s1",
                    zoom,
                    filters: &Filters::default(),
                    max_bytes,
                });
                assert!(rendered.text.len() <= max_bytes);
                if rendered.cut_lines > 0 {
                    let last = rendered.text.lines().last().unwrap_or_default();
                    assert!(
                        (last.contains("not shown")
                            || last.contains("[cut ")
                            || last.contains("[outline:"))
                            && last.contains("zoom"),
                        "silent cut at {max_bytes} bytes, zoom {zoom:?}: {}",
                        rendered.text
                    );
                }
            }
        }
    }

    #[test]
    fn an_outline_budget_cut_still_ends_with_a_disclosure_after_later_content() {
        let mut records = vec![
            record(0, "RootWebArea", "Page", Some("e1")),
            record(1, "main", "Comments", Some("e2")),
        ];
        for i in 3..200 {
            records.push(record(
                2,
                "button",
                &format!("Comment {i} {}", "reply ".repeat(40)),
                Some(&format!("e{i}")),
            ));
        }
        records.push(record(1, "region", "Later content", Some("e200")));
        let rendered = render_plain(&records, &HashMap::new());
        assert_eq!(rendered.cut_lines, 0);
        assert!(
            rendered.text.contains("more button like this"),
            "{}",
            rendered.text
        );
        assert!(
            rendered.text.lines().last().unwrap().contains("[outline:"),
            "{}",
            rendered.text
        );
    }

    #[test]
    fn classification_notices_survive_filtered_rows_and_byte_cuts() {
        let records = vec![
            record(0, "RootWebArea", "Page", Some("e1")),
            record(1, "generic", "", Some("e2")),
            record(2, "StaticText", "event", Some("e3")),
            record(2, "StaticText", ":", Some("e4")),
            record(2, "StaticText", "loaded", Some("e5")),
            record(1, "textbox", "Notes", Some("e6")),
        ];
        let facts = records
            .iter()
            .map(|record| {
                (
                    record.reference.clone().unwrap(),
                    NodeFacts {
                        classification_unavailable: Some("dom_read_failed"),
                        ..NodeFacts::default()
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        for filters in [
            Filters {
                text: Some("event".into()),
                roles: vec![],
            },
            Filters {
                text: None,
                roles: vec!["textbox".into()],
            },
        ] {
            for max_bytes in [200, 1024] {
                let rendered = render(&RenderInput {
                    records: &records,
                    facts: &facts,
                    filters: &filters,
                    page_url: "https://example.com",
                    snapshot_id: "s1",
                    zoom: None,
                    max_bytes,
                });
                assert!(rendered.text.len() <= max_bytes);
                if max_bytes == 1024 {
                    assert!(!rendered.printed_refs.is_empty());
                }
                for reference in rendered.printed_refs {
                    assert!(
                        rendered.text.contains(&format!(
                            "[{reference} classification unavailable: dom_read_failed]"
                        )) || rendered.text.contains(
                            "Classification unavailable for 6 captured refs: dom_read_failed"
                        ),
                        "{}",
                        rendered.text
                    );
                }
            }
        }
        let ax = crate::snapshot_store::render_ax_text(&records, &facts, 1024).unwrap();
        for reference in ax.printed_refs {
            assert!(
                ax.text.contains(&format!(
                    "[{reference} classification unavailable: dom_read_failed]"
                )) || ax
                    .text
                    .contains("Classification unavailable for 6 captured refs: dom_read_failed"),
                "{}",
                ax.text
            );
        }
    }

    #[test]
    #[ignore = "manual debug-render timing on a wide container"]
    fn wide_container_text_filter_timing() {
        use sha2::Digest;

        let mut records = vec![
            record(0, "RootWebArea", "Page", Some("e1")),
            record(1, "generic", "", Some("e2")),
        ];
        let mut facts = HashMap::new();
        // Chrome can omit line wrappers from the AX tree, leaving all texts
        // as siblings. Their ignored ancestors still identify each line.
        for line in 0..4_000 {
            for field in 0..5 {
                let reference = format!("e{}", records.len() + 1);
                let name = if field == 0 {
                    format!("line {line}")
                } else {
                    format!("field {field}")
                };
                records.push(record(2, "StaticText", &name, Some(&reference)));
                facts.insert(
                    reference,
                    NodeFacts {
                        ignored_ancestors: vec![format!("line-{line}")],
                        ..NodeFacts::default()
                    },
                );
            }
        }
        let filters = Filters {
            text: Some("line".into()),
            roles: Vec::new(),
        };
        let input = RenderInput {
            records: &records,
            facts: &facts,
            filters: &filters,
            page_url: "https://example.com",
            snapshot_id: "s1",
            zoom: None,
            max_bytes: 262_144,
        };
        let start = std::time::Instant::now();
        let rendered = render(&input);
        println!("wide container: {:?}", start.elapsed());
        assert!(rendered.text.contains("line 3999"), "{}", rendered.text);
        println!(
            "rendered output: {} bytes sha256 {:x}",
            rendered.text.len(),
            sha2::Sha256::digest(rendered.text.as_bytes())
        );
    }

    #[test]
    fn settings_text_filter_searches_the_label_beyond_its_printed_prefix() {
        let name = format!("{} Require status checks", "Long label ".repeat(100));
        let records = vec![record(0, "checkbox", &name, Some("e1"))];
        let found = render(&RenderInput {
            records: &records,
            facts: &HashMap::new(),
            filters: &Filters {
                text: Some("Require status checks".into()),
                roles: vec!["checkbox".into()],
            },
            page_url: "https://example.com",
            snapshot_id: "s1",
            zoom: None,
            max_bytes: 1000,
        });
        assert!(found.printed_refs.contains("e1"), "{}", found.text);
        assert!(!found.text.contains("No element matched"));
    }

    #[test]
    fn stable_refs_filters_cannot_match_withheld_field_values() {
        let records = vec![
            record(0, "textbox", "Password", Some("e1")),
            record(1, "StaticText", "hidden-secret", Some("e2")),
        ];
        let mut fields = records.clone();
        fields[0].value = Some("hidden-secret".into());
        let facts = HashMap::from([(
            "e1".into(),
            NodeFacts {
                credential: Some(true),
                ..NodeFacts::default()
            },
        )]);
        let filtered = render(&RenderInput {
            records: &fields,
            facts: &facts,
            page_url: "https://example.com",
            snapshot_id: "0123456789abcdef0123456789abcdef",
            zoom: None,
            filters: &Filters {
                text: Some("hidden".into()),
                roles: Vec::new(),
            },
            max_bytes: 4096,
        });
        assert!(
            filtered.text.contains("No element matched text_filter"),
            "{}",
            filtered.text
        );
        assert!(!filtered.text.contains("hidden-secret"));
        assert!(filtered.printed_refs.is_empty());
    }

    /// A table whose rows hold a link prints a filtered match as it did
    /// before row blocks: the matching cell or text under its table, without
    /// the link, whether the link sits in its own cell or beside the matching
    /// text in one cell. A table keeps its own row rule (see `Tree::leaf_row`).
    #[test]
    fn a_match_in_a_table_row_with_a_link_prints_only_the_cell() {
        let records = vec![
            record(0, "RootWebArea", "Page", Some("e1")),
            record(1, "table", "Apps", Some("e2")),
            record(2, "row", "", Some("e3")),
            record(3, "cell", "alpha", Some("e4")),
            record(4, "StaticText", "alpha", Some("e5")),
            record(3, "cell", "", Some("e6")),
            record(4, "link", "Open", Some("e7")),
            record(2, "row", "", Some("e8")),
            record(3, "cell", "", Some("e9")),
            record(4, "StaticText", "beta", Some("e10")),
            record(4, "link", "Edit", Some("e11")),
        ];
        for (filter, expected) in [
            (
                "alpha",
                "e1 page Page\n  e2 table Apps\n    e4 cell alpha\n",
            ),
            ("beta", "e1 page Page\n  e2 table Apps\n    e10 text beta\n"),
        ] {
            let found = render(&RenderInput {
                records: &records,
                facts: &HashMap::new(),
                filters: &Filters {
                    text: Some(filter.into()),
                    roles: Vec::new(),
                },
                page_url: "https://example.com",
                snapshot_id: "s1",
                zoom: None,
                max_bytes: 4096,
            });
            assert_eq!(
                found.text.split_once('\n').map(|(_, body)| body),
                Some(expected),
                "{}",
                found.text
            );
        }
    }

    /// A page holding one unlabelled row: the text `alpha`, an `Open` link and
    /// `extra` more texts. Filtered on `alpha`, it prints the row with its
    /// link while the row has at most `ROW_LEAVES` leaves, and the matching
    /// text alone once it has more.
    #[test]
    fn a_match_whose_row_is_over_the_row_bound_prints_as_itself() {
        let filtered = |extra: usize| {
            let mut records = vec![
                record(0, "RootWebArea", "Page", Some("e1")),
                record(1, "generic", "", Some("e2")),
                record(2, "StaticText", "alpha", Some("e3")),
                record(2, "link", "Open", Some("e4")),
            ];
            for index in 0..extra {
                let reference = format!("e{}", index + 5);
                records.push(record(
                    2,
                    "StaticText",
                    &format!("note {index}"),
                    Some(&reference),
                ));
            }
            render(&RenderInput {
                records: &records,
                facts: &HashMap::new(),
                filters: &Filters {
                    text: Some("alpha".into()),
                    roles: Vec::new(),
                },
                page_url: "https://example.com",
                snapshot_id: "s1",
                zoom: None,
                max_bytes: 4096,
            })
            .text
        };
        let within = filtered(ROW_LEAVES - 2);
        assert!(
            within.contains("\n  e2 generic\n    e3 text alpha\n    e4 link Open\n"),
            "{within}"
        );
        let over = filtered(ROW_LEAVES - 1);
        assert!(
            over.ends_with("\ne1 page Page\n  e3 text alpha\n"),
            "{over}"
        );
        assert!(!over.contains("Open"), "{over}");
    }

    /// How a JSON viewer renders a property's value next to its key chip.
    #[derive(Clone, Copy, Debug)]
    enum ValueShape {
        /// A span holding the value as three texts (quote, value, quote).
        Element,
        /// The same span as a click-to-filter button.
        ClickableElement,
        /// One text right after the chip.
        NextText,
        /// A click-to-filter button right after the chip, its one text
        /// repeating its name.
        NextClickable,
    }

    /// An expanded Workers Observability event,
    /// `{ 'event': 'boat_pool_retire', 'eventType': 'cron' }`, one line
    /// wrapper per property. Each key is a click-to-filter chip: a button
    /// named `'event':` whose texts are `'`, `event` and `':`, which is why
    /// the key's text prints as `event`. Refs follow document order.
    ///
    /// Cloudflare's own viewer is not built this way: Chrome exposes its key
    /// and value spans and each line wrapper as ignored nodes, and its keys
    /// are no buttons (see `fixtures/json_viewer_real_tree.json` and
    /// `ignored_wrapper_viewer`). These shapes still cover a viewer whose
    /// keys are chips and whose lines are recorded.
    fn json_viewer(shape: ValueShape) -> Vec<AxRecord> {
        let mut records = Vec::new();
        let mut push = |depth: i64, role: &str, name: &str| {
            let reference = format!("e{}", records.len() + 1);
            records.push(record(depth, role, name, Some(&reference)));
        };
        push(0, "RootWebArea", "Workers Observability");
        push(1, "main", "");
        push(2, "generic", "");
        push(3, "StaticText", "{");
        for (key, value) in [("event", "boat_pool_retire"), ("eventType", "cron")] {
            let quoted = format!("'{value}'");
            push(3, "generic", "");
            push(4, "button", &format!("'{key}':"));
            push(5, "StaticText", "'");
            push(5, "StaticText", key);
            push(5, "StaticText", "':");
            match shape {
                ValueShape::Element | ValueShape::ClickableElement => {
                    if matches!(shape, ValueShape::Element) {
                        push(4, "generic", "");
                    } else {
                        push(4, "button", &quoted);
                    }
                    push(5, "StaticText", "'");
                    push(5, "StaticText", value);
                    push(5, "StaticText", "'");
                }
                ValueShape::NextText => push(4, "StaticText", &quoted),
                ValueShape::NextClickable => {
                    push(4, "button", &quoted);
                    push(5, "StaticText", &quoted);
                }
            }
            push(4, "StaticText", ",");
        }
        push(3, "StaticText", "}");
        records
    }

    fn filtered(records: &[AxRecord], text: &str) -> RenderedState {
        render(&RenderInput {
            records,
            facts: &HashMap::new(),
            filters: &Filters {
                text: Some(text.into()),
                roles: Vec::new(),
            },
            page_url: "https://dash.cloudflare.com/",
            snapshot_id: "s1",
            zoom: None,
            max_bytes: 65_536,
        })
    }

    /// The rendered text below its header line.
    fn body(state: &RenderedState) -> &str {
        state.text.split_once('\n').map_or("", |(_, body)| body)
    }

    /// A filter on a key prints each matching property line with its value,
    /// element by element, so the key's chip keeps its ref and can be
    /// clicked. Both value shapes are covered, plain and clickable. A plain
    /// value already printed this way, the value being a label beside the
    /// chip; a clickable value used to leave the line with no label outside
    /// a control, so the key printed alone.
    #[test]
    fn a_text_filter_on_a_json_viewer_key_chip_prints_its_property_line() {
        let element = |value: &str, quote_refs: [usize; 3]| {
            format!(
                "      e{} text '\n      e{} text {value}\n      e{} text '\n",
                quote_refs[0], quote_refs[1], quote_refs[2]
            )
        };
        let line = |first: usize, key: &str, value: String, comma: usize| {
            format!(
                "  e{first} generic\n    e{} button '{key}':\n      e{} text '\n      e{} text {key}\n      e{} text ':\n{value}    e{comma} text ,\n",
                first + 1,
                first + 2,
                first + 3,
                first + 4,
            )
        };
        let cases = [
            (
                ValueShape::Element,
                line(
                    5,
                    "event",
                    format!(
                        "    e10 generic\n{}",
                        element("boat_pool_retire", [11, 12, 13])
                    ),
                    14,
                ) + &line(
                    15,
                    "eventType",
                    format!("    e20 generic\n{}", element("cron", [21, 22, 23])),
                    24,
                ),
            ),
            (
                ValueShape::ClickableElement,
                line(
                    5,
                    "event",
                    format!(
                        "    e10 button 'boat_pool_retire'\n{}",
                        element("boat_pool_retire", [11, 12, 13])
                    ),
                    14,
                ) + &line(
                    15,
                    "eventType",
                    format!("    e20 button 'cron'\n{}", element("cron", [21, 22, 23])),
                    24,
                ),
            ),
            (
                ValueShape::NextText,
                line(5, "event", "    e10 text 'boat_pool_retire'\n".into(), 11)
                    + &line(12, "eventType", "    e17 text 'cron'\n".into(), 18),
            ),
            (
                ValueShape::NextClickable,
                line(5, "event", "    e10 button 'boat_pool_retire'\n".into(), 12)
                    + &line(13, "eventType", "    e18 button 'cron'\n".into(), 20),
            ),
        ];
        for (shape, expected) in cases {
            let found = filtered(&json_viewer(shape), "event");
            assert_eq!(
                body(&found),
                format!("e1 page Workers Observability\n{expected}"),
                "{shape:?}"
            );
            assert!(
                found.printed_refs.contains("e6"),
                "{shape:?}: the chip's ref"
            );
        }
    }

    /// A key chip in a table cell: a table keeps its own row rule, so the
    /// cell is the row, and the chip in it no longer refuses that row. The
    /// cell prints element by element, so the chip keeps its ref.
    #[test]
    fn a_key_chip_in_a_table_cell_prints_with_its_value_and_keeps_its_ref() {
        let records = vec![
            record(0, "RootWebArea", "Log", Some("e1")),
            record(1, "table", "Properties", Some("e2")),
            record(2, "row", "", Some("e3")),
            record(3, "cell", "", Some("e4")),
            record(4, "button", "'event':", Some("e5")),
            record(5, "StaticText", "'", Some("e6")),
            record(5, "StaticText", "event", Some("e7")),
            record(5, "StaticText", "':", Some("e8")),
            record(4, "StaticText", "'boat_pool_retire'", Some("e9")),
        ];
        let found = filtered(&records, "event");
        assert_eq!(
            body(&found),
            "e1 page Log\n  e2 table Properties\n    e4 cell\n      e5 button 'event':\n        e6 text '\n        e7 text event\n        e8 text ':\n      e9 text 'boat_pool_retire'\n"
        );
        assert!(found.printed_refs.contains("e5"));
    }

    /// A control whose text holds more than the match is a separate control,
    /// and a matched control is never its own key chip: a link matched among
    /// other links prints alone, as before.
    #[test]
    fn a_control_holding_more_than_the_match_or_matched_itself_is_no_key_chip() {
        let records = vec![
            record(0, "RootWebArea", "Page", Some("e1")),
            record(1, "generic", "", Some("e2")),
            record(2, "button", "Retry event", Some("e3")),
            record(3, "StaticText", "Retry", Some("e4")),
            record(3, "StaticText", "event", Some("e5")),
            record(2, "link", "Open", Some("e6")),
            record(1, "generic", "", Some("e7")),
            record(2, "link", "Close", Some("e8")),
            record(2, "link", "Edit", Some("e9")),
        ];
        assert_eq!(
            body(&filtered(&records, "event")),
            "e1 page Page\n  e3 button Retry event\n    e5 text event\n"
        );
        assert_eq!(
            body(&filtered(&records, "Close")),
            "e1 page Page\n  e8 link Close\n"
        );
    }

    /// A JSON viewer as Chrome exposes it: each property line and its key
    /// and value spans are ignored nodes, so the texts of both lines hang off
    /// one container, and only the facts' ignored ancestors (`line-N` the
    /// property line, `key-N` and `value-N` its spans) say which texts share
    /// a line. With `chip`, each key is a button whose texts are recorded
    /// below it. Refs follow document order.
    fn ignored_wrapper_viewer(chip: bool) -> (Vec<AxRecord>, HashMap<String, NodeFacts>) {
        let mut records = Vec::new();
        let mut facts = HashMap::new();
        let mut push = |depth: i64, role: &str, name: &str, ignored: &[String]| {
            let reference = format!("e{}", records.len() + 1);
            records.push(record(depth, role, name, Some(&reference)));
            if !ignored.is_empty() {
                facts.insert(
                    reference,
                    NodeFacts {
                        ignored_ancestors: ignored.to_vec(),
                        ..NodeFacts::default()
                    },
                );
            }
        };
        push(0, "RootWebArea", "Page", &[]);
        push(1, "main", "", &[]);
        push(2, "generic", "", &[]);
        for (line, (key, value)) in [("status", "status_ok"), ("region", "eu")]
            .into_iter()
            .enumerate()
        {
            let key_span = [format!("key-{line}"), format!("line-{line}")];
            if chip {
                push(3, "button", &format!("\"{key}\":"), &key_span);
                push(4, "StaticText", "\"", &[]);
                push(4, "StaticText", key, &[]);
                push(4, "StaticText", "\":", &[]);
            } else {
                push(3, "StaticText", "\"", &key_span);
                push(3, "StaticText", key, &key_span);
                push(3, "StaticText", "\":", &key_span);
            }
            push(
                3,
                "generic",
                "",
                &[format!("value-{line}"), format!("line-{line}")],
            );
            push(4, "StaticText", &format!("\"{value}\""), &[]);
            push(4, "StaticText", ",", &[]);
        }
        (records, facts)
    }

    fn filtered_with(
        records: &[AxRecord],
        facts: &HashMap<String, NodeFacts>,
        text: &str,
    ) -> RenderedState {
        render(&RenderInput {
            records,
            facts,
            filters: &Filters {
                text: Some(text.into()),
                roles: Vec::new(),
            },
            page_url: "https://dash.cloudflare.com/",
            snapshot_id: "s1",
            zoom: None,
            max_bytes: 65_536,
        })
    }

    /// A key whose line exists only as an ignored wrapper prints that line,
    /// joined, under the key's own ref. The value's text matches too, and the
    /// line prints once. Without the ignored ancestors each text prints
    /// alone, as before: nothing else marks where a line ends.
    #[test]
    fn a_text_filter_on_a_key_in_an_ignored_wrapper_prints_the_wrapper_line_once() {
        let (records, facts) = ignored_wrapper_viewer(false);
        let found = filtered_with(&records, &facts, "status");
        assert_eq!(
            body(&found),
            "e1 page Page\n  e5 \" status \": \"status_ok\" ,\n"
        );
        assert!(found.printed_refs.contains("e5"));
        assert_eq!(
            body(&filtered_with(&records, &HashMap::new(), "status")),
            "e1 page Page\n  e5 text status\n  e8 text \"status_ok\"\n"
        );
    }

    /// A key chip inside an ignored line wrapper prints the line element by
    /// element, so the chip keeps its ref, and the value matching too adds
    /// nothing.
    #[test]
    fn a_key_chip_in_an_ignored_wrapper_prints_the_line_with_its_ref() {
        let (records, facts) = ignored_wrapper_viewer(true);
        let found = filtered_with(&records, &facts, "status");
        assert_eq!(
            body(&found),
            "e1 page Page\n  e4 button \"status\":\n    e5 text \"\n    e6 text status\n    e7 text \":\n  e8 generic\n    e9 text \"status_ok\"\n    e10 text ,\n"
        );
        assert!(found.printed_refs.contains("e4"));
        assert!(!found.text.contains("region"), "{}", found.text);
    }
    fn zoomed(records: &[AxRecord], target: &str, max_bytes: usize) -> RenderedState {
        render(&RenderInput {
            records,
            facts: &HashMap::new(),
            filters: &Filters::default(),
            page_url: "https://dash.cloudflare.com/",
            snapshot_id: "s1",
            zoom: Some(Zoom {
                requested: target,
                target: Some(target),
            }),
            max_bytes,
        })
    }

    /// A row's Copy button named with the whole event JSON (about 1.4 KB),
    /// and a container carrying the same name.
    fn copy_button_page(name: &str) -> Vec<AxRecord> {
        vec![
            record(0, "RootWebArea", "Workers Observability", Some("e1")),
            record(1, "button", name, Some("e2")),
            record(2, "StaticText", "Copy", Some("e3")),
            record(1, "generic", name, Some("e4")),
            record(2, "link", "Open", Some("e5")),
        ]
    }

    fn copy_name() -> String {
        let mut json = String::from("Copy { 'event': 'boat_pool_retire'");
        for index in 0..60 {
            json.push_str(&format!(", 'field{index}': 'value {index}'"));
        }
        json.push_str(" }");
        json
    }

    #[test]
    fn a_zoom_on_a_single_element_prints_its_whole_name() {
        let name = copy_name();
        assert!(name.len() > 1_000 && name.len() < MAX_NAME_BYTES);
        let records = copy_button_page(&name);
        let found = zoomed(&records, "e2", 65_536);
        assert_eq!(body(&found), format!("e2 button {name}\n  e3 text Copy\n"));
        assert_eq!(found.cut_lines, 0);

        // A budget smaller than the name cuts it to fit, with a marker.
        let tight = zoomed(&records, "e2", 800);
        assert!(tight.text.len() <= 800, "{}", tight.text);
        let line = body(&tight).lines().next().unwrap();
        let shown = line
            .strip_prefix("e2 button ")
            .and_then(|line| line.split_once("… [name cut at "))
            .map(|(shown, _)| shown)
            .unwrap_or_else(|| panic!("{}", tight.text));
        assert!(
            shown.len() > NAME_CHARS && name.starts_with(shown),
            "{line}"
        );
        assert!(line.ends_with(&format!("… [name cut at {} bytes]", shown.len())));
        assert!(
            body(&tight).ends_with("\n  e3 text Copy\n"),
            "{}",
            tight.text
        );

        // A name the capture stored at its byte limit says it was cut there.
        let stored = "x".repeat(MAX_NAME_BYTES);
        let found = zoomed(&copy_button_page(&stored), "e2", 65_536);
        assert!(
            body(&found).starts_with(&format!(
                "e2 button {stored}… [name cut at {MAX_NAME_BYTES} bytes]\n"
            )),
            "{}",
            found.text
        );
    }

    #[test]
    fn a_zoom_on_a_container_keeps_its_name_capped() {
        let name = copy_name();
        let found = zoomed(&copy_button_page(&name), "e4", 65_536);
        assert_eq!(
            body(&found),
            format!(
                "e4 generic {}\n  e5 link Open\n",
                cap_chars(name.clone(), NAME_CHARS)
            )
        );
    }

    fn record(depth: i64, role: &str, name: &str, reference: Option<&str>) -> AxRecord {
        AxRecord {
            depth,
            role: role.into(),
            name: name.into(),
            value: None,
            reference: reference.map(str::to_string),
        }
    }

    fn render_plain(records: &[AxRecord], facts: &HashMap<String, NodeFacts>) -> RenderedState {
        render(&RenderInput {
            filters: &Filters::default(),
            records,
            facts,
            page_url: "https://example.com/page?q=1#top",
            snapshot_id: "s1",
            zoom: None,
            max_bytes: 65_536,
        })
    }

    #[test]
    fn line_grammar_states_values_and_placeholders() {
        let mut records = vec![
            record(0, "RootWebArea", "Example", Some("e1")),
            record(1, "link", "Home\n page", Some("e2")),
            record(1, "textbox", "Search", Some("e3")),
            record(1, "slider", "Volume", Some("e4")),
        ];
        records[2].value = Some("rust\nlang".into());
        records[3].value = Some("40".into());
        let facts = HashMap::from([
            (
                "e2".to_string(),
                NodeFacts {
                    states: vec!["focused".into()],
                    url: Some("https://user:pw@example.com/home?tab=1#x".into()),
                    ..NodeFacts::default()
                },
            ),
            (
                "e3".to_string(),
                NodeFacts {
                    credential: Some(false),
                    placeholder: Some("Search the docs".into()),
                    ..NodeFacts::default()
                },
            ),
        ]);
        assert_eq!(
            render_plain(&records, &facts).text,
            "Example · example.com/page · snapshot s1\n\
             e2 link (focused) Home page, Value: example.com/home\n\
             e3 textbox Search, Value: rust lang, Placeholder: Search the docs\n\
             e4 slider Volume, Value: 40\n"
        );
    }

    #[test]
    fn a_field_whose_markup_was_not_read_withholds_its_value() {
        let mut records = vec![record(0, "textbox", "Email", Some("e1"))];
        records[0].value = Some("person@example.com".into());
        let text = render_plain(&records, &HashMap::new()).text;
        assert_eq!(text, "example.com/page · snapshot s1\ne1 textbox Email\n");
    }

    #[test]
    fn collapse_drops_wrappers_and_repeated_text_but_never_a_control() {
        let records = vec![
            record(0, "RootWebArea", "Page", Some("e1")),
            record(1, "generic", "", Some("e2")),
            record(2, "generic", "", Some("e3")),
            record(3, "button", "Save", Some("e4")),
            record(4, "generic", "", Some("e5")),
            record(5, "StaticText", "Save", Some("e6")),
            record(6, "InlineTextBox", "Save", None),
            record(1, "generic", "", Some("e7")),
            record(1, "group", "", Some("e8")),
            record(2, "link", "One", Some("e9")),
            record(2, "link", "Two", Some("e10")),
            record(1, "generic", "", Some("e11")),
            record(2, "generic", "", Some("e12")),
            record(3, "button", "", Some("e13")),
        ];
        let text = render_plain(&records, &HashMap::new()).text;
        assert_eq!(
            text,
            "Page · example.com/page · snapshot s1\n\
             e4 button Save\n\
             e8 group\n  e9 link One\n  e10 link Two\n\
             e13 button\n"
        );
    }

    fn settings_outline_records() -> Vec<AxRecord> {
        let mut records = vec![
            record(0, "RootWebArea", "Settings", Some("e1")),
            record(1, "link", "Skip to content", Some("e4")),
            record(1, "banner", "GitHub", Some("e6")),
        ];
        for index in 0..24 {
            records.push(record(
                2,
                "link",
                &format!("Banner destination {}", char::from(b'a' + index)),
                Some(&format!("b{index}")),
            ));
        }
        records.extend([
            record(1, "main", "", Some("e72")),
            record(2, "sectionheader", "cortexkit settings", Some("e73")),
            record(3, "heading", "Organization settings", Some("e74")),
            record(2, "navigation", "Organization settings", Some("e88")),
            record(3, "list", "", Some("e89")),
        ]);
        for index in 0..4 {
            records.push(record(
                4,
                "listitem",
                &format!("Settings category {index}"),
                Some(&format!("n{index}")),
            ));
            records.push(record(
                5,
                "link",
                &format!("Category {index}"),
                Some(&format!("l{index}")),
            ));
        }
        records.extend([
            record(2, "form", "Actions settings", Some("e500")),
            record(3, "heading", "Cache", Some("e507")),
            record(3, "spinbutton", "Cache storage limit", Some("e514")),
            record(3, "spinbutton", "Cache retention days", Some("e529")),
        ]);
        records
    }

    #[test]
    fn redundant_text_cannot_disconnect_the_later_settings_form() {
        let mut records = settings_outline_records();
        let form = records
            .iter()
            .position(|record| record.reference.as_deref() == Some("e500"))
            .unwrap();
        for record in &mut records[form..] {
            record.depth += 1;
        }
        records.insert(form, record(2, "StaticText", "", Some("e499")));
        let state = render_plain(&records, &HashMap::new());
        for reference in ["e500", "e507", "e514", "e529"] {
            assert!(
                state.printed_refs.contains(reference),
                "settings form silently disconnected: {}",
                state.text
            );
        }
        assert_eq!(
            accounted_outline_nodes(&state.text, &HashMap::from([("e89", 2)])),
            records.len() - 1,
            "{}",
            state.text
        );
    }

    #[test]
    fn a_named_wrapper_keeps_its_label_and_orders_main_before_chrome() {
        let records = vec![
            record(0, "RootWebArea", "Page", Some("e1")),
            record(1, "generic", "Settings panel", Some("e2")),
            record(2, "banner", "Site header", Some("e3")),
            record(2, "main", "", Some("e4")),
            record(3, "heading", "Cache", Some("e5")),
            record(3, "spinbutton", "Retention", Some("e6")),
        ];
        let state = render_plain(&records, &HashMap::new());
        assert!(
            state.text.contains("e2 generic Settings panel"),
            "{}",
            state.text
        );
        assert!(
            state.text.find("e4 main") < state.text.find("e3 banner"),
            "{}",
            state.text
        );
        assert_eq!(
            accounted_outline_nodes(&state.text, &HashMap::new()),
            records.len(),
            "{}",
            state.text
        );
    }

    #[test]
    fn a_settings_outline_never_silently_loses_the_later_form() {
        let records = settings_outline_records();
        for max_bytes in (256..2_048).step_by(17) {
            let state = render(&RenderInput {
                filters: &Filters::default(),
                records: &records,
                facts: &HashMap::new(),
                page_url: "https://github.com/organizations/cortexkit/settings/actions",
                snapshot_id: "s1",
                zoom: None,
                max_bytes,
            });
            assert!(
                state.text.len() <= max_bytes,
                "budget {max_bytes}: {}",
                state.text
            );
            assert_eq!(
                accounted_outline_nodes(&state.text, &HashMap::from([("e89", 2)])),
                records.len(),
                "budget {max_bytes}: {}",
                state.text
            );
            assert!(
                state.text.contains("e500 form")
                    || state
                        .text
                        .lines()
                        .any(|line| line.contains("not shown; zoom e72"))
                    || state
                        .text
                        .lines()
                        .any(|line| line.contains("not shown; zoom e1")),
                "form missing without disclosure at budget {max_bytes}: {}",
                state.text,
            );
            if let Some(banner) = state.text.find("e6 banner") {
                assert!(
                    state
                        .text
                        .find("e72 main")
                        .is_some_and(|main| main < banner),
                    "{}",
                    state.text
                );
                for reference in ["e507", "e514", "e529"] {
                    assert!(
                        state.printed_refs.contains(reference),
                        "banner displaced main content: {}",
                        state.text
                    );
                }
            }
        }
    }

    fn accounted_outline_nodes(text: &str, repeated_sizes: &HashMap<&str, usize>) -> usize {
        let lines: Vec<_> = text.lines().collect();
        let depth = |line: &str| line.len() - line.trim_start().len();
        lines
            .iter()
            .enumerate()
            .map(|(index, line)| {
                let row = line.trim_start();
                if row.starts_with("[outline:") {
                    return 0;
                }
                if let Some(more) = row.strip_prefix('+') {
                    let count = more
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    let owner = row.rsplit_once("; zoom ").unwrap().1;
                    return count * repeated_sizes.get(owner).copied().unwrap_or(1);
                }
                if let Some(more) = row.strip_prefix("… ") {
                    return more
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                }
                if let Some(more) = row.strip_prefix("[cut ") {
                    return more
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                }
                if let Some((_, size)) = row.rsplit_once(" · ") {
                    if size.contains(" lines, ")
                        && !lines
                            .get(index + 1)
                            .is_some_and(|next| depth(next) > depth(line))
                    {
                        return size
                            .split_whitespace()
                            .next()
                            .unwrap()
                            .parse::<usize>()
                            .unwrap();
                    }
                }
                1
            })
            .sum()
    }

    #[test]
    fn random_outlines_account_for_printed_and_disclosed_nodes() {
        for seed in [1_u64, 7, 29, 103, 911, 65_537] {
            let mut random = seed;
            let mut next = || {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                (random >> 32) as usize
            };
            let mut records = vec![
                record(0, "RootWebArea", "Page", Some("e1")),
                record(1, "main", "", Some("e2")),
            ];
            for group in 0..(3 + next() % 5) {
                records.push(record(
                    2,
                    if next() % 2 == 0 { "group" } else { "generic" },
                    &format!("Section {}", char::from(b'a' + group as u8)),
                    Some(&format!("g{group}")),
                ));
                for child in 0..(6 + next() % 12) {
                    let reference = format!("c{group}_{child}");
                    if next() % 4 == 0 {
                        records.push(record(
                            3,
                            "article",
                            &format!("Story {}", char::from(b'a' + child as u8)),
                            Some(&reference),
                        ));
                        records.push(record(
                            4,
                            "heading",
                            "Story title",
                            Some(&format!("{reference}h")),
                        ));
                        records.push(record(
                            4,
                            "button",
                            "Read story",
                            Some(&format!("{reference}b")),
                        ));
                    } else {
                        records.push(record(
                            3,
                            "StaticText",
                            &format!(
                                "Paragraph {} {}",
                                char::from(b'a' + child as u8),
                                "content ".repeat(next() % 20)
                            ),
                            Some(&reference),
                        ));
                    }
                }
                for button in 0..4 {
                    records.push(record(
                        3,
                        "button",
                        &format!("Action {button}"),
                        Some(&format!("a{group}_{button}")),
                    ));
                }
            }
            for max_bytes in [64, 96, 128, 256, 480, 900, 1_500, 65_536] {
                let state = render(&RenderInput {
                    filters: &Filters::default(),
                    records: &records,
                    facts: &HashMap::new(),
                    page_url: "https://example.com/",
                    snapshot_id: "s1",
                    zoom: None,
                    max_bytes,
                });
                assert!(state.text.len() <= max_bytes, "{}", state.text);
                assert_eq!(
                    accounted_outline_nodes(&state.text, &HashMap::new()),
                    records.len(),
                    "seed {seed}, budget {max_bytes}: {}",
                    state.text
                );
                for line in state.text.lines().filter(|line| line.contains("; zoom ")) {
                    let reference = line.rsplit_once("; zoom ").unwrap().1;
                    assert!(
                        state.printed_refs.contains(reference),
                        "missing zoom ref {reference}: {}",
                        state.text
                    );
                }
            }
        }
    }

    #[test]
    fn a_tight_budget_keeps_content_before_chrome_and_reports_the_cut() {
        let mut records = vec![record(0, "RootWebArea", "Page", Some("e1"))];
        records.push(record(1, "navigation", "Primary", Some("e2")));
        for index in 0..40 {
            records.push(record(
                2,
                "link",
                &format!("Chrome link {index}"),
                Some(&format!("e{}", 3 + index)),
            ));
        }
        records.push(record(1, "main", "", Some("e50")));
        records.push(record(2, "heading", "Main heading", Some("e51")));
        let state = render(&RenderInput {
            filters: &Filters::default(),
            records: &records,
            facts: &HashMap::new(),
            page_url: "https://example.com/",
            snapshot_id: "s1",
            zoom: Some(Zoom {
                requested: "e1",
                target: Some("e1"),
            }),
            max_bytes: 320,
        });
        assert!(state.text.len() <= 320, "{}", state.text);
        assert!(
            state.text.contains("e51 heading Main heading"),
            "{}",
            state.text
        );
        assert!(state.text.contains("navigation e2 ("), "{}", state.text);
        assert!(!state.printed_refs.contains("e42"));
        assert!(state.cut_lines > 0);
    }

    /// The CDP reader replaces an unpaired surrogate in page text with
    /// U+FFFD; such a name prints as is and caps on a character boundary.
    #[test]
    fn a_replacement_character_in_a_name_prints_and_caps_cleanly() {
        let long = format!("{}\u{FFFD}", "a".repeat(NAME_CHARS - 2)) + &"\u{FFFD}".repeat(10);
        let records = vec![
            record(0, "RootWebArea", "Bad \u{FFFD} title", Some("e1")),
            record(1, "button", "Send \u{FFFD}", Some("e2")),
            record(1, "link", &long, Some("e3")),
        ];
        let text = render_plain(&records, &HashMap::new()).text;
        let expected_link = format!("{}\u{FFFD}…", "a".repeat(NAME_CHARS - 2));
        assert_eq!(
            text,
            format!(
                "Bad \u{FFFD} title · example.com/page · snapshot s1\n\
                 e2 button Send \u{FFFD}\n\
                 e3 link {expected_link}\n"
            )
        );
        let cut = render(&RenderInput {
            filters: &Filters::default(),
            records: &records,
            facts: &HashMap::new(),
            page_url: "https://example.com/",
            snapshot_id: "s1",
            zoom: None,
            max_bytes: 150,
        });
        assert!(cut.text.len() <= 150, "{}", cut.text);
    }

    #[test]
    fn short_urls_and_relative_hrefs() {
        assert_eq!(short_url("https://x.com/"), Some("x.com".into()));
        assert_eq!(short_url("javascript:void(0)"), None);
        assert_eq!(
            short_url("mailto:a@b.c?subject=x"),
            Some("mailto:a@b.c".into())
        );
        assert_eq!(
            resolve_href("/a/b?c", "https://x.com/home?x=1"),
            "https://x.com/a/b?c"
        );
        assert_eq!(resolve_href("c", "https://x.com/a/b"), "https://x.com/a/c");
        assert_eq!(
            resolve_href("//cdn.x.com/i", "https://x.com/a"),
            "https://cdn.x.com/i"
        );
        assert_eq!(
            resolve_href("#top", "https://x.com/a?q#f"),
            "https://x.com/a#top"
        );
        assert_eq!(
            resolve_href("https://y.com/", "https://x.com/"),
            "https://y.com/"
        );
    }
}
