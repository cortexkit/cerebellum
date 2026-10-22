//! The raw markup view (`dom_full`) when the markup is larger than the
//! caller's `max_bytes`.
//!
//! The markup is the page body serialized in source order, and most pages put
//! their navigation and sidebars before their main content, so a byte prefix
//! of a large page is mostly chrome. When the markup does not fit, it is laid
//! out in the outline's reading order instead: the main-content landmarks
//! first, then everything outside the landmarks, then the chrome landmarks
//! (navigation, header, sidebar, footer, search). Each part starts with a
//! comment naming it, and each part that is cut or left out is marked by a
//! comment with its size and, when one element holds it, the ref a `zoom`
//! reads it through:
//!
//! ```text
//! <!-- navigation omitted: 41.0 KB; zoom e12 -->
//! ```
//!
//! Markup within the limit is returned exactly as it was read.

use std::borrow::Cow;
use std::collections::BTreeSet;

use super::state_text::{landmark_class, size_text, CHROME, CONTENT};

/// One landmark element and its own serialized markup, as the capture read it.
#[derive(Debug, Clone, Copy)]
pub struct DomLandmark<'a> {
    /// The accessibility role, which decides whether the landmark is content
    /// or chrome.
    pub role: &'a str,
    pub reference: &'a str,
    /// The element's outerHTML. It is found again inside the whole markup to
    /// know which bytes it covers.
    pub markup: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomLayout {
    pub text: String,
    /// The refs the text's own comments name. A zoom may use exactly these.
    pub named_refs: BTreeSet<String>,
    /// Bytes and lines of markup left out of `text`; zero when it fits.
    pub omitted_bytes: usize,
    pub omitted_lines: usize,
}

/// One part of the laid-out markup.
struct Part<'a> {
    /// What the comments call the part: a role, or `other content`.
    what: &'a str,
    reference: Option<&'a str>,
    body: Cow<'a, str>,
    /// Where in `body` a comment names another part's ref, so those refs
    /// count as printed only when the comment is.
    named_at: Vec<(usize, &'a str)>,
    /// Whether the part starts with a comment naming it. Off only when the
    /// markup has no landmark to lay out and stays one part.
    headed: bool,
}

impl Part<'_> {
    fn header(&self) -> String {
        if !self.headed {
            return String::new();
        }
        match self.reference {
            Some(reference) => format!("<!-- {} {reference} -->\n", self.what),
            None => format!("<!-- {} -->\n", self.what),
        }
    }

    fn zoom_hint(&self) -> String {
        self.reference
            .map(|reference| format!("; zoom {reference}"))
            .unwrap_or_default()
    }

    fn omitted_marker(&self) -> String {
        format!(
            "<!-- {} omitted: {}{} -->\n",
            self.what,
            size_text(self.body.len()),
            self.zoom_hint()
        )
    }

    fn cut_marker(&self, left_out: usize) -> String {
        format!(
            "<!-- {} cut: {} not shown{} -->\n",
            self.what,
            size_text(left_out),
            self.zoom_hint()
        )
    }
}

/// Fit `markup` in `max_bytes`, main content first. `landmarks` are the
/// outermost content and chrome landmarks the capture read the markup of;
/// any that cannot be found in `markup` stay where they are.
pub fn lay_out(markup: &str, landmarks: &[DomLandmark<'_>], max_bytes: usize) -> DomLayout {
    if markup.len() <= max_bytes {
        return DomLayout {
            text: markup.to_string(),
            named_refs: BTreeSet::new(),
            omitted_bytes: 0,
            omitted_lines: 0,
        };
    }
    let located = locate(markup, landmarks);
    let parts = parts(markup, &located);

    // Every part after the current one may still need its "omitted" comment,
    // so that much room stays reserved while earlier parts are placed.
    let mut reserve = vec![0; parts.len() + 1];
    for index in (0..parts.len()).rev() {
        reserve[index] = reserve[index + 1] + parts[index].omitted_marker().len();
    }
    let mut text = String::new();
    let mut named_refs = BTreeSet::new();
    let mut omitted_bytes = 0;
    let mut omitted_lines = 0;
    for (index, part) in parts.iter().enumerate() {
        let available = max_bytes.saturating_sub(text.len() + reserve[index + 1]);
        let header = part.header();
        let named = |kept: usize, named_refs: &mut BTreeSet<String>| {
            named_refs.extend(part.reference.map(str::to_string));
            named_refs.extend(
                part.named_at
                    .iter()
                    .filter(|(at, _)| *at < kept)
                    .map(|(_, reference)| reference.to_string()),
            );
        };
        let whole = header.len() + part.body.len() + 1;
        if whole <= available {
            text.push_str(&header);
            text.push_str(&part.body);
            text.push('\n');
            named(part.body.len(), &mut named_refs);
            continue;
        }
        if let Some((kept, marker)) = cut_point(part, available.saturating_sub(header.len())) {
            text.push_str(&header);
            text.push_str(&part.body[..kept]);
            text.push('\n');
            text.push_str(&marker);
            named(kept, &mut named_refs);
            omitted_bytes += part.body.len() - kept;
            omitted_lines += part.body[kept..].lines().count();
            continue;
        }
        let marker = part.omitted_marker();
        if marker.len() <= available {
            text.push_str(&marker);
            named_refs.extend(part.reference.map(str::to_string));
        }
        omitted_bytes += part.body.len();
        omitted_lines += part.body.lines().count();
    }
    DomLayout {
        text,
        named_refs,
        omitted_bytes,
        omitted_lines,
    }
}

/// The longest prefix of `part`'s body that fits in `room` bytes together
/// with a newline and the comment saying what was cut, and that comment.
/// The prefix ends after a tag when one closes in its second half, so the
/// cut rarely splits a tag. `None` when no byte of the body fits.
fn cut_point(part: &Part<'_>, room: usize) -> Option<(usize, String)> {
    let body = part.body.as_ref();
    let mut limit = room.saturating_sub(part.cut_marker(body.len()).len() + 1);
    // The comment's size figure can change length as the prefix shrinks, so
    // settle the prefix and the comment together.
    for _ in 0..4 {
        let mut kept = limit.min(body.len());
        while !body.is_char_boundary(kept) {
            kept -= 1;
        }
        if let Some(tag_end) = body[..kept].rfind('>').filter(|end| *end >= kept / 2) {
            kept = tag_end + 1;
        }
        if kept == 0 {
            return None;
        }
        let marker = part.cut_marker(body.len() - kept);
        if kept + 1 + marker.len() <= room {
            return Some((kept, marker));
        }
        limit = room.saturating_sub(marker.len() + 1);
    }
    None
}

/// Where each landmark's markup sits in the whole markup, in source order.
/// A landmark found nowhere, found only overlapping one already placed, or
/// covering the whole markup (a zoom on the landmark itself) is skipped.
fn locate<'a>(markup: &str, landmarks: &[DomLandmark<'a>]) -> Vec<(usize, usize, DomLandmark<'a>)> {
    let mut located: Vec<(usize, usize, DomLandmark<'a>)> = Vec::new();
    for landmark in landmarks {
        if landmark_class(landmark.role) == super::state_text::NEUTRAL
            || landmark.markup.is_empty()
            || landmark.markup.len() >= markup.len()
        {
            continue;
        }
        let found = markup
            .match_indices(landmark.markup)
            .map(|(start, found)| (start, start + found.len()))
            .find(|(start, end)| {
                located
                    .iter()
                    .all(|(other_start, other_end, _)| end <= other_start || start >= other_end)
            });
        if let Some((start, end)) = found {
            located.push((start, end, *landmark));
        }
    }
    located.sort_by_key(|(start, ..)| *start);
    located
}

/// The parts in reading order: content landmarks, then the markup outside
/// every landmark (each landmark replaced by a comment naming it), then
/// chrome landmarks.
fn parts<'a>(markup: &'a str, located: &[(usize, usize, DomLandmark<'a>)]) -> Vec<Part<'a>> {
    if located.is_empty() {
        return vec![Part {
            what: "markup",
            reference: None,
            body: Cow::Borrowed(markup),
            named_at: Vec::new(),
            headed: false,
        }];
    }
    let landmark = |landmark: &DomLandmark<'a>| Part {
        what: landmark.role,
        reference: Some(landmark.reference),
        body: Cow::Borrowed(landmark.markup),
        named_at: Vec::new(),
        headed: true,
    };
    let mut parts: Vec<Part<'a>> = located
        .iter()
        .filter(|(_, _, found)| landmark_class(found.role) == CONTENT)
        .map(|(_, _, found)| landmark(found))
        .collect();
    let mut rest = String::new();
    let mut named_at = Vec::new();
    let mut cursor = 0;
    for (start, end, found) in located {
        rest.push_str(&markup[cursor..*start]);
        named_at.push((rest.len(), found.reference));
        rest.push_str(&format!(
            "<!-- {} {}: laid out separately -->",
            found.role, found.reference
        ));
        cursor = *end;
    }
    rest.push_str(&markup[cursor..]);
    parts.push(Part {
        what: "other content",
        reference: None,
        body: Cow::Owned(rest),
        named_at,
        headed: true,
    });
    parts.extend(
        located
            .iter()
            .filter(|(_, _, found)| landmark_class(found.role) == CHROME)
            .map(|(_, _, found)| landmark(found)),
    );
    parts
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A signed-in dashboard's body: a header, a 60-link sidebar, then the
    /// main content (an events list with one row expanded into a property
    /// viewer), then a footer. Source order puts the sidebar first.
    pub(in crate::browser) const DASHBOARD: &str = include_str!("fixtures/dom_full_dashboard.html");

    /// The outerHTML of the first element opened by `open`, as Chrome's
    /// `DOM.getOuterHTML` returns it for that node.
    pub(in crate::browser) fn element<'a>(markup: &'a str, open: &str, close: &str) -> &'a str {
        let start = markup.find(open).unwrap();
        let end = start + markup[start..].find(close).unwrap() + close.len();
        &markup[start..end]
    }

    pub(in crate::browser) fn dashboard_landmarks() -> Vec<DomLandmark<'static>> {
        vec![
            DomLandmark {
                role: "banner",
                reference: "e2",
                markup: element(DASHBOARD, "<header", "</header>"),
            },
            DomLandmark {
                role: "navigation",
                reference: "e3",
                markup: element(DASHBOARD, "<nav", "</nav>"),
            },
            DomLandmark {
                role: "main",
                reference: "e10",
                markup: element(DASHBOARD, "<main", "</main>"),
            },
            DomLandmark {
                role: "contentinfo",
                reference: "e20",
                markup: element(DASHBOARD, "<footer", "</footer>"),
            },
        ]
    }

    #[test]
    fn markup_within_max_bytes_is_returned_exactly() {
        for max_bytes in [DASHBOARD.len(), 262_144] {
            let layout = lay_out(DASHBOARD, &dashboard_landmarks(), max_bytes);
            assert_eq!(layout.text, DASHBOARD);
            assert!(layout.named_refs.is_empty());
            assert_eq!((layout.omitted_bytes, layout.omitted_lines), (0, 0));
        }
    }

    #[test]
    fn over_max_bytes_main_content_comes_first_and_cut_chrome_is_marked() {
        let max_bytes = 1_500;
        // In source order the same budget holds only the header and the
        // first links of the sidebar.
        assert!(!DASHBOARD[..max_bytes].contains("boat_endpoint_withdrawn"));

        let layout = lay_out(DASHBOARD, &dashboard_landmarks(), max_bytes);
        let text = &layout.text;
        assert!(text.len() <= max_bytes, "{} bytes", text.len());
        let main = element(DASHBOARD, "<main", "</main>");
        assert!(
            text.starts_with(&format!("<!-- main e10 -->\n{main}\n")),
            "{text}"
        );
        assert!(text.contains("<!-- other content -->\n"), "{text}");
        assert!(
            text.contains("<!-- navigation e3: laid out separately -->"),
            "{text}"
        );
        // The sidebar gets what room is left and is cut with a marker; the
        // footer after it is left out with one.
        let cut = text.find("<!-- navigation cut: ").expect(text);
        assert!(
            text[cut..].starts_with(&format!(
                "<!-- navigation cut: {} not shown; zoom e3 -->\n",
                size_text(layout.omitted_bytes - 33)
            )),
            "{text}"
        );
        assert!(
            text.ends_with("<!-- contentinfo omitted: 33 B; zoom e20 -->\n"),
            "{text}"
        );
        // Chrome keeps its own source order after the other content.
        let banner = text.find("<!-- banner e2 -->").unwrap();
        let navigation = text.find("<!-- navigation e3 -->").unwrap();
        assert!(text.find("<!-- other content -->").unwrap() < banner && banner < navigation);
        assert!(layout.named_refs.contains("e3"));
        assert!(layout.named_refs.contains("e10"));
        assert!(layout.named_refs.contains("e20"));
        assert!(layout.omitted_lines > 0);
    }

    #[test]
    fn a_main_larger_than_max_bytes_is_cut_with_a_marker_naming_its_ref() {
        let layout = lay_out(DASHBOARD, &dashboard_landmarks(), 400);
        let text = &layout.text;
        assert!(text.len() <= 400, "{} bytes: {text}", text.len());
        assert!(text.starts_with("<!-- main e10 -->\n<main>"), "{text}");
        let cut = text.find("<!-- main cut: ").unwrap();
        assert!(text[cut..].contains(" not shown; zoom e10 -->\n"), "{text}");
        for marker in [
            "<!-- other content omitted: ",
            "<!-- banner omitted: ",
            "<!-- navigation omitted: ",
            "<!-- contentinfo omitted: ",
        ] {
            assert!(text.contains(marker), "{marker}: {text}");
        }
        for reference in ["e2", "e3", "e10", "e20"] {
            assert!(layout.named_refs.contains(reference), "{reference}");
        }
    }

    #[test]
    fn markup_without_landmarks_is_cut_in_source_order_and_marked() {
        let layout = lay_out(DASHBOARD, &[], 1_000);
        assert!(layout.text.len() <= 1_000);
        let marker = layout.text.find("\n<!-- markup cut: ").unwrap();
        assert!(DASHBOARD.starts_with(&layout.text[..marker]));
        assert!(layout.text.ends_with(" not shown -->\n"), "{}", layout.text);
        assert!(layout.named_refs.is_empty());
        assert_eq!(layout.omitted_bytes, DASHBOARD.len() - marker);
    }

    /// Every budget yields text within it, and every ref the layout reports
    /// is printed in its text.
    #[test]
    fn every_budget_is_respected_and_reported_refs_are_printed() {
        for max_bytes in (1..DASHBOARD.len()).step_by(7) {
            let layout = lay_out(DASHBOARD, &dashboard_landmarks(), max_bytes);
            assert!(layout.text.len() <= max_bytes, "budget {max_bytes}");
            for reference in &layout.named_refs {
                assert!(
                    layout.text.contains(&format!(" {reference}")),
                    "budget {max_bytes}: {reference} not printed"
                );
            }
        }
    }
}
