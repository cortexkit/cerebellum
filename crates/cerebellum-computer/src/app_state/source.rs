//! What one read of an application's state yields, and the seam it is read
//! through.
//!
//! The seam is a trait so the element map, the renderer and the diff can be
//! driven by a fixture on any host: the macOS reader lives in
//! `cerebellum-macos`, which only compiles where the frameworks exist, and a
//! test that needed it could not run anywhere else.

use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::platform::ProcessGrant;

/// An opaque reference to one live element of another application.
///
/// The platform reader keeps whatever it needs to act on the element again
/// (on macOS a retained accessibility element) behind this trait, so nothing
/// platform-specific crosses into this crate and the element map can still
/// tell whether two reads saw the same element.
pub trait ElementToken: Send + Sync + fmt::Debug {
    /// Whether `other` names the same element as this token. Tokens from a
    /// different reader never do.
    fn same_element(&self, other: &dyn ElementToken) -> bool;

    /// A hash that agrees with [`ElementToken::same_element`]: two tokens
    /// naming the same element hash equal. Used to find a token among
    /// thousands without comparing it against each one.
    fn identity_hash(&self) -> u64;

    /// For a reader to recognise its own tokens in `same_element`.
    fn as_any(&self) -> &dyn Any;

    /// Whether the Windows-specific blocklist of session-ending menu titles applies.
    fn uses_windows_menu_titles(&self) -> bool {
        false
    }
}

/// A shared handle on an element token.
pub type ElementHandle = Arc<dyn ElementToken>;

/// An element's `AXValue`, typed as the application reported it.
///
/// Kept typed rather than flattened to text, because a checkbox reports a
/// number and a text field a string, and they are rendered differently: the
/// string is part of the label, while a number becomes a marker or a
/// `value=` so that toggling a checkbox shows up as a change.
#[derive(Debug, Clone, PartialEq)]
pub enum ElementValue {
    Absent,
    Text(String),
    Boolean(bool),
    Number(f64),
    /// A value of a type the renderer does not show, such as a URL or a
    /// geometry structure.
    Other,
}

/// One element as the platform reader saw it, with its descendants.
#[derive(Debug, Clone)]
pub struct RawElement {
    pub handle: ElementHandle,
    pub role: Option<String>,
    pub subrole: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub value_description: Option<String>,
    pub value: ElementValue,
    /// Whether the application reports `AXValue` as settable.
    pub value_settable: bool,
    pub selected: bool,
    /// `false` only when the application reports the element disabled; an
    /// absent or unreadable `AXEnabled` reads as enabled, so no element is
    /// marked disabled on a guess.
    pub enabled: bool,
    pub focused: bool,
    /// Whether this window is the application's main window: the window
    /// reports `AXMain`, or the application names it as its `AXMainWindow`.
    /// `false` when neither could be read, so no window is called main on a
    /// guess.
    pub main_window: bool,
    /// Whether this window is the application's focused window, the one its
    /// `AXFocusedWindow` names. `false` when that could not be read.
    pub focused_window: bool,
    /// `None` where the element exposes no expanded state.
    pub expanded: Option<bool>,
    /// Whether a menu is currently on screen; only menu roles use this field.
    pub menu_visible: bool,
    /// Direct children deliberately not traversed in a closed menu.
    pub closed_menu_children: usize,
    /// The address a link or a web page points at (`AXURL`), when it has one.
    pub url: Option<String>,
    pub children: Vec<RawElement>,
    /// Children reported beneath this element that could not be read. Their
    /// descendants are unknown, which is why a read carrying any is never
    /// allowed to report an element as removed.
    pub unreadable_children: usize,
}

/// Everything one read of an application saw.
#[derive(Debug, Clone)]
pub struct RawAppState {
    /// The application's top-level elements: its windows, with any sheets
    /// and dialogs attached to them beneath, and its menu bar.
    pub roots: Vec<RawElement>,
    /// The application's own focused element, read from the application
    /// rather than from whichever application is frontmost.
    pub focused: Option<ElementHandle>,
    /// Subtrees the read reached but could not open.
    pub unreadable_subtrees: usize,
    /// Whether the read stopped at its element, depth or time bound before
    /// visiting everything. Like an unreadable subtree, it means an element
    /// missing from this read may still exist.
    pub read_bound_reached: bool,
}

impl RawAppState {
    /// Empty web areas and windows holding only layout shells or their own
    /// window controls (see [`is_empty_shell_window`]) cannot prove that
    /// their content is absent. WebKit can expose these shells before its
    /// accessibility tree is populated, sometimes with a subtree the reader
    /// could not open yet. Mark the gap before filtering, so a no-match
    /// result does not certify that a control is missing.
    ///
    /// Returns how many such shells are still present, whether this call
    /// marked them or the reader had already flagged them as unreadable:
    /// either way the page's content is still missing from the read. Only
    /// newly marked ones raise the unreadable count, so a shell the reader
    /// already counted is not counted twice.
    pub fn mark_unpopulated_content(&mut self) -> usize {
        fn mark(node: &mut RawElement, fresh: &mut usize) -> usize {
            let shell = (node.role.as_deref() == Some("AXWebArea") && node.children.is_empty())
                || is_empty_shell_window(node);
            if shell {
                if node.unreadable_children == 0 {
                    node.unreadable_children = 1;
                    *fresh += 1;
                }
                return 1;
            }
            node.children
                .iter_mut()
                .map(|child| mark(child, fresh))
                .sum()
        }
        let mut fresh = 0;
        let shells: usize = self
            .roots
            .iter_mut()
            .map(|root| mark(root, &mut fresh))
            .sum();
        self.unreadable_subtrees += fresh;
        shells
    }

    /// Read each top-level window that is an empty shell (see
    /// [`is_empty_shell_window`]) once more, after one wait of
    /// [`SHELL_RETRY_DELAY_MS`], and put what that read found in its place.
    ///
    /// WebKit can answer the first read of a window with only the window's
    /// own buttons and fill in the page a moment later, so one short wait
    /// often turns a read that would say "read again" into the page itself.
    /// `wait` sleeps for the delay it is given and returns `false` when the
    /// call has no time left or was stopped, in which case nothing is read
    /// again.
    ///
    /// All the re-reads of one call share one allowance, `timing.phase`,
    /// counted from the end of the wait: each is held to whichever ends
    /// first of what is left of that allowance and what is left of the call,
    /// and once that is nothing, the remaining windows are not read again. A
    /// window is read again at most once per call. A re-read that fails or
    /// still finds a shell leaves the first read's window in place, for
    /// [`RawAppState::mark_unpopulated_content`] to flag. Returns how many
    /// windows were read again.
    pub fn reread_shell_windows(
        &mut self,
        source: &dyn AppStateSource,
        target: &ProcessGrant,
        timing: RereadTiming<'_>,
        wait: impl FnOnce(Duration) -> bool,
    ) -> usize {
        let shells: Vec<usize> = self
            .roots
            .iter()
            .enumerate()
            .filter(|(_, root)| is_empty_shell_window(root))
            .map(|(index, _)| index)
            .collect();
        if shells.is_empty() || !wait(Duration::from_millis(SHELL_RETRY_DELAY_MS)) {
            return 0;
        }
        let phase_end = (timing.now)() + timing.phase;
        let mut reread_count = 0;
        for &index in &shells {
            let left = phase_end
                .min(timing.call_end)
                .saturating_duration_since((timing.now)());
            if left.is_zero() {
                break;
            }
            reread_count += 1;
            let bounds = ReadBounds {
                timeout: left,
                ..ReadBounds::default()
            };
            let window = &self.roots[index];
            let Ok(mut reread) = source.read_element_state(target, &window.handle, bounds, false)
            else {
                continue;
            };
            if reread.roots.len() != 1
                || !reread.roots[0].handle.same_element(window.handle.as_ref())
                || is_empty_shell_window(&reread.roots[0])
            {
                continue;
            }
            self.roots[index] = reread.roots.remove(0);
            self.unreadable_subtrees += reread.unreadable_subtrees;
            self.read_bound_reached |= reread.read_bound_reached;
        }
        reread_count
    }

    /// Whether every requested subtree was read. Closed menu contents are
    /// deliberately unrequested, not unreadable; the session preserves known
    /// descendant identities beneath those menus instead of removing them.
    pub fn is_complete(&self) -> bool {
        self.unreadable_subtrees == 0 && !self.read_bound_reached
    }
}

/// How long a read waits before reading an empty-shell window again (see
/// [`RawAppState::reread_shell_windows`]): long enough for WebKit to expose a
/// page it was still building, short enough to cost a read little.
pub const SHELL_RETRY_DELAY_MS: u64 = 200;

/// The time [`RawAppState::reread_shell_windows`] may spend reading windows
/// again.
#[derive(Clone, Copy)]
pub struct RereadTiming<'a> {
    /// What all of one call's re-reads may take together.
    pub phase: Duration,
    /// The current time, on the clock `call_end` is on.
    pub now: &'a dyn Fn() -> Instant,
    /// When the call's work must be done.
    pub call_end: Instant,
}

/// Whether a window exposes nothing of its own content: everything in it is
/// a layout container with no content inside, or, in a standard window, one
/// of the window's own buttons (close, minimize, zoom, full screen) or the
/// text of its title. Such a window cannot show that its content is absent;
/// WebKit exposes exactly this while it is still building a page's
/// accessibility tree.
///
/// The window's buttons and title count as chrome wherever they sit beneath
/// the window, not only as its direct children: an application may wrap them
/// in an unnamed group, and a button may carry an empty element of its own.
/// Layout means groups, generic and unknown elements, layout areas and
/// items (the container roles the renderer looks through when they carry no
/// name), scroll areas, split groups and web areas; any of these counts as
/// layout whatever its label, and is looked through to what it holds. The
/// title text is matched on the label the renderer gives it, whichever
/// attribute holds it.
/// So a standard window whose read prints nothing but its own buttons is
/// taken for a shell.
///
/// Any other element makes the window not a shell, whatever it is: a
/// dialog's own buttons, an empty text area of a blank document, a button
/// with no title. Only window chrome and empty layout are taken for missing
/// content.
pub fn is_empty_shell_window(node: &RawElement) -> bool {
    if node.role.as_deref() != Some("AXWindow") {
        return false;
    }
    // A dialog, sheet-like or floating window's few buttons may be all it
    // has, so only a standard window's chrome is set aside.
    let standard = matches!(node.subrole.as_deref(), None | Some("AXStandardWindow"));
    let window_names: Vec<String> = [
        super::render::one_line(node.title.as_deref().unwrap_or("")),
        super::render::one_line(&super::render::describe(node).label),
    ]
    .into_iter()
    .filter(|name| !name.is_empty())
    .collect();
    let content = |element: &RawElement| shows_content(element, standard, &window_names);
    !node.children.iter().any(content)
}

/// Whether `node`, beneath a window, shows anything but that window's chrome
/// and empty layout (see [`is_empty_shell_window`]). `standard` says whether
/// the window is a standard one, whose buttons and title count as chrome;
/// `window_names` are the one-line forms of the window's title and label.
fn shows_content(node: &RawElement, standard: bool, window_names: &[String]) -> bool {
    match node.role.as_deref() {
        // One of the window's own buttons, together with anything it holds:
        // what is inside a close or full-screen button is still that button.
        Some("AXButton")
            if standard
                && matches!(
                    node.subrole.as_deref(),
                    Some(
                        "AXCloseButton"
                            | "AXMinimizeButton"
                            | "AXZoomButton"
                            | "AXFullScreenButton"
                    )
                ) =>
        {
            false
        }
        Some("AXStaticText") => {
            let text = super::render::one_line(&super::render::describe(node).label);
            !(standard && node.children.is_empty() && window_names.contains(&text))
        }
        Some(
            "AXGroup" | "AXGenericElement" | "AXUnknown" | "AXLayoutArea" | "AXLayoutItem"
            | "AXScrollArea" | "AXSplitGroup" | "AXWebArea",
        ) => node
            .children
            .iter()
            .any(|child| shows_content(child, standard, window_names)),
        // A window attached beneath this one shows content unless it is a
        // shell itself, judged by its own kind and title.
        Some("AXWindow") => !is_empty_shell_window(node),
        _ => true,
    }
}

/// The bounds one read is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadBounds {
    pub max_elements: usize,
    pub max_depth: usize,
    pub timeout: Duration,
}

/// The most elements one read visits. The element map holds twice this, so a
/// whole read can always be numbered.
pub const READ_BOUND_ELEMENTS: usize = 4_000;

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_elements: READ_BOUND_ELEMENTS,
            max_depth: 48,
            timeout: Duration::from_secs(4),
        }
    }
}

/// Why an application's state could not be read at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppStateReadError {
    /// This process may not read other applications' accessibility trees.
    AccessibilityNotPermitted,
    /// The process is gone.
    TargetGone,
    /// The application did not answer its own root element.
    Unreadable,
    /// This platform has no reader.
    UnsupportedOnPlatform,
}

impl AppStateReadError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccessibilityNotPermitted => "accessibility_not_permitted",
            Self::TargetGone => "target_gone",
            Self::Unreadable => "application_unreadable",
            Self::UnsupportedOnPlatform => "unsupported_on_platform",
        }
    }
}

/// What an action needs to know about one element before acting on it, read
/// fresh at action time rather than taken from the read that numbered it: an
/// element's title, settability and actions can all change in between.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ElementFacts {
    /// The process the element belongs to, when the platform reports it.
    pub pid: Option<u32>,
    pub role: Option<String>,
    pub subrole: Option<String>,
    pub title: Option<String>,
    /// The actions the element advertises, as the application names them.
    pub actions: Vec<String>,
    /// Whether `AXValue` may be written.
    pub value_settable: bool,
    /// Whether `AXSelectedText` may be written.
    pub selected_text_settable: bool,
}

impl ElementFacts {
    /// Whether the element carries the secure-text subrole. Trustworthy when
    /// present; its absence says nothing.
    pub fn is_secure(&self) -> bool {
        self.role.as_deref() == Some("AXSecureTextField")
            || self.subrole.as_ref().is_some_and(|role| {
                let role = role.to_ascii_lowercase();
                role.contains("secure") || role.contains("password")
            })
    }
}

/// Why an action on an element did not happen or could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementActionError {
    /// This process may not use the accessibility API.
    NotPermitted,
    /// The element or its application no longer exists.
    Gone,
    /// The element does not offer the attribute or action.
    Unsupported,
    /// The application answered with some other failure.
    Failed,
    /// The message was sent but the application did not complete its answer
    /// in time, so the action may or may not have happened. Never a refusal
    /// that is safe to retry.
    Indeterminate,
    /// This platform has no implementation.
    UnsupportedOnPlatform,
}

/// Why a retained element's subtree could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementReadError {
    /// The element no longer exists in the granted process.
    Gone,
    /// The element could not be resolved or answered within the read budget.
    Unreadable,
}

/// Which text attribute a write sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextAttribute {
    /// The element's whole value.
    Value,
    /// The current selection, which is the caret when nothing is selected.
    SelectedText,
}

/// Where a hit test looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitScope {
    /// Only this process's elements, so the hit belongs to it or to nothing.
    Application { pid: u32 },
    /// Whatever is on top at the point, in any application. Nothing that acts
    /// on a hit uses it: an element found this way may belong to an
    /// application the caller holds no grant for.
    SystemWide,
}

/// A running watch on one window for a cosmetic picture. Dropping it stops
/// the watch and releases everything it holds.
pub trait CursorWindowWatch: Send {
    /// Visibility states whose notifications are unavailable (minimized,
    /// application hidden). The badge owner polls only these states, and only
    /// while the badge remains visible. Most watches need no polling.
    fn poll_visibility(&self) -> (bool, bool) {
        (false, false)
    }
}

/// Reads an application's state and acts on its elements. One implementation
/// per platform, and a fixture for tests.
///
/// Everything but the read has a refusing default, so a platform or fixture
/// that only reads still compiles and every action on it is refused by name.
pub trait AppStateSource: Send + Sync {
    /// A title and secure-field flag, without reading the element's value.
    fn cursor_label(&self, element: &ElementHandle) -> Option<(Option<String>, bool)> {
        let facts = self.element_facts(element).ok()?;
        let secure = facts.is_secure();
        Some((facts.title, secure))
    }
    /// Best-effort geometry for a cosmetic picture. No values are read.
    fn cursor_frame(&self, _element: &ElementHandle) -> Option<[f64; 4]> {
        None
    }
    /// Read-only AX selection bounds for the focused keyboard target. A zero
    /// width caret is valid; unsupported or unreadable geometry returns none.
    fn cursor_caret_frame(&self, _element: &ElementHandle) -> Option<[f64; 4]> {
        None
    }

    /// Whether this source can determine if an element has an on-screen position.
    /// Sources without geometry support keep their existing press behavior;
    /// supporting sources must refuse a press when required geometry is unreadable.
    fn reports_screen_geometry(&self) -> bool {
        false
    }

    /// Live element geometry for deciding whether a press has an on-screen position.
    fn element_frame(&self, element: &ElementHandle) -> Option<[f64; 4]> {
        self.cursor_frame(element)
    }

    /// Desktop-coordinate display bounds, or `None` when unavailable.
    fn display_frames(&self) -> Option<Vec<[f64; 4]>> {
        None
    }

    /// On-screen ordinary window numbers for this process, without window content.
    /// `None` means the platform cannot enumerate them, not an empty desktop.
    fn visible_window_numbers(&self, _target: &ProcessGrant) -> Option<Vec<u32>> {
        None
    }

    /// Desktop frame of this exact window number, if owned by the target.
    fn window_frame(&self, _target: &ProcessGrant, _window_number: u32) -> Option<[f64; 4]> {
        None
    }

    /// A point in a target window not hidden by another app's normal window.
    /// An exact point wins; otherwise the centre of the element frame's
    /// visible part; with neither, the middle of the window's content.
    fn visible_cursor_point(
        &self,
        _target: &ProcessGrant,
        _point: Option<[f64; 2]>,
        _frame: Option<[f64; 4]>,
    ) -> Option<[f64; 2]> {
        None
    }

    /// The window a cosmetic picture's element sits in, or with no element
    /// the application's focused window. Best-effort: it prepares nothing in
    /// the application and reads no values.
    fn cursor_window(
        &self,
        _target: &ProcessGrant,
        _element: Option<&ElementHandle>,
    ) -> Option<ElementHandle> {
        None
    }

    /// Report each move or resize of `window`, and its leaving the screen
    /// (minimized, closed, or its application hidden or quit), to `changed`,
    /// from a thread of the platform's choosing, until the returned watch is
    /// dropped. Event-driven: nothing runs between changes. `None` when the
    /// platform cannot watch windows.
    fn watch_cursor_window(
        &self,
        _window: &ElementHandle,
        _changed: Box<dyn Fn(crate::cursor::WindowChange) + Send + Sync>,
    ) -> Option<Box<dyn CursorWindowWatch>> {
        None
    }

    fn read_app_state(
        &self,
        target: &ProcessGrant,
        bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError>;

    /// A zoom may explicitly request the contents of closed menus.
    fn read_app_state_expanding_menus(
        &self,
        target: &ProcessGrant,
        bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        self.read_app_state(target, bounds)
    }

    /// Read only the subtree rooted at the retained element, without walking
    /// from the application's root first.
    fn read_element_state(
        &self,
        _target: &ProcessGrant,
        _element: &ElementHandle,
        _bounds: ReadBounds,
        _expand_menus: bool,
    ) -> Result<RawAppState, ElementReadError> {
        Err(ElementReadError::Unreadable)
    }

    /// What the element is now: owner, role, title, actions, settability.
    fn element_facts(&self, _element: &ElementHandle) -> Result<ElementFacts, ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// The live accessibility parent, with errors distinct from a root's absent parent.
    fn element_parent(
        &self,
        _element: &ElementHandle,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// The element's live `AXEnabled`, read now rather than taken from an
    /// earlier read. `None` when it cannot be read, which a caller must treat
    /// as unknown, never as disabled.
    fn element_enabled(&self, _element: &ElementHandle) -> Option<bool> {
        None
    }

    /// Whether `window` (a window element, as `cursor_window` returns one)
    /// is minimized, read now. `None` when it cannot be read, which a caller
    /// must treat as unknown: not known to be minimized.
    fn window_minimized(&self, _window: &ElementHandle) -> Option<bool> {
        None
    }

    /// The granted application's live hidden state. Unknown visibility is not
    /// sufficient to draw a cosmetic badge.
    fn application_hidden(&self, _target: &ProcessGrant) -> Option<bool> {
        None
    }

    /// Ask the element to perform its press action.
    fn press(&self, _element: &ElementHandle) -> Result<(), ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// Ask the element to open its menu without moving the pointer.
    fn show_menu(&self, _element: &ElementHandle) -> Result<(), ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// The element's value when it is text; `Ok(None)` when it has none.
    fn text_value(&self, _element: &ElementHandle) -> Result<Option<String>, ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// The selection as `(start, length)` in UTF-16 code units; `Ok(None)`
    /// when the element reports none.
    fn selected_range(
        &self,
        _element: &ElementHandle,
    ) -> Result<Option<(usize, usize)>, ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// Select UTF-16 code units without writing the editor's text. An accepted
    /// setter is not evidence of selection; callers must read the range back.
    fn select_range(
        &self,
        _element: &ElementHandle,
        _range: (usize, usize),
    ) -> Result<(), ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// Set one text attribute. `Ok` means the application accepted the
    /// message, not that the text is there.
    fn write_text(
        &self,
        _element: &ElementHandle,
        _attribute: TextAttribute,
        _text: &str,
    ) -> Result<(), ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// The element at a desktop point, with the pid that owns it when known.
    fn element_at(
        &self,
        _scope: HitScope,
        _point: (f64, f64),
    ) -> Result<Option<(ElementHandle, Option<u32>)>, ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// Hit-test the target process, checking its generation on platforms that support it.
    fn element_at_for_target(
        &self,
        target: &ProcessGrant,
        point: (f64, f64),
    ) -> Result<Option<(ElementHandle, Option<u32>)>, ElementActionError> {
        self.element_at(HitScope::Application { pid: target.pid }, point)
    }

    /// The window-server number of the window `element` sits in, the same
    /// number an image's capture names its window by. `None` when it cannot
    /// be positively established, which a caller must treat as "not the
    /// window it expected", never as a match.
    fn element_window_number(&self, _element: &ElementHandle) -> Option<u32> {
        None
    }

    /// The window-server number of the topmost on-screen window at a desktop
    /// point: the window a real pointer event there would reach. `None` when
    /// it cannot be established.
    fn topmost_window_at(&self, _point: (f64, f64)) -> Option<u32> {
        None
    }

    /// Mouse-down recipient hit test, distinct from geometric window
    /// coverage. An unavailable/uninitialized native query refuses.
    fn pointer_window_at(&self, _point: (f64, f64)) -> Option<u32> {
        None
    }

    /// The same query with a failure step for the guarded posting refusal.
    fn pointer_recipient(&self, point: (f64, f64)) -> Result<Option<u32>, &'static str> {
        Ok(self.pointer_window_at(point))
    }

    /// Bound helper startup and its reply by the caller-provided deadline.
    fn pointer_recipient_until(
        &self,
        point: (f64, f64),
        _deadline: std::time::Instant,
    ) -> Result<Option<u32>, &'static str> {
        self.pointer_recipient(point)
    }

    /// Best-effort no-query preparation before placement or temporary fronting.
    /// Sources without a separate helper have nothing to prepare.
    fn prewarm_pointer_query(&self, _deadline: std::time::Instant) -> Result<(), &'static str> {
        Ok(())
    }

    /// The real cursor, not the agent's visual badge. Missing telemetry refuses scroll.
    fn cursor_position(&self) -> Option<(f64, f64)> {
        None
    }

    /// The target application's own focused element, asked of that
    /// application rather than of whichever one is frontmost.
    fn focused_element(
        &self,
        _target: &ProcessGrant,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// The pid of the frontmost application, or `None` when it cannot be
    /// read.
    fn frontmost_pid(&self) -> Option<u32> {
        None
    }

    /// The target application's own focused window and its title, asked of
    /// that application rather than of whichever one is frontmost. `Ok(None)`
    /// when it reports no focused window.
    fn focused_window(
        &self,
        _target: &ProcessGrant,
    ) -> Result<Option<WindowMark>, ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// Session-wide hardware key, button and scroll timestamps, without
    /// event content or target attribution. The guard uses this signal only
    /// when the target is frontmost at check time.
    /// `Ok((coverage_start, latest))` certifies continuous observation since
    /// `coverage_start`; `latest` excludes synthetic input.
    /// An unavailable observer must not fall back to sender-blind HID ages.
    fn hardware_input(
        &self,
        _target: &ProcessGrant,
    ) -> Result<(std::time::Instant, Option<std::time::Instant>), ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// How long ago the session last received a key press, a mouse-button
    /// press or a scroll, from anyone: the platform's own count, which on
    /// macOS includes input this module posted. Pointer movement alone is
    /// not counted, because a person resting a hand on the mouse has not
    /// changed anything an agent read. `None` when it cannot be read.
    fn time_since_last_input(&self) -> Option<Duration> {
        None
    }

    /// The regular applications running now: the ones with a Dock icon and
    /// windows a person works in, not agents, helpers or menu-bar extras.
    /// Names and identities only; nothing of any window's content.
    fn running_apps(&self) -> Result<Vec<RunningApp>, AppStateReadError> {
        Err(AppStateReadError::UnsupportedOnPlatform)
    }

    /// Kernel process generations and executable paths for this bundle identity.
    /// Unlike display names, these can distinguish installed copies.
    fn running_app_instances(
        &self,
        _bundle: &str,
    ) -> Result<Vec<RunningAppInstance>, AppStateReadError> {
        Err(AppStateReadError::UnsupportedOnPlatform)
    }

    /// Observe only this process generation; never launch a replacement.
    fn opened_running_app(
        &self,
        _app: &InstalledApp,
        _process: &ProcessGrant,
    ) -> Result<OpenedApp, OpenAppError> {
        Err(OpenAppError::Failed)
    }

    /// Deliver to this exact bundle and process generation without activation.
    /// A replacement or additional process must not be reported as already running.
    fn open_running_app_url(
        &self,
        _app: &InstalledApp,
        _process: &ProcessGrant,
        _url: &str,
        _bounds: OpenAppBounds,
    ) -> Result<OpenedApp, OpenAppError> {
        Err(OpenAppError::Failed)
    }

    /// Read only installed bundle names and identities, stopping at the deadline.
    fn installed_apps(&self, _timeout: Duration) -> InstalledApps {
        InstalledApps {
            apps: Vec::new(),
            complete: false,
        }
    }

    /// Read and validate the signature of the selected bundle on disk.
    fn bundle_signature(&self, _app: &InstalledApp) -> Result<BundleSignature, AppStateReadError> {
        Err(AppStateReadError::UnsupportedOnPlatform)
    }

    /// Validate that the bundle still satisfies the approved signer requirement.
    fn bundle_satisfies(&self, _app: &InstalledApp, _requirement: &str) -> bool {
        false
    }

    /// Schemes declared by this exact bundle's CFBundleURLTypes, not defaults
    /// chosen by LaunchServices or by another installed application.
    fn bundle_url_schemes(&self, _app: &InstalledApp) -> Result<Vec<String>, AppStateReadError> {
        Err(AppStateReadError::UnsupportedOnPlatform)
    }

    fn open_app_url(
        &self,
        _app: &InstalledApp,
        _url: &str,
        _bounds: OpenAppBounds,
    ) -> Result<OpenedApp, OpenAppError> {
        Err(OpenAppError::Failed)
    }

    /// Launch via the platform application service, not as our child. The
    /// caller requests no activation and bounds both process and window waits.
    fn open_app(
        &self,
        _app: &InstalledApp,
        _bounds: OpenAppBounds,
    ) -> Result<OpenedApp, OpenAppError> {
        Err(OpenAppError::Failed)
    }
}

/// An application's focused window as one reading saw it: which window, and
/// the title it showed. A browser's title follows its active tab, so a tab
/// switch shows up as a changed title on the same window.
#[derive(Debug, Clone)]
pub struct WindowMark {
    pub handle: ElementHandle,
    pub title: Option<String>,
}

impl WindowMark {
    /// Whether `other` is the same window showing the same title.
    pub fn same_as(&self, other: &WindowMark) -> bool {
        self.handle.same_element(other.handle.as_ref()) && self.title == other.title
    }
}

/// One running application, as `list_apps` reports it and as a `target`
/// given by name is matched against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningApp {
    /// The name the person sees. An application picks its own name, so it
    /// is only ever matched to a bundle identity, never used as one.
    pub name: String,
    pub bundle_identity: String,
    pub pid: u32,
    pub frontmost: bool,
}

/// A bundle discovered without reading its executable or resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledApp {
    pub name: String,
    pub bundle_identity: String,
    pub path: std::path::PathBuf,
    pub version: Option<String>,
    pub build_version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RunningAppInstance {
    pub process: ProcessGrant,
    pub executable_path: std::path::PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct InstalledApps {
    pub apps: Vec<InstalledApp>,
    /// False on deadline, unreadable directories or malformed metadata.
    pub complete: bool,
}

#[derive(Debug, Clone)]
pub struct BundleSignature {
    pub signed: bool,
    pub ad_hoc: bool,
    pub team_id: Option<String>,
    pub designated_requirement: Option<String>,
    pub apple_anchored: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenAppBounds {
    pub activates: bool,
    pub process_timeout: Duration,
    pub window_timeout: Duration,
    /// Total budget from launch dispatch, shared by both wait stages.
    pub ready_timeout: Duration,
}

impl Default for OpenAppBounds {
    fn default() -> Self {
        Self {
            activates: false,
            process_timeout: Duration::from_secs(30),
            window_timeout: Duration::from_secs(10),
            ready_timeout: Duration::from_secs(40),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OpenedApp {
    pub pid: u32,
    pub already_running: bool,
    pub has_window: bool,
    pub frontmost: bool,
    /// Elapsed from launch dispatch to the platform's process callback.
    pub process_started_ms: u64,
    /// Elapsed from launch dispatch to the first observed window, if any.
    pub first_window_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAppError {
    TimedOut,
    Failed,
    RunningChanged,
}

/// The reader for a platform with none: every read is refused by name.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedAppStateSource;

impl AppStateSource for UnsupportedAppStateSource {
    fn read_app_state(
        &self,
        _target: &ProcessGrant,
        _bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        Err(AppStateReadError::UnsupportedOnPlatform)
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    #[test]
    fn unsupported_sources_cannot_select_text() {
        let handle: ElementHandle = std::sync::Arc::new(FixtureElementToken(1));
        assert_eq!(
            UnsupportedAppStateSource.select_range(&handle, (0, 4)),
            Err(ElementActionError::UnsupportedOnPlatform),
        );
    }
}

/// A token for fixture trees: two tokens name the same element when their
/// numbers are equal, the way two retained references to one live element
/// compare equal on a real host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixtureElementToken(pub u64);

impl ElementToken for FixtureElementToken {
    fn same_element(&self, other: &dyn ElementToken) -> bool {
        other
            .as_any()
            .downcast_ref::<Self>()
            .is_some_and(|other| other.0 == self.0)
    }

    fn identity_hash(&self) -> u64 {
        self.0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl RawElement {
    /// A fixture element with the given token number and role, and nothing
    /// else set. Tests fill in the attributes they are about.
    pub fn fixture(token: u64, role: &str) -> Self {
        Self {
            handle: Arc::new(FixtureElementToken(token)),
            role: Some(role.to_string()),
            subrole: None,
            title: None,
            description: None,
            value_description: None,
            value: ElementValue::Absent,
            value_settable: false,
            selected: false,
            enabled: true,
            focused: false,
            main_window: false,
            focused_window: false,
            expanded: None,
            menu_visible: false,
            closed_menu_children: 0,
            url: None,
            children: Vec::new(),
            unreadable_children: 0,
        }
    }

    pub fn titled(mut self, title: &str) -> Self {
        self.title = Some(title.to_string());
        self
    }

    pub fn with_children(mut self, children: Vec<RawElement>) -> Self {
        self.children = children;
        self
    }

    pub fn described(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    pub fn with_subrole(mut self, subrole: &str) -> Self {
        self.subrole = Some(subrole.to_string());
        self
    }

    pub fn with_url(mut self, url: &str) -> Self {
        self.url = Some(url.to_string());
        self
    }
}
