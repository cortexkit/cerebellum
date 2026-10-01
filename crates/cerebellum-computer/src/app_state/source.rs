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
use std::time::Duration;

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
    /// `None` where the element exposes no expanded state.
    pub expanded: Option<bool>,
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
    /// Whether every element that exists was visited, so one missing from
    /// this read is known to be gone.
    pub fn is_complete(&self) -> bool {
        self.unreadable_subtrees == 0 && !self.read_bound_reached
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
        self.subrole.as_deref() == Some("AXSecureTextField")
            || self.role.as_deref() == Some("AXSecureTextField")
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
    /// This platform has no implementation.
    UnsupportedOnPlatform,
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

/// Reads an application's state and acts on its elements. One implementation
/// per platform, and a fixture for tests.
///
/// Everything but the read has a refusing default, so a platform or fixture
/// that only reads still compiles and every action on it is refused by name.
pub trait AppStateSource: Send + Sync {
    fn read_app_state(
        &self,
        target: &ProcessGrant,
        bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError>;

    /// What the element is now: owner, role, title, actions, settability.
    fn element_facts(&self, _element: &ElementHandle) -> Result<ElementFacts, ElementActionError> {
        Err(ElementActionError::UnsupportedOnPlatform)
    }

    /// Ask the element to perform its press action.
    fn press(&self, _element: &ElementHandle) -> Result<(), ElementActionError> {
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
            expanded: None,
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
