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

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            // Past the element map's own cap, so a large application reaches
            // that cap and says so rather than stopping silently at a smaller
            // read bound.
            max_elements: 4_000,
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

/// Reads an application's state. One implementation per platform, and a
/// fixture for tests.
pub trait AppStateSource: Send + Sync {
    fn read_app_state(
        &self,
        target: &ProcessGrant,
        bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError>;
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
}
