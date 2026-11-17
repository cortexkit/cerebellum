//! Whether the person used an application since the agent last saw it.
//!
//! Element ids stay valid while the person works in an application, and a
//! press finds its element again by identity, so nothing about the id itself
//! says the screen moved on. An agent that read a draft, waited while the
//! person switched tabs or edited the text, and then pressed Send from its
//! old read would act on a screen it has not seen. Before an action, the
//! application's focused element and focused window are read again and
//! compared with what they were when the agent last saw the application, and
//! a continuously observed hardware-input signal is checked. Sender-blind
//! input ages cannot establish that a person acted: other programs can post
//! synthetic events too. The legacy posting ledger below remains available
//! for compatibility, but cannot attribute input to the person.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::source::{AppStateSource, ElementHandle, WindowMark};
use crate::platform::ProcessGrant;

/// How long after a post call returns its input may still appear in the
/// platform's input count. The HID system's table takes the event when the
/// window server processes it, not when it is posted; the dispatch idle gate
/// measured that lag and allows the same margin.
pub const OWN_INPUT_LAG: Duration = Duration::from_millis(crate::dispatch::HID_IDLE_TABLE_LAG_MS);

/// How many of this module's recent posting spans are remembered. The check
/// only asks about input since the conversation's last read or action reply,
/// and a span that ended before that moment cannot explain such input, so a
/// short history is enough.
const REMEMBERED_POSTS: usize = 64;

/// One reading, or the fact that it could not be taken. A reading that
/// could not be taken never counts as a change: it says nothing either way.
#[derive(Debug, Clone)]
pub enum Reading<T> {
    Read(T),
    Unreadable,
}

impl<T> Reading<T> {
    fn from_result<E>(result: Result<T, E>) -> Self {
        match result {
            Ok(value) => Self::Read(value),
            Err(_) => Self::Unreadable,
        }
    }
}

/// What the agent was shown of an application: its focused element and
/// focused window, and when they were read.
#[derive(Debug, Clone)]
pub struct SeenMarks {
    pub focused: Reading<Option<ElementHandle>>,
    pub window: Reading<Option<WindowMark>>,
    pub windows: Reading<Vec<u32>>,
    /// These marks came from an action reply after the agent dispatched input,
    /// rather than from an explicit read.
    pub after_agent_input: bool,
    /// Taken before either reading, so input that arrives while they are
    /// read counts as unseen. That errs towards asking the agent to read
    /// again, never towards acting on a change it did not see.
    pub at: Instant,
}

impl SeenMarks {
    /// Read the application's focused element and focused window now.
    pub fn read(source: &dyn AppStateSource, target: &ProcessGrant) -> Self {
        // Start hardware observation before establishing the read baseline.
        // Its coverage timestamp is checked again before a frontmost action.
        let _ = source.hardware_input(target);
        let at = Instant::now();
        Self {
            focused: Reading::from_result(source.focused_element(target)),
            window: Reading::from_result(source.focused_window(target)),
            windows: source.visible_window_numbers(target).map_or(
                Reading::Unreadable,
                |mut windows| {
                    windows.sort_unstable();
                    Reading::Read(windows)
                },
            ),
            after_agent_input: false,
            at,
        }
    }
}

/// Which sign of the person's use was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonChange {
    /// The application's focused element is another one, or it gained or
    /// lost one.
    FocusChanged,
    /// The application's focused window is another one, or shows another
    /// title.
    WindowChanged,
    /// Hardware key, click or scroll input arrived since the read, and the
    /// application is frontmost when checked.
    InputSeen,
}

impl PersonChange {
    /// The word a refusal carries as its `reason`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FocusChanged => "focus_changed",
            Self::WindowChanged => "window_changed",
            Self::InputSeen => "input_seen",
        }
    }
}

/// Compare what the agent saw with the application now.
///
/// `frontmost_now` is whether the application is frontmost at this moment,
/// and `person_input_at` when session-wide hardware input last arrived,
/// as reported by a continuously covering observer. Input
/// counts only when the application is frontmost at check time. This is
/// deliberately conservative: input in another app followed by a switch to
/// this target can require a fresh read too, but background actions proceed.
pub fn person_change(
    seen: &SeenMarks,
    now: &SeenMarks,
    frontmost_now: bool,
    person_input_at: Option<Instant>,
) -> Option<PersonChange> {
    if let (Reading::Read(before), Reading::Read(after)) = (&seen.windows, &now.windows) {
        if before != after {
            return Some(PersonChange::WindowChanged);
        }
    }
    if let (Reading::Read(before), Reading::Read(after)) = (&seen.focused, &now.focused) {
        let same = match (before, after) {
            (Some(before), Some(after)) => before.same_element(after.as_ref()),
            (None, None) => true,
            _ => false,
        };
        if !same {
            return Some(PersonChange::FocusChanged);
        }
    }
    if let (Reading::Read(before), Reading::Read(after)) = (&seen.window, &now.window) {
        let same = match (before, after) {
            (Some(before), Some(after)) => before.same_as(after),
            (None, None) => true,
            _ => false,
        };
        if !same {
            return Some(PersonChange::WindowChanged);
        }
    }
    if frontmost_now && person_input_at.is_some_and(|at| at > seen.at) {
        return Some(PersonChange::InputSeen);
    }
    None
}

/// Legacy bookkeeping of this module's posting intervals.
///
/// This excludes only our posts, not synthetic input from other programs.
/// It is not a hardware-input observer and must not be used as evidence of
/// person activity.
///
/// The count says only when the latest input arrived, not who sent it, and
/// on macOS it includes events this module posts. A post therefore hides any
/// earlier input of the person's from later readings; the person's latest
/// input seen just before each post is kept here so it is not lost.
#[derive(Debug, Default)]
pub struct OwnInputLedger {
    state: Mutex<LedgerState>,
}

#[derive(Debug, Default)]
struct LedgerState {
    /// When each recent post began and, once it is over, when it ended.
    posts: VecDeque<(Instant, Option<Instant>)>,
    /// The person's latest input as the platform reported it just before
    /// this module posted. The platform reports only the newest input, so
    /// once this module's post is newer the person's is no longer reported
    /// and would be lost without this copy.
    person_before_posts: Option<Instant>,
}

impl LedgerState {
    /// Whether input that arrived at `at` can be this module's own: it fell
    /// inside a post, or within the platform's lag after one.
    fn is_own(&self, at: Instant) -> bool {
        self.posts
            .iter()
            .any(|(start, end)| at >= *start && end.is_none_or(|end| at <= end + OWN_INPUT_LAG))
    }
}

/// One post in progress, returned by [`OwnInputLedger::begin_posting`] and
/// handed back to [`OwnInputLedger::end_posting`].
#[derive(Debug)]
#[must_use = "a post that is never ended keeps counting all later input as this module's own"]
pub struct Posting {
    start: Instant,
}

impl Posting {
    /// When the interval began. Pass it to `end_posting_at` to close this
    /// interval without the `Posting` itself.
    pub fn start(&self) -> Instant {
        self.start
    }
}

impl OwnInputLedger {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LedgerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Note that this module is about to post input. `last_input` is when
    /// the platform last counted input, read just before; if that input was
    /// not this module's own it was the person's, and it is kept, because
    /// the post about to be made will replace it as the newest input the
    /// platform reports.
    pub fn begin_posting(&self, last_input: Option<Instant>) -> Posting {
        let mut state = self.lock();
        if let Some(at) = last_input.filter(|at| !state.is_own(*at)) {
            state.person_before_posts = state.person_before_posts.max(Some(at));
        }
        let start = Instant::now();
        state.posts.push_back((start, None));
        while state.posts.len() > REMEMBERED_POSTS {
            state.posts.pop_front();
        }
        Posting { start }
    }

    /// Note that a post has ended, however it ended.
    pub fn end_posting(&self, posting: Posting) {
        self.end_posting_at(posting.start);
    }

    /// Close the interval that began at `start`, if it is still open.
    ///
    /// For a post whose call reached its terminal decision while the post
    /// was still blocked: the interval is closed at the terminal, so later
    /// input on other applications is not taken for this module's own. A
    /// second close, including the worker's own `end_posting` when it
    /// finally returns, changes nothing.
    pub fn end_posting_at(&self, start: Instant) {
        let mut state = self.lock();
        let end = Instant::now();
        if let Some(entry) = state
            .posts
            .iter_mut()
            .rev()
            .find(|entry| entry.0 == start && entry.1.is_none())
        {
            entry.1 = Some(end);
        }
    }

    /// Whether any posting interval is still open.
    pub fn has_open_posting(&self) -> bool {
        self.lock().posts.iter().any(|(_, end)| end.is_none())
    }

    /// The latest input not explained by this module's posting intervals.
    /// Despite the legacy name, this may be another process's synthetic
    /// input and must not establish that a person acted.
    pub fn latest_person_input(&self, last_input: Option<Instant>) -> Option<Instant> {
        let state = self.lock();
        let current = last_input.filter(|at| !state.is_own(*at));
        current.max(state.person_before_posts)
    }
}

/// When the platform last counted input, as an instant: the reading is an
/// age, taken now.
pub fn last_input_instant(source: &dyn AppStateSource) -> Option<Instant> {
    let age = source.time_since_last_input()?;
    Instant::now().checked_sub(age)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_inside_or_just_after_a_post_is_this_module_s_own() {
        let ledger = OwnInputLedger::new();
        let posting = ledger.begin_posting(None);
        let during = Instant::now();
        ledger.end_posting(posting);
        assert_eq!(ledger.latest_person_input(Some(during)), None);
        assert_eq!(
            ledger.latest_person_input(Some(Instant::now() + OWN_INPUT_LAG / 2)),
            None,
            "input within the platform's lag after a post was taken for the person's"
        );
        let later = Instant::now() + OWN_INPUT_LAG * 3;
        assert_eq!(ledger.latest_person_input(Some(later)), Some(later));
    }

    #[test]
    fn the_person_s_input_hidden_by_a_later_post_is_remembered() {
        let ledger = OwnInputLedger::new();
        let person = Instant::now();
        std::thread::sleep(Duration::from_millis(2));
        let posting = ledger.begin_posting(Some(person));
        let own = Instant::now();
        ledger.end_posting(posting);
        assert_eq!(ledger.latest_person_input(Some(own)), Some(person));
    }
}
