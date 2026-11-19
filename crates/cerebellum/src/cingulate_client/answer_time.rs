//! When a consent answer that grants access for 30 minutes was given.
//!
//! A card's answer is usually applied by the call that waits on it, moments
//! after the person chose. An answer that arrives after that call stopped
//! waiting is applied later, by the session's next admitted call draining the
//! answers feed, possibly long after the person answered. The 30 minutes the
//! person was offered run from their answer, not from that later drain, so the
//! drain names the answer's time here while it applies the answer, and the
//! grant writers take their window from it.

use std::cell::Cell;

/// How long a "for 30 minutes" choice grants access.
pub(crate) const THIRTY_MINUTES_MS: u64 = 30 * 60 * 1000;

/// What the drain knows about when an answer was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnswerTime {
    /// The consent service's record says when the person answered.
    Answered(u64),
    /// The record carries no answer time, but the card was raised then: the
    /// answer came no earlier, so its 30 minutes end no later than 30 minutes
    /// after this.
    RaisedNoEarlierThan(u64),
    /// Neither time is known (a card raised by an older build, answered by a
    /// peer that does not stamp answers). No 30-minute window can be bounded,
    /// so such an answer grants nothing.
    Unknown,
}

thread_local! {
    static APPLYING: Cell<Option<AnswerTime>> = const { Cell::new(None) };
}

/// Run `apply`, a synchronous application of one drained answer, with that
/// answer's time in effect for the 30-minute grant writers it calls.
pub(crate) fn applying<T>(time: AnswerTime, apply: impl FnOnce() -> T) -> T {
    struct Restore(Option<AnswerTime>);
    impl Drop for Restore {
        fn drop(&mut self) {
            APPLYING.with(|cell| cell.set(self.0));
        }
    }
    let _restore = Restore(APPLYING.with(|cell| cell.replace(Some(time))));
    apply()
}

/// The start and end of a 30-minute grant being written at `now_ms`, or `None`
/// when its 30 minutes have already passed and nothing may be granted.
///
/// Outside a drain the answer is being applied as it is given, so the window
/// starts now. Inside one it starts at the answer, never later than now (a
/// clock that runs ahead must not lengthen the window).
pub(crate) fn thirty_minute_window(now_ms: u64) -> Option<(u64, u64)> {
    let start = match APPLYING.with(Cell::get) {
        None => now_ms,
        Some(AnswerTime::Answered(at)) => at.min(now_ms),
        Some(AnswerTime::RaisedNoEarlierThan(at)) => at.min(now_ms),
        Some(AnswerTime::Unknown) => return None,
    };
    let end = start.saturating_add(THIRTY_MINUTES_MS);
    (end > now_ms).then_some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_runs_from_the_answer_and_closes_after_thirty_minutes() {
        let now = 10 * THIRTY_MINUTES_MS;
        assert_eq!(
            thirty_minute_window(now),
            Some((now, now + THIRTY_MINUTES_MS))
        );
        let twenty_minutes_ago = now - 20 * 60 * 1000;
        applying(AnswerTime::Answered(twenty_minutes_ago), || {
            assert_eq!(
                thirty_minute_window(now),
                Some((twenty_minutes_ago, now + 10 * 60 * 1000))
            );
        });
        applying(AnswerTime::Answered(now - THIRTY_MINUTES_MS), || {
            assert_eq!(thirty_minute_window(now), None);
        });
        applying(
            AnswerTime::RaisedNoEarlierThan(now - 31 * 60 * 1000),
            || {
                assert_eq!(thirty_minute_window(now), None);
            },
        );
        applying(AnswerTime::Answered(now + 60_000), || {
            assert_eq!(
                thirty_minute_window(now),
                Some((now, now + THIRTY_MINUTES_MS))
            );
        });
        applying(AnswerTime::Unknown, || {
            assert_eq!(thirty_minute_window(now), None);
        });
        assert_eq!(
            thirty_minute_window(now),
            Some((now, now + THIRTY_MINUTES_MS))
        );
    }
}
