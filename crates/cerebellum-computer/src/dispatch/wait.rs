//! Bounded polling for the shared post-condition vocabulary.
//!
//! Post-action observation asks one predicate once. A wait asks the same typed
//! judgment repeatedly until it is satisfied or its deadline passes. The
//! cadence changes; the vocabulary and evaluator do not.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::post_condition::{evaluate, ConditionOutcome, ObservedElement, PostCondition};
use crate::platform::{
    AccessibilityElementReadRequest, AccessibilityReadFailure, DriverError, PlatformDriver,
    ProcessGrant, SemanticDriverError,
};

/// Minimum spacing between completed reads.
///
/// Fifty milliseconds caps polling at twenty reads per second while still
/// noticing ordinary UI changes within a frame or two. macOS accessibility
/// observers can eventually replace this polling without changing predicates
/// or evidence, once `AXObserver` notifications are wired into this crate.
pub const WAIT_POLL_INTERVAL_MS: u64 = 50;

/// Match the full-tree reader's four-second bound while remaining inside the wait deadline.
const MAX_SCOPED_READ_MS: u64 = 4_000;

/// The terminal fact produced by a bounded wait.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WaitEvidence {
    Settled {
        predicate: PostCondition,
        readback: ObservedElement,
    },
    TimedOut {
        predicate: PostCondition,
        readback: ObservedElement,
    },
    Cancelled {
        predicate: PostCondition,
        readback: ObservedElement,
    },
    Indeterminate {
        predicate: PostCondition,
        readback: Option<ObservedElement>,
        reason: String,
    },
}

/// Terminal states exposed by the wait wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    Settled,
    TimedOut,
    Indeterminate,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitResult {
    pub outcome: WaitOutcome,
    pub evidence: WaitEvidence,
    pub attempts: u64,
}

/// Clock, scoped read, and sleep seam used by the bounded polling engine.
pub trait PredicatePoller {
    fn elapsed(&self) -> Duration;
    fn read(
        &mut self,
        predicate: &PostCondition,
        deadline_ms: u32,
    ) -> Result<ObservedElement, String>;
    fn sleep(&mut self, duration: Duration);
}

/// Production poller backed by one platform driver and one authorized target.
pub struct PlatformPredicatePoller<D> {
    driver: D,
    target: ProcessGrant,
    started: Instant,
}

impl<D> PlatformPredicatePoller<D> {
    pub fn new(driver: D, target: ProcessGrant) -> Self {
        Self {
            driver,
            target,
            started: Instant::now(),
        }
    }
}

impl<D: PlatformDriver> PredicatePoller for PlatformPredicatePoller<D> {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    fn read(
        &mut self,
        predicate: &PostCondition,
        deadline_ms: u32,
    ) -> Result<ObservedElement, String> {
        let readback = self
            .driver
            .read_accessibility_element(AccessibilityElementReadRequest {
                target: self.target.clone(),
                element_name: predicate.element().clone(),
                attribute: predicate.readback_attribute(),
                deadline_ms,
            })
            .map_err(|error| readback_failure_reason(&error).to_string())?;
        Ok(ObservedElement {
            present: readback.present,
            focused: readback.focused,
            enabled: readback.enabled,
            value: readback.value,
            unreadable_subtrees: readback.unreadable_subtrees,
        })
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

fn readback_failure_reason(error: &DriverError) -> &'static str {
    match error {
        DriverError::AccessibilityUnreadable(failure) => match failure {
            AccessibilityReadFailure::PermissionRequired => "accessibility_permission_required",
            AccessibilityReadFailure::TargetGone => "target_gone",
            AccessibilityReadFailure::TargetReplaced => "target_replaced",
            AccessibilityReadFailure::TargetNotInspectable => "target_not_inspectable",
            AccessibilityReadFailure::RetryableDeadlineExceeded => "read_deadline_exceeded",
            AccessibilityReadFailure::TreeExceedsBound => "search_bound_exceeded",
            AccessibilityReadFailure::IncompatiblePlatformValue => {
                "incompatible_accessibility_value"
            }
            AccessibilityReadFailure::PlatformReadFailed => "accessibility_read_failed",
        },
        DriverError::Semantic(SemanticDriverError::ElementNameAmbiguous { .. }) => {
            "element_name_ambiguous"
        }
        DriverError::Semantic(SemanticDriverError::TargetNoLongerCurrent { .. }) => {
            "target_no_longer_current"
        }
        DriverError::ElementNotFound => "element_not_found",
        DriverError::SessionNotInspectable(_) => "session_not_console",
        DriverError::WindowVisibilityUnknown { .. } => "window_visibility_unknown",
        DriverError::Unsupported(_) => "scoped_read_unsupported",
        DriverError::InvalidRequest(_) => "invalid_scoped_read",
        DriverError::StartupRefused(_) => "platform_startup_refused",
        DriverError::EventConstructionFailed(_) => "event_construction_failed",
        DriverError::SyntheticDispatchFailed(_) => "synthetic_dispatch_failed",
        DriverError::ObservedDispatchAborted(_) => "observed_dispatch_aborted",
        DriverError::Semantic(_) => "semantic_read_failed",
    }
}

/// Poll one shared predicate until it settles, times out, cannot be read, or is cancelled.
///
/// Cancellation is observed before each read and before sleeping. A cancel during
/// a read therefore waits at most one in-flight scoped read (500 ms), not another
/// polling interval. A cancel during sleep waits at most the 50 ms interval.
pub fn wait_until_predicate<P: PredicatePoller>(
    poller: &mut P,
    predicate: PostCondition,
    timeout_ms: u64,
    cancelled: &dyn Fn() -> bool,
) -> WaitResult {
    let timeout = Duration::from_millis(timeout_ms);
    let maximum_attempts = timeout_ms
        .checked_div(WAIT_POLL_INTERVAL_MS)
        .unwrap_or(0)
        .saturating_add(2);
    let mut attempts = 0_u64;
    let mut last_readback = ObservedElement::absent();
    // Why the last read failed, kept so a wait that never manages one read can
    // say which obstacle it kept hitting rather than reporting a bare timeout.
    let mut last_read_failure: Option<String> = None;
    let mut ever_read = false;

    // The attempt bound is derived from the deadline and remains a second guard
    // if a faulty clock or sleeper stops advancing. The elapsed-time checks are
    // still authoritative when a scoped read consumes part of the deadline.
    for _ in 0..maximum_attempts {
        if cancelled() {
            return cancelled_result(predicate, last_readback, attempts);
        }
        if attempts > 0 && poller.elapsed() >= timeout {
            return deadline_result(
                predicate,
                last_readback,
                attempts,
                ever_read,
                last_read_failure,
            );
        }
        let remaining = timeout.saturating_sub(poller.elapsed());
        let read_budget_ms = u64::try_from(remaining.as_millis())
            .unwrap_or(u64::MAX)
            .clamp(1, MAX_SCOPED_READ_MS);
        attempts = attempts.saturating_add(1);
        let observed = match poller.read(
            &predicate,
            u32::try_from(read_budget_ms).expect("the scoped read cap fits u32"),
        ) {
            Ok(observed) => {
                ever_read = true;
                last_read_failure = None;
                observed
            }
            // A FAILED READ IS NOT A VERDICT. This is a polling primitive, and
            // the commonest reason a scoped read fails is that the element is
            // not there yet: searching a large tree for something absent cannot
            // exit early, so it spends the whole read budget and reports the
            // deadline. Returning here made `computer.wait` one-shot in
            // practice -- measured against Finder, an `element_present` wait for
            // an element that did not exist ended `indeterminate` after a single
            // attempt, which is precisely the case the capability exists to
            // serve. So the reason is remembered and the loop keeps polling;
            // only a wait that reaches its deadline without ever completing a
            // read reports that it could not look.
            Err(reason) => {
                last_read_failure = Some(reason);
                if poller.elapsed() >= timeout {
                    break;
                }
                let remaining = timeout.saturating_sub(poller.elapsed());
                poller.sleep(remaining.min(Duration::from_millis(WAIT_POLL_INTERVAL_MS)));
                continue;
            }
        };

        if observed.unreadable_subtrees > 0 {
            last_readback = observed.clone();
            // Seeing a named element proves presence even if other branches are
            // unreadable. Every other predicate needs a complete search to
            // prove absence, uniqueness, or the selected element's attributes.
            if matches!(predicate, PostCondition::ElementPresent { .. }) && observed.present {
                return WaitResult {
                    outcome: WaitOutcome::Settled,
                    evidence: WaitEvidence::Settled {
                        predicate,
                        readback: observed,
                    },
                    attempts,
                };
            }
        } else {
            match evaluate(&predicate, &observed) {
                ConditionOutcome::Satisfied => {
                    return WaitResult {
                        outcome: WaitOutcome::Settled,
                        evidence: WaitEvidence::Settled {
                            predicate,
                            readback: observed,
                        },
                        attempts,
                    }
                }
                ConditionOutcome::Indeterminate => {
                    return WaitResult {
                        outcome: WaitOutcome::Indeterminate,
                        evidence: WaitEvidence::Indeterminate {
                            predicate,
                            readback: Some(observed),
                            reason: "predicate_attribute_unavailable".to_string(),
                        },
                        attempts,
                    }
                }
                ConditionOutcome::Unsatisfied => last_readback = observed,
            }
        }

        if poller.elapsed() >= timeout {
            return deadline_result(
                predicate,
                last_readback,
                attempts,
                ever_read,
                last_read_failure,
            );
        }
        let remaining = timeout.saturating_sub(poller.elapsed());
        if cancelled() {
            return cancelled_result(predicate, last_readback, attempts);
        }
        poller.sleep(remaining.min(Duration::from_millis(WAIT_POLL_INTERVAL_MS)));
    }

    deadline_result(
        predicate,
        last_readback,
        attempts,
        ever_read,
        last_read_failure,
    )
}

/// What a wait that ran out of time should say.
///
/// A wait that never completed a single read cannot claim the condition was
/// unmet; it can only say it could not look, and name what stopped it. One
/// place decides that, because the loop can reach its deadline at three
/// different points and they must not disagree.
fn deadline_result(
    predicate: PostCondition,
    last_readback: ObservedElement,
    attempts: u64,
    ever_read: bool,
    last_read_failure: Option<String>,
) -> WaitResult {
    if last_readback.unreadable_subtrees > 0 {
        return WaitResult {
            outcome: WaitOutcome::Indeterminate,
            evidence: WaitEvidence::Indeterminate {
                predicate,
                readback: Some(last_readback),
                reason: "partial_accessibility_tree".to_string(),
            },
            attempts,
        };
    }
    match last_read_failure {
        Some(reason) if !ever_read => WaitResult {
            outcome: WaitOutcome::Indeterminate,
            evidence: WaitEvidence::Indeterminate {
                predicate,
                readback: None,
                reason,
            },
            attempts,
        },
        _ => timed_out(predicate, last_readback, attempts),
    }
}

fn cancelled_result(
    predicate: PostCondition,
    readback: ObservedElement,
    attempts: u64,
) -> WaitResult {
    WaitResult {
        outcome: WaitOutcome::Cancelled,
        evidence: WaitEvidence::Cancelled {
            predicate,
            readback,
        },
        attempts,
    }
}

fn timed_out(predicate: PostCondition, readback: ObservedElement, attempts: u64) -> WaitResult {
    WaitResult {
        outcome: WaitOutcome::TimedOut,
        evidence: WaitEvidence::TimedOut {
            predicate,
            readback,
        },
        attempts,
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::VecDeque, rc::Rc};

    use super::*;
    use crate::platform::{process_event::never_cancelled, AccessibilityElementName};

    struct FakePoller {
        elapsed: Duration,
        reads: VecDeque<Result<ObservedElement, String>>,
        repeat: Result<ObservedElement, String>,
        read_count: Rc<Cell<u64>>,
        read_deadlines_ms: Vec<u32>,
        sleep_count: u64,
        cancel_on_sleep: Option<Rc<Cell<bool>>>,
        advance_sleep: bool,
    }

    impl FakePoller {
        /// Answer a scripted sequence of reads, then repeat the last one.
        fn scripted(reads: Vec<Result<ObservedElement, String>>) -> Self {
            let repeat = reads
                .last()
                .cloned()
                .expect("a scripted poller needs at least one read");
            Self {
                elapsed: Duration::ZERO,
                reads: reads.into(),
                repeat,
                read_count: Rc::new(Cell::new(0)),
                read_deadlines_ms: Vec::new(),
                sleep_count: 0,
                cancel_on_sleep: None,
                advance_sleep: true,
            }
        }

        fn repeating(readback: Result<ObservedElement, String>) -> Self {
            Self {
                elapsed: Duration::ZERO,
                reads: VecDeque::new(),
                repeat: readback,
                read_count: Rc::new(Cell::new(0)),
                read_deadlines_ms: Vec::new(),
                sleep_count: 0,
                cancel_on_sleep: None,
                advance_sleep: true,
            }
        }
    }

    impl PredicatePoller for FakePoller {
        fn elapsed(&self) -> Duration {
            self.elapsed
        }

        fn read(
            &mut self,
            _predicate: &PostCondition,
            deadline_ms: u32,
        ) -> Result<ObservedElement, String> {
            self.read_count.set(self.read_count.get() + 1);
            self.read_deadlines_ms.push(deadline_ms);
            self.reads
                .pop_front()
                .unwrap_or_else(|| self.repeat.clone())
        }

        fn sleep(&mut self, duration: Duration) {
            self.sleep_count += 1;
            if let Some(cancelled) = &self.cancel_on_sleep {
                cancelled.set(true);
            }
            if self.advance_sleep {
                self.elapsed += duration;
            }
        }
    }

    fn focused(role: &str, title: &str) -> PostCondition {
        PostCondition::ElementFocused {
            element: AccessibilityElementName::role_and_title(role, title),
        }
    }

    fn observed_focus(value: bool) -> ObservedElement {
        ObservedElement {
            present: true,
            focused: Some(value),
            enabled: None,
            value: None,
            unreadable_subtrees: 0,
        }
    }

    fn partial_observation(present: bool, unreadable_subtrees: u64) -> ObservedElement {
        ObservedElement {
            present,
            focused: None,
            enabled: None,
            value: None,
            unreadable_subtrees,
        }
    }

    #[test]
    fn wait_engine_consumes_post_condition_directly_without_a_second_predicate_type() {
        let shared_vocabulary: fn(
            &mut FakePoller,
            PostCondition,
            u64,
            &dyn Fn() -> bool,
        ) -> WaitResult = wait_until_predicate::<FakePoller>;
        let _ = shared_vocabulary;
    }

    #[test]
    fn an_already_true_role_and_title_predicate_settles_immediately_and_names_itself() {
        let predicate = focused("AXTextField", "Account");
        let readback = observed_focus(true);
        let mut poller = FakePoller::repeating(Ok(readback.clone()));

        let result = wait_until_predicate(&mut poller, predicate.clone(), 1_000, &never_cancelled);

        assert_eq!(result.outcome, WaitOutcome::Settled);
        assert_eq!(result.attempts, 1);
        assert_eq!(
            result.evidence,
            WaitEvidence::Settled {
                predicate,
                readback,
            }
        );
    }

    #[test]
    fn a_never_true_predicate_reports_timed_out_not_settled() {
        let predicate = focused("AXTextField", "Account");
        let readback = observed_focus(false);
        let mut poller = FakePoller::repeating(Ok(readback.clone()));

        let result = wait_until_predicate(&mut poller, predicate.clone(), 100, &never_cancelled);

        assert_eq!(result.outcome, WaitOutcome::TimedOut);
        assert_eq!(
            result.evidence,
            WaitEvidence::TimedOut {
                predicate,
                readback,
            }
        );
    }

    /// A read that fails is not an answer, and a wait that stops on one is not
    /// a wait.
    ///
    /// Measured on the running module against Finder: an `element_present` wait
    /// for an element that did not exist ended `indeterminate` after ONE
    /// attempt, because searching a large tree for something absent cannot exit
    /// early and so spends the whole scoped-read budget. That is the case the
    /// capability exists to serve -- wait for a thing to appear -- and it was
    /// the one case it could not serve.
    #[test]
    fn a_failing_read_is_retried_until_the_predicate_can_be_evaluated() {
        let predicate = focused("AXTextField", "Account");
        let mut poller = FakePoller::scripted(vec![
            Err("read_deadline_exceeded".to_string()),
            Err("read_deadline_exceeded".to_string()),
            Ok(ObservedElement {
                present: true,
                focused: Some(true),
                enabled: None,
                value: None,
                unreadable_subtrees: 0,
            }),
        ]);

        let result = wait_until_predicate(&mut poller, predicate.clone(), 10_000, &never_cancelled);

        assert_eq!(result.outcome, WaitOutcome::Settled);
        assert_eq!(
            result.attempts, 3,
            "the two failed reads must be attempts, not the end of the wait"
        );
    }

    /// The distinction the retry must not erase: a wait that never managed a
    /// read says so, rather than reporting the condition unmet.
    #[test]
    fn a_wait_that_never_reads_names_the_obstacle_rather_than_timing_out() {
        let predicate = focused("AXTextField", "Account");
        let mut poller = FakePoller::repeating(Err("target_not_inspectable".to_string()));

        let result = wait_until_predicate(&mut poller, predicate.clone(), 100, &never_cancelled);

        assert_eq!(result.outcome, WaitOutcome::Indeterminate);
        assert!(
            result.attempts > 1,
            "it must keep trying rather than give up on the first failure, got {}",
            result.attempts
        );
    }

    #[test]
    fn an_unreadable_target_reports_indeterminate_not_timed_out() {
        let predicate = focused("AXTextField", "Account");
        let mut poller = FakePoller::repeating(Err("target_not_inspectable".to_string()));

        let result = wait_until_predicate(&mut poller, predicate.clone(), 100, &never_cancelled);

        assert_eq!(result.outcome, WaitOutcome::Indeterminate);
        assert_eq!(
            result.evidence,
            WaitEvidence::Indeterminate {
                predicate,
                readback: None,
                reason: "target_not_inspectable".to_string(),
            }
        );
    }

    #[test]
    fn a_cancelled_wait_stops_before_the_next_read() {
        let mut poller = FakePoller::repeating(Ok(observed_focus(false)));
        let reads = poller.read_count.clone();
        let result = wait_until_predicate(
            &mut poller,
            focused("AXTextField", "Account"),
            1_000,
            &|| reads.get() >= 2,
        );
        assert_eq!(result.outcome, WaitOutcome::Cancelled);
        assert_eq!(result.attempts, 2);
        assert_eq!(poller.read_count.get(), 2);
    }

    #[test]
    fn a_wait_cancelled_before_the_first_read_reads_nothing() {
        let mut poller = FakePoller::repeating(Ok(observed_focus(false)));
        let result = wait_until_predicate(
            &mut poller,
            focused("AXTextField", "Account"),
            1_000,
            &|| true,
        );
        assert_eq!(result.outcome, WaitOutcome::Cancelled);
        assert_eq!(result.attempts, 0);
        assert_eq!(poller.read_count.get(), 0);
        assert_eq!(poller.sleep_count, 0);
    }

    #[test]
    fn a_cancel_during_sleep_stops_before_another_read() {
        let mut poller = FakePoller::repeating(Ok(observed_focus(false)));
        let cancelled = Rc::new(Cell::new(false));
        poller.cancel_on_sleep = Some(cancelled.clone());
        let result = wait_until_predicate(
            &mut poller,
            focused("AXTextField", "Account"),
            1_000,
            &|| cancelled.get(),
        );
        assert_eq!(result.outcome, WaitOutcome::Cancelled);
        assert_eq!(result.attempts, 1);
        assert_eq!(poller.read_count.get(), 1);
    }

    #[test]
    fn a_cancel_during_read_does_not_pay_another_poll_interval() {
        let mut poller = FakePoller::repeating(Ok(observed_focus(false)));
        let reads = poller.read_count.clone();
        let result = wait_until_predicate(
            &mut poller,
            focused("AXTextField", "Account"),
            1_000,
            &|| reads.get() >= 2,
        );
        assert_eq!(result.outcome, WaitOutcome::Cancelled);
        assert_eq!(poller.sleep_count, 1);
        assert_eq!(poller.elapsed, Duration::from_millis(50));
    }

    #[test]
    fn a_cancelled_wait_carries_the_last_observed_state() {
        let predicate = focused("AXTextField", "Account");
        let readback = observed_focus(false);
        let mut poller = FakePoller::repeating(Ok(readback.clone()));
        poller.reads.push_back(Ok(ObservedElement::absent()));
        let reads = poller.read_count.clone();
        let result =
            wait_until_predicate(&mut poller, predicate.clone(), 1_000, &|| reads.get() >= 2);
        assert_eq!(
            result.evidence,
            WaitEvidence::Cancelled {
                predicate,
                readback
            }
        );
    }

    #[test]
    fn a_wait_with_no_canceller_polls_to_its_timeout() {
        let mut poller = FakePoller::repeating(Ok(observed_focus(false)));
        let result = wait_until_predicate(
            &mut poller,
            focused("AXTextField", "Account"),
            100,
            &never_cancelled,
        );
        assert_eq!(result.outcome, WaitOutcome::TimedOut);
        assert_eq!(result.attempts, 2);
        assert_eq!(poller.read_count.get(), 2);
        assert_eq!(poller.elapsed, Duration::from_millis(100));
    }

    #[test]
    fn windows_read_preconditions_keep_distinct_wait_reason_names() {
        assert_eq!(
            readback_failure_reason(&DriverError::SessionNotInspectable(
                crate::platform::SessionProvenanceRefusal::OtherSession {
                    session_id: 0,
                    console_session_id: 1,
                },
            )),
            "session_not_console"
        );
        assert_eq!(
            readback_failure_reason(&DriverError::WindowVisibilityUnknown { pid: 41 }),
            "window_visibility_unknown"
        );
    }

    #[test]
    fn deadline_bounds_a_wait_even_when_the_clock_stalls() {
        let predicate = focused("AXTextField", "Account");
        let mut poller = FakePoller::repeating(Ok(observed_focus(false)));
        poller.advance_sleep = false;

        let result = wait_until_predicate(&mut poller, predicate, 100, &never_cancelled);

        assert_eq!(result.outcome, WaitOutcome::TimedOut);
        assert_eq!(poller.read_count.get(), 4);
    }

    #[test]
    fn element_present_is_satisfied_when_found_in_a_partial_accessibility_read() {
        let predicate = PostCondition::ElementPresent {
            element: AccessibilityElementName::identifier("ready"),
        };
        let readback = partial_observation(true, 101);
        let mut poller = FakePoller::repeating(Ok(readback.clone()));

        let result = wait_until_predicate(&mut poller, predicate.clone(), 6_000, &never_cancelled);

        assert_eq!(result.outcome, WaitOutcome::Settled);
        assert_eq!(result.attempts, 1);
        assert_eq!(
            result.evidence,
            WaitEvidence::Settled {
                predicate,
                readback,
            }
        );
    }

    #[test]
    fn element_absent_is_indeterminate_when_the_accessibility_read_is_partial() {
        let predicate = PostCondition::ElementAbsent {
            element: AccessibilityElementName::identifier("dialog"),
        };
        let readback = ObservedElement {
            present: true,
            focused: Some(true),
            enabled: Some(true),
            value: Some("ready".to_string()),
            unreadable_subtrees: 101,
        };
        assert_eq!(
            evaluate(&predicate, &readback),
            ConditionOutcome::Indeterminate
        );
        for attribute_predicate in [
            PostCondition::ElementFocused {
                element: predicate.element().clone(),
            },
            PostCondition::ElementEnabledIs {
                element: predicate.element().clone(),
                expected: true,
            },
            PostCondition::ElementValueEquals {
                element: predicate.element().clone(),
                expected: "ready".to_string(),
            },
        ] {
            assert_eq!(
                evaluate(&attribute_predicate, &readback),
                ConditionOutcome::Indeterminate,
                "partial trees cannot establish {attribute_predicate:?}"
            );
        }
        assert_eq!(
            evaluate(
                &PostCondition::ElementPresent {
                    element: predicate.element().clone(),
                },
                &readback
            ),
            ConditionOutcome::Satisfied,
            "a visible match proves presence even when other parts were unreadable"
        );
        let mut poller = FakePoller::repeating(Ok(readback.clone()));

        let result = wait_until_predicate(&mut poller, predicate.clone(), 100, &never_cancelled);

        assert_eq!(result.outcome, WaitOutcome::Indeterminate);
        assert_eq!(
            result.evidence,
            WaitEvidence::Indeterminate {
                predicate,
                readback: Some(readback),
                reason: "partial_accessibility_tree".to_string(),
            }
        );
    }

    #[test]
    fn element_present_not_found_in_partial_reads_times_out_as_indeterminate() {
        let predicate = PostCondition::ElementPresent {
            element: AccessibilityElementName::identifier("ready"),
        };
        let readback = partial_observation(false, 101);
        let mut poller = FakePoller::repeating(Ok(readback.clone()));

        let result = wait_until_predicate(&mut poller, predicate.clone(), 100, &never_cancelled);

        assert_eq!(result.outcome, WaitOutcome::Indeterminate);
        assert_eq!(result.attempts, 2);
        assert_eq!(
            result.evidence,
            WaitEvidence::Indeterminate {
                predicate,
                readback: Some(readback),
                reason: "partial_accessibility_tree".to_string(),
            }
        );
    }

    #[test]
    fn a_wait_poll_uses_the_full_tree_read_budget_without_exceeding_its_timeout() {
        let mut poller = FakePoller::repeating(Ok(observed_focus(false)));
        let _ = wait_until_predicate(
            &mut poller,
            focused("AXTextField", "Account"),
            10_000,
            &never_cancelled,
        );
        assert_eq!(poller.read_deadlines_ms[0], 4_000);

        let mut short_poller = FakePoller::repeating(Ok(observed_focus(false)));
        let _ = wait_until_predicate(
            &mut short_poller,
            focused("AXTextField", "Account"),
            2_500,
            &never_cancelled,
        );
        assert_eq!(short_poller.read_deadlines_ms[0], 2_500);
        assert!(short_poller
            .read_deadlines_ms
            .iter()
            .all(|deadline| *deadline <= 2_500));
    }
}
