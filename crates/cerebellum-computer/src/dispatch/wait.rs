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

/// No single accessibility call may consume more than half a second.
const MAX_SCOPED_READ_MS: u64 = 500;

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
    Indeterminate {
        predicate: PostCondition,
        readback: Option<ObservedElement>,
        reason: String,
    },
}

/// The runtime distinguishes all three terminal states even though the current
/// wire format represents only settled and timed-out results. Keep this enum
/// separate until the wire can represent indeterminate directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    Settled,
    TimedOut,
    Indeterminate,
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
        DriverError::Unsupported(_) => "scoped_read_unsupported",
        DriverError::InvalidRequest(_) => "invalid_scoped_read",
        DriverError::StartupRefused(_) => "platform_startup_refused",
        DriverError::Semantic(_) => "semantic_read_failed",
    }
}

/// Poll one shared predicate until it settles, times out, or cannot be read.
pub fn wait_until_predicate<P: PredicatePoller>(
    poller: &mut P,
    predicate: PostCondition,
    timeout_ms: u64,
) -> WaitResult {
    let timeout = Duration::from_millis(timeout_ms);
    let maximum_attempts = timeout_ms
        .checked_div(WAIT_POLL_INTERVAL_MS)
        .unwrap_or(0)
        .saturating_add(2);
    let mut attempts = 0_u64;
    let mut last_readback = ObservedElement::absent();

    // The attempt bound is derived from the deadline and remains a second guard
    // if a faulty clock or sleeper stops advancing. The elapsed-time checks are
    // still authoritative when a scoped read consumes part of the deadline.
    for _ in 0..maximum_attempts {
        if attempts > 0 && poller.elapsed() >= timeout {
            return timed_out(predicate, last_readback, attempts);
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
            Ok(observed) => observed,
            Err(reason) => {
                return WaitResult {
                    outcome: WaitOutcome::Indeterminate,
                    evidence: WaitEvidence::Indeterminate {
                        predicate,
                        readback: None,
                        reason,
                    },
                    attempts,
                }
            }
        };

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

        if poller.elapsed() >= timeout {
            return timed_out(predicate, last_readback, attempts);
        }
        let remaining = timeout.saturating_sub(poller.elapsed());
        poller.sleep(remaining.min(Duration::from_millis(WAIT_POLL_INTERVAL_MS)));
    }

    timed_out(predicate, last_readback, attempts)
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
    use std::collections::VecDeque;

    use super::*;
    use crate::platform::AccessibilityElementName;

    struct FakePoller {
        elapsed: Duration,
        reads: VecDeque<Result<ObservedElement, String>>,
        repeat: Result<ObservedElement, String>,
        read_count: u64,
        advance_sleep: bool,
    }

    impl FakePoller {
        fn repeating(readback: Result<ObservedElement, String>) -> Self {
            Self {
                elapsed: Duration::ZERO,
                reads: VecDeque::new(),
                repeat: readback,
                read_count: 0,
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
            _deadline_ms: u32,
        ) -> Result<ObservedElement, String> {
            self.read_count += 1;
            self.reads
                .pop_front()
                .unwrap_or_else(|| self.repeat.clone())
        }

        fn sleep(&mut self, duration: Duration) {
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
        }
    }

    #[test]
    fn wait_engine_consumes_post_condition_directly_without_a_second_predicate_type() {
        let shared_vocabulary: fn(&mut FakePoller, PostCondition, u64) -> WaitResult =
            wait_until_predicate::<FakePoller>;
        let _ = shared_vocabulary;
    }

    #[test]
    fn an_already_true_role_and_title_predicate_settles_immediately_and_names_itself() {
        let predicate = focused("AXTextField", "Account");
        let readback = observed_focus(true);
        let mut poller = FakePoller::repeating(Ok(readback.clone()));

        let result = wait_until_predicate(&mut poller, predicate.clone(), 1_000);

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

        let result = wait_until_predicate(&mut poller, predicate.clone(), 100);

        assert_eq!(result.outcome, WaitOutcome::TimedOut);
        assert_eq!(
            result.evidence,
            WaitEvidence::TimedOut {
                predicate,
                readback,
            }
        );
    }

    #[test]
    fn an_unreadable_target_reports_indeterminate_not_timed_out() {
        let predicate = focused("AXTextField", "Account");
        let mut poller = FakePoller::repeating(Err("target_not_inspectable".to_string()));

        let result = wait_until_predicate(&mut poller, predicate.clone(), 100);

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
    fn deadline_bounds_a_wait_even_when_the_clock_stalls() {
        let predicate = focused("AXTextField", "Account");
        let mut poller = FakePoller::repeating(Ok(observed_focus(false)));
        poller.advance_sleep = false;

        let result = wait_until_predicate(&mut poller, predicate, 100);

        assert_eq!(result.outcome, WaitOutcome::TimedOut);
        assert_eq!(poller.read_count, 4);
    }
}
