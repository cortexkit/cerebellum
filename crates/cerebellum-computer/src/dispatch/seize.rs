//! The two-channel observed-mode abort guard.
//!
//! The session tap sees our events and therefore needs the self-echo filter;
//! the raw-HID channel cannot see injected events and is the independent second
//! signal.  Once the guard records an abort, queued work is cancelled and the
//! guard never permits another post.

use crate::platform::{InputObservationResult, InputObserverLiveness};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeizeWatcherState {
    pub session_tap_live: bool,
    pub raw_hid_live: bool,
    pub self_echo_filter_live: bool,
}

impl From<InputObserverLiveness> for SeizeWatcherState {
    fn from(value: InputObserverLiveness) -> Self {
        Self {
            session_tap_live: value.session_tap_live,
            raw_hid_live: value.raw_hid_live,
            self_echo_filter_live: value.self_echo_filter_live,
        }
    }
}

impl SeizeWatcherState {
    pub fn live(self) -> bool {
        self.session_tap_live && self.raw_hid_live && self.self_echo_filter_live
    }
}

/// The next protected post must not be scheduled before the observer's worst
/// case abort signal can arrive.  Otherwise a human event could be detected only
/// after the following post had already escaped the stop path.
pub const fn seize_latency_fits_inter_post_interval(
    maximum_detection_latency_ms: u32,
    inter_post_interval_ms: u32,
) -> bool {
    inter_post_interval_ms >= maximum_detection_latency_ms
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    UserSeizedControl,
    ObserverUnavailable,
    SeizeLatencyBoundExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortDecision {
    pub reason: AbortReason,
    pub stopped_action_index: usize,
    pub detection_latency_ms: Option<u32>,
    pub maximum_detection_latency_ms: u32,
    pub queued_posts_cancelled: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeizeWatcher {
    abort: Option<AbortDecision>,
    queued_posts: u32,
    maximum_detection_latency_ms: u32,
}

impl SeizeWatcher {
    pub fn new(maximum_detection_latency_ms: u32) -> Self {
        Self {
            abort: None,
            queued_posts: 0,
            maximum_detection_latency_ms,
        }
    }

    pub fn queue_post(&mut self) -> bool {
        if self.abort.is_some() {
            return false;
        }
        self.queued_posts = self.queued_posts.saturating_add(1);
        true
    }

    pub fn can_post(&self) -> bool {
        self.abort.is_none()
    }

    pub fn abort(&mut self, reason: AbortReason, index: usize, latency: Option<u32>) {
        if self.abort.is_some() {
            return;
        }
        let cancelled = self.queued_posts;
        self.queued_posts = 0;
        self.abort = Some(AbortDecision {
            reason,
            stopped_action_index: index,
            detection_latency_ms: latency,
            maximum_detection_latency_ms: self.maximum_detection_latency_ms,
            queued_posts_cancelled: cancelled,
        });
    }

    pub fn observe_liveness(&mut self, state: SeizeWatcherState, index: usize) {
        if !state.live() {
            self.abort(AbortReason::ObserverUnavailable, index, None);
        }
    }

    pub fn observe_input(&mut self, observation: InputObservationResult, index: usize) {
        if observation.human_or_ambiguous_input {
            let reason = if observation.detection_latency_ms > self.maximum_detection_latency_ms {
                AbortReason::SeizeLatencyBoundExceeded
            } else {
                AbortReason::UserSeizedControl
            };
            self.abort(reason, index, Some(observation.detection_latency_ms));
        }
    }

    pub fn take_post_slot(&mut self) -> bool {
        if self.abort.is_some() {
            return false;
        }
        self.queued_posts = self.queued_posts.saturating_sub(1);
        true
    }

    pub fn abort_decision(&self) -> Option<AbortDecision> {
        self.abort
    }

    pub fn queued_posts(&self) -> u32 {
        self.queued_posts
    }
}
