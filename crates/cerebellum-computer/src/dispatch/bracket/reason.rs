//! Why fronting stopped, as the reply names it.
//!
//! Every way a front can stop maps to exactly one reason from a closed set,
//! and each reason carries its own remedy. Only a change the target-change
//! guard detected is reported as the person changing the target; every other
//! stop says what actually happened, so a caller is never told the person
//! used an application when nothing showed that.

use serde::{Deserialize, Serialize};

use super::BracketStop;
use crate::dispatch::seize::{AbortReason, IdleGateRefusal};

/// Every way fronting can stop before, or while, the target is brought
/// forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontingStop {
    /// A release posted by an earlier call is still unconfirmed, so a key or
    /// button may be held down.
    HeldInputUnconfirmed,
    /// The target-change guard saw the person change the target since the
    /// agent last read it.
    PersonChangedTarget,
    /// The target-change guard could not read what it compares.
    PersonCheckUnreadable,
    /// The action would send input to the target once it is in front, and
    /// the conversation never read the target, so the target-change guard
    /// has nothing to compare against.
    TargetNotRead,
    /// No input observer could be started.
    ObserverUnavailable,
    /// The idle gate refused: unreadable, or the person was recently active.
    IdleGateRefused(IdleGateRefusal),
    /// The observer's heartbeat did not come back, or it could not keep up.
    ObserverBlind,
    /// Input Monitoring is not live, so no person input could be seen.
    InputMonitoringNotLive,
    /// Input that was not ours arrived.
    UserSeizedControl,
    /// The target stopped being frontmost.
    FocusMoved,
    /// The frontmost application could not be read, so it could not be put
    /// back.
    PreviousUnknown,
    /// The target did not come to the front.
    FrontFailed,
    /// The front wait used up its bound.
    BoundExceeded,
    /// The caller cancelled.
    Cancelled,
    /// The dispatch gate closed: the route closed, the work deadline passed,
    /// or authorization was lost.
    DispatchGateClosed,
    /// The call's terminal reply was already chosen when the restore
    /// obligation was registered.
    TerminalAlreadyChosen,
    /// Cleanup took the restore obligation before the front was dispatched.
    CleanupTookObligation,
    /// The process-wide fronting lock was not taken in time.
    FrontingLockTimedOut,
    /// No person is attending the session.
    Unattended,
    /// This build is not admitted to front applications.
    FrontingNotAdmitted,
}

impl FrontingStop {
    /// The stop an observed-sequence abort stands for.
    pub fn from_abort(reason: AbortReason) -> Self {
        match reason {
            AbortReason::UserSeizedControl => Self::UserSeizedControl,
            AbortReason::ObserverUnavailable => Self::ObserverUnavailable,
            AbortReason::SeizeLatencyBoundExceeded => Self::ObserverBlind,
            AbortReason::IdleGateRefused(refusal) => Self::IdleGateRefused(refusal),
            AbortReason::FocusMismatch => Self::FocusMoved,
        }
    }

    /// The stop a bracket that fronted nothing stands for. `None` for the
    /// stops that only happen after units were posted: a post failure, or a
    /// restore failure, which are reported as themselves rather than as a
    /// reason for not fronting.
    pub fn from_bracket_stop(stop: &BracketStop) -> Option<Self> {
        match stop {
            BracketStop::PreviousUnknown => Some(Self::PreviousUnknown),
            BracketStop::ObserverUnavailable => Some(Self::ObserverUnavailable),
            BracketStop::FrontFailed => Some(Self::FrontFailed),
            BracketStop::BoundExceeded => Some(Self::BoundExceeded),
            BracketStop::Aborted(abort) => Some(Self::from_abort(abort.reason)),
            BracketStop::Cancelled => Some(Self::Cancelled),
            BracketStop::PostFailed(_) | BracketStop::RestoreFailed => None,
        }
    }
}

/// The reply's `not_fronted_reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotFrontedReason {
    HeldInputUnconfirmed,
    PersonChangedTarget,
    ObserverUnavailable,
    PersonActive,
    PreviousUnknown,
    FrontFailed,
    Cancelled,
    FrontingBusy,
    Unattended,
    FrontingUnavailable,
    TargetNotRead,
}

impl NotFrontedReason {
    /// Every reason, in the order the reply vocabulary lists them.
    pub const ALL: [Self; 11] = [
        Self::HeldInputUnconfirmed,
        Self::PersonChangedTarget,
        Self::ObserverUnavailable,
        Self::PersonActive,
        Self::PreviousUnknown,
        Self::FrontFailed,
        Self::Cancelled,
        Self::FrontingBusy,
        Self::Unattended,
        Self::FrontingUnavailable,
        Self::TargetNotRead,
    ];

    /// The wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HeldInputUnconfirmed => "held_input_unconfirmed",
            Self::PersonChangedTarget => "person_changed_target",
            Self::ObserverUnavailable => "observer_unavailable",
            Self::PersonActive => "person_active",
            Self::PreviousUnknown => "previous_unknown",
            Self::FrontFailed => "front_failed",
            Self::Cancelled => "cancelled",
            Self::FrontingBusy => "fronting_busy",
            Self::Unattended => "unattended",
            Self::FrontingUnavailable => "fronting_unavailable",
            Self::TargetNotRead => "target_not_read",
        }
    }

    /// What the caller can do about it. Only `person_changed_target` says the
    /// person used the target.
    pub const fn remedy(self) -> &'static str {
        match self {
            Self::HeldInputUnconfirmed => {
                "a key or button released by an earlier action is not yet confirmed up; \
                 retry once that release is confirmed"
            }
            Self::PersonChangedTarget => {
                "the person changed this application since it was last read; read it again \
                 before acting"
            }
            Self::ObserverUnavailable => {
                "person input could not be observed, so the application was not brought forward; \
                 check that Input Monitoring is granted, then retry"
            }
            Self::PersonActive => "the person is using the computer; wait a moment, then retry",
            Self::PreviousUnknown => {
                "the frontmost application could not be read, so it could not have been put back; \
                 retry"
            }
            Self::FrontFailed => "the application did not come to the front in time; retry",
            Self::Cancelled => {
                "the action was cancelled before the application was brought forward"
            }
            Self::FrontingBusy => {
                "another action is bringing an application forward; retry after it finishes"
            }
            Self::Unattended => {
                "no person is attending this session, so no application is brought forward"
            }
            Self::FrontingUnavailable => {
                "this build cannot bring applications forward; the action ran without fronting"
            }
            Self::TargetNotRead => "Read the app with read_state first, then retry.",
        }
    }
}

/// The reason a fronting stop is reported with. Total: every stop has one.
pub fn not_fronted_reason(stop: FrontingStop) -> NotFrontedReason {
    match stop {
        FrontingStop::HeldInputUnconfirmed => NotFrontedReason::HeldInputUnconfirmed,
        FrontingStop::PersonChangedTarget => NotFrontedReason::PersonChangedTarget,
        FrontingStop::TargetNotRead => NotFrontedReason::TargetNotRead,
        FrontingStop::PersonCheckUnreadable
        | FrontingStop::ObserverUnavailable
        | FrontingStop::IdleGateRefused(IdleGateRefusal::Unreadable(_))
        | FrontingStop::ObserverBlind
        | FrontingStop::InputMonitoringNotLive => NotFrontedReason::ObserverUnavailable,
        FrontingStop::IdleGateRefused(IdleGateRefusal::BelowThreshold { .. })
        | FrontingStop::UserSeizedControl
        | FrontingStop::FocusMoved => NotFrontedReason::PersonActive,
        FrontingStop::PreviousUnknown => NotFrontedReason::PreviousUnknown,
        FrontingStop::FrontFailed | FrontingStop::BoundExceeded => NotFrontedReason::FrontFailed,
        FrontingStop::Cancelled
        | FrontingStop::DispatchGateClosed
        | FrontingStop::TerminalAlreadyChosen
        | FrontingStop::CleanupTookObligation => NotFrontedReason::Cancelled,
        FrontingStop::FrontingLockTimedOut => NotFrontedReason::FrontingBusy,
        FrontingStop::Unattended => NotFrontedReason::Unattended,
        FrontingStop::FrontingNotAdmitted => NotFrontedReason::FrontingUnavailable,
    }
}
