//! Platform-neutral control flow for walking across ptrace signal-delivery stops.

/// What one wait observed while looking for the next exec event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecStopObservation {
    Exec,
    SignalDelivery(i32),
    UnexpectedStop(i32),
    ProcessExited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExecStopLoopError<E> {
    Control(E),
    UnexpectedStop { signal: i32 },
    ProcessExited,
    SignalStopLimitExceeded { last_signal: i32, limit: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecStopOutcome {
    Exec,
    Deadline,
}

/// Continue until exec, preserving intervening signals and bounding their noise.
pub(crate) fn continue_to_exec_stop<E>(
    signal_stop_limit: usize,
    mut continue_tracee: impl FnMut(Option<i32>) -> Result<(), E>,
    mut wait_for_stop: impl FnMut() -> Result<Option<ExecStopObservation>, E>,
) -> Result<ExecStopOutcome, ExecStopLoopError<E>> {
    let mut signal_to_deliver = None;
    let mut signal_stop_count = 0;

    loop {
        continue_tracee(signal_to_deliver).map_err(ExecStopLoopError::Control)?;
        let Some(observation) = wait_for_stop().map_err(ExecStopLoopError::Control)? else {
            return Ok(ExecStopOutcome::Deadline);
        };
        match observation {
            ExecStopObservation::Exec => return Ok(ExecStopOutcome::Exec),
            ExecStopObservation::ProcessExited => return Err(ExecStopLoopError::ProcessExited),
            ExecStopObservation::UnexpectedStop(signal) => {
                return Err(ExecStopLoopError::UnexpectedStop { signal });
            }
            ExecStopObservation::SignalDelivery(signal) => {
                if signal_stop_count >= signal_stop_limit {
                    return Err(ExecStopLoopError::SignalStopLimitExceeded {
                        last_signal: signal,
                        limit: signal_stop_limit,
                    });
                }
                signal_stop_count += 1;
                signal_to_deliver = Some(signal);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn exec_walk_crosses_and_reinjects_signal_delivery_stops() {
        let mut observations = VecDeque::from([
            ExecStopObservation::SignalDelivery(17),
            ExecStopObservation::SignalDelivery(17),
            ExecStopObservation::Exec,
        ]);
        let mut delivered = Vec::new();

        let outcome = continue_to_exec_stop(
            8,
            |signal| {
                delivered.push(signal);
                Ok::<_, ()>(())
            },
            || Ok(observations.pop_front()),
        );

        assert_eq!(outcome, Ok(ExecStopOutcome::Exec));
        assert_eq!(delivered, vec![None, Some(17), Some(17)]);
    }

    #[test]
    fn exec_walk_signal_noise_has_its_own_bound_and_diagnostic() {
        let mut observations = VecDeque::from([
            ExecStopObservation::SignalDelivery(10),
            ExecStopObservation::SignalDelivery(17),
        ]);

        let outcome =
            continue_to_exec_stop(1, |_| Ok::<_, ()>(()), || Ok(observations.pop_front()));

        assert_eq!(
            outcome,
            Err(ExecStopLoopError::SignalStopLimitExceeded {
                last_signal: 17,
                limit: 1,
            })
        );
    }

    #[test]
    fn unexpected_stop_reports_the_observed_signal() {
        let outcome = continue_to_exec_stop(
            1,
            |_| Ok::<_, ()>(()),
            || Ok(Some(ExecStopObservation::UnexpectedStop(17))),
        );

        assert_eq!(
            outcome,
            Err(ExecStopLoopError::UnexpectedStop { signal: 17 })
        );

        let exited = continue_to_exec_stop(
            1,
            |_| Ok::<_, ()>(()),
            || Ok(Some(ExecStopObservation::ProcessExited)),
        );
        assert_eq!(exited, Err(ExecStopLoopError::ProcessExited));
    }

    #[test]
    fn deadline_is_rechecked_after_each_signal_stop() {
        let mut observations =
            VecDeque::from([Some(ExecStopObservation::SignalDelivery(17)), None]);
        let mut continue_count = 0;

        let outcome = continue_to_exec_stop(
            8,
            |_| {
                continue_count += 1;
                Ok::<_, ()>(())
            },
            || Ok(observations.pop_front().flatten()),
        );

        assert_eq!(outcome, Ok(ExecStopOutcome::Deadline));
        assert_eq!(continue_count, 2);
    }
}
