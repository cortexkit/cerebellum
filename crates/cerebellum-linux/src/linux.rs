use std::{fs, io};

/// What procfs reports when asked when a process started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStartTime {
    /// Microseconds since the Unix epoch.
    Started(u64),
    /// No process holds this ID.
    NoSuchProcess,
    /// The process exists but procfs would not reveal its stat record.
    NotPermitted,
    /// Procfs did not yield the process stat record for an unclassified read failure.
    StatReadFailed,
    /// The system boot time or clock tick rate needed to calculate the start time was unavailable.
    SystemTimeBaseUnavailable,
    /// Procfs did not have the layout this parser requires.
    LayoutMismatch,
    /// The process reported a start value that cannot name a generation.
    NoStartTime,
}

/// Read a kernel-sourced process start time that distinguishes PID reuse.
///
/// The full enum is intentional: collapsing `NotPermitted` and `NoSuchProcess`
/// would erase the distinction between an unreadable generation and a mismatch.
pub fn process_start_time(pid: u32) -> ProcessStartTime {
    process_start_time_from_readings(
        fs::read_to_string(format!("/proc/{pid}/stat")),
        || fs::read_to_string("/proc/stat"),
        || {
            // SAFETY: sysconf reads a process-global kernel configuration value.
            unsafe { libc::sysconf(libc::_SC_CLK_TCK) }
        },
    )
}

fn process_start_time_from_readings(
    stat: Result<String, io::Error>,
    system_stat: impl FnOnce() -> Result<String, io::Error>,
    ticks_per_second: impl FnOnce() -> libc::c_long,
) -> ProcessStartTime {
    let stat = match stat {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return ProcessStartTime::NoSuchProcess
        }
        Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
            return ProcessStartTime::NotPermitted
        }
        Err(_) => return ProcessStartTime::StatReadFailed,
    };
    let start_ticks = match stat_start_ticks(&stat) {
        Ok(ticks) => ticks,
        Err(outcome) => return outcome,
    };
    let system_stat = match system_stat() {
        Ok(stat) => stat,
        Err(_) => return ProcessStartTime::SystemTimeBaseUnavailable,
    };
    let boot_seconds = match boot_time_seconds(&system_stat) {
        Some(seconds) => seconds,
        None => return ProcessStartTime::SystemTimeBaseUnavailable,
    };
    let ticks_per_second = ticks_per_second();
    if ticks_per_second <= 0 {
        return ProcessStartTime::SystemTimeBaseUnavailable;
    }
    let ticks_per_second = ticks_per_second as u64;
    boot_seconds
        .checked_mul(1_000_000)
        .and_then(|boot| {
            start_ticks
                .checked_mul(1_000_000)
                .map(|ticks| (boot, ticks))
        })
        .and_then(|(boot, ticks)| {
            ticks
                .checked_div(ticks_per_second)
                .and_then(|ticks| boot.checked_add(ticks))
        })
        .map(ProcessStartTime::Started)
        .unwrap_or(ProcessStartTime::NoStartTime)
}

fn boot_time_seconds(stat: &str) -> Option<u64> {
    stat.lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()
}

fn stat_start_ticks(stat: &str) -> Result<u64, ProcessStartTime> {
    // `comm` is parenthesized but may itself contain spaces or parentheses, so
    // field counting can start only after its final closing delimiter.
    let close = stat.rfind(')').ok_or(ProcessStartTime::LayoutMismatch)?;
    let mut fields = stat
        .get(close + 1..)
        .ok_or(ProcessStartTime::LayoutMismatch)?
        .split_ascii_whitespace();
    fields
        .nth(19)
        .ok_or(ProcessStartTime::LayoutMismatch)?
        .parse()
        .map_err(|_| ProcessStartTime::NoStartTime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parser_counts_after_the_last_comm_parenthesis() {
        let stat = "42 (a name) with )  S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 98765";
        assert_eq!(stat_start_ticks(stat), Ok(98765));
    }

    #[test]
    fn an_unclassified_stat_read_failure_is_not_a_layout_or_absence() {
        assert_eq!(
            process_start_time_from_readings(
                Err(std::io::Error::from(std::io::ErrorKind::Other)),
                || panic!("stat failure must not read the system time base"),
                || 100,
            ),
            ProcessStartTime::StatReadFailed
        );
    }

    #[test]
    fn unavailable_system_time_base_is_not_a_target_layout_mismatch() {
        let process_stat =
            "42 (a name) with )  S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 98765";
        for system_stat in [
            Err(std::io::ErrorKind::Other),
            Ok("cpu 1 2 3 4\nbtime not-a-number\n"),
        ] {
            assert_eq!(
                process_start_time_from_readings(
                    Ok(process_stat.to_owned()),
                    || system_stat.map(str::to_owned).map_err(std::io::Error::from),
                    || 100,
                ),
                ProcessStartTime::SystemTimeBaseUnavailable
            );
        }
        assert_eq!(
            process_start_time_from_readings(
                Ok(process_stat.to_owned()),
                || Ok("btime 1\n".to_owned()),
                || 0,
            ),
            ProcessStartTime::SystemTimeBaseUnavailable
        );
    }

    #[test]
    fn structural_stat_failures_are_layout_mismatches() {
        for process_stat in [
            "42 (unterminated S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 98765",
            "42 (a name) with )  S 1 2 3",
        ] {
            assert_eq!(
                process_start_time_from_readings(
                    Ok(process_stat.to_owned()),
                    || Ok("btime 1\n".to_owned()),
                    || 100,
                ),
                ProcessStartTime::LayoutMismatch
            );
        }
    }

    #[test]
    fn an_observed_but_nonnumeric_start_time_remains_unusable() {
        let process_stat =
            "42 (a name) with )  S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 nope";
        assert_eq!(
            process_start_time_from_readings(
                Ok(process_stat.to_owned()),
                || Ok("btime 1\n".to_owned()),
                || 100,
            ),
            ProcessStartTime::NoStartTime
        );
    }
}
