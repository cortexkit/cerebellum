use std::fs;

/// What procfs reports when asked when a process started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStartTime {
    /// Microseconds since the Unix epoch.
    Started(u64),
    /// No process holds this ID.
    NoSuchProcess,
    /// The process exists but procfs would not reveal its stat record.
    NotPermitted,
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
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ProcessStartTime::NoSuchProcess
        }
        Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
            return ProcessStartTime::NotPermitted
        }
        Err(_) => return ProcessStartTime::LayoutMismatch,
    };
    let start_ticks = match stat_start_ticks(&stat) {
        Some(ticks) => ticks,
        None => return ProcessStartTime::NoStartTime,
    };
    let boot_seconds = match boot_time_seconds() {
        Some(seconds) => seconds,
        None => return ProcessStartTime::LayoutMismatch,
    };
    // SAFETY: sysconf reads a process-global kernel configuration value.
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks_per_second <= 0 {
        return ProcessStartTime::NoStartTime;
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

fn boot_time_seconds() -> Option<u64> {
    fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()
}

fn stat_start_ticks(stat: &str) -> Option<u64> {
    // `comm` is parenthesized but may itself contain spaces or parentheses, so
    // field counting can start only after its final closing delimiter.
    let close = stat.rfind(')')?;
    let mut fields = stat.get(close + 1..)?.split_ascii_whitespace();
    fields.nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parser_counts_after_the_last_comm_parenthesis() {
        let stat = "42 (a name) with )  S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 98765";
        assert_eq!(stat_start_ticks(stat), Some(98765));
    }
}
