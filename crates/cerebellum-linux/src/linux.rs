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

/// What procfs reports about a process generation, in facts the wall clock cannot move.
///
/// `boot_id` names one boot of the kernel and `start_ticks` counts clock ticks
/// from that boot to the process's creation. Neither is derived from realtime,
/// so the pair reads the same before and after a wall-clock step, unlike the
/// epoch start time from [`process_start_time`]. Ticks alone repeat across
/// boots, which is why the boot is part of the reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessGenerationReading {
    /// The process holds this ID in the named boot.
    Started { boot_id: [u8; 16], start_ticks: u64 },
    /// No process holds this ID.
    NoSuchProcess,
    /// The process exists but procfs would not reveal its stat record.
    NotPermitted,
    /// Procfs did not yield the process stat record for an unclassified read failure.
    StatReadFailed,
    /// The kernel's boot identity could not be read.
    BootIdUnavailable,
    /// Procfs or the boot identity did not have the layout this parser requires.
    LayoutMismatch,
    /// The process reported a start value that cannot name a generation.
    NoStartTime,
}

/// Read the clock-independent generation of `pid`: this boot's ID and the
/// process's start in ticks since boot.
///
/// The boot ID is read first and a failure there is reported even when the
/// process is absent, so a caller never sees a verdict that skipped half of
/// the identity.
pub fn process_generation(pid: u32) -> ProcessGenerationReading {
    process_generation_from_readings(
        fs::read_to_string("/proc/sys/kernel/random/boot_id"),
        || fs::read_to_string(format!("/proc/{pid}/stat")),
    )
}

fn process_generation_from_readings(
    boot_id: Result<String, io::Error>,
    stat: impl FnOnce() -> Result<String, io::Error>,
) -> ProcessGenerationReading {
    let boot_id = match boot_id {
        Ok(text) => match parse_boot_id(&text) {
            Some(boot_id) => boot_id,
            None => return ProcessGenerationReading::LayoutMismatch,
        },
        Err(_) => return ProcessGenerationReading::BootIdUnavailable,
    };
    let stat = match stat() {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return ProcessGenerationReading::NoSuchProcess
        }
        Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
            return ProcessGenerationReading::NotPermitted
        }
        Err(_) => return ProcessGenerationReading::StatReadFailed,
    };
    match stat_start_ticks(&stat) {
        Ok(start_ticks) => ProcessGenerationReading::Started {
            boot_id,
            start_ticks,
        },
        Err(ProcessStartTime::LayoutMismatch) => ProcessGenerationReading::LayoutMismatch,
        Err(_) => ProcessGenerationReading::NoStartTime,
    }
}

/// Parse the kernel's boot ID: one hyphenated UUID, `8-4-4-4-12` hex digits,
/// followed by the newline procfs appends.
fn parse_boot_id(text: &str) -> Option<[u8; 16]> {
    let text = text.strip_suffix('\n').unwrap_or(text);
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    let mut digits = [0_u8; 32];
    let mut count = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return None;
            }
            continue;
        }
        digits[count] = (byte as char).to_digit(16)? as u8;
        count += 1;
    }
    let mut boot_id = [0_u8; 16];
    for (index, byte) in boot_id.iter_mut().enumerate() {
        *byte = (digits[2 * index] << 4) | digits[2 * index + 1];
    }
    Some(boot_id)
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

    const BOOT_ID: &str = "3f1c2a4e-9b7d-4c21-8e0f-a1b2c3d4e5f6\n";
    const BOOT_ID_BYTES: [u8; 16] = [
        0x3f, 0x1c, 0x2a, 0x4e, 0x9b, 0x7d, 0x4c, 0x21, 0x8e, 0x0f, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5,
        0xf6,
    ];
    const PROCESS_STAT: &str =
        "42 (a (name)) with )  S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 98765 0 0";

    #[test]
    fn generation_reads_the_boot_id_and_field_22_after_the_last_parenthesis() {
        assert_eq!(
            process_generation_from_readings(
                Ok(BOOT_ID.to_owned()),
                || Ok(PROCESS_STAT.to_owned())
            ),
            ProcessGenerationReading::Started {
                boot_id: BOOT_ID_BYTES,
                start_ticks: 98765,
            }
        );
    }

    #[test]
    fn a_malformed_boot_id_is_a_layout_mismatch() {
        for boot_id in [
            "",
            "3f1c2a4e9b7d4c218e0fa1b2c3d4e5f6\n",
            "3f1c2a4e-9b7d-4c21-8e0f-a1b2c3d4e5fz\n",
            "3f1c2a4e-9b7d-4c21-8e0f-a1b2c3d4e5f6-\n",
            "3f1c2a4e_9b7d-4c21-8e0f-a1b2c3d4e5f6\n",
        ] {
            assert_eq!(
                process_generation_from_readings(Ok(boot_id.to_owned()), || Ok(
                    PROCESS_STAT.to_owned()
                )),
                ProcessGenerationReading::LayoutMismatch,
                "{boot_id:?}"
            );
        }
    }

    #[test]
    fn an_unreadable_boot_id_is_reported_before_the_process_is_read() {
        assert_eq!(
            process_generation_from_readings(
                Err(std::io::Error::from(std::io::ErrorKind::Other)),
                || panic!("a missing boot identity must not fall through to the process read"),
            ),
            ProcessGenerationReading::BootIdUnavailable
        );
    }

    #[test]
    fn generation_read_failures_keep_their_distinct_meanings() {
        let read = |error: std::io::Error| {
            process_generation_from_readings(Ok(BOOT_ID.to_owned()), || Err(error))
        };
        assert_eq!(
            read(std::io::Error::from(std::io::ErrorKind::NotFound)),
            ProcessGenerationReading::NoSuchProcess
        );
        assert_eq!(
            read(std::io::Error::from_raw_os_error(libc::EACCES)),
            ProcessGenerationReading::NotPermitted
        );
        assert_eq!(
            read(std::io::Error::from(std::io::ErrorKind::Other)),
            ProcessGenerationReading::StatReadFailed
        );
        let stat = |text: &str| {
            process_generation_from_readings(Ok(BOOT_ID.to_owned()), || Ok(text.to_owned()))
        };
        assert_eq!(
            stat("42 (unterminated S 1 2 3"),
            ProcessGenerationReading::LayoutMismatch
        );
        assert_eq!(
            stat("42 (a) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 nope"),
            ProcessGenerationReading::NoStartTime
        );
    }

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
