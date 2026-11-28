//! Windows install writability is a recorded fact, not a launch condition.

pub use cerebellum_windows::writability::{inspect_install, InstallWritability};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTERS: Counters = Counters {
    writable: AtomicU64::new(0),
    unknown: AtomicU64::new(0),
};

#[derive(Debug, PartialEq, Eq)]
pub struct InstallWritabilityCounts {
    pub writable: u64,
    pub unknown: u64,
}

#[derive(Default)]
struct Counters {
    writable: AtomicU64,
    unknown: AtomicU64,
}

impl Counters {
    fn record(&self, writability: InstallWritability) {
        match writability {
            InstallWritability::Writable => self.writable.fetch_add(1, Ordering::Relaxed),
            InstallWritability::Unknown => self.unknown.fetch_add(1, Ordering::Relaxed),
            InstallWritability::NotWritable => return,
        };
    }

    fn snapshot(&self) -> InstallWritabilityCounts {
        InstallWritabilityCounts {
            writable: self.writable.load(Ordering::Relaxed),
            unknown: self.unknown.load(Ordering::Relaxed),
        }
    }
}

/// Record once after the journal durably records the verified launch request,
/// including this measurement, and before process creation. Preparation
/// failures and offline probes do not contribute to health.
pub fn record_committed_install_writability(writability: InstallWritability) {
    COUNTERS.record(writability);
}

pub fn install_writability_counts() -> InstallWritabilityCounts {
    COUNTERS.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_install_writability_health_counts_true_and_unknown_separately() {
        let counters = Counters::default();
        counters.record(InstallWritability::NotWritable);
        assert_eq!(
            counters.snapshot(),
            InstallWritabilityCounts {
                writable: 0,
                unknown: 0
            }
        );
        counters.record(InstallWritability::Writable);
        assert_eq!(
            counters.snapshot(),
            InstallWritabilityCounts {
                writable: 1,
                unknown: 0
            }
        );
        counters.record(InstallWritability::Unknown);
        assert_eq!(
            counters.snapshot(),
            InstallWritabilityCounts {
                writable: 1,
                unknown: 1
            }
        );
    }
}
