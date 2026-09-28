//! Chromium builds its accessibility tree lazily and can drop it on reload.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualAccessibility {
    Enabled,
    NotSupported,
    Failed(i32),
}

/// One retry only: an accepted opt-in does not mean the renderer has finished
/// building the tree. Native applications that reject the optional attribute
/// are read once, without waiting for a web tree they will never build.
pub(crate) fn read_with_manual_accessibility<T, E>(
    mut enable: impl FnMut(bool) -> (ManualAccessibility, bool),
    mut read: impl FnMut(Duration) -> Result<T, E>,
    populated_web: impl Fn(&T) -> bool,
    pause: impl FnOnce(Duration),
    requested_bound: Duration,
) -> Result<T, E> {
    let (status, fresh) = enable(false);
    let bound = if status == ManualAccessibility::Enabled {
        requested_bound.min(Duration::from_millis(400))
    } else {
        requested_bound
    };
    let first = read(bound)?;
    if status != ManualAccessibility::Enabled || populated_web(&first) {
        return Ok(first);
    }
    // A fresh enable is already in flight. Otherwise a reload may have cleared
    // the flag, so set it again before spending the one retry.
    if !fresh && enable(true).0 != ManualAccessibility::Enabled {
        return Ok(first);
    }
    pause(Duration::from_millis(100));
    read(bound)
}

#[cfg(target_os = "macos")]
pub(crate) fn prepare(pid: u32, force: bool) -> (ManualAccessibility, bool) {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static ENABLED: OnceLock<Mutex<HashMap<u32, (u64, ManualAccessibility)>>> = OnceLock::new();
    let crate::ProcessStartTime::Started(generation) = crate::process_start_time(pid) else {
        return (ManualAccessibility::Failed(-1), false);
    };
    let mut cache = ENABLED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !force {
        if let Some((previous, status)) = cache.get(&pid) {
            if *previous == generation {
                return (*status, false);
            }
        }
    }
    let status = crate::ax_actions::enable_manual_accessibility(pid);
    if !matches!(status, ManualAccessibility::Failed(_)) {
        cache.insert(pid, (generation, status));
    }
    (status, status == ManualAccessibility::Enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn native_not_supported_reads_once_successfully() {
        let reads = Cell::new(0);
        let result = read_with_manual_accessibility(
            |_| (ManualAccessibility::NotSupported, false),
            |_| {
                reads.set(reads.get() + 1);
                Ok::<_, ()>(false)
            },
            |tree| *tree,
            |_| panic!("native app must not wait"),
            Duration::from_secs(4),
        );
        assert_eq!(result, Ok(false));
        assert_eq!(reads.get(), 1);
    }

    #[test]
    fn fresh_empty_web_tree_gets_exactly_one_bounded_reread() {
        for fresh in [true, false] {
            let reads = Cell::new(0);
            let enables = Cell::new(0);
            let budget = Cell::new(Duration::ZERO);
            let result = read_with_manual_accessibility(
                |_| {
                    enables.set(enables.get() + 1);
                    (ManualAccessibility::Enabled, fresh)
                },
                |bound| {
                    reads.set(reads.get() + 1);
                    budget.set(budget.get() + bound);
                    Ok::<_, ()>(false)
                },
                |tree| *tree,
                |wait| budget.set(budget.get() + wait),
                Duration::from_secs(4),
            );
            assert_eq!(result, Ok(false), "an empty retry is reported honestly");
            assert_eq!(reads.get(), 2);
            assert_eq!(enables.get(), if fresh { 1 } else { 2 });
            assert!(budget.get() <= Duration::from_secs(1));
        }
    }

    #[test]
    fn populated_web_or_failed_enable_never_retries() {
        for status in [
            ManualAccessibility::Enabled,
            ManualAccessibility::Failed(-42),
        ] {
            let reads = Cell::new(0);
            assert_eq!(
                read_with_manual_accessibility(
                    |_| (status, true),
                    |_| {
                        reads.set(reads.get() + 1);
                        Ok::<_, ()>(true)
                    },
                    |tree| *tree,
                    |_| panic!("no retry"),
                    Duration::from_secs(4),
                ),
                Ok(true)
            );
            assert_eq!(reads.get(), 1);
        }
    }
}
