//! Chromium builds its accessibility tree lazily and can drop it on reload.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualAccessibility {
    NewlyEnabled,
    AlreadyEnabled,
    NotSupported,
    Failed(i32),
}

/// One retry only: an accepted opt-in does not mean the renderer has finished
/// building the tree. Native applications that reject the optional attribute
/// are read once, without waiting for a web tree they will never build.
///
/// The two reads share the caller's bound: the first may use all of it, and
/// the retry gets what is left after the first read and the pause. The first
/// read is never cut shorter than the caller asked. An empty, still-building
/// web tree reads in milliseconds whatever its bound, so a short bound saves
/// nothing there, while a populated one (a Discord window is some two
/// thousand elements) cut short loses the elements past the cut, reported only
/// as unreadable subtrees.
pub(crate) fn read_with_manual_accessibility<T, E>(
    mut enable: impl FnMut(bool) -> (ManualAccessibility, bool),
    mut read: impl FnMut(Duration) -> Result<T, E>,
    populated_web: impl Fn(&T) -> bool,
    pause: impl FnOnce(Duration),
    requested_bound: Duration,
) -> Result<T, E> {
    const RETRY_PAUSE: Duration = Duration::from_millis(100);
    let started = std::time::Instant::now();
    let (status, fresh) = enable(false);
    let first = read(requested_bound)?;
    if !status.enabled() || populated_web(&first) {
        return Ok(first);
    }
    // A fresh enable is already in flight. Otherwise a reload may have cleared
    // the flag, so set it again before spending the one retry.
    if !fresh && !enable(true).0.enabled() {
        return Ok(first);
    }
    let Some(remaining) = requested_bound
        .checked_sub(started.elapsed())
        .and_then(|left| left.checked_sub(RETRY_PAUSE))
        .filter(|left| !left.is_zero())
    else {
        return Ok(first);
    };
    pause(RETRY_PAUSE);
    read(remaining)
}

#[derive(Default)]
struct EnableCache(std::collections::HashMap<u32, (u64, ManualAccessibility)>);

impl EnableCache {
    fn prepare(
        &mut self,
        pid: u32,
        generation: u64,
        force: bool,
        enable: impl FnOnce() -> ManualAccessibility,
    ) -> (ManualAccessibility, bool) {
        if !force {
            if let Some((previous, status)) = self.0.get(&pid) {
                if *previous == generation {
                    return (
                        match status {
                            ManualAccessibility::NewlyEnabled => {
                                ManualAccessibility::AlreadyEnabled
                            }
                            status => *status,
                        },
                        false,
                    );
                }
            }
        }
        let status = enable();
        if !matches!(status, ManualAccessibility::Failed(_)) {
            self.0.insert(pid, (generation, status));
        }
        (status, status == ManualAccessibility::NewlyEnabled)
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn prepare(pid: u32, force: bool) -> (ManualAccessibility, bool) {
    use std::sync::{Mutex, OnceLock};
    static ENABLED: OnceLock<Mutex<EnableCache>> = OnceLock::new();
    let result =
        if let crate::ProcessStartTime::Started(generation) = crate::process_start_time(pid) {
            ENABLED
                .get_or_init(Default::default)
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .prepare(pid, generation, force, || {
                    crate::ax_actions::enable_manual_accessibility(pid)
                })
        } else {
            (ManualAccessibility::Failed(-1), false)
        };
    ManualAccessibilityScope::record(pid, result.0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn manual_accessibility_audit_records_process_generation_outcomes() {
        let mut cache = EnableCache::default();
        let calls = Cell::new(0);
        let mut action = |pid, generation, result| {
            let _scope = ManualAccessibilityScope::new(pid, None);
            let tree = read_with_manual_accessibility(
                |force| {
                    let enabled = cache.prepare(pid, generation, force, || {
                        calls.set(calls.get() + 1);
                        result
                    });
                    record(pid, enabled.0);
                    enabled
                },
                |_| Ok::<_, ()>(true),
                |populated| *populated,
                |_| panic!("populated tree must not retry"),
                Duration::from_secs(1),
            );
            assert_eq!(tree, Ok(true));
            ManualAccessibilityScope::current().unwrap().as_str()
        };
        assert_eq!(
            action(42, 7, ManualAccessibility::NewlyEnabled),
            "newly_enabled"
        );
        assert_eq!(
            action(42, 7, ManualAccessibility::NewlyEnabled),
            "already_enabled"
        );
        assert_eq!(
            action(43, 8, ManualAccessibility::NotSupported),
            "not_supported"
        );
        assert_eq!(
            action(43, 8, ManualAccessibility::NotSupported),
            "not_supported"
        );
        assert_eq!(
            action(42, 9, ManualAccessibility::NewlyEnabled),
            "newly_enabled"
        );
        assert_eq!(action(44, 10, ManualAccessibility::Failed(-42)), "failed");
        assert_eq!(
            action(44, 10, ManualAccessibility::NewlyEnabled),
            "newly_enabled"
        );
        assert_eq!(
            calls.get(),
            5,
            "only successful generation results are cached"
        );
        assert_eq!(ManualAccessibilityScope::current(), None);
    }

    #[test]
    fn action_scope_preserves_new_enable_and_isolates_threads_and_targets() {
        let _scope = ManualAccessibilityScope::new(42, None);
        record(43, ManualAccessibility::NotSupported);
        assert_eq!(ManualAccessibilityScope::current(), None);
        record(42, ManualAccessibility::NewlyEnabled);
        record(42, ManualAccessibility::AlreadyEnabled);
        assert_eq!(
            ManualAccessibilityScope::current(),
            Some(ManualAccessibility::NewlyEnabled)
        );
        std::thread::spawn(|| {
            assert_eq!(ManualAccessibilityScope::current(), None);
        })
        .join()
        .unwrap();
        {
            let _nested = ManualAccessibilityScope::new(43, None);
            record(43, ManualAccessibility::NotSupported);
            assert_eq!(
                ManualAccessibilityScope::current(),
                Some(ManualAccessibility::NotSupported)
            );
        }
        assert_eq!(
            ManualAccessibilityScope::current(),
            Some(ManualAccessibility::NewlyEnabled)
        );
    }

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
            let bounds = std::cell::RefCell::new(Vec::new());
            let paused = Cell::new(Duration::ZERO);
            let result = read_with_manual_accessibility(
                |_| {
                    enables.set(enables.get() + 1);
                    (ManualAccessibility::NewlyEnabled, fresh)
                },
                |bound| {
                    reads.set(reads.get() + 1);
                    bounds.borrow_mut().push(bound);
                    Ok::<_, ()>(false)
                },
                |tree| *tree,
                |wait| paused.set(wait),
                Duration::from_secs(4),
            );
            assert_eq!(result, Ok(false), "an empty retry is reported honestly");
            assert_eq!(reads.get(), 2);
            assert_eq!(enables.get(), if fresh { 1 } else { 2 });
            // The two reads and the pause together stay inside the caller's
            // bound: the retry gets only what the first read left.
            let bounds = bounds.borrow();
            assert_eq!(bounds[0], Duration::from_secs(4));
            assert!(
                bounds[1] + paused.get() <= Duration::from_secs(4),
                "{bounds:?}"
            );
        }
    }

    /// A web app whose accessibility is already on gets the caller's whole
    /// bound for its read. Cutting it to a fixed fraction truncated a slow
    /// Discord window partway, so its message box never appeared.
    #[test]
    fn an_enabled_web_app_is_read_with_the_whole_requested_bound() {
        let bound = Cell::new(Duration::ZERO);
        let result = read_with_manual_accessibility(
            |_| (ManualAccessibility::AlreadyEnabled, false),
            |given| {
                bound.set(given);
                Ok::<_, ()>(true)
            },
            |tree| *tree,
            |_| panic!("a populated tree is not read again"),
            Duration::from_secs(4),
        );
        assert_eq!(result, Ok(true));
        assert_eq!(bound.get(), Duration::from_secs(4));
    }

    /// No time left after the first read means no retry: the first read's
    /// result is returned rather than a second read with a zero bound.
    #[test]
    fn no_retry_when_the_first_read_used_the_whole_bound() {
        let reads = Cell::new(0);
        let result = read_with_manual_accessibility(
            |_| (ManualAccessibility::NewlyEnabled, true),
            |_| {
                reads.set(reads.get() + 1);
                std::thread::sleep(Duration::from_millis(30));
                Ok::<_, ()>(false)
            },
            |tree| *tree,
            |_| panic!("no time left to retry"),
            Duration::from_millis(20),
        );
        assert_eq!(result, Ok(false));
        assert_eq!(reads.get(), 1);
    }

    #[test]
    fn populated_web_or_failed_enable_never_retries() {
        for status in [
            ManualAccessibility::NewlyEnabled,
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

impl ManualAccessibility {
    fn enabled(self) -> bool {
        matches!(self, Self::NewlyEnabled | Self::AlreadyEnabled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewlyEnabled => "newly_enabled",
            Self::AlreadyEnabled => "already_enabled",
            Self::NotSupported => "not_supported",
            Self::Failed(_) => "failed",
        }
    }
}

thread_local! {
    static ACTION: std::cell::Cell<Option<(u32, Option<ManualAccessibility>)>> = const { std::cell::Cell::new(None) };
}

/// Binds synchronous AX reads to one action, not to a reusable worker thread.
/// The guard is deliberately not Send: async callers keep it inside a blocking task.
pub struct ManualAccessibilityScope {
    previous: Option<(u32, Option<ManualAccessibility>)>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ManualAccessibilityScope {
    pub fn new(pid: u32, initial: Option<ManualAccessibility>) -> Self {
        Self {
            previous: ACTION.replace(Some((pid, initial))),
            _thread: std::marker::PhantomData,
        }
    }

    /// Record an enable result only when `pid` matches the current scope's
    /// target, so reading another process cannot change this action's evidence.
    pub fn record(pid: u32, status: ManualAccessibility) {
        record(pid, status);
    }

    pub fn current() -> Option<ManualAccessibility> {
        ACTION.get().and_then(|(_, status)| status)
    }
}

impl Drop for ManualAccessibilityScope {
    fn drop(&mut self) {
        ACTION.set(self.previous);
    }
}

fn record(pid: u32, status: ManualAccessibility) {
    ACTION.with(|action| {
        if let Some((target, previous)) = action.get() {
            if target == pid {
                // Later cache hits must not hide a flag set earlier in this action.
                let status = match previous {
                    Some(ManualAccessibility::NewlyEnabled) => ManualAccessibility::NewlyEnabled,
                    _ => status,
                };
                action.set(Some((target, Some(status))));
            }
        }
    });
}

/// Opt in once for a process generation before a scoped accessibility read.
#[cfg(target_os = "macos")]
pub fn prepare_manual_accessibility(pid: u32) -> ManualAccessibility {
    prepare(pid, false).0
}
