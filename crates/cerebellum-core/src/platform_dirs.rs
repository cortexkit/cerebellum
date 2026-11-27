//! The daemon's data-home and config-home, CALLED rather than copied.
//!
//! This module used to carry a copy of the daemon's resolution ladder, and a
//! copy of a sibling's path resolution is a defect class: the two sides drift
//! silently, every gate stays green, and the symptom is a correct answer
//! about the wrong directory. The tree once held three independent copies of
//! the data-home rung, every one missing `XDG_DATA_HOME`; an operator with it
//! set had the journal land under a root the backup catalog never resolves.
//!
//! Now both homes come from `cortexkit-store-types`, which mirrors the
//! daemon's ladder under a golden fixture pinned on both sides:
//!   1. `$XDG_DATA_HOME` / `$XDG_CONFIG_HOME`          (every platform)
//!   2. `%APPDATA%`                                     (Windows)
//!   3. `%USERPROFILE%\AppData\Roaming`                 (Windows)
//!   4. `$HOME/.local/share` / `$HOME/.config`          (every platform)
//!
//! Empty values count as unset at every rung.
//!
//! One arm is deliberately NOT inherited. The callable can return a RELATIVE
//! path in two cases it does not distinguish: no rung answered and it fell
//! through to `.local/share` or `.config`, or the operator set `XDG_*_HOME`
//! to a relative value, which the XDG rung passes through as-is (a pinned
//! case on both sides, not an accident). Either way the path resolves
//! against whatever the process's cwd happens to be, and a module that
//! writes an audit journal there has written it somewhere no catalog will
//! find, with every gate green. Both functions here refuse a relative result
//! for that reason: not because it proves nothing was set, but because it
//! proves the directory depends on the cwd, and `None` sends the caller to
//! a named error rather than to a directory nobody chose.

use std::path::PathBuf;

/// `<data home>` in the daemon's sense: the root under which
/// `cortexkit/<module id>/` lives and against which the backup catalog
/// resolves every declared path. `None` when no environment rung answers.
pub fn data_home() -> Option<PathBuf> {
    absolute_or_none(cortexkit_store_types::resolve_data_home())
}

/// `<config home>` in the daemon's sense: where `cortexkit/<file>.jsonc`
/// lives. `None` when no environment rung answers.
pub fn config_home() -> Option<PathBuf> {
    absolute_or_none(cortexkit_store_types::resolve_config_home())
}

/// The fail-closed arm, kept separate from the environment read so it is
/// testable without mutating the process environment. A relative result
/// means the directory depends on the cwd (nothing set, or a relative
/// `XDG_*_HOME`), and is refused.
fn absolute_or_none(resolved: String) -> Option<PathBuf> {
    let path = PathBuf::from(resolved);
    path.is_absolute().then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A relative result is a refusal, never a directory, whichever of the
    /// two ways it arose. The wrong implementation (pass the result through)
    /// would return `Some(".local/share")`, so the assertion is on `None` for
    /// the two fallback shapes the callable produces AND for a relative XDG
    /// value it would pass through unchanged.
    #[test]
    fn a_cwd_dependent_result_is_refused_not_used() {
        assert_eq!(absolute_or_none(".local/share".to_string()), None);
        assert_eq!(absolute_or_none(".config".to_string()), None);
        assert_eq!(absolute_or_none("relative/xdg/home".to_string()), None);
        assert_eq!(absolute_or_none(String::new()), None);
    }

    /// Every populated rung yields an absolute path, and those pass through
    /// unchanged. Fixed against the refusal above so the discriminator is
    /// absoluteness and nothing narrower (a wrong implementation keyed on a
    /// `/home` prefix would fail the Windows shape).
    #[test]
    fn absolute_results_pass_through_unchanged() {
        #[cfg(not(windows))]
        let paths = [
            "/home/op/.local/share",
            "/tmp/x/.config",
            "/Users/op/Library",
        ];
        #[cfg(windows)]
        let paths = [
            r"C:\Users\op\AppData\Roaming",
            r"D:\Config",
            r"\\server\share\config",
        ];
        for absolute in paths {
            assert_eq!(
                absolute_or_none(absolute.to_string()),
                Some(PathBuf::from(absolute))
            );
        }
    }

    /// The live call agrees with the callable on this host, which has a
    /// HOME: both homes resolve and both are absolute. This is the arm that
    /// would notice the dependency being wired to the wrong function.
    #[test]
    fn live_homes_resolve_absolute_on_a_host_with_a_home() {
        let data = data_home().expect("this host has a data home");
        let config = config_home().expect("this host has a config home");
        assert!(data.is_absolute());
        assert!(config.is_absolute());
        assert_eq!(
            data,
            PathBuf::from(cortexkit_store_types::resolve_data_home())
        );
        assert_eq!(
            config,
            PathBuf::from(cortexkit_store_types::resolve_config_home())
        );
    }
}
