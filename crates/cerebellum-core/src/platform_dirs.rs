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
//! One arm is deliberately NOT inherited. When no rung answers, the callable
//! falls through to a RELATIVE `.local/share` or `.config`, resolved against
//! whatever the process's cwd happens to be. A module that writes an audit
//! journal there has written it somewhere no catalog will find, with every
//! gate green. Both functions here refuse that case instead: every populated
//! rung yields an absolute path, so a relative result can only mean nothing
//! was set, and `None` sends the caller to a named error rather than to a
//! directory nobody chose.

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
/// testable without mutating the process environment. A relative result is
/// the callable's "nothing was set" fallback and is refused.
fn absolute_or_none(resolved: String) -> Option<PathBuf> {
    let path = PathBuf::from(resolved);
    path.is_absolute().then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The callable's no-rung fallback is a relative path; here that is a
    /// refusal, never a directory. The wrong implementation (pass the result
    /// through) would return `Some(".local/share")`, so the assertion is on
    /// `None` for exactly the two fallback shapes the callable produces.
    #[test]
    fn the_relative_fallback_is_refused_not_used() {
        assert_eq!(absolute_or_none(".local/share".to_string()), None);
        assert_eq!(absolute_or_none(".config".to_string()), None);
        assert_eq!(absolute_or_none(String::new()), None);
    }

    /// Every populated rung yields an absolute path, and those pass through
    /// unchanged. Fixed against the refusal above so the discriminator is
    /// absoluteness and nothing narrower (a wrong implementation keyed on a
    /// `/home` prefix would fail the Windows shape).
    #[test]
    fn absolute_results_pass_through_unchanged() {
        for absolute in ["/home/op/.local/share", "/tmp/x/.config", "/Users/op/Library"] {
            assert_eq!(
                absolute_or_none(absolute.to_string()),
                Some(PathBuf::from(absolute))
            );
        }
        #[cfg(windows)]
        assert_eq!(
            absolute_or_none(r"C:\Users\op\AppData\Roaming".to_string()),
            Some(PathBuf::from(r"C:\Users\op\AppData\Roaming"))
        );
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
