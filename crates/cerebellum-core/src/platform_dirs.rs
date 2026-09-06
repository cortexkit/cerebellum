//! The daemon's data-home and config-home ladders, mirrored rung for rung.
//!
//! These are COPIES of `subc-core::daemon_config::default_data_home` and
//! `default_config_path`, and a copy of a sibling's path resolution is a
//! defect class: the two sides drift silently, every gate stays green, and
//! the symptom is a correct answer about the wrong directory. This module
//! exists because the tree carried THREE independent copies of the data-home
//! rung and one of the config-home rung, and every one of them was missing
//! the first rung the daemon consults -- `XDG_DATA_HOME` / `XDG_CONFIG_HOME`
//! -- plus both Windows rungs. An operator with `XDG_CONFIG_HOME` set had
//! `subc.jsonc` found under it and `cerebellum.jsonc` searched under
//! `~/.config`: config read as absent, browser silently unconfigured, no
//! error anywhere. With `XDG_DATA_HOME` set the journal and browser profiles
//! landed under a root the backup catalog does not resolve against.
//!
//! Why a copy and not a call: the daemon's resolvers are private to
//! `subc-core`, which is a dev-dependency here. SUBC has a callable form in
//! flight (`default_data_home` / `default_config_home` beside the daemon's
//! own derivation, announced 2026-09-06); when that lock wave lands, both
//! functions below become calls and this file shrinks to nothing. Until
//! then the date on each ladder is the only mechanism that keeps it true:
//! re-derive against `subc-core/src/daemon_config.rs` and bump the date.
//!
//! Last re-derived 2026-09-06 against subconscious 65416bc0.

use std::ffi::OsString;
use std::path::PathBuf;

/// A non-empty environment value, or None. Empty is treated as unset, the
/// way the daemon treats it, so an `export XDG_DATA_HOME=` clears the rung
/// rather than producing an empty root.
fn non_empty_os_var(key: &str) -> Option<OsString> {
    std::env::var_os(key).filter(|value| !value.is_empty())
}

/// `<data home>` in the daemon's sense: the root under which
/// `cortexkit/<module id>/` lives and against which the backup catalog
/// resolves every declared path.
///
/// Ladder, in the daemon's order:
///   1. `$XDG_DATA_HOME`                              (every platform)
///   2. `%APPDATA%`                                   (Windows)
///   3. `%USERPROFILE%\AppData\Roaming`               (Windows)
///   4. `$HOME/.local/share`                          (every platform)
///
/// None when no rung answers. The daemon falls through to a relative
/// `.local/share`; this module does not, because a module that writes an
/// audit journal relative to whatever its cwd happens to be has written it
/// somewhere no catalog will find.
pub fn data_home() -> Option<PathBuf> {
    resolve_home(
        "XDG_DATA_HOME",
        &["AppData", "Roaming"],
        &[".local", "share"],
    )
}

/// `<config home>` in the daemon's sense: where `cortexkit/<file>.jsonc`
/// lives.
///
/// Ladder, in the daemon's order:
///   1. `$XDG_CONFIG_HOME`                            (every platform)
///   2. `%APPDATA%`                                   (Windows)
///   3. `%USERPROFILE%\AppData\Roaming`               (Windows)
///   4. `$HOME/.config`                               (every platform)
pub fn config_home() -> Option<PathBuf> {
    resolve_home("XDG_CONFIG_HOME", &["AppData", "Roaming"], &[".config"])
}

/// The one ladder both homes share, with the platform gate as a value so
/// every rung is testable on every host. The daemon gates its Windows rungs
/// with `#[cfg(windows)]`; here the same rungs are gated by
/// [`current_platform`], which a test can override, because an ordering that
/// only compiles on one platform is an ordering no other host can check.
fn resolve_home(xdg_var: &str, roaming_suffix: &[&str], home_suffix: &[&str]) -> Option<PathBuf> {
    resolve_home_on(
        current_platform(),
        xdg_var,
        roaming_suffix,
        home_suffix,
        non_empty_os_var,
    )
}

/// Which family of rungs applies. Only Windows has rungs the other platforms
/// lack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomePlatform {
    Windows,
    Posix,
}

fn current_platform() -> HomePlatform {
    if cfg!(windows) {
        HomePlatform::Windows
    } else {
        HomePlatform::Posix
    }
}

/// The ladder over an injected environment. Public so the ladder itself --
/// order, guards, and which rung wins -- is asserted by tests on every host
/// rather than only on the platform each rung happens to compile for.
pub fn resolve_home_on(
    platform: HomePlatform,
    xdg_var: &str,
    roaming_suffix: &[&str],
    home_suffix: &[&str],
    env: impl Fn(&str) -> Option<OsString>,
) -> Option<PathBuf> {
    if let Some(xdg) = env(xdg_var) {
        return Some(PathBuf::from(xdg));
    }
    if platform == HomePlatform::Windows {
        if let Some(app_data) = env("APPDATA") {
            return Some(PathBuf::from(app_data));
        }
        if let Some(user_profile) = env("USERPROFILE") {
            let mut path = PathBuf::from(user_profile);
            for part in roaming_suffix {
                path.push(part);
            }
            return Some(path);
        }
    }
    let home = env("HOME")?;
    let mut path = PathBuf::from(home);
    for part in home_suffix {
        path.push(part);
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key: &str| map.get(key).filter(|v| !v.is_empty()).map(OsString::from)
    }

    fn data(platform: HomePlatform, pairs: &[(&str, &str)]) -> Option<PathBuf> {
        resolve_home_on(
            platform,
            "XDG_DATA_HOME",
            &["AppData", "Roaming"],
            &[".local", "share"],
            env_of(pairs),
        )
    }

    /// The rung the three old copies were missing. This is the divergence
    /// that was live: the daemon honoured it and cerebellum did not.
    #[test]
    fn xdg_data_home_wins_over_home_on_every_platform() {
        for platform in [HomePlatform::Posix, HomePlatform::Windows] {
            assert_eq!(
                data(
                    platform,
                    &[
                        ("XDG_DATA_HOME", "/xdg"),
                        ("HOME", "/home/u"),
                        ("APPDATA", "C:\\ad")
                    ]
                ),
                Some(PathBuf::from("/xdg")),
                "{platform:?}: XDG_DATA_HOME must be the first rung"
            );
        }
    }

    /// An exported-but-empty variable clears the rung, as it does in the
    /// daemon; otherwise `export XDG_DATA_HOME=` would produce an empty root.
    #[test]
    fn an_empty_xdg_value_is_unset() {
        assert_eq!(
            data(
                HomePlatform::Posix,
                &[("XDG_DATA_HOME", ""), ("HOME", "/home/u")]
            ),
            Some(PathBuf::from("/home/u/.local/share"))
        );
    }

    /// The Windows rungs exist only on Windows, in the daemon's order:
    /// APPDATA before USERPROFILE, and USERPROFILE gets the Roaming suffix.
    #[test]
    fn windows_rungs_apply_only_on_windows_and_in_order() {
        let both = &[
            ("APPDATA", "C:\\ad"),
            ("USERPROFILE", "C:\\up"),
            ("HOME", "/home/u"),
        ];
        assert_eq!(
            data(HomePlatform::Windows, both),
            Some(PathBuf::from("C:\\ad"))
        );
        assert_eq!(
            data(
                HomePlatform::Windows,
                &[("USERPROFILE", "C:\\up"), ("HOME", "/home/u")]
            ),
            Some(PathBuf::from("C:\\up").join("AppData").join("Roaming"))
        );
        // The same environment on POSIX ignores both and reaches HOME.
        assert_eq!(
            data(HomePlatform::Posix, both),
            Some(PathBuf::from("/home/u/.local/share"))
        );
    }

    /// No rung answering is None, never a relative path: a journal written
    /// relative to the cwd is written where no catalog looks.
    #[test]
    fn nothing_set_is_none_not_a_relative_fallback() {
        assert_eq!(data(HomePlatform::Posix, &[]), None);
        assert_eq!(data(HomePlatform::Windows, &[]), None);
    }

    /// The config ladder is the same shape with its own XDG variable and
    /// HOME suffix.
    #[test]
    fn config_home_ladder_mirrors_the_daemon() {
        let cfg = |platform, pairs: &[(&str, &str)]| {
            resolve_home_on(
                platform,
                "XDG_CONFIG_HOME",
                &["AppData", "Roaming"],
                &[".config"],
                env_of(pairs),
            )
        };
        assert_eq!(
            cfg(
                HomePlatform::Posix,
                &[("XDG_CONFIG_HOME", "/xc"), ("HOME", "/home/u")]
            ),
            Some(PathBuf::from("/xc"))
        );
        assert_eq!(
            cfg(HomePlatform::Posix, &[("HOME", "/home/u")]),
            Some(PathBuf::from("/home/u/.config"))
        );
        assert_eq!(
            cfg(
                HomePlatform::Windows,
                &[("APPDATA", "C:\\ad"), ("HOME", "/home/u")]
            ),
            Some(PathBuf::from("C:\\ad"))
        );
    }
}
