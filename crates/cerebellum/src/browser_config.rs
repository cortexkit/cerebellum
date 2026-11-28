//! Browser-plane configuration parsing kept out of the shared substrate.

use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::ffi::OsString;

use serde_json::{Map, Value};

// Each renderer step gets at most the 30s budget already used by computer.wait.
// Launch may use the same budget to reach its pipe handshake. Teardown gets
// two 5s windows (grace and exit observation), matching the shipped defaults:
// it must not turn a failed launch or close into another full action wait.
pub(crate) const MAX_ACTION_DEADLINE_MS: u64 = 30_000;
pub(crate) const MAX_LAUNCH_DEADLINE_MS: u64 = MAX_ACTION_DEADLINE_MS;
pub(crate) const MAX_TERMINATION_DEADLINE_MS: u64 = 5_000;
pub(crate) const WINDOWS_DISCOVERS_CHROME: bool =
    cfg!(all(windows, feature = "windows-browser-release"));

#[cfg(all(windows, feature = "windows-browser-release"))]
pub(crate) use crate::windows_launch::discovery::CHROME_PUBLISHER;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserConfig {
    pub executable_path: Option<PathBuf>,
    pub expected_identity: Option<String>,
    pub launch_handshake_deadline_ms: u64,
    pub termination_grace_period_ms: u64,
    pub browser_idle_timeout_ms: u64,
    pub browser_exit_observation_deadline_ms: u64,
    pub navigation_settle_deadline_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserConfigError {
    pub field: String,
    pub reason: BrowserConfigReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserConfigReason {
    Malformed(String),
    NotObject,
    UnknownMember(String),
    MissingMember,
    WrongType,
    NotInteger,
    NotPositive,
    OutOfRange,
    AboveDeadlineCap {
        cap_ms: u64,
    },
    PathNotAbsolute,
    ExpectedIdentityRequired,
    ExecutableProbeFailed(String),
    FinalImageMismatch {
        expected: String,
        path: PathBuf,
        sha256: String,
    },
    /// The identity probe reported a mismatch but did not say what it saw.
    /// Its own contract is to name both the final image path and its digest,
    /// so this is a fault in the probe rather than in the configuration. Kept
    /// apart from `FinalImageMismatch` because that variant's remedy is "pin
    /// this digest", and with the digest missing that remedy would tell an
    /// operator to pin an empty string.
    FinalImageMismatchUndisclosed {
        expected: String,
    },
    BelowSettlementQuietWindow {
        quiet_ms: u64,
    },
}

impl BrowserConfigReason {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::NotObject => "not_object",
            Self::UnknownMember(_) => "unknown_member",
            Self::MissingMember => "missing_member",
            Self::WrongType => "wrong_type",
            Self::NotInteger => "not_integer",
            Self::NotPositive => "not_positive",
            Self::OutOfRange => "out_of_range",
            Self::AboveDeadlineCap { .. } => "above_deadline_cap",
            Self::PathNotAbsolute => "path_not_absolute",
            Self::ExpectedIdentityRequired => "expected_identity_required",
            Self::ExecutableProbeFailed(_) => "executable_probe_failed",
            Self::FinalImageMismatch { .. } => "final_image_mismatch",
            Self::FinalImageMismatchUndisclosed { .. } => "final_image_mismatch_undisclosed",
            Self::BelowSettlementQuietWindow { .. } => "below_settlement_quiet_window",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Malformed(detail)
            | Self::UnknownMember(detail)
            | Self::ExecutableProbeFailed(detail) => Some(detail),
            Self::NotObject
            | Self::MissingMember
            | Self::WrongType
            | Self::NotInteger
            | Self::NotPositive
            | Self::OutOfRange
            | Self::AboveDeadlineCap { .. }
            | Self::PathNotAbsolute
            | Self::ExpectedIdentityRequired
            | Self::FinalImageMismatch { .. }
            | Self::FinalImageMismatchUndisclosed { .. }
            | Self::BelowSettlementQuietWindow { .. } => None,
        }
    }
}

impl std::fmt::Display for BrowserConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.reason {
            BrowserConfigReason::Malformed(reason) => write!(f, "{}: {reason}", self.field),
            BrowserConfigReason::NotObject => write!(f, "{}: expected a JSON object", self.field),
            BrowserConfigReason::UnknownMember(member) => {
                write!(f, "{}: unknown member `{member}`", self.field)
            }
            BrowserConfigReason::MissingMember => {
                write!(f, "{}: required member is missing", self.field)
            }
            BrowserConfigReason::WrongType => write!(f, "{}: value has the wrong type", self.field),
            BrowserConfigReason::NotInteger => {
                write!(f, "{}: expected a positive integer", self.field)
            }
            BrowserConfigReason::NotPositive => {
                write!(f, "{}: value must be greater than zero", self.field)
            }
            BrowserConfigReason::OutOfRange => write!(f, "{}: value exceeds u64", self.field),
            BrowserConfigReason::AboveDeadlineCap { cap_ms } => {
                write!(f, "{}: deadline must not exceed {cap_ms}ms", self.field)
            }
            BrowserConfigReason::PathNotAbsolute => {
                write!(f, "{}: expected an absolute path", self.field)
            }
            BrowserConfigReason::ExpectedIdentityRequired => write!(
                f,
                "browser.expected_identity: required when browser.executable_path is set"
            ),
            BrowserConfigReason::ExecutableProbeFailed(reason) => {
                write!(f, "browser.executable_path: executable identity probe failed: {reason}")
            }
            BrowserConfigReason::FinalImageMismatch {
                expected,
                path,
                sha256,
            } => write!(
                f,
                "browser.expected_identity: configured sha256={expected} is not final; pin sha256={sha256} for {}",
                path.display()
            ),
            BrowserConfigReason::FinalImageMismatchUndisclosed { expected } => write!(
                f,
                "browser.expected_identity: configured sha256={expected} is not final, but the \
                 identity probe did not report the digest it observed; re-run the probe and \
                 report this as a module fault if it recurs"
            ),
            BrowserConfigReason::BelowSettlementQuietWindow { quiet_ms } => write!(
                f,
                "{}: must exceed {quiet_ms}ms, the network-quiet window a navigation \
                 must observe before it can settle; at or below it, wait=\"settle\" \
                 could never succeed on any page",
                self.field
            ),
        }
    }
}

impl std::error::Error for BrowserConfigError {}

pub fn validate_browser_config_at_load(config: &BrowserConfig) -> Result<(), BrowserConfigError> {
    #[cfg(target_os = "linux")]
    return probe_browser_config_at_load(config).map(|_| ());
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn probe_browser_config_at_load(
    config: &BrowserConfig,
) -> Result<Option<PathBuf>, BrowserConfigError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let Some(path) = config.executable_path.as_deref() else {
        return Ok(None);
    };
    // Missing paths retain the existing launch-time `executable_missing`
    // refusal; there is no image to probe during config loading.
    if !path.is_file() {
        return Ok(None);
    }
    let expected = config
        .expected_identity
        .as_deref()
        .ok_or_else(|| BrowserConfigError {
            field: "browser.expected_identity".to_string(),
            reason: BrowserConfigReason::ExpectedIdentityRequired,
        })?;
    crate::browser_executable_identity::verify_configured_executable(path, expected).map_err(
        |refusal| BrowserConfigError {
            field: "browser.expected_identity".to_string(),
            reason: BrowserConfigReason::ExecutableProbeFailed(refusal.to_string()),
        },
    )?;
    let (command_child, _command_parent) =
        UnixStream::pair().map_err(|error| BrowserConfigError {
            field: "browser.executable_path".to_string(),
            reason: BrowserConfigReason::ExecutableProbeFailed(error.to_string()),
        })?;
    let (_response_parent, response_child) =
        UnixStream::pair().map_err(|error| BrowserConfigError {
            field: "browser.executable_path".to_string(),
            reason: BrowserConfigReason::ExecutableProbeFailed(error.to_string()),
        })?;
    let mut launcher = crate::browser_launch::LinuxProcessLauncher::new(
        command_child.as_raw_fd(),
        response_child.as_raw_fd(),
    );
    let probe_profile = browser_probe_profile_path();
    // A killed browser leaves `SingletonLock` as a symlink naming
    // `<hostname>-<pid>` without a timestamp or generation counter. The
    // profile lock check cannot prove that link stale and refuses to break it,
    // so probing the real profile would make the first real launch after
    // every boot fail with `profile_held_externally`. Crashpad's database
    // path does not follow `--user-data-dir`, so it needs its own
    // throwaway path as well. `XDG_CONFIG_HOME` contains that database and
    // any other home-derived Chromium writes without changing argv. The
    // `--crash-dumps-dir` switch remains belt-and-braces for builds that
    // honor it; this Chromium build (measured 2026-08-25) still derives
    // the handler database from XDG configuration.
    let crash_dumps_directory = probe_profile.join("crash-dumps");
    let probe_environment = browser_probe_environment(&probe_profile);
    let arguments = crate::browser_launch_service::browser_launch_arguments(
        &probe_profile,
        &crash_dumps_directory,
    );
    let result = crate::browser_executable_identity::validate_configured_executable_at_load(
        &mut launcher,
        path,
        &arguments,
        &probe_environment,
        expected,
    )
    .map_err(|refusal| BrowserConfigError {
        field: "browser.expected_identity".to_string(),
        reason: reason_from_identity_refusal(&refusal, expected),
    });
    // Probe cleanup is part of config refusal: leaving SingletonLock or
    // XDG-derived Crashpad state behind would turn every later boot into a
    // false `profile_held_externally` refusal. Removal is strict rather
    // than best-effort so a cleanup failure remains visible at boot.
    let cleanup = cleanup_browser_probe(&probe_profile);
    let path = result?;
    cleanup?;
    Ok(Some(path))
}

#[cfg(target_os = "linux")]
fn browser_probe_environment(probe_profile: &Path) -> Vec<(OsString, OsString)> {
    vec![(
        OsString::from("XDG_CONFIG_HOME"),
        probe_profile.join("config").into_os_string(),
    )]
}

#[cfg(target_os = "linux")]
fn browser_probe_profile_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "cerebellum-config-probe-profile-{}",
        std::process::id()
    ))
}

#[cfg(target_os = "linux")]
fn cleanup_browser_probe(probe_profile: &Path) -> Result<(), BrowserConfigError> {
    match std::fs::remove_dir_all(probe_profile) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BrowserConfigError {
            field: "browser.executable_path".to_string(),
            reason: BrowserConfigReason::ExecutableProbeFailed(format!(
                "cannot remove browser probe tree {}: {error}",
                probe_profile.display()
            )),
        }),
    }
}

pub fn parse_browser_config(text: &str) -> Result<Option<BrowserConfig>, BrowserConfigError> {
    let stripped = subc_jsonc::jsonc_to_json(text).map_err(|reason| BrowserConfigError {
        field: "config".to_string(),
        reason: BrowserConfigReason::Malformed(reason),
    })?;
    let value: Value = serde_json::from_str(&stripped).map_err(|error| BrowserConfigError {
        field: "config".to_string(),
        reason: BrowserConfigReason::Malformed(error.to_string()),
    })?;
    parse_browser_config_value(&value)
}

pub(crate) fn parse_browser_config_value(
    value: &Value,
) -> Result<Option<BrowserConfig>, BrowserConfigError> {
    let top = value.as_object().ok_or_else(|| BrowserConfigError {
        field: "config".to_string(),
        reason: BrowserConfigReason::NotObject,
    })?;
    top.get("browser").map(parse_browser).transpose()
}

fn parse_browser(value: &Value) -> Result<BrowserConfig, BrowserConfigError> {
    let object = value.as_object().ok_or_else(|| BrowserConfigError {
        field: "browser".to_string(),
        reason: BrowserConfigReason::NotObject,
    })?;
    const ACCEPTED: &[&str] = &[
        "executable_path",
        "expected_identity",
        "launch_handshake_deadline_ms",
        "termination_grace_period_ms",
        "browser_idle_timeout_ms",
        "browser_exit_observation_deadline_ms",
        "navigation_settle_deadline_ms",
    ];
    if let Some(member) = object
        .keys()
        .filter(|member| !ACCEPTED.contains(&member.as_str()))
        .min()
    {
        return Err(BrowserConfigError {
            field: "browser".to_string(),
            reason: BrowserConfigReason::UnknownMember(member.clone()),
        });
    }

    let executable_path = match object.get("executable_path") {
        None => None,
        Some(Value::String(path)) if Path::new(path).is_absolute() => Some(PathBuf::from(path)),
        Some(Value::String(_)) => {
            return Err(BrowserConfigError {
                field: "browser.executable_path".to_string(),
                reason: BrowserConfigReason::PathNotAbsolute,
            });
        }
        Some(_) => {
            return Err(BrowserConfigError {
                field: "browser.executable_path".to_string(),
                reason: BrowserConfigReason::WrongType,
            });
        }
    };
    let expected_identity = parse_expected_identity(object.get("expected_identity"))?;
    if executable_path.is_some() && expected_identity.is_none() {
        return Err(BrowserConfigError {
            field: "browser.expected_identity".to_string(),
            reason: BrowserConfigReason::ExpectedIdentityRequired,
        });
    }

    Ok(BrowserConfig {
        executable_path,
        expected_identity,
        launch_handshake_deadline_ms: bounded_deadline_ms(
            object,
            "launch_handshake_deadline_ms",
            MAX_LAUNCH_DEADLINE_MS,
        )?,
        termination_grace_period_ms: bounded_deadline_ms(
            object,
            "termination_grace_period_ms",
            MAX_TERMINATION_DEADLINE_MS,
        )?,
        browser_idle_timeout_ms: required_positive_ms(object, "browser_idle_timeout_ms")?,
        browser_exit_observation_deadline_ms: bounded_deadline_ms(
            object,
            "browser_exit_observation_deadline_ms",
            MAX_TERMINATION_DEADLINE_MS,
        )?,
        navigation_settle_deadline_ms: settle_deadline_ms(object)?,
    })
}

#[cfg(not(all(windows, feature = "windows-browser-release")))]
fn parse_expected_identity(value: Option<&Value>) -> Result<Option<String>, BrowserConfigError> {
    Ok(match value {
        None => None,
        Some(Value::String(identity)) if !identity.is_empty() => Some(identity.clone()),
        Some(_) => {
            return Err(BrowserConfigError {
                field: "browser.expected_identity".to_string(),
                reason: BrowserConfigReason::WrongType,
            });
        }
    })
}

#[cfg(all(windows, feature = "windows-browser-release"))]
fn parse_expected_identity(value: Option<&Value>) -> Result<Option<String>, BrowserConfigError> {
    if let Some(value) = value {
        let table = value.as_object().ok_or_else(|| BrowserConfigError {
            field: "browser.expected_identity".into(),
            reason: BrowserConfigReason::WrongType,
        })?;
        if let Some(key) = table.keys().filter(|key| *key != "windows_publisher").min() {
            return Err(BrowserConfigError {
                field: "browser.expected_identity".into(),
                reason: BrowserConfigReason::UnknownMember(key.clone()),
            });
        }
        match table.get("windows_publisher") {
            Some(Value::String(name)) if name == CHROME_PUBLISHER => {}
            invalid => {
                return Err(BrowserConfigError {
                    field: "browser.expected_identity.windows_publisher".into(),
                    reason: if invalid.is_none() {
                        BrowserConfigReason::MissingMember
                    } else {
                        BrowserConfigReason::WrongType
                    },
                })
            }
        }
    }
    Ok(Some(CHROME_PUBLISHER.into()))
}

/// The settle deadline, refused when it cannot reach the quiet window.
///
/// Settlement needs `QUIET_MS` of network silence after load, and the drive
/// loop runs only while the clock is before the deadline. A deadline that does
/// not exceed the quiet window therefore makes `wait: "settle"` unable to
/// succeed on any page -- not slow, IMPOSSIBLE, and silently so: every
/// navigation returns not_settled with nothing to say why.
///
/// Refused here rather than documented, because a validator that accepts a
/// value which disables a capability leaves the next person to discover it the
/// hard way.
fn settle_deadline_ms(object: &Map<String, Value>) -> Result<u64, BrowserConfigError> {
    let value = bounded_deadline_ms(
        object,
        "navigation_settle_deadline_ms",
        MAX_ACTION_DEADLINE_MS,
    )?;
    if value <= crate::browser::QUIET_MS {
        return Err(BrowserConfigError {
            field: "browser.navigation_settle_deadline_ms".to_string(),
            reason: BrowserConfigReason::BelowSettlementQuietWindow {
                quiet_ms: crate::browser::QUIET_MS,
            },
        });
    }
    Ok(value)
}

fn required_positive_ms(
    object: &Map<String, Value>,
    member: &str,
) -> Result<u64, BrowserConfigError> {
    let field = format!("browser.{member}");
    let value = object.get(member).ok_or_else(|| BrowserConfigError {
        field: field.clone(),
        reason: BrowserConfigReason::MissingMember,
    })?;
    match value {
        Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                if value == 0 {
                    Err(BrowserConfigError {
                        field,
                        reason: BrowserConfigReason::NotPositive,
                    })
                } else {
                    Ok(value)
                }
            } else if number.is_i64() {
                Err(BrowserConfigError {
                    field,
                    reason: BrowserConfigReason::NotPositive,
                })
            } else if number.as_f64().is_some() {
                Err(BrowserConfigError {
                    field,
                    reason: BrowserConfigReason::NotInteger,
                })
            } else {
                Err(BrowserConfigError {
                    field,
                    reason: BrowserConfigReason::OutOfRange,
                })
            }
        }
        _ => Err(BrowserConfigError {
            field,
            reason: BrowserConfigReason::NotInteger,
        }),
    }
}

fn bounded_deadline_ms(
    object: &Map<String, Value>,
    member: &str,
    cap_ms: u64,
) -> Result<u64, BrowserConfigError> {
    let value = required_positive_ms(object, member)?;
    if value > cap_ms {
        return Err(BrowserConfigError {
            field: format!("browser.{member}"),
            reason: BrowserConfigReason::AboveDeadlineCap { cap_ms },
        });
    }
    Ok(value)
}

/// Map an executable-identity refusal to the configuration reason it means.
///
/// A mismatch names what the probe observed so the operator can pin it. When
/// the refusal carries no observed digest -- or no path -- the mismatch is
/// reported as undisclosed rather than as a mismatch against an empty value,
/// which would print a remedy nobody can follow.
// The load-time identity probe only runs on Linux (macOS pins by code-signing
// identity instead), but the mapping is host-neutral and its tests run
// everywhere, so the wrong-remedy case is caught on the macOS gate too.
#[cfg(any(target_os = "linux", test))]
fn reason_from_identity_refusal(refusal: &Value, expected: &str) -> BrowserConfigReason {
    if refusal["outcome"] != "executable_identity_mismatch" {
        return BrowserConfigReason::ExecutableProbeFailed(refusal.to_string());
    }
    let path = refusal["final_image_path"]
        .as_str()
        .filter(|path| !path.is_empty());
    let sha256 = refusal["final_image_sha256"]
        .as_str()
        .filter(|sha| !sha.is_empty());
    match (path, sha256) {
        (Some(path), Some(sha256)) => BrowserConfigReason::FinalImageMismatch {
            expected: expected.to_string(),
            path: PathBuf::from(path),
            sha256: sha256.to_string(),
        },
        _ => BrowserConfigReason::FinalImageMismatchUndisclosed {
            expected: expected.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mismatch that names what it saw becomes the pinnable remedy; one
    /// that omits either the path or the digest becomes its own reason. The
    /// wrong implementation -- defaulting a missing field to "" -- would
    /// print "pin sha256=" with nothing after it, so the assertion is on the
    /// variant and the rendered text, not on absence of a panic.
    #[test]
    fn a_mismatch_without_an_observed_digest_is_undisclosed_not_a_mismatch_against_empty() {
        let full = serde_json::json!({
            "outcome": "executable_identity_mismatch",
            "final_image_path": "/opt/google/chrome/chrome",
            "final_image_sha256": "abc123",
        });
        match reason_from_identity_refusal(&full, "expected") {
            BrowserConfigReason::FinalImageMismatch { path, sha256, .. } => {
                assert_eq!(path, PathBuf::from("/opt/google/chrome/chrome"));
                assert_eq!(sha256, "abc123");
            }
            other => panic!("a full refusal must be a pinnable mismatch, got {other:?}"),
        }

        for stripped in [
            serde_json::json!({"outcome": "executable_identity_mismatch", "final_image_path": "/opt/google/chrome/chrome"}),
            serde_json::json!({"outcome": "executable_identity_mismatch", "final_image_sha256": "abc123"}),
            serde_json::json!({"outcome": "executable_identity_mismatch", "final_image_path": "", "final_image_sha256": ""}),
        ] {
            let reason = reason_from_identity_refusal(&stripped, "expected");
            assert!(
                matches!(
                    reason,
                    BrowserConfigReason::FinalImageMismatchUndisclosed { .. }
                ),
                "{stripped} must be undisclosed, got {reason:?}"
            );
            assert_eq!(reason.reason_code(), "final_image_mismatch_undisclosed");
            let rendered = BrowserConfigError {
                field: "browser.expected_identity".to_string(),
                reason,
            }
            .to_string();
            assert!(
                !rendered.contains("pin sha256="),
                "an undisclosed mismatch must not tell the operator to pin anything: {rendered}"
            );
        }

        let other = serde_json::json!({"outcome": "identity_unverifiable"});
        assert!(matches!(
            reason_from_identity_refusal(&other, "expected"),
            BrowserConfigReason::ExecutableProbeFailed(_)
        ));
    }

    fn configured() -> String {
        r#"{
            "browser": {
                "launch_handshake_deadline_ms": 1000,
                "termination_grace_period_ms": 2000,
                "browser_idle_timeout_ms": 3000,
                "browser_exit_observation_deadline_ms": 4000,
                "navigation_settle_deadline_ms": 5000
            }
        }"#
        .to_string()
    }

    #[test]
    fn deadlines_above_caps_are_refused_with_field_and_cap() {
        for (member, cap_ms) in [
            ("launch_handshake_deadline_ms", 30_000),
            ("termination_grace_period_ms", 5_000),
            ("browser_exit_observation_deadline_ms", 5_000),
            ("navigation_settle_deadline_ms", 30_000),
        ] {
            let mut value: Value = serde_json::from_str(&configured()).unwrap();
            value["browser"][member] = serde_json::json!(cap_ms);
            parse_browser_config(&value.to_string()).expect("cap itself must load");
            for above in [cap_ms + 1, u64::MAX] {
                value["browser"][member] = serde_json::json!(above);
                let error =
                    parse_browser_config(&value.to_string()).expect_err("never clamp a deadline");
                assert_eq!(error.field, format!("browser.{member}"));
                assert_eq!(
                    error.reason,
                    BrowserConfigReason::AboveDeadlineCap { cap_ms }
                );
                assert_eq!(error.reason.reason_code(), "above_deadline_cap");
                assert!(error.to_string().contains(&format!("{cap_ms}ms")));
                assert!(error.to_string().contains(member));
            }
        }
    }

    #[test]
    fn default_browser_deadlines_load_unchanged() {
        let config = parse_browser_config(
            r#"{"browser":{
            "launch_handshake_deadline_ms":10000,
            "termination_grace_period_ms":5000,
            "browser_idle_timeout_ms":60000,
            "browser_exit_observation_deadline_ms":5000,
            "navigation_settle_deadline_ms":30000
        }}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(config.launch_handshake_deadline_ms, 10_000);
        assert_eq!(config.termination_grace_period_ms, 5_000);
        assert_eq!(config.browser_idle_timeout_ms, 60_000);
        assert_eq!(config.browser_exit_observation_deadline_ms, 5_000);
        assert_eq!(config.navigation_settle_deadline_ms, 30_000);
    }

    #[test]
    fn absence_and_misspelling_are_both_unconfigured() {
        assert_eq!(parse_browser_config("{}").unwrap(), None);
        assert_eq!(parse_browser_config(r#"{"browsers": {}}"#).unwrap(), None);
    }

    #[test]
    fn a_present_browser_member_is_complete_and_closed() {
        let parsed = parse_browser_config(&configured()).unwrap().unwrap();
        assert_eq!(parsed.browser_idle_timeout_ms, 3000);

        let mut value: Value = serde_json::from_str(&configured()).unwrap();
        value["browser"]["unknown"] = Value::Bool(true);
        let error = parse_browser_config(&value.to_string()).unwrap_err();
        assert_eq!(error.field, "browser");
        assert_eq!(
            error.reason,
            BrowserConfigReason::UnknownMember("unknown".to_string())
        );
    }

    #[test]
    fn every_duration_is_required_and_positive() {
        let members = [
            "launch_handshake_deadline_ms",
            "termination_grace_period_ms",
            "browser_idle_timeout_ms",
            "browser_exit_observation_deadline_ms",
            "navigation_settle_deadline_ms",
        ];
        for member in members {
            let mut missing: Value = serde_json::from_str(&configured()).unwrap();
            missing["browser"].as_object_mut().unwrap().remove(member);
            assert_eq!(
                parse_browser_config(&missing.to_string())
                    .unwrap_err()
                    .reason,
                BrowserConfigReason::MissingMember
            );
            for (value, reason) in [
                (serde_json::json!(0), BrowserConfigReason::NotPositive),
                (serde_json::json!(-1), BrowserConfigReason::NotPositive),
                (serde_json::json!(1.5), BrowserConfigReason::NotInteger),
                (serde_json::json!("1"), BrowserConfigReason::NotInteger),
            ] {
                let mut invalid: Value = serde_json::from_str(&configured()).unwrap();
                invalid["browser"][member] = value;
                assert_eq!(
                    parse_browser_config(&invalid.to_string())
                        .unwrap_err()
                        .reason,
                    reason
                );
            }
        }
    }

    #[test]
    fn configured_executable_requires_absolute_pinned_identity() {
        let mut value: Value = serde_json::from_str(&configured()).unwrap();
        value["browser"]["executable_path"] = serde_json::json!("relative/chrome");
        assert_eq!(
            parse_browser_config(&value.to_string()).unwrap_err().reason,
            BrowserConfigReason::PathNotAbsolute
        );
        let absolute_executable = if cfg!(windows) {
            r"C:\Chrome\chrome.exe"
        } else {
            "/Applications/Chrome"
        };
        value["browser"]["executable_path"] = serde_json::json!(absolute_executable);
        if WINDOWS_DISCOVERS_CHROME {
            assert_eq!(
                parse_browser_config(&value.to_string())
                    .unwrap()
                    .unwrap()
                    .expected_identity
                    .as_deref(),
                Some("Google LLC")
            );
            value["browser"]["expected_identity"] =
                serde_json::json!({"windows_publisher": "Google LLC"});
        } else {
            assert_eq!(
                parse_browser_config(&value.to_string()).unwrap_err().reason,
                BrowserConfigReason::ExpectedIdentityRequired
            );
            value["browser"]["expected_identity"] = serde_json::json!("com.example.Chrome");
        }
        assert!(parse_browser_config(&value.to_string()).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn config_probe_redirects_home_derived_writes_without_changing_argv() {
        let environment = browser_probe_environment(Path::new("/tmp/probe-profile"));
        assert_eq!(
            environment,
            vec![(
                OsString::from("XDG_CONFIG_HOME"),
                OsString::from("/tmp/probe-profile/config"),
            )]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn config_load_refuses_a_wrapper_pin_with_the_final_image_sha256() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "cerebellum-linux-config-load-{}",
            std::process::id()
        ));
        std::fs::create_dir(&root).expect("create config probe directory");
        let wrapper = root.join("wrapper");
        // Keep the interpreter alive beyond the 100 ms observation window so
        // a quiet interval cannot masquerade as the end of the exec chain.
        std::fs::write(&wrapper, "#!/bin/sh\n/bin/sleep 1\nexec /bin/sleep 30\n")
            .expect("write wrapper");
        let mut permissions = std::fs::metadata(&wrapper)
            .expect("wrapper metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&wrapper, permissions).expect("make wrapper executable");
        let mut config = parse_browser_config(&configured()).unwrap().unwrap();
        config.executable_path = Some(wrapper.clone());
        config.expected_identity = Some(sha256_file_for_test(&wrapper));

        let refusal = validate_browser_config_at_load(&config).expect_err("wrapper pin refused");
        let text = refusal.to_string();
        assert!(text.contains("is not final"), "unexpected refusal: {text}");
        let final_image = std::fs::canonicalize("/bin/sleep").expect("resolve fixture binary");
        assert!(
            text.contains(final_image.to_str().expect("fixture binary path is UTF-8")),
            "missing final image path: {text}"
        );
        assert!(
            text.contains(&sha256_file_for_test(Path::new("/bin/sleep"))),
            "missing final image digest: {text}"
        );
        assert!(!probe_profile_path().exists(), "refusal leaked probe tree");
        std::fs::remove_dir_all(root).expect("remove config probe directory");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn config_load_accepts_a_pin_for_the_terminal_image() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "cerebellum-linux-config-load-terminal-{}",
            std::process::id()
        ));
        std::fs::create_dir(&root).expect("create terminal config directory");
        let wrapper = root.join("terminal");
        // A slow wrapper that reaches the pinned image within the bounded
        // wait must not be refused just because its interpreter ran first.
        std::fs::write(&wrapper, "#!/bin/sh\n/bin/sleep 1\nexec /bin/sleep 30\n")
            .expect("write terminal wrapper");
        let mut permissions = std::fs::metadata(&wrapper)
            .expect("terminal metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&wrapper, permissions).expect("make terminal wrapper executable");
        let mut config = parse_browser_config(&configured()).unwrap().unwrap();
        config.executable_path = Some(wrapper);
        config.expected_identity = Some(sha256_file_for_test(Path::new("/bin/sleep")));

        assert_eq!(
            probe_browser_config_at_load(&config).expect("terminal image pin accepted"),
            Some(std::fs::canonicalize("/bin/sleep").expect("resolve fixture binary")),
        );
        assert!(!probe_profile_path().exists(), "success leaked probe tree");
        std::fs::remove_dir_all(root).expect("remove terminal config directory");
    }

    #[cfg(target_os = "linux")]
    fn probe_profile_path() -> PathBuf {
        browser_probe_profile_path()
    }

    #[cfg(target_os = "linux")]
    fn sha256_file_for_test(path: &Path) -> String {
        use sha2::{Digest, Sha256};
        format!(
            "{:x}",
            Sha256::digest(std::fs::read(path).expect("read digest fixture"))
        )
    }
}

#[cfg(test)]
mod settle_deadline_tests {
    use super::*;

    /// A settle deadline at or below the quiet window cannot ever settle.
    ///
    /// Settlement requires `QUIET_MS` of network silence AFTER load, and the
    /// drive loop runs only while the clock is before the deadline. So a
    /// deadline that does not exceed the quiet window leaves `wait: "settle"`
    /// structurally unable to succeed: every navigation returns not_settled, on
    /// every page, forever, with nothing in the logs to say why.
    ///
    /// Rejected at parse rather than documented, because a validator that
    /// accepts a value which disables a capability is a footgun the next person
    /// steps on for the same reason this one existed.
    #[test]
    fn a_settle_deadline_that_cannot_reach_the_quiet_window_is_refused() {
        let with = |ms: u64| {
            format!(
                r#"{{"browser":{{
                    "launch_handshake_deadline_ms": 10000,
                    "termination_grace_period_ms": 5000,
                    "browser_idle_timeout_ms": 60000,
                    "browser_exit_observation_deadline_ms": 5000,
                    "navigation_settle_deadline_ms": {ms}
                }}}}"#
            )
        };

        let quiet = crate::browser::QUIET_MS;

        let refused = parse_browser_config(&with(quiet)).expect_err("equal to the quiet window");
        assert_eq!(refused.field, "browser.navigation_settle_deadline_ms");

        parse_browser_config(&with(quiet - 1)).expect_err("below the quiet window");
        parse_browser_config(&with(1)).expect_err("far below the quiet window");

        // Above it is accepted: the check must not refuse everything, which
        // would pass this test while making the browser unconfigurable.
        let accepted = parse_browser_config(&with(quiet + 1))
            .expect("above the quiet window parses")
            .expect("a browser section is present");
        assert_eq!(accepted.navigation_settle_deadline_ms, quiet + 1);
    }
}
