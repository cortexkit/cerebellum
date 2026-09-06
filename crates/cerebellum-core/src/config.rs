//! `ck-cerebellum` configuration parsing.
//!
//! Spec A freezes the health configuration surface as two positive-integer
//! millisecond thresholds:
//!
//! - `health.dispatch_heartbeat_stale_ms` (default `2000`): the heartbeat age
//!   above which dispatch is considered impaired.
//! - `health.action_age_stale_ms` (default `30000`): applied independently to
//!   the oldest queued-action age and the oldest in-flight-action age.
//!
//! An absent `health` object or absent member uses the stated default. When
//! `health` is present it must be an object whose only accepted members are
//! those two keys. Unknown members, zero, negative, fractional, non-numeric,
//! and out-of-`u64` values are configuration errors that prevent registration
//! rather than being silently clamped or replaced with defaults. Configuring
//! one threshold leaves the other at its independent default.
//!
//! The config file is `~/.config/cortexkit/cerebellum.jsonc` (JSONC: comments
//! and trailing commas are stripped via `subc_jsonc` before JSON parsing).

use std::path::PathBuf;
use std::time::Duration;

/// Default heartbeat staleness threshold: 2 seconds.
pub const DEFAULT_DISPATCH_HEARTBEAT_STALE_MS: u64 = 2000;

/// Default action-age staleness threshold: 30 seconds, applied independently to
/// queued and in-flight ages.
pub const DEFAULT_ACTION_AGE_STALE_MS: u64 = 30000;

/// A configuration error. Returned by [`parse_config`] for any malformed or
/// out-of-range `health` value. The error is deterministic: the same input
/// always produces the same reason, with no silent fallback. Registration
/// fails deterministically when this is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub field: &'static str,
    pub reason: ConfigReason,
}

/// The kind of configuration failure. `UnknownMember` carries the offending
/// member name; the other variants name the rejected value shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigReason {
    /// `health` was present but not a JSON object.
    HealthNotObject,
    /// `health` contained a member other than the two accepted keys.
    UnknownMember(String),
    /// A threshold was not a JSON integer (e.g. a string, bool, null, or
    /// fractional number).
    NotInteger,
    /// A threshold was an integer but not strictly positive.
    NotPositive,
    /// A threshold was a positive integer but exceeded `u64::MAX` in the
    /// parsed representation.
    OutOfRange,
    /// The config document was not valid JSONC/JSON.
    Malformed(String),
    /// The config document was not a JSON object at the top level.
    TopLevelNotObject,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.reason {
            ConfigReason::HealthNotObject => write!(f, "health: expected a JSON object"),
            ConfigReason::UnknownMember(m) => write!(f, "health: unknown member `{m}`"),
            ConfigReason::NotInteger => write!(f, "{}: expected a positive integer", self.field),
            ConfigReason::NotPositive => {
                write!(
                    f,
                    "{}: expected a positive integer (got zero or negative)",
                    self.field
                )
            }
            ConfigReason::OutOfRange => write!(f, "{}: value out of u64 range", self.field),
            ConfigReason::Malformed(msg) => write!(f, "config: malformed document: {msg}"),
            ConfigReason::TopLevelNotObject => {
                write!(f, "config: top-level value must be an object")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// The parsed health configuration: two independent positive-integer
/// millisecond thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthConfig {
    /// Heartbeat age staleness threshold in milliseconds.
    pub dispatch_heartbeat_stale_ms: u64,
    /// Action (queued and in-flight) age staleness threshold in milliseconds.
    pub action_age_stale_ms: u64,
}

impl HealthConfig {
    /// The default configuration: heartbeat 2000 ms, action age 30000 ms.
    pub const DEFAULT: Self = Self {
        dispatch_heartbeat_stale_ms: DEFAULT_DISPATCH_HEARTBEAT_STALE_MS,
        action_age_stale_ms: DEFAULT_ACTION_AGE_STALE_MS,
    };

    /// Heartbeat staleness threshold as a [`Duration`].
    pub fn heartbeat_threshold(&self) -> Duration {
        Duration::from_millis(self.dispatch_heartbeat_stale_ms)
    }

    /// Action-age staleness threshold as a [`Duration`], applied independently
    /// to queued and in-flight ages.
    pub fn action_age_threshold(&self) -> Duration {
        Duration::from_millis(self.action_age_stale_ms)
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The top-level parsed configuration. Spec A owns only the `health` surface;
/// other top-level keys are permitted (later cerebellum specifications own
/// them) and ignored by this slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub health: HealthConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            health: HealthConfig::DEFAULT,
        }
    }
}

/// The canonical config file path: `~/.config/cortexkit/cerebellum.jsonc`.
pub fn config_path() -> Option<PathBuf> {
    // The daemon's config ladder, so `cerebellum.jsonc` is looked for where
    // `subc.jsonc` is found. With only HOME consulted, an operator who set
    // XDG_CONFIG_HOME had the daemon reading its config from there and this
    // module reading "no config" from ~/.config -- browser silently
    // unconfigured, no error anywhere.
    crate::platform_dirs::config_home().map(|mut p| {
        p.push("cortexkit");
        p.push("cerebellum.jsonc");
        p
    })
}

/// Parse a JSONC configuration document (the contents of
/// `~/.config/cortexkit/cerebellum.jsonc`) into a [`Config`].
///
/// JSONC comments and trailing commas are stripped via `subc_jsonc` before
/// JSON parsing. An absent `health` member uses [`HealthConfig::DEFAULT`].
/// When `health` is present it must be an object; unknown members, zero,
/// negative, fractional, non-numeric, and out-of-`u64` values are rejected
/// deterministically without silent fallback. Configuring one threshold
/// leaves the other at its independent default.
pub fn parse_config(text: &str) -> Result<Config, ConfigError> {
    let stripped = subc_jsonc::jsonc_to_json(text).map_err(|e| ConfigError {
        field: "config",
        reason: ConfigReason::Malformed(e),
    })?;
    let value: serde_json::Value = serde_json::from_str(&stripped).map_err(|e| ConfigError {
        field: "config",
        reason: ConfigReason::Malformed(e.to_string()),
    })?;
    parse_config_value(&value)
}

/// Parse an already-deserialized top-level JSON value into a [`Config`].
pub fn parse_config_value(value: &serde_json::Value) -> Result<Config, ConfigError> {
    let obj = value.as_object().ok_or(ConfigError {
        field: "config",
        reason: ConfigReason::TopLevelNotObject,
    })?;

    let health = if let Some(h) = obj.get("health") {
        parse_health(h)?
    } else {
        HealthConfig::DEFAULT
    };

    Ok(Config { health })
}

fn parse_health(value: &serde_json::Value) -> Result<HealthConfig, ConfigError> {
    let obj = value.as_object().ok_or(ConfigError {
        field: "health",
        reason: ConfigReason::HealthNotObject,
    })?;

    // Reject unknown members before reading thresholds so the failure is
    // deterministic and surfaces the offending key rather than silently
    // ignoring it.
    const ACCEPTED: &[&str] = &["dispatch_heartbeat_stale_ms", "action_age_stale_ms"];
    for (key, _v) in obj {
        if !ACCEPTED.contains(&key.as_str()) {
            return Err(ConfigError {
                field: "health",
                reason: ConfigReason::UnknownMember(key.clone()),
            });
        }
    }

    let dispatch_heartbeat_stale_ms = match obj.get("dispatch_heartbeat_stale_ms") {
        Some(v) => parse_positive_ms(v, "dispatch_heartbeat_stale_ms")?,
        None => DEFAULT_DISPATCH_HEARTBEAT_STALE_MS,
    };
    let action_age_stale_ms = match obj.get("action_age_stale_ms") {
        Some(v) => parse_positive_ms(v, "action_age_stale_ms")?,
        None => DEFAULT_ACTION_AGE_STALE_MS,
    };

    Ok(HealthConfig {
        dispatch_heartbeat_stale_ms,
        action_age_stale_ms,
    })
}

/// Parse a threshold value as a strictly positive integer millisecond count.
/// Rejects non-integers (strings, bools, null, fractional numbers), zero,
/// negatives, and values exceeding `u64::MAX`.
fn parse_positive_ms(value: &serde_json::Value, field: &'static str) -> Result<u64, ConfigError> {
    // serde_json distinguishes integers from floats in the parsed tree. A
    // fractional number like `2000.5` parses as a `f64`; an integer like `2000`
    // parses as `u64`/`i64`. We accept only the integer forms.
    match value {
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u == 0 {
                    return Err(ConfigError {
                        field,
                        reason: ConfigReason::NotPositive,
                    });
                }
                Ok(u)
            } else if let Some(i) = n.as_i64() {
                // Negative integer.
                if i <= 0 {
                    return Err(ConfigError {
                        field,
                        reason: ConfigReason::NotPositive,
                    });
                }
                // Positive i64 that fits in u64 (guaranteed by i > 0 and i64
                // range, but be explicit).
                Ok(u64::try_from(i).map_err(|_| ConfigError {
                    field,
                    reason: ConfigReason::OutOfRange,
                })?)
            } else if n.as_f64().is_some() {
                // Fractional or out-of-i64-range float.
                Err(ConfigError {
                    field,
                    reason: ConfigReason::NotInteger,
                })
            } else {
                Err(ConfigError {
                    field,
                    reason: ConfigReason::NotInteger,
                })
            }
        }
        _ => Err(ConfigError {
            field,
            reason: ConfigReason::NotInteger,
        }),
    }
}

/// Load and parse the config file at [`config_path`]. If the file is absent,
/// returns the default config (no file = defaults). If the file is present but
/// malformed or has an invalid `health` value, returns a [`ConfigError`] so
/// registration fails deterministically rather than silently falling back.
pub fn load_config_file() -> Result<Config, ConfigError> {
    let Some(path) = config_path() else {
        return Ok(Config::default());
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_config(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(ConfigError {
            field: "config",
            reason: ConfigReason::Malformed(format!("reading {}: {e}", path.display())),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_2000_and_30000() {
        assert_eq!(DEFAULT_DISPATCH_HEARTBEAT_STALE_MS, 2000);
        assert_eq!(DEFAULT_ACTION_AGE_STALE_MS, 30000);
        assert_eq!(
            HealthConfig::DEFAULT,
            HealthConfig {
                dispatch_heartbeat_stale_ms: 2000,
                action_age_stale_ms: 30000,
            }
        );
    }

    #[test]
    fn absent_health_uses_defaults() {
        let cfg = parse_config(r#"{"other": 1}"#).unwrap();
        assert_eq!(cfg.health, HealthConfig::DEFAULT);
    }

    #[test]
    fn empty_object_uses_defaults() {
        let cfg = parse_config("{}").unwrap();
        assert_eq!(cfg.health, HealthConfig::DEFAULT);
    }

    #[test]
    fn absent_member_uses_default_for_that_member_only() {
        // Configuring heartbeat leaves action age at default.
        let cfg = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": 5000}}"#).unwrap();
        assert_eq!(cfg.health.dispatch_heartbeat_stale_ms, 5000);
        assert_eq!(cfg.health.action_age_stale_ms, DEFAULT_ACTION_AGE_STALE_MS);

        // Configuring action age leaves heartbeat at default.
        let cfg = parse_config(r#"{"health": {"action_age_stale_ms": 70000}}"#).unwrap();
        assert_eq!(
            cfg.health.dispatch_heartbeat_stale_ms,
            DEFAULT_DISPATCH_HEARTBEAT_STALE_MS
        );
        assert_eq!(cfg.health.action_age_stale_ms, 70000);
    }

    #[test]
    fn non_default_positive_integer_thresholds() {
        let cfg = parse_config(
            r#"{"health": {"dispatch_heartbeat_stale_ms": 3000, "action_age_stale_ms": 45000}}"#,
        )
        .unwrap();
        assert_eq!(cfg.health.dispatch_heartbeat_stale_ms, 3000);
        assert_eq!(cfg.health.action_age_stale_ms, 45000);
    }

    #[test]
    fn jsonc_comments_and_trailing_commas_are_stripped() {
        let text = r#"{
            // line comment
            "health": {
                "dispatch_heartbeat_stale_ms": 1234, /* block */
                "action_age_stale_ms": 5678,
            }
        }"#;
        let cfg = parse_config(text).unwrap();
        assert_eq!(cfg.health.dispatch_heartbeat_stale_ms, 1234);
        assert_eq!(cfg.health.action_age_stale_ms, 5678);
    }

    #[test]
    fn health_not_object_rejected() {
        let err = parse_config(r#"{"health": 2000}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::HealthNotObject);

        let err = parse_config(r#"{"health": [1, 2]}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::HealthNotObject);

        let err = parse_config(r#"{"health": "fast"}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::HealthNotObject);

        let err = parse_config(r#"{"health": null}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::HealthNotObject);
    }

    #[test]
    fn unknown_member_rejected() {
        let err = parse_config(r#"{"health": {"heartbeat_ms": 2000}}"#).unwrap_err();
        assert_eq!(
            err.reason,
            ConfigReason::UnknownMember("heartbeat_ms".to_string())
        );

        let err = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": 2000, "extra": 1}}"#)
            .unwrap_err();
        assert_eq!(err.reason, ConfigReason::UnknownMember("extra".to_string()));
    }

    #[test]
    fn zero_threshold_rejected() {
        let err = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": 0}}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::NotPositive);

        let err = parse_config(r#"{"health": {"action_age_stale_ms": 0}}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::NotPositive);
    }

    #[test]
    fn negative_threshold_rejected() {
        let err = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": -1}}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::NotPositive);

        let err = parse_config(r#"{"health": {"action_age_stale_ms": -30000}}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::NotPositive);
    }

    #[test]
    fn fractional_threshold_rejected() {
        let err =
            parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": 2000.5}}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::NotInteger);

        let err = parse_config(r#"{"health": {"action_age_stale_ms": 30000.0}}"#).unwrap_err();
        // 30000.0 parses as f64 in serde_json, so it is NotInteger (not an
        // integer form).
        assert_eq!(err.reason, ConfigReason::NotInteger);
    }

    #[test]
    fn non_numeric_threshold_rejected() {
        let err =
            parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": "2000"}}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::NotInteger);

        let err = parse_config(r#"{"health": {"action_age_stale_ms": true}}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::NotInteger);

        let err = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": null}}"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::NotInteger);
    }

    #[test]
    fn large_u64_threshold_accepted() {
        let cfg =
            parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": 18446744073709551615}}"#)
                .unwrap();
        assert_eq!(cfg.health.dispatch_heartbeat_stale_ms, u64::MAX);
    }

    #[test]
    fn malformed_json_rejected() {
        let err = parse_config(r#"{"health": {"dispatch_heartbeat_stale_ms": 2000,}"#).unwrap_err();
        // Trailing comma inside the object is stripped by subc_jsonc, but the
        // outer document is still missing a closing brace, so it is malformed.
        assert!(matches!(err.reason, ConfigReason::Malformed(_)));
    }

    #[test]
    fn top_level_not_object_rejected() {
        let err = parse_config(r#"2000"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::TopLevelNotObject);

        let err = parse_config(r#"[1, 2, 3]"#).unwrap_err();
        assert_eq!(err.reason, ConfigReason::TopLevelNotObject);
    }
}
