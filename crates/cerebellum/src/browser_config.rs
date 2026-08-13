//! Browser-plane configuration parsing kept out of the shared substrate.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

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
    PathNotAbsolute,
    ExpectedIdentityRequired,
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
            BrowserConfigReason::PathNotAbsolute => {
                write!(f, "{}: expected an absolute path", self.field)
            }
            BrowserConfigReason::ExpectedIdentityRequired => write!(
                f,
                "browser.expected_identity: required when browser.executable_path is set"
            ),
        }
    }
}

impl std::error::Error for BrowserConfigError {}

pub fn load_browser_config_file() -> Result<Option<BrowserConfig>, BrowserConfigError> {
    let Some(path) = cerebellum_core::config::config_path() else {
        return Ok(None);
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_browser_config(&text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(BrowserConfigError {
            field: "config".to_string(),
            reason: BrowserConfigReason::Malformed(format!("reading {}: {error}", path.display())),
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
    let expected_identity = match object.get("expected_identity") {
        None => None,
        Some(Value::String(identity)) if !identity.is_empty() => Some(identity.clone()),
        Some(_) => {
            return Err(BrowserConfigError {
                field: "browser.expected_identity".to_string(),
                reason: BrowserConfigReason::WrongType,
            });
        }
    };
    if executable_path.is_some() && expected_identity.is_none() {
        return Err(BrowserConfigError {
            field: "browser.expected_identity".to_string(),
            reason: BrowserConfigReason::ExpectedIdentityRequired,
        });
    }

    Ok(BrowserConfig {
        executable_path,
        expected_identity,
        launch_handshake_deadline_ms: required_positive_ms(object, "launch_handshake_deadline_ms")?,
        termination_grace_period_ms: required_positive_ms(object, "termination_grace_period_ms")?,
        browser_idle_timeout_ms: required_positive_ms(object, "browser_idle_timeout_ms")?,
        browser_exit_observation_deadline_ms: required_positive_ms(
            object,
            "browser_exit_observation_deadline_ms",
        )?,
        navigation_settle_deadline_ms: required_positive_ms(
            object,
            "navigation_settle_deadline_ms",
        )?,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

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
        value["browser"]["executable_path"] = serde_json::json!("/Applications/Chrome");
        assert_eq!(
            parse_browser_config(&value.to_string()).unwrap_err().reason,
            BrowserConfigReason::ExpectedIdentityRequired
        );
        value["browser"]["expected_identity"] = serde_json::json!("com.example.Chrome");
        assert!(parse_browser_config(&value.to_string()).is_ok());
    }
}
