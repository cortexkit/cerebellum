//! Cerebellum's user-only managed settings. Reviews use immutable snapshots;
//! only the delivery path can touch runtime state or probe the browser binary.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use cerebellum_core::config::{self, AppUse, ConfigReason, HealthConfig};
use serde_json::{json, Value};
use subc_client_rs::config::{
    ApplyKind, ConfigDeclareRequest, ConfigReviewRefusal, ConfigReviewReply, ConfigReviewRequest,
    ConfigStatus, ConfigView, FieldChange, Layer, LayerValue, RecordedValue, Schema,
    ValidationContext,
};

use crate::browser_config::{
    self, BrowserConfigReason, MAX_ACTION_DEADLINE_MS, MAX_LAUNCH_DEADLINE_MS,
    MAX_TERMINATION_DEADLINE_MS,
};
use crate::{BrowserSurface, ModuleError};

mod session;
pub(crate) use session::Session;

const PATH: &str = "/browser/executable_path";
const IDENTITY: &str = "/browser/expected_identity";
const APP_USE: &str = "/computer_use/app_use";

static SCHEMA: LazyLock<(Value, Schema)> = LazyLock::new(|| {
    let declaration = schema_declaration();
    let schema = Schema::new(declaration.clone()).expect("Cerebellum's settings schema is valid");
    (declaration, schema)
});

fn schema_declaration() -> Value {
    fn field(kind: &str, description: &str, default: Value, apply: ApplyKind) -> Value {
        json!({"type": kind, "description": description, "default": default,
            "x-ck-apply": apply, "x-ck-layers": ["user"]})
    }
    fn integer(description: &str, default: u64, minimum: u64, maximum: u64) -> Value {
        let mut value = field(
            "integer",
            description,
            json!(default),
            ApplyKind::ModuleRestart,
        );
        value["minimum"] = json!(minimum);
        value["maximum"] = json!(maximum);
        value
    }
    use ApplyKind::{Live, ModuleRestart};
    let mut app_use = field("string", "Whether computer use acts in the background or brings the application to the front. Foreground use of unapproved settings requires operator confirmation.", json!("background"), Live);
    app_use["enum"] = json!(AppUse::ALLOWED);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object", "unevaluatedProperties": false,
        "properties": {
            "health": {"type": "object", "unevaluatedProperties": false, "properties": {
                "dispatch_heartbeat_stale_ms": integer("Milliseconds before an unresponsive dispatch heartbeat is reported stale.", config::DEFAULT_DISPATCH_HEARTBEAT_STALE_MS, 1, u64::MAX),
                "queue_age_stale_ms": integer("Milliseconds before the oldest queued action is reported stale.", config::DEFAULT_QUEUE_AGE_STALE_MS, 1, u64::MAX)
            }},
            "computer_use": {"type": "object", "unevaluatedProperties": false, "properties": {
                "agent_cursor": field("boolean", "Show the agent cursor while computer use acts on screen.", json!(true), ModuleRestart),
                "app_use": app_use
            }},
            "browser": {"type": "object", "unevaluatedProperties": false, "properties": {
                "executable_path": field("string", "Absolute path to the browser executable. Omit to leave the browser unconfigured; a path requires an expected identity.", json!(""), ModuleRestart),
                "expected_identity": field("string", "Expected executable identity used to verify the configured browser. Omit when no browser path is configured.", json!(""), ModuleRestart),
                "launch_handshake_deadline_ms": integer("Milliseconds allowed for the initial browser handshake, including cold-start macOS code signature validation.", 10_000, 1, MAX_LAUNCH_DEADLINE_MS),
                "termination_grace_period_ms": integer("Milliseconds for the browser to exit gracefully. Shortening this can force-kill the browser before it saves profile writes.", 5_000, 1, MAX_TERMINATION_DEADLINE_MS),
                "browser_idle_timeout_ms": integer("Milliseconds of inactivity after which to close an idle browser session.", 600_000, 1, u64::MAX),
                "browser_exit_observation_deadline_ms": integer("Milliseconds allowed to observe the browser exit after termination, separate from the grace period.", 5_000, 1, MAX_TERMINATION_DEADLINE_MS),
                "navigation_settle_deadline_ms": integer("Milliseconds allowed for navigation to settle. Must exceed the network-quiet window or a navigation can never settle.", 10_000, crate::browser::QUIET_MS + 1, MAX_ACTION_DEADLINE_MS)
            }}
        }
    })
}

pub(crate) fn config_declaration(path: &Path) -> Option<ConfigDeclareRequest> {
    Some(ConfigDeclareRequest::new(
        SCHEMA.0.clone(),
        path.to_str()?,
        vec![],
    ))
}

fn refusal(code: &str, paths: &[&str], reason: &str) -> ConfigReviewRefusal {
    ConfigReviewRefusal::new(
        code,
        paths.iter().map(|p| (*p).into()).collect(),
        vec![reason.into()],
    )
}

fn core_refusal(error: config::ConfigError) -> ConfigReviewRefusal {
    let path = match error.field {
        "dispatch_heartbeat_stale_ms" | "queue_age_stale_ms" => format!("/health/{}", error.field),
        "config" => String::new(),
        field => format!("/{}", field.replace('.', "/")),
    };
    let reason = match error.reason {
        ConfigReason::HealthNotObject
        | ConfigReason::TopLevelNotObject
        | ConfigReason::ComputerUseNotObject => "not_object",
        ConfigReason::UnknownMember(_) => "unknown_member",
        ConfigReason::NotInteger => "not_integer",
        ConfigReason::NotPositive => "not_positive",
        ConfigReason::OutOfRange => "out_of_range",
        ConfigReason::Malformed(_) => "malformed",
        ConfigReason::NotBoolean => "not_boolean",
        ConfigReason::NotOneOf(_) => "not_one_of",
    };
    refusal("value_invalid", &[&path], reason)
}

fn browser_refusal(error: browser_config::BrowserConfigError) -> ConfigReviewRefusal {
    if error.reason == BrowserConfigReason::ExpectedIdentityRequired {
        return refusal(
            "value_invalid",
            &[PATH, IDENTITY],
            error.reason.reason_code(),
        );
    }
    let path = format!("/{}", error.field.replace('.', "/"));
    refusal("value_invalid", &[&path], error.reason.reason_code())
}

pub(crate) fn config_review(module_id: &str, request: ConfigReviewRequest) -> ConfigReviewReply {
    match review(module_id, request) {
        Ok(fields) => ConfigReviewReply::new(fields, vec![]),
        Err(refusal) => ConfigReviewReply::new(vec![], vec![refusal]),
    }
}

fn review(
    module_id: &str,
    request: ConfigReviewRequest,
) -> Result<Vec<FieldChange>, ConfigReviewRefusal> {
    let schema = &SCHEMA.1;
    let mut layers = Vec::new();
    for snapshot in request.layers {
        let layer = snapshot
            .layer
            .known_layer()
            .ok_or_else(|| refusal("layer_forbidden", &[], "unknown layer"))?;
        let Some(bytes) = snapshot.bytes else {
            continue;
        };
        if layer != Layer::User
            || snapshot.module_id != module_id
            || snapshot.project_id.is_some()
            || snapshot.workspace_id.is_some()
        {
            return Err(refusal(
                "layer_forbidden",
                &[],
                "Cerebellum accepts only its own user settings",
            ));
        }
        let value = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| subc_jsonc::jsonc_to_json(text).ok())
            .and_then(|json| serde_json::from_str::<Value>(&json).ok())
            .ok_or_else(|| refusal("value_invalid", &[], "malformed"))?;
        config::parse_config_value(&value).map_err(core_refusal)?;

        // Keep browser_config's refusal reasons (such as PathNotAbsolute), but
        // fill managed defaults before checking the five required deadlines.
        // An explicitly empty path or identity is still invalid.
        let mut candidate = value.clone();
        if let Some(browser) = candidate.get_mut("browser").and_then(Value::as_object_mut) {
            let defaults = schema.defaults();
            for (key, value) in defaults["browser"].as_object().expect("browser defaults") {
                if key != "executable_path" && key != "expected_identity" {
                    browser.entry(key).or_insert_with(|| value.clone());
                }
            }
        }
        browser_config::parse_browser_config_value(&candidate).map_err(browser_refusal)?;
        layers.push(LayerValue::new(layer, value));
    }
    let tuple = schema
        .review_tuple(&layers, &ValidationContext::new(module_id, None))
        .map_err(|error| {
            let code = serde_json::to_value(error.code).expect("schema refusal code serializes");
            refusal(
                code.as_str().expect("schema refusal code is a string"),
                &[&error.path],
                "settings schema refused this field",
            )
        })?;
    let mut fields = Vec::new();
    for (path, &new_source) in &tuple.sources {
        let Some(new) = tuple.effective.pointer(path) else {
            continue;
        };
        if new.is_object() {
            continue;
        }
        let old = request
            .base
            .as_ref()
            .and_then(|view| view.effective.pointer(path));
        let old_source = request
            .base
            .as_ref()
            .and_then(|view| view.sources.get(path))
            .copied()
            .unwrap_or(Layer::Default);
        if old == Some(new) && old_source == new_source {
            continue;
        }
        let apply = if path == APP_USE {
            ApplyKind::Live
        } else {
            ApplyKind::ModuleRestart
        };
        let mut field = FieldChange::new(
            module_id,
            path,
            RecordedValue::new(old.cloned().unwrap_or(Value::Null)),
            RecordedValue::new(new.clone()),
            apply,
        );
        field.old_source = old_source;
        field.new_source = new_source;
        fields.push(field);
    }
    Ok(fields)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LiveSettings {
    pub(crate) app_use: AppUse,
    pub(crate) approved: bool,
}

pub(crate) struct StartupSettings {
    pub(crate) health: HealthConfig,
    pub(crate) agent_cursor: bool,
    pub(crate) browser: BrowserSurface,
    pub(crate) live: LiveSettings,
    pub(crate) legacy_file: Option<PathBuf>,
}

fn validate_view(view: &ConfigView) -> Result<(), &'static str> {
    if view.project_id.is_some()
        || view
            .layers
            .iter()
            .any(|layer| layer.layer.known_layer().is_none())
    {
        return Err("settings delivery has an unknown layer or project");
    }
    match view.status {
        ConfigStatus::Active | ConfigStatus::Pending | ConfigStatus::Unstamped => Ok(()),
        _ => Err("settings delivery is not active, pending, or unstamped"),
    }
}

pub(crate) fn config_apply(view: &ConfigView) -> Result<LiveSettings, String> {
    StartupSettings::from_view(view).map(|settings| settings.live)
}

impl StartupSettings {
    pub(crate) fn from_view(view: &ConfigView) -> Result<Self, String> {
        validate_view(view)?;
        let core =
            config::parse_config_value(&view.effective).map_err(|error| error.to_string())?;
        let mut value = view.effective.clone();
        if let Some(browser) = value.get_mut("browser").and_then(Value::as_object_mut) {
            for (path, key) in [(PATH, "executable_path"), (IDENTITY, "expected_identity")] {
                if view.sources.get(path) == Some(&Layer::Default)
                    && browser.get(key) == Some(&json!(""))
                {
                    browser.remove(key);
                }
            }
        }
        let browser = browser_config::parse_browser_config_value(&value)
            .map_err(|error| error.to_string())?;
        let browser = match browser {
            Some(browser) if browser.executable_path.is_some() => {
                BrowserSurface::Available(browser)
            }
            _ => BrowserSurface::NotConfigured,
        };
        Ok(Self {
            health: core.health,
            agent_cursor: core.computer_use.agent_cursor,
            browser,
            live: LiveSettings {
                app_use: core.computer_use.app_use,
                approved: matches!(view.status, ConfigStatus::Active | ConfigStatus::Pending),
            },
            legacy_file: None,
        })
    }

    pub(crate) fn validate_browser(&mut self) {
        if let BrowserSurface::Available(browser) = &self.browser {
            if let Err(error) = browser_config::validate_browser_config_at_load(browser) {
                self.browser = BrowserSurface::Refused(error);
            }
        }
    }
}

/// The pre-managed daemon leaves the original JSONC file in the module's care.
/// The supplied path is explicit so fixtures never need the operator's file.
pub(crate) fn config_files(path: Option<&Path>) -> Result<StartupSettings, ModuleError> {
    let text = match path.map(std::fs::read_to_string).transpose() {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(ModuleError::Config(config::ConfigError {
                field: "config",
                reason: ConfigReason::Malformed(format!(
                    "reading {}: {error}",
                    path.expect("file was read").display()
                )),
            }))
        }
    };
    let core = text
        .as_deref()
        .map(config::parse_config)
        .transpose()
        .map_err(ModuleError::Config)?
        .unwrap_or_default();
    let browser = match text
        .as_deref()
        .map(browser_config::parse_browser_config)
        .transpose()
    {
        Ok(Some(Some(browser))) => BrowserSurface::Available(browser),
        Ok(_) => BrowserSurface::NotConfigured,
        Err(error) => BrowserSurface::Refused(error),
    };
    Ok(StartupSettings {
        health: core.health,
        agent_cursor: core.computer_use.agent_cursor,
        browser,
        live: LiveSettings {
            app_use: core.computer_use.app_use,
            approved: false,
        },
        legacy_file: path.map(Path::to_path_buf),
    })
}

#[cfg(test)]
mod tests;
