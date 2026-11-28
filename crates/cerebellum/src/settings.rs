//! Cerebellum's user-only managed settings. Reviews use immutable snapshots;
//! only the delivery path can touch runtime state or probe the browser binary.

use std::path::Path;
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
use crate::BrowserSurface;

mod session;
pub(crate) use session::Session;

const PATH: &str = "/browser/executable_path";
const IDENTITY: &str = "/browser/expected_identity";
const APP_USE: &str = "/computer_use/app_use";
// After a day, a stale queue or idle browser should already have expired.
const MAX_STALE_OR_IDLE_MS: u64 = 24 * 60 * 60 * 1_000;

static SCHEMA: LazyLock<(Value, Schema)> = LazyLock::new(|| {
    let declaration = schema_declaration();
    let schema = Schema::new(declaration.clone()).expect("Cerebellum's settings schema is valid");
    (declaration, schema)
});

fn schema_declaration() -> Value {
    // Every title is the label a person reads in the apps' Settings page; the
    // description is the one-line help under it.
    fn field(
        kind: &str,
        title: &str,
        description: &str,
        default: Value,
        apply: ApplyKind,
    ) -> Value {
        json!({"type": kind, "title": title, "description": description, "default": default,
            "x-ck-apply": apply, "x-ck-layers": ["user"]})
    }
    fn integer(title: &str, description: &str, default: u64, minimum: u64, maximum: u64) -> Value {
        let mut value = field(
            "integer",
            title,
            description,
            json!(default),
            ApplyKind::ModuleRestart,
        );
        value["minimum"] = json!(minimum);
        value["maximum"] = json!(maximum);
        value
    }
    fn group(title: &str, properties: Value) -> Value {
        json!({"type": "object", "title": title, "unevaluatedProperties": false, "properties": properties})
    }
    use ApplyKind::{Live, ModuleRestart};
    let mut app_use = field("string", "How the agent uses apps", "Whether the agent works in apps from the background or brings them to the front. Bringing apps to the front needs your confirmation on this computer.", json!("background"), Live);
    app_use["enum"] = json!(AppUse::ALLOWED);
    #[cfg(not(all(windows, feature = "windows-browser-release")))]
    let (executable_path, expected_identity) = (
        field("string", "Browser program", "Full path to the browser program the agent uses. Leave empty to turn the agent browser off; a path also needs the expected identity.", json!(""), ModuleRestart),
        field("string", "Expected browser identity", "The signature the browser program must carry before the agent starts it. Leave empty when no browser program is set.", json!(""), ModuleRestart),
    );
    #[cfg(all(windows, feature = "windows-browser-release"))]
    let (executable_path, expected_identity) = {
        let publisher = browser_config::CHROME_PUBLISHER;
        let mut identity = field(
            "string",
            "Browser publisher",
            "The publisher that must sign the browser program before the agent starts it.",
            json!(publisher),
            ModuleRestart,
        );
        identity["enum"] = json!([publisher]);
        (
            field("string", "Browser program", "Full path to the browser program the agent uses. Omit it to search the standard install locations.", json!(""), ModuleRestart),
            group("Expected browser identity", json!({"windows_publisher": identity})),
        )
    };
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Browser and desktop control",
        "type": "object", "unevaluatedProperties": false,
        "properties": {
            "health": group("Health checks", json!({
                "dispatch_heartbeat_stale_ms": integer("Report a stuck action after", "Milliseconds an action may go without progress before health reports it stuck.", config::DEFAULT_DISPATCH_HEARTBEAT_STALE_MS, 1, MAX_STALE_OR_IDLE_MS),
                "queue_age_stale_ms": integer("Report a waiting action after", "Milliseconds an action may wait in line before health reports it stuck.", config::DEFAULT_QUEUE_AGE_STALE_MS, 1, MAX_STALE_OR_IDLE_MS)
            })),
            "computer_use": group("Desktop control", json!({
                "agent_cursor": field("boolean", "Show the agent's cursor", "Show the agent's cursor and preview while it works in an app.", json!(true), ModuleRestart),
                "app_use": app_use
            })),
            "browser": group("Agent browser", json!({
                "executable_path": executable_path,
                "expected_identity": expected_identity,
                "launch_handshake_deadline_ms": integer("Browser start time limit", "Milliseconds the browser may take to start, including the system's first check of its signature.", 10_000, 1, MAX_LAUNCH_DEADLINE_MS),
                "termination_grace_period_ms": integer("Browser close time limit", "Milliseconds the browser gets to close by itself. A shorter time can force it closed before it saves its profile.", 5_000, 1, MAX_TERMINATION_DEADLINE_MS),
                "browser_idle_timeout_ms": integer("Close an unused browser after", "Milliseconds without agent activity before the agent browser closes.", 600_000, 1, MAX_STALE_OR_IDLE_MS),
                "browser_exit_observation_deadline_ms": integer("Browser exit check time limit", "Milliseconds to confirm the browser has exited after it is told to close, apart from the close time limit.", 5_000, 1, MAX_TERMINATION_DEADLINE_MS),
                "navigation_settle_deadline_ms": integer("Page load time limit", "Milliseconds a page may take to finish loading. It must be longer than the page's quiet period, or no page counts as loaded.", 10_000, crate::browser::QUIET_MS + 1, MAX_ACTION_DEADLINE_MS)
            }))
        }
    })
}

/// Tell the daemon where to find the user's configuration file. Cerebellum
/// consumes the resolved settings sent by the daemon.
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
    #[cfg(target_os = "linux")]
    pub(crate) stamped: bool,
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
        let browser = browser_surface(view, browser);
        Ok(Self {
            health: core.health,
            agent_cursor: core.computer_use.agent_cursor,
            browser,
            #[cfg(target_os = "linux")]
            stamped: matches!(view.status, ConfigStatus::Active | ConfigStatus::Pending),
            live: LiveSettings {
                app_use: core.computer_use.app_use,
                approved: matches!(view.status, ConfigStatus::Active | ConfigStatus::Pending),
            },
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn validate_browser(&mut self) -> crate::doctor::AppliedBrowser {
        let mut applied = crate::doctor::AppliedBrowser::new(self.stamped);
        if let BrowserSurface::Available(browser) = &self.browser {
            applied.executable_path = browser.executable_path.clone();
            applied.expected_identity = browser.expected_identity.clone();
            match browser_config::probe_browser_config_at_load(browser) {
                Ok(path) => applied.final_image_path = path,
                Err(error) => {
                    if let BrowserConfigReason::FinalImageMismatch { path, .. } = &error.reason {
                        applied.final_image_path = Some(path.clone());
                    }
                    self.browser = BrowserSurface::Refused(error);
                }
            }
        }
        applied
    }
}

fn browser_surface(
    view: &ConfigView,
    browser: Option<browser_config::BrowserConfig>,
) -> BrowserSurface {
    let available = |browser: &browser_config::BrowserConfig| {
        if browser_config::WINDOWS_DISCOVERS_CHROME {
            view.sources.iter().any(|(path, layer)| {
                *layer != Layer::Default && (path == "/browser" || path.starts_with("/browser/"))
            })
        } else {
            browser.executable_path.is_some()
        }
    };
    match browser {
        Some(browser) if available(&browser) => BrowserSurface::Available(browser),
        _ => BrowserSurface::NotConfigured,
    }
}

#[cfg(test)]
mod tests;
