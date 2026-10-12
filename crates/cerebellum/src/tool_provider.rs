//! Provider operations use the tool route but are not model tools. Catalogs
//! share HELLO's flat definitions; pulls read only the verified custodian's log.

use crate::*;
use cortexkit_role_tool_provider::call::SchemaPin;
use cortexkit_role_tool_provider::catalog::{
    composition_digest, schema_digest, session_capabilities, CatalogAnswer, CatalogRequest,
    CatalogTool,
};
use cortexkit_role_tool_provider::describe::{Major, RoleDescribe};
use cortexkit_role_tool_provider::late_results::{AckRequest, LateResultsRequest};
use cortexkit_role_tool_provider::ops;
use cortexkit_role_tool_provider::{check_capability_tag, errors, PROVIDES};
use serde_json::Map;

pub(crate) fn is_operation(name: &str) -> bool {
    matches!(
        name,
        ops::ROLE_DESCRIBE | ops::TOOL_CATALOG | ops::LATE_RESULTS | ops::LATE_RESULTS_ACK
    )
}

pub(crate) fn browser_tools() -> Vec<subc_protocol::manifest::Tool> {
    manifest::browser_control_tools()
        .into_iter()
        .chain(manifest::browser_wire_tools())
        .filter(|tool| dispatchable_tool_with_browser(&tool.name, true).is_some())
        .collect()
}

fn catalog_tools(planes: &Planes) -> Vec<CatalogTool> {
    let browser_names = if planes.browser_config.is_some() {
        browser_tools().into_iter().map(|tool| tool.name).collect()
    } else {
        Vec::new()
    };
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let computer_names = planes.computer_admitted.iter().cloned().collect::<Vec<_>>();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let computer_names = Vec::new();
    definitions(&browser_names, &computer_names)
}

fn definitions(browser_names: &[String], computer_names: &[String]) -> Vec<CatalogTool> {
    [
        (flat_tools::computer_tool(computer_names), "computer.use/v1"),
        (flat_tools::browser_tool(browser_names), "browser.use/v1"),
    ]
    .into_iter()
    .filter_map(|(tool, tag)| {
        let tool = tool?;
        let tags = vec![tag.to_string(), format!("cerebellum:{tag}")];
        for tag in &tags {
            check_capability_tag(tag).expect("provider capability tag is valid");
        }
        // No reply deadline is declared: browser queue waits and configured
        // action deadlines are unbounded. A finite max_ms would promise a
        // receive-to-terminal bound execution does not currently enforce.
        let mut definition = CatalogTool::new(
            tool.name,
            schema_digest(&tool.schema).expect("flat schema canonicalizes structurally"),
            1,
            tool.schema,
        )
        .with_capabilities(tags);
        definition.description = tool.description;
        Some(definition)
    })
    .collect()
}

fn catalog(arguments: &Map<String, Value>, planes: &Planes) -> Result<Value, ErrorBody> {
    for field in arguments.keys() {
        if !matches!(
            field.as_str(),
            "params" | "preset" | "composition" | "system_text" | "digest_only"
        ) {
            return Err(errors::invalid_request(field, "unknown catalog member"));
        }
    }
    // There are no variants or text-resolution axes. Refuse them rather than
    // silently offering a default configuration the caller did not request.
    for field in ["preset", "system_text"] {
        if arguments.contains_key(field) {
            return Err(errors::invalid_request(
                field,
                "no variants or system text are served",
            ));
        }
    }
    for (field, value) in arguments {
        let valid = match field.as_str() {
            "params" | "composition" => value.is_object(),
            "digest_only" => value.is_boolean(),
            _ => true,
        };
        if !valid {
            return Err(errors::invalid_request(field, "wrong catalog member type"));
        }
    }
    let request: CatalogRequest = serde_json::from_value(Value::Object(arguments.clone()))
        .map_err(|error| errors::invalid_request("arguments", error.to_string()))?;
    if !request.params.is_empty() {
        return Err(errors::invalid_request(
            "params",
            "no catalog params are defined",
        ));
    }
    let mut answer = CatalogAnswer::new("", "")
        .with_tools(catalog_tools(planes))
        .with_capabilities(Map::from_iter([(
            session_capabilities::LATE_RESULTS.into(),
            json!(true),
        )]));
    if let Some(composition) = request.composition {
        answer.composition_digest = Some(
            composition_digest(&Value::Object(composition))
                .map_err(|error| errors::invalid_request("composition", error.to_string()))?,
        );
    }
    // CatalogAnswer::new above leaves generation and catalog_digest empty;
    // hash that content before filling them to avoid hashing a digest into
    // itself. Content-addressed generation needs no mutable counter.
    let digest = manifest::sha256_hex(&manifest::canonical_json_bytes(
        &serde_json::to_value(&answer).expect("catalog serializes"),
    ));
    answer.generation = digest.clone();
    answer.catalog_digest = digest;
    if request.digest_only == Some(true) {
        Ok(json!({"generation":answer.generation,"catalog_digest":answer.catalog_digest}))
    } else {
        Ok(serde_json::to_value(answer).expect("catalog serializes"))
    }
}

pub(crate) fn check_tool_call(
    object: &Map<String, Value>,
    planes: &Planes,
) -> Result<(), ErrorBody> {
    let Some(name) = object.get("name").and_then(Value::as_str) else {
        return Ok(());
    };
    if is_operation(name) || name == ops::TOOL_WITHDRAW {
        return Ok(());
    }
    let pin = match object.get("schema_pin") {
        None => None,
        Some(Value::String(value)) => Some(
            SchemaPin::parse(value)
                .map_err(|error| errors::invalid_request("schema_pin", error.to_string()))?,
        ),
        Some(_) => {
            return Err(errors::invalid_request(
                "schema_pin",
                "expected a canonical pin string",
            ))
        }
    };
    if pin.as_ref().is_some_and(|pin| pin.tool != name) {
        return Err(errors::invalid_request(
            "schema_pin",
            "pin names another tool",
        ));
    }
    if pin.is_none() && !matches!(name, flat_tools::BROWSER_USE | flat_tools::COMPUTER_USE) {
        return Ok(());
    }
    let tool = catalog_tools(planes)
        .into_iter()
        .find(|tool| tool.name == name);
    let Some(tool) = tool else {
        return Err(
            if matches!(name, flat_tools::BROWSER_USE | flat_tools::COMPUTER_USE) {
                errors::tool_disabled(name)
            } else {
                errors::unknown_tool(name)
            },
        );
    };
    if let Some(pin) = pin {
        let (code, expected, current) = if pin.schema_digest != tool.schema_digest {
            (
                "tool_schema_changed",
                json!(pin.schema_digest),
                json!(tool.schema_digest),
            )
        } else if pin.semantics != tool.semantics {
            (
                "tool_semantics_changed",
                json!(pin.semantics),
                json!(tool.semantics),
            )
        } else {
            return Ok(());
        };
        return Err(
            ErrorBody::new(code, "the tool no longer honors this schema pin")
                .with_detail(json!({"tool":name,"expected":expected,"current":current})),
        );
    }
    Ok(())
}

pub(crate) async fn send_error(
    error: ErrorBody,
    (ver, channel, epoch, corr): (u8, u16, u32, u64),
    writer: &mpsc::Sender<Frame>,
) -> Result<(), ModuleError> {
    let out = Frame::build_with_version(
        ver,
        FrameType::Error,
        control_flags(),
        channel,
        epoch,
        corr,
        serde_json::to_vec(&error).map_err(ModuleError::Json)?,
    )
    .map_err(|error| ModuleError::Message(error.to_string()))?;
    send(writer, out).await
}

pub(crate) async fn serve(
    object: &Map<String, Value>,
    (ver, channel, epoch, corr): (u8, u16, u32, u64),
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    let Some(facts) = planes.routes.get(channel, epoch) else {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "route_not_bound",
            "provider operations require an accepted tool route",
        )
        .await;
    };
    // Reading a late result is not acting in a conversation. Requiring current
    // session authority here would strand results after a scope ends.
    if !matches!(
        facts.principal,
        Some(subc_protocol::Principal::Direct | subc_protocol::Principal::Reserved { .. })
    ) {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "principal_denied",
            "provider operations require a verified principal",
        )
        .await;
    }
    if let Some(field) = object.keys().find(|field| {
        !matches!(
            field.as_str(),
            "name" | "arguments" | "progress_token" | "tool_call_id"
        )
    }) {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            field,
            "unknown_field",
        )
        .await;
    }
    let Some(Value::Object(arguments)) = object.get("arguments") else {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "arguments",
            "wrong_type",
        )
        .await;
    };
    let name = object["name"]
        .as_str()
        .expect("operation name checked by dispatcher");
    let principal = journal::call_records::principal_label(facts.principal.as_ref());
    let result: Result<Value, ErrorBody> = match name {
        ops::ROLE_DESCRIBE => {
            if let Some(field) = arguments.keys().next() {
                Err(errors::invalid_request(
                    field,
                    "role.describe takes no arguments",
                ))
            } else {
                Ok(serde_json::to_value(RoleDescribe {
                    majors: vec![Major {
                        version: PROVIDES.into(),
                        ops: vec![
                            ops::ROLE_DESCRIBE.into(),
                            ops::TOOL_CATALOG.into(),
                            ops::TOOL_WITHDRAW.into(),
                            ops::LATE_RESULTS.into(),
                            ops::LATE_RESULTS_ACK.into(),
                        ],
                        stability: "alpha".into(),
                    }],
                    implementation_version: env!("CARGO_PKG_VERSION").into(),
                    capabilities: Vec::new(),
                })
                .expect("role description serializes"))
            }
        }
        ops::TOOL_CATALOG => catalog(arguments, planes),
        ops::LATE_RESULTS | ops::LATE_RESULTS_ACK => {
            let allowed = if name == ops::LATE_RESULTS {
                &["since", "limit"][..]
            } else {
                &["through"][..]
            };
            if let Some(field) = arguments
                .keys()
                .find(|field| !allowed.contains(&field.as_str()))
            {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    &format!("arguments.{field}"),
                    "unknown_field",
                )
                .await;
            }
            let calls = Arc::clone(&planes.calls);
            if name == ops::LATE_RESULTS {
                let request = match serde_json::from_value::<LateResultsRequest>(Value::Object(
                    arguments.clone(),
                )) {
                    Ok(request) if arguments.contains_key("since") => request,
                    _ => {
                        return send_invalid_request_response(
                            writer,
                            ver,
                            channel,
                            epoch,
                            corr,
                            "arguments",
                            "wrong_type",
                        )
                        .await
                    }
                };
                tokio::task::spawn_blocking(move || {
                    calls
                        .late_results(&principal, &request, wall_clock_ms())
                        .map(|reply| {
                            serde_json::to_value(reply).expect("published reply serializes")
                        })
                })
                .await
                .map_err(|error| ModuleError::Message(error.to_string()))?
            } else {
                let request =
                    match serde_json::from_value::<AckRequest>(Value::Object(arguments.clone())) {
                        Ok(request) => request,
                        Err(_) => {
                            return send_invalid_request_response(
                                writer,
                                ver,
                                channel,
                                epoch,
                                corr,
                                "arguments.through",
                                "wrong_type",
                            )
                            .await
                        }
                    };
                tokio::task::spawn_blocking(move || {
                    calls
                        .ack_late_results(&principal, &request, wall_clock_ms())
                        .map(|()| json!({}))
                })
                .await
                .map_err(|error| ModuleError::Message(error.to_string()))?
            }
        }
        _ => unreachable!("provider operation checked"),
    };
    match result {
        Ok(result) => send_tool_response(writer, ver, channel, epoch, corr, result).await,
        Err(error) => {
            let out = Frame::build_with_version(
                ver,
                FrameType::Error,
                control_flags(),
                channel,
                epoch,
                corr,
                serde_json::to_vec(&error).map_err(ModuleError::Json)?,
            )
            .map_err(|error| ModuleError::Message(error.to_string()))?;
            send(writer, out).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_preserves_flat_definition_bytes() {
        let browser_names = browser_tools()
            .into_iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>();
        let computer_names = cerebellum_computer::audit::ComputerCapability::ALL
            .into_iter()
            .map(|capability| capability.capability_id().to_string())
            .filter(|name| crate::computer_capability::servable(name).is_some())
            .collect::<Vec<_>>();
        let flat = [
            flat_tools::computer_tool(&computer_names).unwrap(),
            flat_tools::browser_tool(&browser_names).unwrap(),
        ];
        for (definition, flat) in definitions(&browser_names, &computer_names)
            .iter()
            .zip(flat)
        {
            assert_eq!(definition.name.as_bytes(), flat.name.as_bytes());
            assert_eq!(
                definition.description.as_ref().unwrap().as_bytes(),
                flat.description.as_ref().unwrap().as_bytes()
            );
            assert_eq!(
                serde_json::to_vec(&definition.input_schema).unwrap(),
                serde_json::to_vec(&flat.schema).unwrap()
            );
            // Freeze the entire model-visible definition separately from the
            // shared builder, so editing both advertisement paths cannot hide drift.
            let bytes = serde_json::to_vec(&json!({"name":definition.name,"description":definition.description,"input_schema":definition.input_schema})).unwrap();
            let frozen = match definition.name.as_str() {
                "browser_use" => "54dda58db3986210189226f18c9aaa9ba132c1ad54268cd384b3a8f12dfe782e",
                "computer_use" => {
                    "70c988de06bdcd72c67c2fbc2966c8ae2d6e6e791b9cf518acc9d695dd77dade"
                }
                _ => unreachable!("only the two flat model tools are served"),
            };
            assert_eq!(
                manifest::sha256_hex(&bytes),
                frozen,
                "{} model-visible bytes changed",
                definition.name
            );
        }
    }

    #[test]
    fn computer_catalog_carries_exact_capability_tags() {
        let names = vec!["computer.wait".to_string()];
        let tools = definitions(&[], &names);
        assert_eq!(tools.len(), 1);
        assert_eq!(
            tools[0].capabilities,
            ["computer.use/v1", "cerebellum:computer.use/v1"]
        );
    }
}
