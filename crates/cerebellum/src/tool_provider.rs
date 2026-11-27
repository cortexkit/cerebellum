//! Provider operations use the tool route but are not model tools. Catalogs
//! share HELLO's flat definitions; pulls read only the verified custodian's log.

use crate::*;
use cortexkit_role_tool_provider::call::SchemaPin;
use cortexkit_role_tool_provider::catalog::{
    composition_digest, schema_digest, session_capabilities, CatalogAnswer, CatalogRequest,
    CatalogTool, Reply,
};
use cortexkit_role_tool_provider::describe::{Major, RoleDescribe};
use cortexkit_role_tool_provider::late_results::{AckRequest, LateResultsRequest};
use cortexkit_role_tool_provider::ops;
use cortexkit_role_tool_provider::result::ResultFormat;
use cortexkit_role_tool_provider::{check_capability_tag, errors, PROVIDES};
use serde_json::Map;
use subc_protocol::call_mode::CallMode;

mod views;

pub(crate) fn view_replies() -> Vec<(String, Vec<u8>)> {
    views::published_replies()
}

pub(crate) fn is_operation(name: &str) -> bool {
    matches!(
        name,
        ops::ROLE_DESCRIBE
            | ops::TOOL_CATALOG
            | ops::TOOL_VIEWS
            | ops::LATE_RESULTS
            | ops::LATE_RESULTS_ACK
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
    let browser_names = if planes.browser_admitted() {
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
        (
            flat_tools::computer_tool(computer_names),
            "computer.use/v1",
            budgets::COMPUTER_REPLY_MAX_MS,
        ),
        (
            flat_tools::browser_tool(browser_names),
            "browser.use/v1",
            budgets::BROWSER_REPLY_MAX_MS,
        ),
    ]
    .into_iter()
    .filter_map(|(tool, tag, max_ms)| {
        let tool = tool?;
        let tags = vec![tag.to_string(), format!("cerebellum:{tag}")];
        for tag in &tags {
            check_capability_tag(tag).expect("provider capability tag is valid");
        }
        // The bound ends at terminal-frame delivery or connection failure,
        // not at enqueueing the reply on the connection's output channel.
        let mut definition = CatalogTool::new(
            tool.name,
            schema_digest(&tool.schema).expect("flat schema canonicalizes structurally"),
            1,
            tool.schema,
        )
        .with_capabilities(tags)
        .with_reply(Reply::new(max_ms));
        definition.modes = Some(vec![CallMode::Classic, CallMode::Codemode, CallMode::Flow]);
        definition.result_format = Some(ResultFormat::ToolResultV1);
        cortexkit_role_tool_provider::catalog::check_modes(&definition)
            .expect("only known, unique call modes are declared");
        definition.description = tool.description;
        Some(definition)
    })
    .collect()
}

pub(crate) fn check_call_mode(
    name: &str,
    mode: &CallMode,
    planes: &Planes,
) -> Result<(), ErrorBody> {
    if is_operation(name) || name == ops::TOOL_WITHDRAW {
        return Ok(());
    }
    // Legacy capability names use the same mode policy as the flat tools that
    // dispatch them. Keeping one policy prevents bypassing it through an alias.
    let tool = catalog_tools(planes)
        .into_iter()
        .find(|tool| tool.name == name)
        .unwrap_or_else(|| {
            let mut tool = CatalogTool::new(name, "", 1, json!({}));
            tool.modes = Some(vec![CallMode::Classic, CallMode::Codemode, CallMode::Flow]);
            tool
        });
    if !cortexkit_role_tool_provider::catalog::serves_call_mode(&tool, mode) {
        return Err(ErrorBody::new(
            errors::CALL_MODE_UNSUPPORTED,
            "this tool does not serve the route's call mode",
        )
        .with_detail(json!({"tool": name, "mode": mode})));
    }
    Ok(())
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

/// A role op's refusal of a malformed request, sent as an `ERROR` frame as the
/// tool-provider contract requires of every refusal. A caller decodes a
/// `RESPONSE` body as the op's answer, so a refusal sent that way reads as a
/// broken answer.
fn malformed(field: &str, reason_code: &str) -> ErrorBody {
    errors::invalid_request(field, format!("{field}: {reason_code}"))
        .with_detail(json!({"field": field, "reason_code": reason_code}))
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
            "name" | "arguments" | "preset" | "progress_token" | "tool_call_id"
        )
    }) {
        return send_error(
            malformed(field, "unknown_field"),
            (ver, channel, epoch, corr),
            writer,
        )
        .await;
    }
    // This provider serves no presets. A non-null preset is refused by name,
    // as on tool calls, rather than served as if it were absent.
    if let Some(preset) = object.get("preset").filter(|value| !value.is_null()) {
        return send_error(
            errors::invalid_request("preset", "this provider serves no presets").with_detail(
                json!({"field": "preset", "reason_code": "unsupported_value", "value": preset}),
            ),
            (ver, channel, epoch, corr),
            writer,
        )
        .await;
    }
    let Some(Value::Object(arguments)) = object.get("arguments") else {
        return send_error(
            malformed("arguments", "wrong_type"),
            (ver, channel, epoch, corr),
            writer,
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
                Ok(serde_json::to_value(
                    RoleDescribe::new(
                        vec![Major {
                            version: PROVIDES.into(),
                            ops: vec![
                                ops::ROLE_DESCRIBE.into(),
                                ops::TOOL_CATALOG.into(),
                                ops::TOOL_VIEWS.into(),
                                ops::TOOL_WITHDRAW.into(),
                                ops::LATE_RESULTS.into(),
                                ops::LATE_RESULTS_ACK.into(),
                            ],
                            stability: "alpha".into(),
                        }],
                        env!("CARGO_PKG_VERSION"),
                    )
                    .with_capabilities(vec![
                        cortexkit_role_tool_provider::TOOL_VIEWS_CAPABILITY.into(),
                    ]),
                )
                .expect("role description serializes"))
            }
        }
        ops::TOOL_CATALOG => catalog(arguments, planes),
        ops::TOOL_VIEWS => views::answer(arguments),
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
                return send_error(
                    malformed(&format!("arguments.{field}"), "unknown_field"),
                    (ver, channel, epoch, corr),
                    writer,
                )
                .await;
            }
            let calls = Arc::clone(&planes.calls);
            if name == ops::LATE_RESULTS {
                let reads_content = cortexkit_role_tool_provider::consumer_reads_tool_result_v1(
                    facts.consumer_capabilities(),
                );
                let request = match serde_json::from_value::<LateResultsRequest>(Value::Object(
                    arguments.clone(),
                )) {
                    Ok(request) if arguments.contains_key("since") => request,
                    _ => {
                        return send_error(
                            malformed("arguments", "wrong_type"),
                            (ver, channel, epoch, corr),
                            writer,
                        )
                        .await
                    }
                };
                let mut reply = tokio::task::spawn_blocking(move || {
                    calls.late_results(&principal, &request, wall_clock_ms())
                })
                .await
                .map_err(|error| ModuleError::Message(error.to_string()))?;
                // Wrap results in tool-result/v1 only for readers that declare it.
                // Store outcome/origin unchanged so legacy pulls and replays
                // can still receive their original JSON.
                if reads_content {
                    if let Ok(reply) = &mut reply {
                        for entry in &mut reply.entries {
                            if let Some(result) = entry.result.take() {
                                entry.result = Some(
                                    serde_json::from_slice(&crate::tool_result::encode(result)?)
                                        .map_err(ModuleError::Json)?,
                                );
                            }
                        }
                    }
                }
                reply.map(|reply| serde_json::to_value(reply).expect("published reply serializes"))
            } else {
                let request =
                    match serde_json::from_value::<AckRequest>(Value::Object(arguments.clone())) {
                        Ok(request) => request,
                        Err(_) => {
                            return send_error(
                                malformed("arguments.through", "wrong_type"),
                                (ver, channel, epoch, corr),
                                writer,
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
        Ok(result) => {
            // A resumed browser reply stays in the bounded memory cache until
            // late_results.ack names it: the consumer may lose this response
            // and pull the same cursor again.
            send_tool_response(writer, ver, channel, epoch, corr, result).await?;
            Ok(())
        }
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
    fn catalog_declares_each_tools_formula_derived_reply_bound() {
        let definitions = definitions(
            &[crate::browser::NAVIGATE.to_owned()],
            &["computer.wait".to_owned()],
        );
        assert_eq!(definitions.len(), 2);
        for tool in definitions {
            cortexkit_role_tool_provider::catalog::check_reply(&tool).unwrap();
            let max_ms = match tool.name.as_str() {
                "computer_use" => budgets::COMPUTER_REPLY_MAX_MS,
                "browser_use" => budgets::BROWSER_REPLY_MAX_MS,
                _ => panic!("unexpected tool: {}", tool.name),
            };
            let mut serialized = serde_json::to_value(&tool).unwrap();
            assert_eq!(serialized["reply"], json!({"max_ms": max_ms}));
            let with_bound = manifest::sha256_hex(&manifest::canonical_json_bytes(&serialized));
            serialized.as_object_mut().unwrap().remove("reply");
            assert_ne!(
                with_bound,
                manifest::sha256_hex(&manifest::canonical_json_bytes(&serialized))
            );
        }
    }

    #[test]
    fn catalog_preserves_flat_definition_bytes() {
        let browser_names = browser_tools()
            .into_iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>();
        for pointer_fronting in [false, true] {
            let computer_names = cerebellum_computer::audit::ComputerCapability::ALL
                .into_iter()
                .map(|capability| capability.capability_id().to_string())
                .filter(|name| crate::computer_capability::servable(name).is_some())
                .filter(|name| pointer_fronting || name != "computer.takeover_click")
                .filter(|name| {
                    !pointer_fronting
                        || (name != "computer.takeover_click" && name != "computer.takeover_drag")
                })
                .collect::<Vec<_>>();
            let pointer_fronting = flat_tools::pointer_fronting_definition(&computer_names);
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
                    "browser_use" => {
                        "1f33b4c3d9a05107374be1cadc3454099d72b9140d5de831cd77eb66759dce01"
                    }
                    "computer_use" if !pointer_fronting => {
                        "76491f4fde457660f1697f85a3eddc3df244b6008c3ed0751afb2dad8da28b11"
                    }
                    "computer_use" => {
                        "47f88551fdc964b610ed6f2d197ac454381d2df0dcae57ff343818765c906e70"
                    }
                    _ => unreachable!("only the two flat model tools are served"),
                };
                assert_eq!(
                    manifest::sha256_hex(&bytes),
                    frozen,
                    "{} model-visible bytes changed",
                    definition.name
                );

                let pin = SchemaPin::new(
                    &definition.name,
                    &definition.schema_digest,
                    definition.semantics,
                )
                .encode()
                .unwrap();
                let view =
                    views::answer(json!({"pins":[pin.clone()]}).as_object().unwrap()).unwrap();
                assert_ne!(
                    view["views"][&pin], "unknown",
                    "the frozen definition must have a published view"
                );
            }
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
