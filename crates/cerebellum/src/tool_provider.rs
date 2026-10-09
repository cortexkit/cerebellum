//! Provider operations use the tool route but are not model tools. Pulls read
//! only the verified carrier's log, even after its original scope has ended.

use crate::*;
use cortexkit_role_tool_provider::late_results::{AckRequest, LateResultsRequest};
use cortexkit_role_tool_provider::ops;
use serde_json::Map;

pub(crate) fn is_operation(name: &str) -> bool {
    matches!(name, ops::LATE_RESULTS | ops::LATE_RESULTS_ACK)
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
    if let Some(field) = object
        .keys()
        .find(|field| !matches!(field.as_str(), "name" | "arguments" | "progress_token"))
    {
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
