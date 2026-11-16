//! A filtered wait repeats complete reads, never cached snapshot text.

use serde_json::{json, Value};
use std::{future::Future, time::Duration};
use tokio::time::Instant;

pub(crate) const MATCH_FIELD: &str = "_filter_matched";
const WAIT_LINE_BYTES: usize = "wait: timed_out\n".len();

pub(crate) fn text_budget(args: &Value, max_bytes: usize) -> usize {
    if args.get("wait_for_ms").is_some() {
        max_bytes.saturating_sub(WAIT_LINE_BYTES)
    } else {
        max_bytes
    }
}

fn finished(mut reply: Value, matched: bool, max_bytes: Option<usize>) -> Value {
    let status = if matched { "matched" } else { "timed_out" };
    reply["wait"] = json!(status);
    if let Some(text) = reply["state_text"].as_str() {
        let mut text = format!("wait: {status}\n{text}");
        // Very small caps cannot fit even the wait line. Its structured
        // status remains complete, just like the snapshot's cut counters.
        if let Some(max_bytes) = max_bytes {
            while text.len() > max_bytes {
                text.pop();
            }
        }
        reply["state_text"] = json!(text);
    }
    reply
}

pub(crate) fn validate(args: &Value, action: &str) -> Result<Option<u64>, super::BrowserError> {
    let Some(value) = args.get("wait_for_ms") else {
        return Ok(None);
    };
    let invalid = |reason_code| super::BrowserError::InvalidRequest {
        field: "wait_for_ms".into(),
        reason_code,
    };
    if action != "snapshot"
        || (args.get("text_filter").is_none() && args.get("role_filter").is_none())
    {
        return Err(invalid("unsupported_value"));
    }
    let ms = value.as_u64().ok_or_else(|| invalid("wrong_type"))?;
    if !(1..=10_000).contains(&ms) {
        return Err(invalid("out_of_range"));
    }
    Ok(Some(ms))
}

/// The caller keeps its normal cancellation and deadline around this loop.
pub(crate) async fn read<E, F, Fut>(
    wait_ms: Option<u64>,
    max_bytes: Option<usize>,
    mut read: F,
) -> Result<Value, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Value, E>>,
{
    let end = Instant::now() + Duration::from_millis(wait_ms.unwrap_or(0));
    let end = crate::call_context::CALL_DEADLINE
        .try_with(|deadline| end.min(*deadline))
        .unwrap_or(end);
    loop {
        let mut reply = read().await?;
        let matched =
            reply.as_object_mut().and_then(|o| o.remove(MATCH_FIELD)) == Some(json!(true));
        if wait_ms.is_none() {
            return Ok(reply);
        }
        if reply["outcome"] != "ok" {
            return Ok(reply);
        }
        if matched || Instant::now() >= end {
            return Ok(finished(reply, matched, max_bytes));
        }
        tokio::time::sleep_until(end.min(Instant::now() + Duration::from_millis(250))).await;
        if Instant::now() >= end {
            return Ok(finished(reply, false, max_bytes));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_for_ms_requires_filtered_snapshot_and_bounded_integer() {
        for args in [
            json!({"wait_for_ms":1}),
            json!({"wait_for_ms":0,"text_filter":"a"}),
            json!({"wait_for_ms":10001,"role_filter":["button"]}),
            json!({"wait_for_ms":1.5,"text_filter":"a"}),
        ] {
            assert!(validate(&args, "snapshot").is_err(), "{args}");
        }
        let args = json!({"wait_for_ms":10000,"role_filter":["button"]});
        assert!(validate(&args, "navigate").is_err());
        assert_eq!(validate(&args, "snapshot").unwrap(), Some(10000));
    }

    #[tokio::test(start_paused = true)]
    async fn scripted_reads_match_or_time_out_without_real_sleeps() {
        for after in [Some(3), None] {
            let mut calls = 0;
            let start = Instant::now();
            let reply = read(Some(600), None, || {
                calls += 1;
                std::future::ready(Ok::<_, ()>(
                    json!({"outcome":"ok", "state_text":"Page", MATCH_FIELD: after == Some(calls)}),
                ))
            })
            .await
            .unwrap();
            let expected = if after.is_some() {
                "matched"
            } else {
                "timed_out"
            };
            assert_eq!(reply["wait"], expected, "{reply}");
            assert!(reply["state_text"]
                .as_str()
                .unwrap()
                .starts_with(&format!("wait: {expected}\n")));
            assert!(reply.get(MATCH_FIELD).is_none());
            assert_eq!(calls, 3);
            assert_eq!(
                Instant::now() - start,
                Duration::from_millis(if after.is_some() { 500 } else { 600 })
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn reread_refusal_stops_waiting_and_outer_deadline_cancels_polling() {
        let mut calls = 0;
        let reply = read(Some(10000), None, || {
            calls += 1;
            std::future::ready(Ok::<_, ()>(if calls == 1 {
                json!({"outcome":"ok"})
            } else {
                json!({"outcome":"authorization_denied"})
            }))
        })
        .await
        .unwrap();
        assert_eq!(reply["outcome"], "authorization_denied");
        assert_eq!(calls, 2);
        let result = tokio::time::timeout(
            Duration::from_millis(300),
            read(Some(10000), None, || {
                std::future::ready(Ok::<_, ()>(json!({"outcome":"ok"})))
            }),
        )
        .await;
        assert!(result.is_err());
    }
}
