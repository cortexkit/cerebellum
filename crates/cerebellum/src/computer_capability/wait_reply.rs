use cerebellum_computer::dispatch::post_condition::PostCondition;
use cerebellum_computer::dispatch::WaitEvidence;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux", test))]
use cerebellum_computer::dispatch::{WaitOutcome, WaitResult};
use serde_json::{json, Value};

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux", test))]
pub(super) fn wait_wire_reply(result: WaitResult) -> Value {
    let outcome = match result.outcome {
        WaitOutcome::Settled => "predicate_satisfied",
        WaitOutcome::TimedOut => "timeout",
        WaitOutcome::Indeterminate => "indeterminate",
        WaitOutcome::Cancelled => "cancelled",
    };
    json!({
        "outcome": outcome,
        // Count the reads actually attempted for this predicate.
        "attempts": result.attempts,
        "evidence": serde_json::to_string(&result.evidence)
            .expect("the closed wait evidence type serializes"),
        "settle_path": "poll_with_deadline",
    })
}

pub(super) fn wait_indeterminate_reply(predicate: Option<PostCondition>, reason: Value) -> Value {
    let evidence = match predicate {
        Some(predicate) => serde_json::to_string(&WaitEvidence::Indeterminate {
            predicate,
            readback: None,
            reason: reason.to_string(),
        })
        .expect("the closed wait evidence type serializes"),
        None => json!({
            "status": "indeterminate",
            "predicate": null,
            "readback": null,
            "reason": reason,
        })
        .to_string(),
    };
    json!({
        "outcome": "indeterminate",
        "evidence": evidence,
        "settle_path": "poll_with_deadline",
    })
}

/// A wait cancelled during consent uses the polled `cancelled` outcome with no reads.
pub(super) fn cancelled_before_polling_reply(predicate: PostCondition) -> Value {
    let evidence = WaitEvidence::Indeterminate {
        predicate,
        readback: None,
        reason: "cancelled_while_awaiting_consent".to_string(),
    };
    json!({
        "outcome": "cancelled", "attempts": 0,
        "evidence": serde_json::to_string(&evidence)
            .expect("the closed wait evidence type serializes"),
        "settle_path": "poll_with_deadline",
    })
}
