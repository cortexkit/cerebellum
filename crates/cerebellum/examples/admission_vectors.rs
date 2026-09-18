//! Mint the admission-contract test vectors from the served decoder.
//!
//! A consumer stamping bind facts needs to know what this module accepts and
//! what it refuses, by name. Written by hand that would be a statement of
//! belief about our own code, and the belief and the code drift the first time
//! either moves. Every vector here is produced by DRIVING the production
//! validator and recording what came back, so the file cannot describe a
//! module that does not exist.
//!
//! Run: `cargo run -p cerebellum --example admission_vectors`
//!
//! The output is JSON on stdout, intended to be committed by the consumer as a
//! fixture and re-minted whenever this module's contract moves.

use cerebellum::profile::{stamped_bind_context, BindFacts, BindValidationError};
use serde_json::{json, Value};

/// The shape a correct stamp produces. Every refusal vector is this with one
/// fact broken, so a reader can see exactly which field carries which refusal.
fn accepted_facts() -> BindFacts {
    BindFacts {
        principal: "direct:agent".to_string(),
        conversation_key: "conv-01HQ8ZK3M4N5P6Q7R8S9T0".to_string(),
        agent_project_id: "pj-9f2b1c7d4e8a".to_string(),
        session_kind: Some("primary".to_string()),
        session_kind_attested: true,
        profile_disposition: Some("durable".to_string()),
        effective_capability_scope: Some(vec![
            "browser.launch".to_string(),
            "browser.navigate".to_string(),
            "browser_use".to_string(),
            "computer_use".to_string(),
        ]),
        provenance: "daemon_attested_spec_a".to_string(),
    }
}

fn facts_json(facts: &BindFacts) -> Value {
    json!({
        "principal": facts.principal,
        "conversation_key": facts.conversation_key,
        "agent_project_id": facts.agent_project_id,
        "session_kind": facts.session_kind,
        "session_kind_attested": facts.session_kind_attested,
        "profile_disposition": facts.profile_disposition,
        "effective_capability_scope": facts.effective_capability_scope,
        "provenance": facts.provenance,
    })
}

/// Drive the real validator and record its answer.
fn vector(name: &str, why: &str, facts: BindFacts) -> Value {
    let observed = stamped_bind_context(facts.clone());
    let result = match &observed {
        Ok(context) => json!({
            "admitted": true,
            "profile_disposition": format!("{:?}", context.profile_disposition()),
        }),
        Err(error) => json!({
            "admitted": false,
            "refusal": refusal_name(error),
            "message": error.to_string(),
        }),
    };
    json!({ "name": name, "why": why, "facts": facts_json(&facts), "expect": result })
}

/// The refusal's stable name, matched exhaustively so a variant added later
/// fails to compile here rather than minting a vector set that silently omits
/// it. A consumer reading this file would otherwise believe the taxonomy is
/// complete because nothing said it was not.
fn refusal_name(error: &BindValidationError) -> String {
    match error {
        BindValidationError::MissingFact(name) => format!("missing_fact:{name}"),
        BindValidationError::EmptyFact(name) => format!("empty_fact:{name}"),
        BindValidationError::MissingAttestation(name) => format!("missing_attestation:{name}"),
        BindValidationError::InvalidProvenance => "invalid_provenance".to_string(),
        BindValidationError::UnknownSessionKind => "unknown_session_kind".to_string(),
        BindValidationError::UnknownDisposition => "unknown_disposition".to_string(),
        BindValidationError::IncompatibleKindDisposition => {
            "incompatible_kind_disposition".to_string()
        }
        BindValidationError::InvalidScope => "invalid_scope".to_string(),
    }
}

fn main() {
    let mut vectors = vec![vector(
        "accept_primary_durable",
        "A fully stamped primary session receives the durable profile that holds its logins.",
        accepted_facts(),
    )];

    for (kind, disposition, why) in [
        (
            "subagent",
            "disposable",
            "A subagent gets an isolated profile torn down with the task.",
        ),
        (
            "ephemeral",
            "none",
            "An ephemeral seat gets no profile at all.",
        ),
    ] {
        vectors.push(vector(
            &format!("accept_{kind}_{disposition}"),
            why,
            BindFacts {
                session_kind: Some(kind.to_string()),
                profile_disposition: Some(disposition.to_string()),
                ..accepted_facts()
            },
        ));
    }

    // The refusal this contract exists for. A defaulted `primary` is PRESENT and
    // still unattested, and admitting it would hand an unauthenticated bind the
    // durable profile holding a human's live logins.
    vectors.push(vector(
        "refuse_unattested_kind_for_durable",
        "session_kind is present but nobody attested it; a durable profile must not be issued on a default.",
        BindFacts {
            session_kind_attested: false,
            ..accepted_facts()
        },
    ));

    vectors.push(vector(
        "refuse_undaemon_stamped_provenance",
        "Facts a consumer assembled rather than the daemon stamping them.",
        BindFacts {
            provenance: "compatibility_derived".to_string(),
            ..accepted_facts()
        },
    ));

    for field in ["principal", "conversation_key", "agent_project_id"] {
        let mut facts = accepted_facts();
        match field {
            "principal" => facts.principal = String::new(),
            "conversation_key" => facts.conversation_key = String::new(),
            _ => facts.agent_project_id = String::new(),
        }
        vectors.push(vector(
            &format!("refuse_empty_{field}"),
            "A present-but-empty fact is refused by name rather than treated as absent.",
            facts,
        ));
    }

    vectors.push(vector(
        "refuse_unknown_session_kind",
        "A kind outside the closed vocabulary, rather than being coerced to the nearest one.",
        BindFacts {
            session_kind: Some("supervisor".to_string()),
            ..accepted_facts()
        },
    ));

    vectors.push(vector(
        "refuse_unknown_disposition",
        "A disposition outside the closed vocabulary.",
        BindFacts {
            profile_disposition: Some("shared".to_string()),
            ..accepted_facts()
        },
    ));

    vectors.push(vector(
        "refuse_incompatible_kind_disposition",
        "A subagent asking for the durable profile: each kind may hold only its own disposition.",
        BindFacts {
            session_kind: Some("subagent".to_string()),
            profile_disposition: Some("durable".to_string()),
            ..accepted_facts()
        },
    ));

    let document = json!({
        "contract": "ck-cerebellum-admission-facts/v1",
        "minted_from": "cerebellum::profile::stamped_bind_context",
        "not_covered": "BindValidationError::MissingFact has no vector here: BindFacts makes \
                        principal, conversation_key and agent_project_id required Strings, so \
                        absence cannot be expressed at this entry point -- only emptiness. That \
                        refusal is raised upstream where wire JSON becomes BindFacts. A consumer \
                        omitting a fact entirely will receive it, and this file cannot show it.",
        "note": "Produced by driving the production validator. Re-mint with \
                 `cargo run -p cerebellum --example admission_vectors` rather than \
                 editing: a hand-edited vector describes a belief about this module \
                 instead of the module.",
        "vectors": vectors,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("vectors serialize")
    );
}
