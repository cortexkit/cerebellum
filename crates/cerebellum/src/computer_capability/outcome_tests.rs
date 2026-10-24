//! Exercise reply builders through the same withholding boundary used by serving.

use super::*;
use cerebellum_computer::audit::redaction::ExcludeApplicationText;
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::capture_custody::{
    CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
};
use cerebellum_computer::dispatch::IdleGateRefusal;
use cerebellum_computer::platform::{
    AccessibilityKeyForm, IdleUnreadable, ProcessEventRefusal, SemanticActionIntent,
    SemanticActionPlatform, SessionProvenanceRefusal, TargetDisposition, TargetResolution,
    UnreadableReason,
};
use cerebellum_core::journal::{InMemoryJournalStorage, JournalConfig};
use std::collections::BTreeSet;

// These literals are independent of both the artifact and the reply builders.
const COMMON_OUTCOMES: &[&str] = &[
    "invalid_request",
    "semantic_action_unsupported",
    "element_name_ambiguous",
    "element_not_found",
    "action_not_advertised",
    "application_refused",
    "accessibility_permission_unavailable",
    "target_no_longer_current",
    "semantic_dispatch_transient",
    "semantic_path_unavailable",
    "session_not_console",
    "window_visibility_unknown",
    "synthetic_unavailable",
    "cancelled",
    "held_state_unknown",
    "dispatch_failed",
    "envelope_unrecognized",
    "unsupported_mode",
    "observer_unavailable",
    "seize_latency_bound_exceeded",
    "idle_unreadable",
    "not_idle",
    "user_seized_control",
    "attendance_unavailable",
    "fronting_failed",
    "fronting_bound_exceeded",
    "restore_failed",
    "target_focus_mismatch",
    "grounding_untrusted",
    "stale_element",
    "stale_grounding",
    "grant_identity_mismatch",
    "identity_verification_unavailable",
    "observation_primitive_unavailable",
    "background_unsupported_target",
    "platform_error",
    "audit_unavailable",
    "consent_pending",
    "consent_denied",
    "consent_granted_not_executed",
    "consent_unavailable",
    "module_draining",
    "queue_wait_expired",
    "route_closed",
    "not_running",
    "ambiguous",
    "targets_unreadable",
    "secure_field_refused",
    "keystrokes_need_foreground",
    "screen_locked",
    "not_servable",
    "delivery_unconfirmed",
    "refused",
    "private_input_auth_failed",
    "ambiguous_app",
    "no_running_app_named",
    "state_changed_by_person",
    "permission_missing",
    "action_deadline_exceeded",
    "dispatch_outcome_unknown",
    "target_busy",
    "blocking_capacity_exhausted",
    "config_invalid",
    "not_fronted",
];

const BOUNDED_OUTCOMES: &[&str] = &[
    "action_deadline_exceeded",
    "dispatch_outcome_unknown",
    "target_busy",
    "blocking_capacity_exhausted",
];

fn bounded_call_replies() -> Vec<Value> {
    let mut replies = Vec::new();
    for step in [
        "admission",
        "queue",
        "consent",
        "preflight",
        "dispatch",
        "release",
    ] {
        replies.push(json!({
            "outcome":"action_deadline_exceeded",
            "detail":{"dispatched":false,"step":step},
        }));
        for reason in [
            "action_deadline_exceeded",
            "cancelled",
            "route_closed",
            "module_draining",
        ] {
            for held_state in ["none_held", "released", "unknown"] {
                replies.push(json!({
                    "outcome":"dispatch_outcome_unknown",
                    "effect_status":"effect_indeterminate",
                    "detail":{"reason":reason,"dispatched":true,"step":step,
                        "call":"Input.dispatchKeyEvent","held_state":held_state},
                    "remedy":"read the state before retrying",
                }));
            }
        }
        replies.push(json!({
            "outcome":"target_busy",
            "detail":{"reason":"held_input_unconfirmed","dispatched":false,
                "step":step,"call":"computer.keys","held_state":"unknown"},
            "remedy":"held input could not be confirmed released; the next input action retries the release first",
        }));
        replies.push(json!({
            "outcome":"target_busy",
            "detail":{"dispatched":false,"step":step,"call":"stuck action"},
            "remedy":"retry later or check the app",
        }));
        replies.push(json!({
            "outcome":"blocking_capacity_exhausted",
            "detail":{"dispatched":false,"step":step,"call":"target resolution"},
        }));
    }
    replies
}

fn dispatch_refusals() -> Vec<DispatchError> {
    use DispatchError::*;
    vec![
        InvalidRequest,
        SemanticActionUnsupported {
            intent: SemanticActionIntent::Cancel,
            platform: SemanticActionPlatform::Windows,
        },
        ElementNameAmbiguous {
            key_form: AccessibilityKeyForm::Identifier,
            match_count: 2,
        },
        ElementNotFound {
            key_form: AccessibilityKeyForm::Identifier,
        },
        ActionNotAdvertised {
            action: "AXPress".into(),
            advertised: vec![],
        },
        ApplicationRefused { ax_error: -1 },
        AccessibilityPermissionUnavailable,
        TargetNoLongerCurrent {
            disposition: TargetDisposition::Gone,
        },
        SemanticDispatchTransient { deadline_ms: 1 },
        SemanticPathUnavailable,
        SessionNotInspectable {
            session: SessionProvenanceRefusal::OtherSession {
                session_id: 0,
                console_session_id: 1,
            },
        },
        WindowVisibilityUnknown { pid: 42 },
        SyntheticUnavailable,
        Cancelled {
            posts_returned: 2,
            held_state: HeldStateDisposition::NoneHeld,
        },
        SyntheticSequenceFailed {
            posts_returned: 1,
            refusal: ProcessEventRefusal::ProcessGone,
            held_state: HeldStateDisposition::Unknown,
        },
        SyntheticSequenceFailed {
            posts_returned: 1,
            refusal: ProcessEventRefusal::ProcessGone,
            held_state: HeldStateDisposition::NoneHeld,
        },
        EnvelopeUnrecognized,
        UnsupportedMode,
        ObserverUnavailable,
        SeizeLatencyBoundExceeded,
        IdleGateRefused(IdleGateRefusal::Unreadable(
            IdleUnreadable::TableUnavailable,
        )),
        IdleGateRefused(IdleGateRefusal::BelowThreshold {
            threshold_ms: 100,
            hid_idle_ms: 0,
            user_idle_ms: 0,
        }),
        UserSeizedControl {
            sourced_input_kind: None,
        },
        AttendanceUnavailable,
        FrontingFailed,
        FrontingBoundExceeded,
        FrontingRestoreFailed,
        TargetFocusMismatch,
        GroundingUntrusted,
        StaleElement,
        StaleGrounding,
        GrantIdentityMismatch,
        IdentityVerificationUnavailable,
        EffectObservationUnavailable,
        BackgroundUnsupportedTarget,
        Platform,
        AuditUnavailable,
    ]
}

struct FixedResolution(TargetResolution);
impl crate::management::TargetResolver for FixedResolution {
    fn resolve(&self, _: &str) -> TargetResolution {
        self.0.clone()
    }
}

fn replies(capability: ComputerCapability) -> Vec<Value> {
    let mut replies: Vec<_> = dispatch_refusals()
        .iter()
        .map(keystrokes::dispatch_refusal_reply)
        .collect();
    for refusal in [
        ConsentRefusal::Pending {
            ask_id: "ask-1".into(),
        },
        ConsentRefusal::Denied {
            grant_kind: "app",
            remembered: true,
        },
        ConsentRefusal::GrantedNotExecuted,
        ConsentRefusal::Unavailable {
            reason: "unavailable",
            remedy: "retry",
        },
        ConsentRefusal::Draining,
        ConsentRefusal::RouteClosed,
        ConsentRefusal::Cancelled,
        ConsentRefusal::QueueWaitExpired,
    ] {
        replies.push(AppRefusal::Consent(refusal).reply("com.example.Editor"));
    }
    for resolution in [
        TargetResolution::NotRunning,
        TargetResolution::Ambiguous(vec![]),
        TargetResolution::Unreadable(UnreadableReason::WindowListUnavailable),
    ] {
        let management =
            crate::management::ManagementPlane::new(Arc::new(FixedResolution(resolution)));
        replies.push(
            management
                .resolve_process("com.example.Editor")
                .unwrap_err(),
        );
    }
    replies.extend([
        keystrokes::refused_before_posting(permissions::refusal(capability, &Default::default()).unwrap()),
        parse_synthetic_request(capability, &json!({})).unwrap_err(),
        keystrokes::FocusRefusal::Secure.reply(),
        keystrokes::FocusRefusal::Unreadable.reply(),
        keystrokes::needs_foreground_reply(),
        keystrokes::refused_before_posting(element_actions::state_changed_by_person_reply(
            "Editor",
            cerebellum_computer::app_state::person::PersonChange::InputSeen,
        )),
        screen_locked_reply(),
        synthetic_success_reply("pid_structural", false, "effect_indeterminate", None),
        synthetic_wire_envelope(json!({})),
        // These inline serving replies have no separate builder. The private-input
        // refusal is reserved for the platform authentication path as well.
        json!({"outcome": "not_servable", "remedy": "this capability has no dispatch row; report it"}),
        json!({"outcome": "private_input_auth_failed"}),
        // The config-file refusal and the fronting refusal have no builder
        // yet, so these stand in for them until they do.
        json!({"outcome": "config_invalid",
            "remedy": "fix ~/.config/cortexkit/cerebellum.jsonc: computer_use.app_use must be \"background\" or \"foreground\""}),
        json!({"outcome": "not_fronted", "remedy": "wait, then retry",
            "fronting": {"mode": "foreground", "fronted": false, "purpose": "foreground_mode",
                "restore": "not_needed", "not_fronted_reason": "person_active"}}),
    ]);
    // A target given by name that matches nobody, and one that matches two
    // different applications.
    let editor = |bundle_identity: &str, pid| RunningApp {
        name: "Editor".into(),
        bundle_identity: bundle_identity.into(),
        pid,
        frontmost: false,
    };
    replies.push(match_target_name("Nobody", &[editor("com.example.Editor", 1)]).unwrap_err());
    replies.push(
        match_target_name(
            "Editor",
            &[
                editor("com.example.Editor", 1),
                editor("org.example.Editor", 2),
            ],
        )
        .unwrap_err(),
    );
    match capability {
        ComputerCapability::Type => {
            replies.push(json!({"outcome": "completed", "effect_status": "effect_observed"}));
            // The diff an accepted keystroke carries, as text.
            let mut typed = json!({"outcome": "completed", "effect_status": "effect_observed"});
            element_actions::add_diff(&mut typed, None);
            replies.push(typed);
        }
        ComputerCapability::Keys => replies.extend([
            chord_blocked_refusal("command+option+escape", "session_ending"),
            json!({"outcome": "modifier_chord_needs_foreground"}),
        ]),
        _ => unreachable!(),
    }
    replies
}

fn check_outcomes(capability: ComputerCapability, additional: &[&str]) {
    let custody = CaptureCustody::new(
        CustodyBounds {
            maximum_verification_duration_ms: 100,
            maximum_pin_lifetime_ms: 100,
            maximum_concurrently_pinned_artifacts: 2,
            maximum_total_pinned_artifact_bytes: 1000,
            maximum_custody_attachment_bytes: 1000,
        },
        InMemoryGrantAuthority::default(),
        InMemoryCustodyStorage::new(),
    )
    .unwrap();
    let audit = ComputerAudit::new(
        ExcludeApplicationText,
        cerebellum_computer::platform::severity::load_severity_taxonomy().unwrap(),
        JournalConfig {
            journal_retention_bytes: 20000,
            journal_max_entry_bytes: 4000,
        },
        InMemoryJournalStorage::default(),
        custody,
    )
    .unwrap();
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> =
        ComputerPlane::with_result_schema_enforcement(audit, ResultSchemaEnforcement::Withhold);
    let synthetic = matches!(
        capability,
        ComputerCapability::Type | ComputerCapability::Keys
    );
    let expected: BTreeSet<_> = if synthetic {
        COMMON_OUTCOMES
    } else {
        BOUNDED_OUTCOMES
    }
    .iter()
    .chain(additional)
    .copied()
    .collect();
    let mut observed = BTreeSet::new();
    let mut cases = if synthetic {
        replies(capability)
    } else {
        Vec::new()
    };
    cases.extend(bounded_call_replies());
    for reply in cases {
        let detail = reply.get("detail").cloned();
        let bounded = BOUNDED_OUTCOMES.contains(&reply["outcome"].as_str().unwrap_or(""));
        let reply = if synthetic {
            synthetic_wire_envelope(reply)
        } else {
            reply
        };
        if bounded {
            assert_eq!(
                reply.get("detail"),
                detail.as_ref(),
                "bounded evidence was lost"
            );
        }
        let outcome = reply["outcome"].as_str().unwrap().to_owned();
        assert!(
            expected.contains(outcome.as_str()),
            "unlisted builder outcome: {outcome}"
        );
        let served = plane
            .finish_reply(capability, reply.clone())
            .unwrap_or_else(|error| {
                panic!(
                    "{} {outcome} was withheld: {error}",
                    capability.capability_id()
                )
            });
        assert_eq!(served, reply);
        observed.insert(outcome);
    }
    assert_eq!(observed, expected.iter().map(|s| (*s).to_owned()).collect());
    assert!(plane.result_schema_findings().is_empty());
    let vocabulary: Value = serde_json::from_slice(
        cerebellum_computer::platform::vocabulary::COMPUTER_ACTION_VOCABULARY_ARTIFACT,
    )
    .unwrap();
    let row = vocabulary["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["capability_id"] == capability.capability_id())
        .unwrap();
    let declared: BTreeSet<_> = row["result_schema"]["properties"]["outcome"]["enum"]
        .as_array()
        .expect("outcome is a closed enum")
        .iter()
        .map(|word| word.as_str().unwrap())
        .collect();
    if synthetic {
        assert_eq!(declared, expected);
    } else {
        assert!(
            expected.is_subset(&declared),
            "{} omits bounded outcomes",
            capability.capability_id()
        );
    }
    let properties = &row["result_schema"]["properties"];
    assert_eq!(
        properties["detail"]["properties"]["step"]["enum"],
        json!([
            "admission",
            "queue",
            "consent",
            "preflight",
            "dispatch",
            "release",
        ])
    );
    assert_eq!(
        properties["detail"]["properties"]["held_state"]["enum"],
        json!(["none_held", "released", "unknown"])
    );
    assert_eq!(
        properties["detail"]["properties"]["dispatched"]["type"],
        "boolean"
    );
    assert_eq!(properties["detail"]["properties"]["call"]["type"], "string");
    assert_eq!(
        properties["effect_status"]["enum"],
        if synthetic {
            json!([
                "effect_observed",
                "no_effect_observed",
                "effect_indeterminate",
                "not_dispatched"
            ])
        } else {
            json!([
                "effect_observed",
                "no_effect_observed",
                "effect_indeterminate"
            ])
        }
    );
    assert_eq!(
        row["result_schema"]["properties"]["detail"]["properties"]["reason"]["type"],
        "string"
    );
    assert!(
        row["result_schema"]["properties"]["detail"]["properties"]["reason"]
            .get("enum")
            .is_none()
    );
    for reason in [
        "input_seen",
        "window_list_unavailable",
        "legacy_free_form_reason",
    ] {
        let mut legacy = json!({"outcome":"invalid_request", "detail":{"reason":reason}});
        if synthetic {
            legacy = synthetic_wire_envelope(legacy);
            legacy["detail"] = json!({"reason":reason});
        }
        assert_eq!(
            plane.finish_reply(capability, legacy.clone()).unwrap(),
            legacy
        );
    }
    for status in [
        "effect_observed",
        "no_effect_observed",
        "effect_indeterminate",
    ] {
        let mut reply = json!({"outcome":"action_deadline_exceeded", "effect_status":status,
            "detail":{"dispatched":false,"step":"preflight"}});
        if synthetic {
            reply = synthetic_wire_envelope(reply);
        }
        assert_eq!(
            plane.finish_reply(capability, reply.clone()).unwrap(),
            reply
        );
    }
    for (field, invalid) in [
        ("dispatched", json!("false")),
        ("step", json!("settle")),
        ("step", json!("egress")),
        ("call", json!(true)),
        ("held_state", json!("held")),
        ("reason", json!(false)),
    ] {
        let mut malformed = json!({"outcome":"dispatch_outcome_unknown", "effect_status":"effect_indeterminate", "detail":{}});
        if synthetic {
            malformed = synthetic_wire_envelope(malformed);
        }
        malformed["detail"][field] = invalid;
        assert!(
            plane.finish_reply(capability, malformed).is_err(),
            "{} accepted invalid {field}",
            capability.capability_id()
        );
    }
    let unlisted = json!({"outcome": "unlisted_outcome"});
    let unlisted = if synthetic {
        synthetic_wire_envelope(unlisted)
    } else {
        unlisted
    };
    assert!(plane.finish_reply(capability, unlisted).is_err());
}

#[test]
fn every_computer_capability_accepts_bounded_call_shapes() {
    for capability in ComputerCapability::ALL {
        if !matches!(
            capability,
            ComputerCapability::Type | ComputerCapability::Keys
        ) {
            check_outcomes(capability, &[]);
        }
    }
}

#[test]
fn every_type_outcome_survives_withholding() {
    check_outcomes(ComputerCapability::Type, &["completed"]);
}

#[test]
fn every_keys_outcome_survives_withholding() {
    check_outcomes(
        ComputerCapability::Keys,
        &["chord_blocked", "modifier_chord_needs_foreground"],
    );
}

/// Every reply shape the inventories above build with the production
/// builders, as a tool-result/v1 reader would show it to a model: some plain
/// text, and no JSON object or array anywhere in that text. The frame-loop
/// test in `model_view_tests` covers the replies only a live call produces.
#[test]
fn every_inventoried_reply_reads_as_plain_words() {
    let mut shapes = bounded_call_replies();
    shapes.extend(replies(ComputerCapability::Type));
    shapes.extend(replies(ComputerCapability::Keys));
    let mut failures = Vec::new();
    for reply in shapes {
        let encoded: Value =
            serde_json::from_slice(&crate::tool_result::encode(reply.clone()).unwrap()).unwrap();
        let problems = crate::tool_result::model_view_problems(&encoded);
        if !problems.is_empty() {
            failures.push(format!("{reply}: {problems:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
