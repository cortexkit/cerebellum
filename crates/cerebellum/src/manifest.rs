//! Capability manifest for ck-cerebellum.
//!
//! Spec A advertises exactly one application capability, `browser.status`, with
//! `execution_mode: pure`. Standard wire-v2 health, discovery, and control
//! surfaces (route.bind, route.status, health.check) are NOT application
//! capabilities — they are advertised in the HELLO `control_ops` grant, not in
//! the manifest's `provides` list.

use serde_json::{json, Value};

pub mod connector_evidence {
    pub use crate::connector_evidence::*;
}
pub mod custody {
    pub use crate::custody::*;
}

pub use connector_evidence::{
    admission_proof_is_current, connector_evidence_eligibility, verify_connector_evidence,
    ConnectorEvidence, ConnectorTestPlan, EvidenceCaseResult, EvidenceEligibility,
    EvidenceSelection, TestPlanCase, REQUIREMENTS as CONNECTOR_REQUIREMENTS,
};
pub use custody::{
    arguments_are_quarantinable, canonical_json_bytes, sha256_file, sha256_hex,
    verify_registration, verify_registration_in_profile_directory, verify_registration_path,
    ConnectorAdmissionProof, CustodyArtifact, CustodyArtifactError, LaunchError, LaunchQuarantine,
    LaunchStage, QuarantineMechanism, RegistrationError, RegistrationObservation, SpawnObservation,
};

use crate::browser_type::{
    browser_type_registration_eligible, EvidenceEligibilityInput,
    BROWSER_EVIDENCE_ELIGIBILITY_SHA256, BROWSER_TYPE_TOOL,
};
use crate::journal::JournalConfig;
use subc_protocol::manifest::CapabilityDeclarations;
use subc_protocol::manifest::{
    BuildGitShaAbsenceReason, Concurrency, ExecutionMode, IdentityScope, ManagementOperation,
    ManagementOperationKind, ModuleManifest, ProviderRole, Tool,
};
use subc_protocol::manifest::{
    ManifestProvenance, SelfSignalDeclaration, SelfSignalEffect, SelfSignalKind, SignalAnchor,
    SignalCadence,
};

/// The single application capability this module advertises.
pub const BROWSER_STATUS: &str = "browser.status";

pub fn browser_wire_tools() -> Vec<Tool> {
    crate::browser::tool_definitions()
        .into_iter()
        .filter(|(name, _, _)| crate::browser::has_wire_dispatch_route(name))
        .map(|(name, description, schema)| Tool {
            name: name.to_string(),
            description: Some(description.to_string()),
            execution_mode: if name == crate::browser::SNAPSHOT {
                ExecutionMode::Pure
            } else {
                ExecutionMode::Unfenceable
            },
            schema,
        })
        .collect()
}

pub fn browser_control_tools() -> Vec<Tool> {
    use crate::browser_session::{BROWSER_CLOSE, BROWSER_LAUNCH};
    vec![
        Tool {
            name: BROWSER_LAUNCH.to_string(),
            description: Some("Launch the route-owned browser session.".to_string()),
            execution_mode: ExecutionMode::Unfenceable,
            schema: json!({"type":"object","properties":{},"additionalProperties":false}),
        },
        Tool {
            name: BROWSER_STATUS.to_string(),
            description: Some("Report the route-owned browser session state.".to_string()),
            execution_mode: ExecutionMode::Pure,
            schema: json!({"type":"object","properties":{},"additionalProperties":false}),
        },
        Tool {
            name: BROWSER_CLOSE.to_string(),
            description: Some("Close and reap the route-owned browser session.".to_string()),
            execution_mode: ExecutionMode::Unfenceable,
            schema: json!({"type":"object","properties":{"browser_session_id":{"type":"string","minLength":1}},"required":["browser_session_id"],"additionalProperties":false}),
        },
    ]
}

/// Build the browser-free cerebellum capability manifest.
///
/// The default manifest declares exactly one `ToolProvider` role with the
/// browser.status tool (`execution_mode: pure`). Minted browser routes are added
/// only by `build_with_browser_plane_pins` after their independent release gates
/// pass; this builder never adds the legacy type route.
/// The management operations this module serves.
///
/// Built from the same names the dispatcher matches on, so an operation cannot
/// be advertised without being routable: the list and the routing read one
/// constant rather than two that agree until someone edits one.
///
/// Separate from the tool surface because the two differ in kind, not only in
/// envelope. A tool call acts; a management operation arranges the authority
/// under which acting is possible. Keeping them apart also means an operation
/// never appears in a tool listing, so an agent enumerating its capabilities
/// does not find one it could mistake for an action.
fn management_surface() -> ProviderRole {
    ProviderRole::ManagementSurface {
        // subc may deliver management calls concurrently across channels while
        // preserving FIFO submission within each; this module then schedules
        // them itself. That is what it already does -- the wire loop reads
        // frames in order and spawns each request, and the ordering this
        // module genuinely needs (one dispatch at a time per browser context)
        // is enforced internally by its own lane rather than by subc.
        // Serial would understate what the module can accept and needlessly
        // serialise unrelated conversations; StatelessParallel would overstate
        // it by claiming no ordering matters, which is false for that lane.
        concurrency: Concurrency::ModuleManaged,
        operations: [
            (
                crate::management::OPEN_TARGET,
                "Ask the person for access to an application, so computer actions \
                 can name it as a target. Returns once the request is pending; \
                 access begins only if they agree.",
            ),
            (
                crate::management::OPEN_GRANT,
                "Ask the person to authorise browser actions on an origin, \
                 disclosing the hazards the page carries. Returns once the \
                 request is pending; the grant exists only if they agree.",
            ),
            (
                crate::management::REBIND_PROFILE_ROOT,
                "Ask the person to re-identify a moved or restored browser profile root. \
                 Refuses rather than adopts any profile directory the registry did not mint.",
            ),
        ]
        .into_iter()
        .map(|(name, description)| ManagementOperation {
            name: name.to_string(),
            // These operations return before a person answers. They report the
            // pending request and arrange authority without performing the
            // browser or computer action the authority may later admit.
            kind: ManagementOperationKind::Query,
            // These are the operations our refusals NAME as the remedy -- a
            // caller told to "mint a covering grant" arrives here to find out
            // what that means. An empty description satisfies the compiler and
            // leaves the remedy pointing at nothing.
            description: Some(description.to_string()),
        })
        .collect(),
        config_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false,
        }),
        observability: Vec::new(),
        identity_scope: vec![IdentityScope::Session, IdentityScope::Project],
    }
}

pub fn build(module_id: &str) -> ModuleManifest {
    build_with_browser_config(module_id, false)
}

/// What this binary can honestly say about where it came from.
///
/// The commit is reported only when the tree was CLEAN at build time. A dirty
/// tree produces bytes that no commit describes, so naming one would attest a
/// commit that does not contain what is running -- worse than saying nothing,
/// because the daemon has no way to tell a precise answer from a wrong one. The
/// same reasoning governs staging, which refuses to publish a dirty artifact.
///
/// `unknown` is the build script's answer when there is no git directory at all
/// -- a source tarball is a legitimate way to build this -- and it is not a
/// commit, so it is reported as absence rather than passed through as a value.
///
/// `wire_crate_version` is the linked crate's own compile-time constant, so it
/// describes the code in THIS binary rather than a manifest sitting beside it.
/// That distinction is why it is filled while `build_lock_digest` is not: a lock
/// digest read here would describe the source tree next to the running binary,
/// which is the claim provenance exists to avoid.
///
/// The block is therefore never absent. Absence on the wire reads as
/// `unverifiable` -- the module made no claim at all -- and this module always
/// has at least one honest fact to state.
fn build_provenance() -> Option<ManifestProvenance> {
    let rev = env!("CEREBELLUM_BUILD_REV");
    let tree = env!("CEREBELLUM_BUILD_TREE");
    let build_git_sha = attestable_commit(rev, tree);
    Some(ManifestProvenance {
        build_git_sha_absence_reason: build_git_sha
            .is_none()
            .then(|| build_git_sha_absence_reason(rev, tree)),
        build_git_sha,
        build_lock_digest: None,
        wire_crate_version: Some(subc_protocol::SUBC_PROTOCOL_CRATE_VERSION.to_string()),
        store_schema_version: None,
    })
}

/// Why no commit is attested, when none is. A reader of an absent sha needs
/// to know whether the build declined to name a commit it had (dirty tree,
/// so the sha would not describe the binary) or never had one (build.rs
/// could not run git); the two are repaired in different places.
fn build_git_sha_absence_reason(rev: &str, tree: &str) -> BuildGitShaAbsenceReason {
    if tree != "clean" && !rev.is_empty() && !is_builder_sentinel(rev) {
        BuildGitShaAbsenceReason::DeclinedDirty
    } else {
        BuildGitShaAbsenceReason::NeverDerived
    }
}

/// Every builder sentinel, in any casing, not just the one our own build.rs
/// happens to emit. Matching only "unknown" would be adequate today and
/// silently inadequate the moment that script changes its stand-in -- and a
/// sentinel published as a fact is the failure this check exists to prevent,
/// because a present well-formed field stops the reader asking.
fn is_builder_sentinel(rev: &str) -> bool {
    const SENTINELS: [&str; 3] = ["unknown", "unavailable", "none"];
    SENTINELS.contains(&rev.to_ascii_lowercase().as_str())
}

/// The commit a binary may attest, given what the build observed.
///
/// Separated from its inputs because those arrive through `env!` and are fixed
/// when this file compiles: a test cannot produce a dirty build without
/// rebuilding, so the rule would be exercised in exactly one configuration --
/// whichever one the developer happened to be in -- and the refusing branch
/// would never run.
fn attestable_commit(rev: &str, tree: &str) -> Option<String> {
    if tree != "clean" || rev.is_empty() || is_builder_sentinel(rev) {
        return None;
    }
    Some(rev.to_string())
}

/// The recurring work this module starts on its own.
///
/// An empty list would be an affirmative claim of none, and it would be false:
/// two timers run without a request behind them, and one of them can end a
/// browser session a caller believes is still open.
///
/// Both cadences are `Derived` rather than `Literal`. Neither interval is a
/// compile-time constant -- each is computed from configuration this operator
/// supplied -- and copying a configured value in as a literal would state a
/// number that a different `cerebellum.jsonc` makes wrong.
fn self_signals() -> Vec<SelfSignalDeclaration> {
    vec![
        SelfSignalDeclaration {
            name: "dispatch_heartbeat_restamp".to_string(),
            kind: SelfSignalKind::Heartbeat,
            // Observe: it re-stamps an atomic so an idle module does not read as
            // degraded. Nothing outside this process changes.
            effect: SelfSignalEffect::Observe,
            anchored_to: SignalAnchor::FixedInterval,
            cadence: Some(SignalCadence::Derived {
                source: "half of health.dispatch_heartbeat_stale_ms".to_string(),
            }),
            // No external surface: the effect is confined to this process's own
            // health reading, so naming a domain would invent a reach it has not.
            domain: None,
            note: Some(
                "Re-stamps the dispatch heartbeat on a bounded idle wake so an \
                 idle module does not report degraded. It wakes only the input \
                 wait, so a wedged handler still ages into degraded."
                    .to_string(),
            ),
        },
        SelfSignalDeclaration {
            name: "browser_session_idle_sweep".to_string(),
            kind: SelfSignalKind::Sweep,
            // Mutate, and the honest label: this observes browser exits and
            // expires idle sessions, which tears a browser down and writes its
            // profile to disk. Declaring it Observe because it usually finds
            // nothing would describe the common case rather than the authority.
            effect: SelfSignalEffect::Mutate,
            anchored_to: SignalAnchor::FixedInterval,
            cadence: Some(SignalCadence::Derived {
                source: "minimum of browser.browser_idle_timeout_ms, \
                         browser.browser_exit_observation_deadline_ms, and 50ms"
                    .to_string(),
            }),
            domain: Some("browser-session".to_string()),
            note: Some(
                "Observes browser process exits and expires idle sessions. \
                 Expiry runs the full graceful teardown, so a browser is asked \
                 to close and flush its profile before any force-kill. Present \
                 only when a browser is configured."
                    .to_string(),
            ),
        },
    ]
}

pub fn build_with_browser_config(module_id: &str, browser_configured: bool) -> ModuleManifest {
    // Built through the builder rather than a struct literal: the manifest is
    // `#[non_exhaustive]` upstream precisely so a field added there does not
    // break every module's construction site at once. `protocol_ver` and
    // `consumes` are left to their defaults -- the linked protocol version and
    // an empty list are exactly what this module would have written.
    // No trust tier and no bindings: the daemon reads neither on any
    // production path (subc-protocol 0.19, the manifest diet), so declaring
    // `first_party` and a sqlite/project binding was this module saying
    // things about itself that nothing consumed -- including a storage kind
    // it does not open. Absence is the honest form; an old daemon that still
    // decodes them treats absence as it treated the fabricated values.
    ModuleManifest::builder(module_id.to_string(), env!("CARGO_PKG_VERSION").to_string())
        .provenance(build_provenance())
        .self_signals(Some(self_signals()))
        .provides(vec![
            ProviderRole::ToolProvider {
                tools: if browser_configured {
                    browser_control_tools()
                } else {
                    Vec::new()
                },
                identity_scope: vec![IdentityScope::Session, IdentityScope::Project],
                concurrency: Concurrency::ModuleManaged,
                emits_push: false,
                sub_supervises: false,
            },
            management_surface(),
        ])
        // One negative claim, and nothing else yet.
        //
        // `must_never_reach` fences THIS MODULE AS CALLER: the daemon refuses
        // any route we open toward a provider of the named capability, and
        // force-closes live ones if a matching provider appears later. It is
        // not a claim that nothing may be handed to us -- receipt rides routes
        // the sender opens, so the inbound half of the credential boundary is
        // not expressible here and remains an agreement with the vault module.
        //
        // We declare it because this module must never pull a secret. It holds
        // live browser sessions and durable per-agent profiles, so a path from
        // here into a secret store is the one route whose absence is worth
        // enforcing rather than remembering.
        //
        // Costs nothing today and is not expected to: the vault's sealing
        // surface, which durable profiles are designed to consult, is a
        // SEPARATE capability that does not exist yet. Enforcement is
        // module-granular though, so when sealing lands it will need one of an
        // op-scoped deny, a distinct provider module, or a visible relaxation
        // of this line -- a decision that design pass owns explicitly rather
        // than discovering.
        //
        // `provides` stays empty because it is capability-grammar naming, a
        // different axis from the provider roles above, and this module's
        // capabilities have no grammar names cut yet. Empty claims nothing; it
        // does not claim we provide nothing.
        .capabilities(Some(CapabilityDeclarations {
            provides: Vec::new(),
            requires: Vec::new(),
            must_never_reach: vec!["credentials-provider/v1".to_string()],
        }))
        .build()
}

/// Compose only the browser routes the wire dispatcher admits.
/// A common pin failure suppresses every minted route; an extraction failure
/// suppresses the routes that consume accessibility or DOM data (snapshot and
/// click), leaving navigation available.
pub fn build_with_browser_plane_pins(
    module_id: &str,
    pins: Option<&ManifestPinSet>,
    common_artifacts_eligible: bool,
    extraction_evidence_eligible: bool,
) -> ModuleManifest {
    let mut manifest = build_with_browser_config(module_id, true);
    let Some(pins) = pins else {
        return manifest;
    };
    if pins.validate().is_err() || !common_artifacts_eligible {
        return manifest;
    }
    let ProviderRole::ToolProvider { tools, .. } = &mut manifest.provides[0] else {
        return manifest;
    };
    for (name, description, schema) in crate::browser::tool_definitions()
        .into_iter()
        .filter(|(name, _, _)| crate::browser::has_wire_dispatch_route(name))
    {
        let requires_extraction = matches!(name, crate::browser::SNAPSHOT | crate::browser::CLICK);
        if requires_extraction
            && (!pins.extraction_group_eligible() || !extraction_evidence_eligible)
        {
            continue;
        }
        tools.push(Tool {
            name: name.to_string(),
            description: Some(description.to_string()),
            execution_mode: if matches!(
                name,
                crate::browser::NAVIGATE | crate::browser::CLICK | crate::browser::CLICK_POINT
            ) {
                ExecutionMode::Unfenceable
            } else {
                ExecutionMode::Pure
            },
            schema,
        });
    }
    manifest
}

/// Serialize the standard manifest and its single top-level browser-plane
/// extension for HELLO/release tooling. The external SUBC manifest type used by
/// status-only builds predates extensions, so composition is explicit here.
pub fn serialize_with_browser_plane_pins(
    module_id: &str,
    pins: Option<&ManifestPinSet>,
    common_artifacts_eligible: bool,
    extraction_evidence_eligible: bool,
) -> Value {
    let manifest = build_with_browser_plane_pins(
        module_id,
        pins,
        common_artifacts_eligible,
        extraction_evidence_eligible,
    );
    let mut value = serde_json::to_value(manifest).expect("module manifest serializes");
    if let Some(pins) = pins {
        if common_artifacts_eligible && pins.validate().is_ok() {
            let mut pin_value = serde_json::to_value(pins).expect("pins serialize");
            if !pins
                .browser_type_evidence_eligibility_sha256
                .as_deref()
                .is_some_and(custody::valid_digest)
            {
                pin_value
                    .as_object_mut()
                    .expect("pins are an object")
                    .remove("browser_type_evidence_eligibility_sha256");
            }
            value
                .as_object_mut()
                .expect("manifest is an object")
                .insert("browser_plane_pins".into(), pin_value);
        }
    }
    value
}

/// Evidence that the immutable B1 revision or contract-bundle vendors the B2A
/// journal pin exactly (`b1_journal_pin_compatibility_gate`).
///
/// A tokenless trait, a B1 revision that defines `journal_entry_oversize` as a
/// direct `reserve` result, or an implementation that invokes any journal
/// transition after a failed marked attempt is incompatible and keeps the
/// affected capability unadvertised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct B1PinCompatibility {
    /// The pinned immutable B1 revision or contract-bundle digest.
    pub revision_or_digest: String,
    /// Whether conformance proved every pin rule: invocation-bound reservation
    /// handles and commitment tokens, the exact `reserve` result set,
    /// post-reservation-only `journal_entry_oversize`, no invocation-side
    /// journal transition after a failed marked attempt (recovery-exclusive
    /// retry/cancellation), and matching-token `finalize_dispatched`.
    pub conformance_passed: bool,
}

/// The external manifest-bound inputs required to advertise one unfenceable
/// capability.
///
/// Each input is absent until bound at release time. Absence gates
/// advertisement (the capability stays unadvertised) but never blocks slice
/// implementation, and is reported distinctly from an implementation failure.
#[derive(Debug, Clone, Default)]
pub struct UnfenceableReleaseInputs {
    /// The browser evidence eligibility digests (manifest value, source lock,
    /// computed artifact).
    pub evidence: Option<EvidenceEligibilityInput>,
    /// The immutable B1 revision or contract-bundle digest satisfying the
    /// journal-pin compatibility gate.
    pub b1_pin: Option<B1PinCompatibility>,
    /// The positive journal deployment bounds.
    pub journal_bounds: Option<JournalConfig>,
    /// The computed maximum request-entry size for the capability
    /// (`computed_max_entry_bytes`).
    pub computed_max_entry_bytes: Option<u64>,
}

/// The outcome of evaluating one release gate.
///
/// A missing external input and an implementation failure are DIFFERENT facts
/// and never collapse into one outcome: the former means the gate could not be
/// evaluated because its external dependency is not bound; the latter means the
/// inputs were present but the implementation could not satisfy the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    /// The gate passed.
    Pass,
    /// A required external manifest-bound input is absent or incompatible.
    MissingInput { gate: &'static str },
    /// An implementation check ran against present inputs and failed.
    ImplementationFailure { gate: &'static str },
}

/// The B2A release report: the outcome of every gate evaluated for a surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseReport {
    pub outcomes: Vec<GateOutcome>,
}

impl ReleaseReport {
    /// Whether every gate passed (the surface may be advertised).
    pub fn passed(&self) -> bool {
        self.outcomes.iter().all(|o| matches!(o, GateOutcome::Pass))
    }

    /// The gates suppressed by a missing external input.
    pub fn missing_inputs(&self) -> Vec<&'static str> {
        self.outcomes
            .iter()
            .filter_map(|o| match o {
                GateOutcome::MissingInput { gate } => Some(*gate),
                _ => None,
            })
            .collect()
    }

    /// The gates suppressed by an implementation failure.
    pub fn implementation_failures(&self) -> Vec<&'static str> {
        self.outcomes
            .iter()
            .filter_map(|o| match o {
                GateOutcome::ImplementationFailure { gate } => Some(*gate),
                _ => None,
            })
            .collect()
    }
}

/// Evaluate every B2A release gate applicable to an unfenceable capability.
///
/// The browser evidence eligibility digest is ONE gate among several; it alone
/// never authorizes advertisement. Each gate reports a missing external input
/// distinctly from an implementation failure.
pub fn evaluate_unfenceable_gates(inputs: &UnfenceableReleaseInputs) -> ReleaseReport {
    let mut outcomes = Vec::new();

    // Gate: browser evidence eligibility (manifest value, source lock, computed
    // artifact all agree).
    outcomes.push(match &inputs.evidence {
        None => GateOutcome::MissingInput {
            gate: "browser_evidence",
        },
        Some(evidence) => {
            if browser_type_registration_eligible(evidence) {
                GateOutcome::Pass
            } else {
                GateOutcome::ImplementationFailure {
                    gate: "browser_evidence",
                }
            }
        }
    });

    // Gate: immutable B1 journal-pin compatibility.
    outcomes.push(match &inputs.b1_pin {
        None => GateOutcome::MissingInput {
            gate: "b1_journal_pin",
        },
        Some(pin) if !pin.revision_or_digest.is_empty() && pin.conformance_passed => {
            GateOutcome::Pass
        }
        Some(_) => GateOutcome::ImplementationFailure {
            gate: "b1_journal_pin",
        },
    });

    // Gate: positive, ordered journal deployment bounds.
    outcomes.push(match &inputs.journal_bounds {
        None => GateOutcome::MissingInput {
            gate: "journal_bounds",
        },
        Some(bounds) => {
            if bounds.validate().is_ok() {
                GateOutcome::Pass
            } else {
                GateOutcome::ImplementationFailure {
                    gate: "journal_bounds",
                }
            }
        }
    });

    // Gate: serialization fit (computed_max_entry_bytes <= journal_max_entry_bytes).
    outcomes.push(
        match (&inputs.computed_max_entry_bytes, &inputs.journal_bounds) {
            (Some(max), Some(bounds)) => {
                if *max <= bounds.journal_max_entry_bytes {
                    GateOutcome::Pass
                } else {
                    GateOutcome::ImplementationFailure {
                        gate: "serialization_fit",
                    }
                }
            }
            _ => GateOutcome::MissingInput {
                gate: "serialization_fit",
            },
        },
    );

    ReleaseReport { outcomes }
}

/// The evidence-gated manifest for `browser.type`, which production does not
/// build.
///
/// Advertising requires BOTH that the release gates pass AND that the capability
/// can be dispatched. The second condition is not redundant: the gates are
/// satisfied by supplying release evidence, which is a deployment act, while
/// being dispatchable is a property of the code. Without it, supplying evidence
/// alone would advertise a capability that every call to it rejects as an
/// unknown method — and this one accepts typed text, so the caller would be told
/// it has a facility for entering text that does not exist.
///
/// Today `browser.type` has no dispatch route, so this advertises nothing
/// whatever the evidence says. Adding one is what makes the gate live, which is
/// the point at which its evidence requirements have to be met rather than
/// merely defined.
pub fn build_with_unfenceable_evidence(inputs: &UnfenceableReleaseInputs) -> ModuleManifest {
    let mut manifest = build("cerebellum");
    if !evaluate_unfenceable_gates(inputs).passed() {
        return manifest;
    }
    if crate::dispatchable_tool(BROWSER_TYPE_TOOL).is_none() {
        return manifest;
    }
    let ProviderRole::ToolProvider { tools, .. } = &mut manifest.provides[0] else {
        return manifest;
    };
    tools.push(browser_type_tool());
    manifest
}

/// Construct the fixed `browser.type` tool definition that is added to the
/// manifest only after the eligibility checks have passed.
pub fn browser_type_tool() -> Tool {
    Tool {
        name: BROWSER_TYPE_TOOL.to_string(),
        description: Some(
            "Focus an eligible text target, optionally replace its selection, and insert literal text after two snapshot verifications."
                .to_string(),
        ),
        execution_mode: ExecutionMode::Unfenceable,
        schema: json!({
            "type": "object",
            "properties": {
                "ref": {"type": "string"},
                "snapshot_id": {"type": "string"},
                "text": {"type": "string"},
                "replace": {"type": "boolean"},
                "intent": {"type": "string"},
                "severity": {"type": "object"},
            },
            "required": ["ref", "snapshot_id", "text", "intent", "severity"],
            "additionalProperties": false,
        }),
    }
}

/// Return the manifest's immutable eligibility digest without exposing a
/// mutable approval or ambient registration switch.
pub fn browser_evidence_eligibility_sha256() -> &'static str {
    BROWSER_EVIDENCE_ELIGIBILITY_SHA256
}

#[cfg(test)]
mod tests {
    /// A dirty tree names no commit.
    ///
    /// The rule this fences is that a sha is a claim about WHICH BYTES are
    /// running. A dirty build produces bytes no commit contains, so reporting
    /// the checked-out sha would attest a commit that does not describe them --
    /// and a consumer cannot tell a precise answer from a confidently wrong one,
    /// which makes it worse than absence rather than merely imprecise.
    #[test]
    fn a_commit_is_attested_only_when_the_build_tree_was_clean() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            super::attestable_commit(sha, "clean"),
            Some(sha.to_string()),
            "a clean build knows which commit produced it"
        );
        assert_eq!(
            super::attestable_commit(sha, "dirty"),
            None,
            "a dirty build must not name a commit that does not contain its bytes"
        );
        // The build script's answer when there is no git directory. It is not a
        // commit, and passing it through would put the literal string "unknown"
        // in a field a reader parses as a sha.
        assert_eq!(super::attestable_commit("unknown", "clean"), None);
    }

    /// The absence reason names the repair: a dirty tree with a real revision
    /// is a build that DECLINED (rebuild from a clean tree); a sentinel or an
    /// empty revision is one that never had a commit (build.rs could not run
    /// git). A wrong implementation that always says NeverDerived sends the
    /// dirty-tree case to the wrong place.
    #[test]
    fn the_absence_reason_distinguishes_declined_from_never_derived() {
        use subc_protocol::manifest::BuildGitShaAbsenceReason as R;
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            super::build_git_sha_absence_reason(sha, "dirty"),
            R::DeclinedDirty
        );
        assert_eq!(
            super::build_git_sha_absence_reason("unknown", "clean"),
            R::NeverDerived
        );
        assert_eq!(
            super::build_git_sha_absence_reason("unknown", "dirty"),
            R::NeverDerived
        );
        assert_eq!(
            super::build_git_sha_absence_reason("", "dirty"),
            R::NeverDerived
        );
        assert_eq!(super::attestable_commit("", "clean"), None);

        // Every builder sentinel in the fleet contract, in casings a script
        // might emit. Only "unknown" is reachable from our own build.rs today;
        // the others are refused so that changing that stand-in cannot quietly
        // start publishing one as a fact.
        for sentinel in ["unavailable", "none", "UNKNOWN", "Unavailable", "NONE"] {
            assert_eq!(
                super::attestable_commit(sentinel, "clean"),
                None,
                "{sentinel} is a stand-in for a missing commit, not a commit"
            );
        }
    }

    /// The idle sweep declares that it MUTATES.
    ///
    /// It expires idle browser sessions, which tears a browser down and writes
    /// its profile to disk -- a caller's live session ending without a caller
    /// asking. Declaring it Observe would be defensible on frequency, since it
    /// usually finds nothing, and wrong on authority: the declaration states
    /// what the signal MAY do, and an analyst reading it is asking what can
    /// happen without a request behind it.
    ///
    /// Asserted by name rather than over the list, so a second mutating signal
    /// added later cannot satisfy this by standing in for the sweep.
    #[test]
    fn the_browser_idle_sweep_declares_itself_mutating() {
        let signals = super::self_signals();
        let sweep = signals
            .iter()
            .find(|signal| signal.name == "browser_session_idle_sweep")
            .expect("the idle sweep is declared");
        assert_eq!(sweep.effect, SelfSignalEffect::Mutate);
        assert!(
            sweep
                .note
                .as_deref()
                .is_some_and(|note| note.contains("teardown")),
            "the note must say the expiry runs a graceful teardown: {:?}",
            sweep.note
        );

        // The heartbeat is the contrast. Both are periodic and unrequested; only
        // one can end something, and a reader must be able to tell them apart.
        let heartbeat = signals
            .iter()
            .find(|signal| signal.name == "dispatch_heartbeat_restamp")
            .expect("the heartbeat is declared");
        assert_eq!(heartbeat.effect, SelfSignalEffect::Observe);
        assert!(
            heartbeat.domain.is_none(),
            "the heartbeat touches no external surface, so it must name no domain"
        );
    }

    /// The linked crate's version is a compile-time constant of the code in this
    /// binary, so it is knowable honestly here and the block is never absent.
    /// Absence would read as `unverifiable` -- a module that made no claim --
    /// which is untrue of a module that can state this much.
    #[test]
    fn provenance_states_the_wire_crate_version_it_was_built_against() {
        let provenance = super::build_provenance().expect("provenance block is always present");
        assert_eq!(
            provenance.wire_crate_version.as_deref(),
            Some(subc_protocol::SUBC_PROTOCOL_CRATE_VERSION),
            "the reported wire crate version must be the linked crate's own constant"
        );
        assert!(
            provenance.build_lock_digest.is_none(),
            "a lock digest read here would describe the tree beside the binary, not the binary"
        );
    }

    use super::*;

    #[test]
    fn browser_controls_follow_configuration_presence() {
        let absent = build("cerebellum");
        let ProviderRole::ToolProvider { tools, .. } = &absent.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        assert!(tools.is_empty());

        let configured = build_with_browser_config("cerebellum", true);
        let ProviderRole::ToolProvider { tools, .. } = &configured.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            ["browser.launch", "browser.status", "browser.close"]
        );
    }

    /// The management surface advertises only what the dispatcher will serve.
    ///
    /// Both read one constant, so the two cannot drift: an operation added to
    /// this list without a route to serve it would have to be added to the
    /// routing as well, because there is only one name to add.
    ///
    /// The reverse case is what makes it worth asserting. A capability that is
    /// advertised and cannot be served fails at the moment a caller believes it
    /// can be, which is later and further from the change that caused it.
    #[test]
    fn every_advertised_operation_is_one_the_dispatcher_serves() {
        let manifest = build("cerebellum");
        let Some(ProviderRole::ManagementSurface { operations, .. }) = manifest
            .provides
            .iter()
            .find(|role| matches!(role, ProviderRole::ManagementSurface { .. }))
        else {
            panic!("expected a ManagementSurface role");
        };

        let advertised: Vec<&str> = operations
            .iter()
            .map(|operation| operation.name.as_str())
            .collect();
        assert_eq!(
            advertised,
            vec![
                crate::management::OPEN_TARGET,
                crate::management::OPEN_GRANT,
                crate::management::REBIND_PROFILE_ROOT,
            ]
        );
    }

    /// Opening a target is advertised as a query.
    ///
    /// It reports what authority exists and, when none does, arranges for the
    /// user to be asked. Nothing about the machine it names is changed, and the
    /// distinction is not cosmetic: whether a call is a query decides whether
    /// its response body is written to durable storage as it is forwarded.
    #[test]
    fn opening_a_target_is_a_query() {
        let manifest = build("cerebellum");
        let Some(ProviderRole::ManagementSurface { operations, .. }) = manifest
            .provides
            .iter()
            .find(|role| matches!(role, ProviderRole::ManagementSurface { .. }))
        else {
            panic!("expected a ManagementSurface role");
        };
        assert_eq!(operations[0].kind, ManagementOperationKind::Query);
    }

    #[test]
    fn browser_status_is_pure() {
        let manifest = build_with_browser_config("cerebellum", true);
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        let status = tools
            .iter()
            .find(|tool| tool.name == BROWSER_STATUS)
            .unwrap();
        assert_eq!(status.execution_mode, ExecutionMode::Pure);
    }

    #[test]
    fn browser_status_schema_is_closed() {
        let manifest = build_with_browser_config("cerebellum", true);
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        let schema = &tools
            .iter()
            .find(|tool| tool.name == BROWSER_STATUS)
            .unwrap()
            .schema;
        assert_eq!(schema.get("type").and_then(|v| v.as_str()), Some("object"));
        assert_eq!(
            schema.get("additionalProperties").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn manifest_protocol_version_is_v2() {
        let manifest = build("cerebellum");
        assert_eq!(manifest.protocol_ver, 2);
    }

    /// The diet's honest form: this module claims no trust tier and no
    /// bindings, because the daemon reads neither. A test asserting
    /// `first_party` here would be asserting a fabrication.
    #[test]
    fn manifest_declares_no_trust_tier_and_no_bindings() {
        let manifest = build("cerebellum");
        assert_eq!(manifest.trust_tier, None);
        assert!(manifest.bindings.is_none());
    }

    #[test]
    fn manifest_tool_schema_has_no_evidence_approval_member() {
        let manifest = build_with_browser_config("cerebellum", true);
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        assert!(tools.iter().all(|tool| tool
            .schema
            .get("browser_evidence_eligibility_sha256")
            .is_none()));
    }

    fn valid_evidence() -> EvidenceEligibilityInput {
        let digest = crate::browser_type::computed_eligibility_artifact_digest();
        EvidenceEligibilityInput {
            manifest_digest: Some(digest.clone()),
            source_lock_digest: Some(digest.clone()),
            computed_artifact_digest: Some(digest),
            ..EvidenceEligibilityInput::default()
        }
    }

    fn valid_inputs() -> UnfenceableReleaseInputs {
        UnfenceableReleaseInputs {
            evidence: Some(valid_evidence()),
            b1_pin: Some(B1PinCompatibility {
                revision_or_digest: "b1-rev-1".to_string(),
                conformance_passed: true,
            }),
            journal_bounds: Some(JournalConfig {
                journal_retention_bytes: 1_000_000,
                journal_max_entry_bytes: 100_000,
            }),
            computed_max_entry_bytes: Some(100_000),
        }
    }

    fn valid_browser_pins(with_extraction: bool) -> ManifestPinSet {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        ManifestPinSet {
            schema: MANIFEST_PINS_SCHEMA.to_string(),
            spec_a_contract_sha256: digest.clone(),
            spec_b2_contract_bundle_sha256: digest.clone(),
            browser_custody_sha256: digest.clone(),
            browser_address_policy_sha256: digest.clone(),
            browser_connector_evidence_sha256: digest.clone(),
            browser_connector_runner_revision: "runner-v1".to_string(),
            browser_connector_test_plan_sha256: digest.clone(),
            browser_extraction_corpus_sha256: with_extraction.then(|| digest.clone()),
            browser_extraction_evidence_sha256: with_extraction.then(|| digest.clone()),
            browser_extraction_runner_revision: with_extraction.then(|| "extract-v1".to_string()),
            browser_type_evidence_eligibility_sha256: Some("not-a-digest".to_string()),
        }
    }

    #[test]
    fn browser_plane_routes_are_capability_relative_and_type_free() {
        let common_only = build_with_browser_plane_pins(
            "cerebellum",
            Some(&valid_browser_pins(false)),
            true,
            false,
        );
        let ProviderRole::ToolProvider { tools, .. } = &common_only.provides[0] else {
            panic!("expected tool provider");
        };
        // Three controls, navigate, and screenshot. Screenshot needs no
        // extraction evidence because it runs none of the logic that evidence
        // attests: it captures pixels and reads viewport geometry, where
        // snapshot and click turn a page into structured data and address a
        // ref within it. A capture can be wrong about a rectangle; it cannot
        // be wrong about a corpus it never consults.
        assert_eq!(
            tools.len(),
            6,
            "three controls, navigate, the extraction-free capture, and the \
             coordinate click whose mapping is verified against a live browser"
        );
        assert!(!tools.iter().any(|tool| tool.name == BROWSER_TYPE_TOOL));

        let all = build_with_browser_plane_pins(
            "cerebellum",
            Some(&valid_browser_pins(true)),
            true,
            true,
        );
        let ProviderRole::ToolProvider { tools, .. } = &all.provides[0] else {
            panic!("expected tool provider");
        };
        assert_eq!(
            tools.len(),
            8,
            "three controls, navigate, screenshot, snapshot, click, and the \
             coordinate click"
        );
        assert!(!tools.iter().any(|tool| tool.name == BROWSER_TYPE_TOOL));
        let serialized = serialize_with_browser_plane_pins(
            "cerebellum",
            Some(&valid_browser_pins(true)),
            true,
            true,
        );
        assert!(serialized.get("browser_plane_pins").is_some());
        assert!(serialized["provides"]
            .to_string()
            .find("browser_evidence_eligibility_sha256")
            .is_none());
    }

    fn has_browser_type(manifest: &ModuleManifest) -> bool {
        let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
            panic!("expected a ToolProvider role");
        };
        tools.iter().any(|tool| tool.name == BROWSER_TYPE_TOOL)
    }

    #[test]
    fn unfenceable_advertisement_requires_every_gate_to_pass() {
        // Every gate passing ADMITS browser.type, asserted through the gate
        // report. The manifest cannot carry the positive case: advertising also
        // requires a dispatch route, and browser.type has none, so reading the
        // manifest here would find it absent for that reason and hold however
        // the gates behaved.
        assert!(evaluate_unfenceable_gates(&valid_inputs()).passed());

        // Suppressing any single gate withholds admission. Also asserted
        // through the report rather than through the manifest: browser.type is
        // absent from the manifest whatever the gates say, so a manifest
        // assertion here would pass with the gate deleted.
        let mut no_evidence = valid_inputs();
        no_evidence.evidence = None;
        assert!(!evaluate_unfenceable_gates(&no_evidence).passed());

        let mut no_pin = valid_inputs();
        no_pin.b1_pin = None;
        assert!(!evaluate_unfenceable_gates(&no_pin).passed());

        let mut no_bounds = valid_inputs();
        no_bounds.journal_bounds = None;
        assert!(!evaluate_unfenceable_gates(&no_bounds).passed());

        let mut no_fit = valid_inputs();
        no_fit.computed_max_entry_bytes = None;
        assert!(!evaluate_unfenceable_gates(&no_fit).passed());

        // And the manifest carries none of it, on inputs that pass every gate,
        // so this fails when a dispatch route is added rather than silently
        // starting to advertise.
        assert!(!has_browser_type(&build_with_unfenceable_evidence(
            &valid_inputs()
        )));
    }

    #[test]
    fn digest_alone_never_authorizes_advertisement() {
        // The legacy eligibility-digest-only path is superseded: a valid browser
        // evidence artifact with no B1 pin, bounds, or fit input does NOT
        // advertise browser.type.
        let digest_only = UnfenceableReleaseInputs {
            evidence: Some(valid_evidence()),
            ..UnfenceableReleaseInputs::default()
        };
        assert!(!has_browser_type(&build_with_unfenceable_evidence(
            &digest_only
        )));
    }

    #[test]
    fn advertisement_suppressed_when_a_gate_fails() {
        // A present-but-incompatible B1 pin (conformance not proved) suppresses
        // advertisement and is reported as an implementation failure, not a
        // missing input.
        let mut failing_pin = valid_inputs();
        failing_pin.b1_pin = Some(B1PinCompatibility {
            revision_or_digest: "b1-rev-1".to_string(),
            conformance_passed: false,
        });
        assert!(!has_browser_type(&build_with_unfenceable_evidence(
            &failing_pin
        )));
        let report = evaluate_unfenceable_gates(&failing_pin);
        assert_eq!(report.implementation_failures(), vec!["b1_journal_pin"]);
        assert!(report.missing_inputs().is_empty());
    }

    #[test]
    fn release_report_distinguishes_missing_input_from_implementation_failure() {
        let bounds = JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 100_000,
        };

        // Missing external input: the B1 pin is absent.
        let missing = UnfenceableReleaseInputs {
            evidence: Some(valid_evidence()),
            b1_pin: None,
            journal_bounds: Some(bounds),
            computed_max_entry_bytes: Some(100_000),
        };
        let missing_report = evaluate_unfenceable_gates(&missing);
        assert_eq!(missing_report.missing_inputs(), vec!["b1_journal_pin"]);
        assert!(missing_report.implementation_failures().is_empty());

        // Implementation failure: the B1 pin is present but conformance failed.
        let failed = UnfenceableReleaseInputs {
            evidence: Some(valid_evidence()),
            b1_pin: Some(B1PinCompatibility {
                revision_or_digest: "b1-rev-1".to_string(),
                conformance_passed: false,
            }),
            journal_bounds: Some(bounds),
            computed_max_entry_bytes: Some(100_000),
        };
        let failed_report = evaluate_unfenceable_gates(&failed);
        assert_eq!(
            failed_report.implementation_failures(),
            vec!["b1_journal_pin"]
        );
        assert!(failed_report.missing_inputs().is_empty());

        // The two outcomes are distinct variants for the same gate (index 1).
        assert_ne!(
            missing_report.outcomes[1], failed_report.outcomes[1],
            "missing input and implementation failure must be distinct outcomes"
        );
    }
}

// ---------------------------------------------------------------------------
// Browser-plane release pins: values that identify the exact contracts and
// policies used by the browser-facing execution plane.
// ---------------------------------------------------------------------------

/// The closed top-level browser-plane pin object. It is kept separate from
/// tool JSON schemas so release tooling and browser-facing protocol messages
/// serialize and reuse exactly the same pin bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPinSet {
    pub schema: String,
    pub spec_a_contract_sha256: String,
    pub spec_b2_contract_bundle_sha256: String,
    pub browser_custody_sha256: String,
    pub browser_address_policy_sha256: String,
    pub browser_connector_evidence_sha256: String,
    pub browser_connector_runner_revision: String,
    pub browser_connector_test_plan_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_extraction_corpus_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_extraction_evidence_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_extraction_runner_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_type_evidence_eligibility_sha256: Option<String>,
}

pub const MANIFEST_PINS_SCHEMA: &str = "ck-browser-plane-pins/v1";
pub type BrowserPlanePins = ManifestPinSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrozenTypeEvidenceStatus {
    Absent,
    Accepted,
    OmittedMalformed,
    OmittedMismatched,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestPinParseReport {
    pub frozen_type_evidence: FrozenTypeEvidenceStatus,
    pub messages: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedManifestPins {
    pub pins: ManifestPinSet,
    pub report: ManifestPinParseReport,
    pub canonical_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestPinError {
    InvalidJson,
    NonCanonical,
    UnknownField(String),
    MissingField(&'static str),
    InvalidField(&'static str),
}

impl ManifestPinSet {
    pub fn parse(
        bytes: &[u8],
        expected_frozen_type_digest: &str,
    ) -> Result<ParsedManifestPins, ManifestPinError> {
        parse_manifest_pins(bytes, expected_frozen_type_digest)
    }

    pub fn validate(&self) -> Result<(), ManifestPinError> {
        self.validate_common()
    }

    /// Validate fields that gate every minted capability. Extraction pins are
    /// checked separately because snapshot consumers may be suppressed while
    /// navigate, screenshot, click-point, and wait-for remain live.
    pub fn validate_common(&self) -> Result<(), ManifestPinError> {
        if self.schema != MANIFEST_PINS_SCHEMA {
            return Err(ManifestPinError::InvalidField("schema"));
        }
        for (name, value) in [
            ("spec_a_contract_sha256", &self.spec_a_contract_sha256),
            (
                "spec_b2_contract_bundle_sha256",
                &self.spec_b2_contract_bundle_sha256,
            ),
            ("browser_custody_sha256", &self.browser_custody_sha256),
            (
                "browser_address_policy_sha256",
                &self.browser_address_policy_sha256,
            ),
            (
                "browser_connector_evidence_sha256",
                &self.browser_connector_evidence_sha256,
            ),
            (
                "browser_connector_test_plan_sha256",
                &self.browser_connector_test_plan_sha256,
            ),
        ] {
            if !custody::valid_digest(value) {
                return Err(ManifestPinError::InvalidField(name));
            }
        }
        if !(1..=256).contains(&self.browser_connector_runner_revision.len())
            || matches!(
                self.browser_connector_runner_revision
                    .to_ascii_lowercase()
                    .as_str(),
                "placeholder" | "tbd" | "unknown"
            )
        {
            return Err(ManifestPinError::InvalidField(
                "browser_connector_runner_revision",
            ));
        }
        // The legacy type-route digest is optional and non-blocking. Invalid or
        // mismatched candidates are omitted by `parse_manifest_pins`; they never
        // gate a newly minted browser capability.
        Ok(())
    }

    /// Whether the extraction pins are present and usable as a group.
    ///
    /// The three are eligible together or not at all. A partly supplied group is
    /// refused for the same reason an absent one is, which is deliberate: the
    /// pins describe one artifact set, and two of three would gate a capability
    /// on evidence that does not cover it.
    pub fn extraction_group_eligible(&self) -> bool {
        let extraction = [
            self.browser_extraction_corpus_sha256.as_ref(),
            self.browser_extraction_evidence_sha256.as_ref(),
            self.browser_extraction_runner_revision.as_ref(),
        ];
        if extraction.iter().any(Option::is_none) {
            return false;
        }
        let (Some(corpus), Some(evidence), Some(revision)) = (
            self.browser_extraction_corpus_sha256.as_ref(),
            self.browser_extraction_evidence_sha256.as_ref(),
            self.browser_extraction_runner_revision.as_ref(),
        ) else {
            return false;
        };
        custody::valid_digest(corpus)
            && custody::valid_digest(evidence)
            && (1..=256).contains(&revision.len())
            && !matches!(
                revision.to_ascii_lowercase().as_str(),
                "placeholder" | "tbd" | "unknown"
            )
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        custody::canonical_json_bytes(&serde_json::to_value(self).expect("manifest pins serialize"))
    }
}

/// Parse a canonical pin object. The optional pin for the expected frozen
/// browser type is handled differently: if it is invalid or does not match the
/// expected digest, report and remove it instead of blocking a minted action.
///
/// The expected digest is required rather than optional. It was optional, and a
/// caller passing nothing got [`FrozenTypeEvidenceStatus::Accepted`] for any
/// well-formed digest -- a verified-looking answer produced without comparing
/// anything. A caller that does not know the value it expects is exactly the one
/// that must not be told the pin was accepted, and it can pass the digest it
/// believes correct to have that belief checked. Compare
/// [`browser_type::validate_evidence_eligibility`], which refuses outright when
/// a digest is missing.
pub fn parse_manifest_pins(
    bytes: &[u8],
    expected_frozen_type_digest: &str,
) -> Result<ParsedManifestPins, ManifestPinError> {
    let mut value: Value =
        serde_json::from_slice(bytes).map_err(|_| ManifestPinError::InvalidJson)?;
    if custody::canonical_json_bytes(&value) != bytes {
        return Err(ManifestPinError::NonCanonical);
    }
    let object = value.as_object_mut().ok_or(ManifestPinError::InvalidJson)?;
    let allowed = [
        "schema",
        "spec_a_contract_sha256",
        "spec_b2_contract_bundle_sha256",
        "browser_custody_sha256",
        "browser_address_policy_sha256",
        "browser_connector_evidence_sha256",
        "browser_connector_runner_revision",
        "browser_connector_test_plan_sha256",
        "browser_extraction_corpus_sha256",
        "browser_extraction_evidence_sha256",
        "browser_extraction_runner_revision",
        "browser_type_evidence_eligibility_sha256",
    ];
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(ManifestPinError::UnknownField(field.clone()));
    }
    let candidate = object
        .get("browser_type_evidence_eligibility_sha256")
        .cloned();
    let (status, message) = match candidate {
        None => (FrozenTypeEvidenceStatus::Absent, None),
        Some(Value::String(value))
            if custody::valid_digest(&value) && expected_frozen_type_digest == value =>
        {
            (FrozenTypeEvidenceStatus::Accepted, None)
        }
        Some(Value::String(_)) => {
            object.remove("browser_type_evidence_eligibility_sha256");
            (
                FrozenTypeEvidenceStatus::OmittedMismatched,
                Some("optional frozen-type evidence digest omitted: mismatch"),
            )
        }
        Some(_) => {
            object.remove("browser_type_evidence_eligibility_sha256");
            (
                FrozenTypeEvidenceStatus::OmittedMalformed,
                Some("optional frozen-type evidence digest omitted: malformed"),
            )
        }
    };
    let normalized_bytes = custody::canonical_json_bytes(&value);
    let pins: ManifestPinSet = serde_json::from_value(value).map_err(|error| {
        let text = error.to_string();
        if text.contains("missing field") {
            ManifestPinError::MissingField("browser_plane_pins")
        } else {
            ManifestPinError::InvalidField("browser_plane_pins")
        }
    })?;
    pins.validate()?;
    Ok(ParsedManifestPins {
        pins,
        report: ManifestPinParseReport {
            frozen_type_evidence: status,
            messages: message.into_iter().collect(),
        },
        canonical_bytes: normalized_bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityGateInputs {
    pub common_artifacts_eligible: bool,
    pub extraction_evidence_eligible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityEligibility {
    pub capability: &'static str,
    pub eligible: bool,
    pub requires_extraction: bool,
}

pub fn capability_relative_eligibility(
    pins: &ManifestPinSet,
    capability: &str,
    gates: CapabilityGateInputs,
) -> CapabilityEligibility {
    let requires_extraction = matches!(capability, "browser.snapshot" | "browser.click");
    let known = matches!(
        capability,
        "browser.navigate"
            | "browser.snapshot"
            | "browser.click"
            | "browser.screenshot"
            | "browser.click_point"
            | "browser.wait_for"
    );
    let eligible = known
        && pins.validate().is_ok()
        && gates.common_artifacts_eligible
        && (!requires_extraction
            || (pins.extraction_group_eligible() && gates.extraction_evidence_eligible));
    CapabilityEligibility {
        capability: match capability {
            "browser.navigate" => "browser.navigate",
            "browser.snapshot" => "browser.snapshot",
            "browser.click" => "browser.click",
            "browser.screenshot" => "browser.screenshot",
            "browser.click_point" => "browser.click_point",
            "browser.wait_for" => "browser.wait_for",
            _ => "",
        },
        eligible,
        requires_extraction,
    }
}

pub fn capability_is_eligible(
    pins: &ManifestPinSet,
    capability: &str,
    gates: CapabilityGateInputs,
) -> bool {
    capability_relative_eligibility(pins, capability, gates).eligible
}
