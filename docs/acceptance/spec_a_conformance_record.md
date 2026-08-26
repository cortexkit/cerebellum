# Spec A conformance acceptance record

- **Slice:** `spec_a_conformance_record`
- **Spec source:** `.cortexkit/alfonso/drafts/2026-07-22-browser-plane-spec-a-the-subc-seam-register-health-identity-default-deny.md`
- **Spec source SHA-256:** `48415efd687443f635d1ae287d048f70b5ae05a358784f82aafa9250a798dd41`
- **Dependency record:** [`resolve_spec_a_dependencies.md`](resolve_spec_a_dependencies.md)
- **Dependency-record SHA-256 at execution:** `4b98e2a2291968ee176288eb94b7e92c1dbf4e28c693a5f961e797a77dc2f902`

This record is the executable evidence for the browser-free Spec A seam. The
wire fixtures, principal contract, gateway policy, and design rationale are used
only through the immutable identifiers recorded by `resolve_spec_a_dependencies`.
The local conformance tests do not replace those fixtures with inferred test
doubles, and this slice adds no production browser behavior.

## Execution ledger

All checks below passed in this worktree after the final edit set:

- `cargo fmt --all` — passed.
- `cargo test -p cerebellum --test conformance --no-default-features` — passed (19 tests).
- `cargo test -p cerebellum --test insulated_health --no-default-features` — passed (26 tests).
- `cargo test -p cerebellum --features test-observer --test conformance --no-default-features feature_gated_identity_observer_records_resolved_facts` — passed (1 test).
- `cargo build -p cerebellum --release --no-default-features` — passed.
- `nm -gU target/release/ck-cerebellum` symbol check — passed; `test_observer` and `take_test_observations` were absent.
- `bash scripts/rust-test-gate.sh` — passed (format check, clippy, and workspace tests).
- `cargo test --manifest-path ../subconscious/Cargo.toml -p subc-mcp --test phase1_integration mcp_facade_default_deny_requires_global_enable` — passed (1 test).

## Numbered acceptance criteria

### 1. Registration and spawn attestation

**Executed by:**

- `cargo test -p cerebellum --test conformance --no-default-features`
- `live_daemon_registers_and_serves_browser_status`

The test starts the real `subc-core` TCP daemon with a reserved,
supervisor-configured `ck-cerebellum` child. The supervisor supplies the launch
nonce; the module's HELLO is therefore checked by the daemon's real registration
path. The test then reads `catalog.list` over an authenticated client connection
and asserts exactly one `browser.status` tool with `execution_mode: pure` before
opening a real route to the module.

### 2. Insulated health-v2

**Executed by:**

- `cargo test -p cerebellum --test insulated_health --no-default-features`
- `cargo test -p cerebellum --test conformance --no-default-features health_check_returns_insulated_report`

The fake-clock tests cover healthy values below and exactly at the 2-second and
30-second thresholds, degradation one tick beyond each threshold, queued and
in-flight ages, a frozen heartbeat, and a wedged dispatch future. They also
assert that absent or changed cached browser gauges neither block `health.check`
nor change dispatch status. No browser process is used by this criterion.

### 3. Principal default-deny

**Executed by:**

- `cargo test -p cerebellum --test conformance --no-default-features`
- `ineligible_principal_receives_transport_rejection`
- `absent_principal_is_rejected`
- `mcp_facade_principal_is_untrusted`
- `first_party_route_bind_is_acked`

The pinned subc-mcp gateway policy remains the primary `mcp:*` exclusion, and
its recorded executable default-deny case was run separately. The module tests
exercise the in-module backstop: an untrusted or absent principal produces an
`Error` frame with `principal_denied`, while a first-party bind is acknowledged.
This is transport/routing rejection, not a capability result.

### 4. Three-fact identity thread and profile boundary

**Executed by:**

- `cargo test -p cerebellum --test conformance --no-default-features`
- `live_daemon_registers_and_serves_browser_status`
- `session_kind_matrix_resolves_profile_disposition`
- `accepted_bind_facts_drive_profile_resolution`
- `distinct_agent_project_ids_resolve_to_distinct_profiles`

The live route returns `outcome: no_session` with module-resolved context. The
matrix asserts `primary → durable`, `subagent → disposable`, and `ephemeral →
none`; accepted bind facts, not request-body fields, determine the effective
session kind and logical profile identity. The response does not echo the
conversation-key or `agentProjectId`. No profile storage or browser is opened.

### 5. Closed `browser.status` schema and wire/body boundary

**Executed by:**

- `cargo test -p cerebellum --test conformance --no-default-features`
- `browser_status_unknown_field_returns_invalid_request_in_body`
- `browser_status_rejects_management_envelope`
- `browser_status_rejects_malformed_tool_envelopes`
- `browser_status_top_level_wrong_types_return_response_frames`

Schema violations are application outcomes in ordinary `Response` frames. Their
flat bodies carry `outcome: invalid_request` and
`detail: { field, reason_code }`; they never use a transport `Error` frame. The
live test separately proves the valid empty request returns a flat
`Response` body with `outcome: no_session`.

### 6. Production-build observer exclusion

**Executed by:**

- `cargo test -p cerebellum --features test-observer --test conformance --no-default-features feature_gated_identity_observer_records_resolved_facts`
- `cargo build -p cerebellum --release --no-default-features`
- `nm -gU target/release/ck-cerebellum` symbol check for `test_observer` and
  `take_test_observations`

The feature-enabled test proves the observer can collect identity facts only in
the explicitly test-only build. The release build uses no default features, and
the symbol check reports no observer symbols. Production evidence therefore
contains no test-only identity observer.

## Outcome classification

The evidence deliberately keeps the two rejection planes distinct:

| Situation | Frame | Evidence |
| --- | --- | --- |
| Valid browser-free status request | `Response` with `outcome: no_session` | live daemon test |
| Closed-schema or malformed capability arguments | `Response` with `outcome: invalid_request` and `detail` | criteria 5 tests |
| Untrusted/absent bind principal | `Error` with `code: principal_denied` | criterion 3 tests |
| Accepted route with an explicitly empty capability scope | `Error` with `code: capability_denied` | `accepted_effective_scope_is_not_widened_by_request_body` |

Only the first two rows are application outcomes. The latter rows are pinned
transport/routing rejection behavior and are not reported as capability outcome
values.

## Scope guard

This record makes no claim that Spec A starts a browser, opens CDP, materializes
profile storage, enforces profile selection, or consumes the Spec-B severity
taxonomy. Profile names, logical keys, and dispositions are policy values only;
`browser.status` always reports the no-browser `no_session` state in this slice.
CDP actions, storage/sealing, profile selection, origin enforcement, action
schemas, and per-capability severity floors remain Spec B work.
