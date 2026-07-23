# Spec A dependency resolution acceptance record

- **Slice:** `resolve_spec_a_dependencies`
- **Spec source:** `/Users/ufukaltinok/Work/Projects/CortexKit/cerebellum/.cortexkit/alfonso/drafts/2026-07-22-browser-plane-spec-a-the-subc-seam-register-health-identity-default-deny.md`
- **Spec source SHA-256:** `48415efd687443f635d1ae287d048f70b5ae05a358784f82aafa9250a798dd41`
- **Scope:** immutable dependency identifiers only; this slice adds no production behavior.

## Immutable dependency identifiers

Every path below is an absolute repository path. Each reference is pinned by a
full commit hash or a SHA-256 content digest (most have both); neither a branch
name nor an abbreviated revision is part of the dependency identity.

| Dependency | Immutable repository path | Full commit hash | SHA-256 content digest |
| --- | --- | --- | --- |
| `subc_wire_v2_schema` | `/Users/ufukaltinok/Work/Projects/CortexKit/subconscious/docs/specs/subc-wire-v1-final.md` | `4766dd761d94474829d4a17d4009e598a93da0a1` | `5025b0b5acb155871eaa3793e51405cfb2b3c9241475d90c1334b7de2127c17d` |
| `subc_spawn_attestation_principal_contract` | `/Users/ufukaltinok/Work/Projects/CortexKit/subconscious/docs/subc-principal.md` | `c620db796649e8242b775e5489b592febd8c432f` | `362dd12e29ece5d27b535b398054ae4209c2bfca125ca08cfef8dac26fd1d1d4` |
| `subc_wire_v2_conformance_fixture` | `/Users/ufukaltinok/Work/Projects/CortexKit/subconscious/crates/subc-protocol/tests/golden/module_control_request_route_bind.json` | `449af3592843dfc5225ba836ef0b4779e5a003a7` | `383a5300589c97623849ff62841ec383ef308fc51428f52c9454f655f3ef991f` |
| `subc_mcp_gateway_policy_fixture` | `/Users/ufukaltinok/Work/Projects/CortexKit/subconscious/docs/specs/mcp-facade-policy.md` | `8c8d8ebba5a63a18dd9576ec75188322ab1516f0` | `0c5c721aea6d854ab9b885d9d91ffde7395ec0933505c333f088e28f18105aaa` |
| `docs/design/browser-plane.md` | `/Users/ufukaltinok/Work/Projects/CortexKit/cerebellum/docs/design/browser-plane.md` | — | `4802fb7610610c7615947dcb2adb9e696db8db4b26de3940ae3aa11dd7d5d188` |

### Conformance fixture set

`subc_wire_v2_conformance_fixture` is the pinned golden-vector set, not an
inferred local test double. Its immutable members are:

| Fixture role | Immutable repository path | Full commit hash | SHA-256 content digest |
| --- | --- | --- | --- |
| Fixture-set manifest | `/Users/ufukaltinok/Work/Projects/CortexKit/subconscious/crates/subc-protocol/tests/golden/README.md` | `00b60a80e1733e525a4a77d9d0e38c3a014e6fe8` | `7f5cedcf132e04f5ec56b800708b6a119b6ef8cda2fc9ad7d839f35d00e85da0` |
| Route-bind encoding | `/Users/ufukaltinok/Work/Projects/CortexKit/subconscious/crates/subc-protocol/tests/golden/module_control_request_route_bind.json` | `449af3592843dfc5225ba836ef0b4779e5a003a7` | `383a5300589c97623849ff62841ec383ef308fc51428f52c9454f655f3ef991f` |
| Reserved principal encoding | `/Users/ufukaltinok/Work/Projects/CortexKit/subconscious/crates/subc-protocol/tests/golden/principal_reserved.json` | `289cdad74b561309623f8cb9404c795aff632b8e` | `2b3e4a69d270ab446885c2e1defe444c262f2bbd682c2dbd5d474febada89b4d` |
| Bind identity encoding | `/Users/ufukaltinok/Work/Projects/CortexKit/subconscious/crates/subc-protocol/tests/golden/bind_identity.json` | `00b60a80e1733e525a4a77d9d0e38c3a014e6fe8` | `022dd98e6e3b69492a042e430420a8f746c00d8d762f0edffb53302fac7bdb95` |

The gateway policy fixture is the pinned contract at
`/Users/ufukaltinok/Work/Projects/CortexKit/subconscious/docs/specs/mcp-facade-policy.md`
and its executable default-deny case, `mcp_facade_default_deny_requires_global_enable`,
in `/Users/ufukaltinok/Work/Projects/CortexKit/subconscious/crates/subc-mcp/tests/phase1_integration.rs` at full commit `449af3592843dfc5225ba836ef0b4779e5a003a7` and SHA-256 digest `56c8ff0c9f51ce5f608a6e41e38be131c50a2f995f4dd5c1d34dcfef4f866d68`.
The wire fixture set pins route-bind, principal, and bind-identity encodings; the
source files are immutable at the revisions recorded above.

## Rationale and explicit supersessions

The rationale dependency is interpreted through the Spec A `design` and
`interfaces` sections, rather than by importing unresolved or branch-relative
references from an earlier combined browser-plane draft:

1. **`design` owns the seam boundary.** The immutable source at
   `/Users/ufukaltinok/Work/Projects/CortexKit/cerebellum/docs/design/browser-plane.md`
   supplies the browser-plane rationale. Spec A narrows that rationale to the browser-free
   subc seam: alfonso-core stamps the bind principal, conversation-key,
   `agentProjectId`, and `sessionKind`; cerebellum reads those facts verbatim;
   health is derived from dispatch-published monotonic atomics; and profile
   disposition is policy only. No browser, CDP, profile storage, or browser
   action behavior is pulled into this slice.
2. **Spec A supersedes the combined draft for the seam vertical.** Registration,
   spawn attestation, insulated health-v2, three-fact identity, profile-boundary
   disposition, principal default-deny, and `browser.status` belong to Spec A.
3. **`interfaces` fixes the wire/body boundary.** Spec A's immutable `interfaces`
   section preserves the subc data-plane rule that response bodies are opaque
   bytes. Cerebellum application results are flat
   `{ outcome, context, ... }` bodies with no `{result}` wrapper, carried in a
   normal Response frame; subc Error frames remain transport/routing/bind
   errors. This explicit interface rule supersedes any wrapper or error-shape
   suggestion in the earlier combined draft.
4. **Spec B is the explicit downstream owner.** CDP actions, profile storage,
   network/authz enforcement edges, and the full action schemas are Spec B
   concerns. Spec A's interface and identity rules are prerequisites that Spec B
   inherits; this record does not authorize implementing those surfaces.

These supersessions are the recorded rationale for resolving the dependency
identifiers above and do not add production behavior.
