# S1 type revalidation and evidence-gate closure

- **Slice:** `S1-type-revalidation-and-evidence-gate-closure`
- **Spec source:** `.cortexkit/alfonso/drafts/2026-07-23-browser-plane-spec-b1-drive-and-safety-surface.md`
- **Scope:** ordered `browser.type` verification and immutable eligibility evidence.

## Implementation record

`crates/cerebellum/src/browser_type.rs` owns the ordered seam used by a CDP
adapter:

1. reservation and initial pre-focus epoch/classification verification;
2. one classification record and one authorization call;
3. dispatch commitment, focus acknowledgement, and optional replacement
   selection;
4. a complete classification-fingerprint and epoch verification immediately
   before insertion; and
5. text insertion followed by the dispatched terminal transition.

An epoch change at either verification returns
`stale_snapshot {reason_code: "document_epoch_changed"}`. Any other covered
fingerprint change returns `resolved_node_changed`. The second verification
never authorizes again or adopts its observation, and it dispatches no text
when stale. Focus and selection effects are not represented as rolled back.

The eligibility predicate is centralized in `browser_type_eligibility` and is
used by geometry, dispatch, and final revalidation. It requires a writable text
control or editable region and rejects disabled, readonly, or inert targets.
The deterministic fixture driver exercises focus-handler and replacement-
selection-handler mutations for form ownership, autocomplete/password state,
editability, disabled, readonly, inert, and classified form descendants.

The immutable artifact is
`crates/cerebellum/resources/browser_evidence_eligibility-v1.json`. Its
SHA-256 is `b2dc267d5b4753339686b8546a701959f6b1535cdbbc6cf262018ee73333f40e`
and is repeated in the capability manifest schema metadata, the implementation
source lock, and the implementation constant. Registration accepts only when
all three values equal the digest computed from the artifact; manifest-only,
dependency-bundle-only, ambient, and implementation-defined approvals are
rejected.

## Verification ledger

- `cargo fmt --all` — passed.
- `cargo test -p cerebellum --lib` — passed (74 tests, including the ordered
  type and evidence-gate fixtures).
- `bash scripts/rust-test-gate.sh` — required final gate after the complete
  edit set.
