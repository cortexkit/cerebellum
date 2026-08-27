#!/usr/bin/env bash
#
# Build the module with the release attestations that have been minted.
#
# Six identifiers gate what the computer plane may advertise and serve. Each
# attests that something happened OUTSIDE this repository -- a review was
# conducted, a doctrine was written down -- so none of them can be derived from
# the code they govern. They are supplied to the COMPILER rather than read at
# startup, because a value the environment can set is a value that can be set
# after the review it claims to attest, and one the environment can unset is an
# attestation a misconfigured launch can silently revoke.
#
# An identifier absent here suppresses the capabilities that consume it. That is
# the correct behaviour rather than a limitation: not knowing whether a review
# happened is a reason not to offer the capability.
#
# THIS SCRIPT IS THE RECORD OF WHICH ATTESTATIONS EXIST. Adding one is how a
# minted revision enters the build; a revision that lives only in the message
# that announced it is one nobody can rebuild from.
set -euo pipefail

cd "$(dirname "$0")/.."

# ---------------------------------------------------------------------------
# Minted attestations
# ---------------------------------------------------------------------------

# The capture surface reviewed at source by the reviewer who owns that gate:
# entry points, refusal-path mutations, and a real-capture run record. The
# revision names the commit reviewed, so it cannot be carried forward silently
# onto later code -- a subsequent change to the capture surface needs a new
# review and a new revision.
export CEREBELLUM_CAPTURE_REVIEW_REVISION="cerebellum-capture-review/v1@cb1f669"

# The semantic click path, reviewed at c8e7d2f and amended at 928cf90. This
# binds only identifier-addressed computer.click; synthetic input and the other
# actuating rows remain unreviewed.
#
# The amendment scoped element uniqueness to the tree actually read: a partial
# tree no longer refuses outright, and the count of unreadable subtrees is
# disclosed on the resolution outcome, the caller's outcome and the audit
# record. Uniqueness within the read tree is unchanged -- an in-scope duplicate
# still refuses before any action call, which is the property that prevents
# acting on the wrong control. Fenced by mutation:
# a_duplicate_identifier_in_scope_is_refused_before_any_action_call,
# platform_acceptance_discloses_partial_tree_without_claiming_effect, and
# partial_action_tree_disclosure_reaches_caller_and_decoded_audit_entry each
# fail by name when their guard is removed.
export CEREBELLUM_SEMANTIC_ACTUATION_REVIEW_REVISION="semantic-actuation-review/v2@928cf90"

# The fleet's stage-sign doctrine: sign at build or stage with pinned
# per-deployment identifiers, place with a plain copy, keep environments on
# distinct identities. Held in the subconscious repository at
# docs/specs/signing-topology.md.
#
# The revision advances only when a rule changes MEANING, not when its wording
# changes. That matters more than it sounds: a gate that churns on rewording
# trains whoever maintains this file to rebind without reading, which turns an
# attestation into a version string someone bumps.
# v2 rather than v1, and the difference is operational rather than editorial.
# v1 permitted ad-hoc signing, under which TCC pins a grant to the binary's
# CDHASH -- so every rebuild silently orphaned Screen Recording and
# Accessibility while System Settings kept showing the toggle on, because the
# pane displays the record rather than whether it still applies. This module
# consumes both permissions, so it is precisely the consumer the note in the
# fleet spec means when it says a consumer requiring rebuild-stable grants
# binds v2 specifically.
#
# Binding v2 is a claim about how the binary is SIGNED, which a build cannot
# verify about itself. scripts/stage.sh is what makes the claim true: it signs
# with the fleet identity under a pinned identifier, and checks the designated
# requirement names that identifier and a certificate rather than a cdhash.
export CEREBELLUM_RELEASE_SIGNING_TOPOLOGY_REVISION="signing-topology/v2"

# ---------------------------------------------------------------------------
# Not yet minted
# ---------------------------------------------------------------------------
#
# Deliberately unset rather than filled with a placeholder. The gate rejects
# "placeholder", "tbd" and "unknown" outright, so a stand-in fails louder than
# absence -- but the reason to leave them unset is not that a stand-in would be
# caught. It is that absence is TRUE.
#
#   CEREBELLUM_INPUT_REVIEW_REVISION
#     Synthetic input review. No synthetic input path is implemented, and the
#     semantic actuation review above does not cover manufacturing input events.
#
#   CEREBELLUM_ATTENDANCE_CONTRACT_OWNER
#   CEREBELLUM_ATTENDANCE_CONTRACT_REVISION
#     Ownership defaults to this module, which authored the attendance schema
#     and is its only consumer. Left unbound anyway: both are consumed only by
#     the input dispatch gate, which also requires the input review that does
#     not exist, so binding them today would change nothing about what ships
#     while making the gate report look closer to ready than it is.
#
#     Bind them alongside the input review, and renegotiate ownership if a
#     second module ever reads the contract.

# ---------------------------------------------------------------------------

# The identifiers the compiler reads. Kept as one list so the loop below and
# the check after it cannot disagree about what exists.
readonly ATTESTATIONS=(
  CEREBELLUM_CAPTURE_REVIEW_REVISION
  CEREBELLUM_SEMANTIC_ACTUATION_REVIEW_REVISION
  CEREBELLUM_RELEASE_SIGNING_TOPOLOGY_REVISION
  CEREBELLUM_INPUT_REVIEW_REVISION
  CEREBELLUM_ATTENDANCE_CONTRACT_OWNER
  CEREBELLUM_ATTENDANCE_CONTRACT_REVISION
)

# A misspelled export sets a variable the compiler never reads, so the gate it
# was meant to satisfy reports a missing input and the capability is withheld.
# That fails closed, which is why it is dangerous: the build succeeds, ships
# less than intended, and the report blames an absent attestation for one that
# was supplied. Caught here rather than left to be noticed.
for exported in $(compgen -v | grep '^CEREBELLUM_' || true); do
  known=no
  for name in "${ATTESTATIONS[@]}"; do
    [[ "$exported" == "$name" ]] && known=yes && break
  done
  if [[ "$known" == no ]]; then
    echo "error: $exported is set and the compiler reads no such attestation." >&2
    echo "       Compare it against the names in compiled_release_inputs." >&2
    exit 1
  fi
done

echo "==> building with the attestations that exist"
for name in "${ATTESTATIONS[@]}"; do
  printf '    %-48s %s\n' "$name" "${!name:-<unbound>}"
done

# The sibling SOURCE this binary is built against.
#
# --locked below fences the REGISTRY half of the dependency set: a registry
# crate records its source and checksum in Cargo.lock, so its exact bytes are
# pinned. A PATH dependency records NEITHER -- compare the subc-protocol entry
# in Cargo.lock against serde's and the difference is visible. So a sibling
# whose SOURCE moved without a version bump satisfies --locked completely, and
# most commits do not bump a version.
#
# Pinned per DEPENDED-ON SUBTREE: one hash per crate directory inside the
# sibling subconscious checkout, rather than one hash for that repository's
# HEAD commit. A commit id answers "did anything in subconscious change",
# which is the wrong question -- only a few of its crates are compiled into
# ck-cerebellum, and it also carries documentation that changes daily. A check
# that refuses a release for changes which cannot affect the produced binary
# gets re-pinned reflexively, and a reflex is not a decision: the check would
# still be present and would have stopped meaning anything.
#
# A tree hash answers the right question exactly: it changes when, and only
# when, the contents of that directory change.
#
# THE SET IS THE RUNTIME DEPENDENCIES, NOT EVERY SIBLING CRATE THE WORKSPACE
# NAMES. subc-core and subc-control are dev-dependencies: they build the
# in-process daemon used by the conformance tests and are absent from the
# shipped binary, so a change there cannot alter what is released. Declaring
# them made this fence refuse a release over a supervisor change that this
# artifact does not contain -- the same over-firing as pinning the sibling's
# HEAD, one level subtler, and it was hiding a gap in the other direction:
# subc-jsonc IS linked and was NOT declared, so a change to configuration
# parsing would have shipped unnoticed.
#
# Keep this list equal to the [dependencies] entries that resolve into the
# sibling, and re-derive it rather than editing by hand when they change.
SIBLING_DIR="$(cd "$(dirname "$0")/../../subconscious" 2>/dev/null && pwd || true)"
DECLARATION="$(dirname "$0")/../subconscious-source.txt"

if [ -z "$SIBLING_DIR" ]; then
  echo "The subconscious checkout is not beside this repository." >&2
  echo "Every workspace dependency resolves through it, so there is nothing" >&2
  echo "to build against. Nothing has been produced." >&2
  exit 2
fi

if [ -n "$(git -C "$SIBLING_DIR" status --porcelain -- crates)" ]; then
  echo "The subconscious crates have uncommitted changes." >&2
  echo "A recorded hash does not describe what would be compiled, so the" >&2
  echo "declaration cannot be honoured. Nothing has been produced." >&2
  exit 2
fi

DRIFTED=""
while read -r declared_hash crate; do
  # Skip blanks and comments, so the declaration can explain what it holds.
  # A bare list of hashes reads as commit shas to everyone, which is exactly
  # the mistake that made this check compare a tree against a commit and
  # refuse every release build it was asked to approve.
  case "$declared_hash" in ""|\#*) continue ;; esac
  [ -z "$crate" ] && continue
  actual_hash="$(git -C "$SIBLING_DIR" rev-parse "HEAD:crates/$crate")"
  if [ "$actual_hash" != "$declared_hash" ]; then
    DRIFTED="$DRIFTED  $crate: declared $declared_hash, actual $actual_hash\n"
  fi
done < "$DECLARATION"

if [ -n "$DRIFTED" ]; then
  echo "A subconscious crate this binary links has changed since it was" >&2
  echo "declared:" >&2
  printf "%b" "$DRIFTED" >&2
  echo "A path dependency records no source or checksum in Cargo.lock, so" >&2
  echo "--locked cannot see this and the binary would link code no gate has" >&2
  echo "verified. If the move is intended, update subconscious-source.txt and" >&2
  echo "commit it, so the combination is verified before it ships." >&2
  exit 2
fi

# --locked, because this repo's workspace dependencies are PATH deps on a
# sibling checkout. Without it a release build re-resolves those siblings
# against whatever the sibling happens to be at build time, so a binary can
# ship linked to a version no gate ever verified -- and the only trace is a
# rewritten Cargo.lock, which reads as ordinary post-build noise.
#
# "CI green and the staged sha matches" proves the placed artifact is the built
# artifact. It says nothing about what that artifact was built AGAINST. This
# flag is the other half: the stale-artifact check above asks whether the
# SOURCE is the verified one, and this asks whether the DEPENDENCY SET is.
#
# When it refuses because a sibling moved, that refusal is the point. Commit
# the new lockfile and let the gate verify the combination a staged binary
# would carry, so re-resolving becomes a decision someone made rather than a
# side effect of having built on a particular afternoon.
cargo build --release --locked -p cerebellum "$@"

echo
echo "==> what this build advertises"
# Read from the production path rather than restated here, so this cannot claim
# a capability the build does not actually offer.
cargo run --release -q -p cerebellum --example what_ships
