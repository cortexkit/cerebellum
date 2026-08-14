#!/usr/bin/env bash
#
# Build the module with the release attestations that have been minted.
#
# Five identifiers gate what the computer plane may advertise and serve. Each
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
#     approval that exists covers semantic actuation -- asking an application to
#     invoke its own control -- which is a mechanism rather than a review.
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

cargo build --release -p cerebellum "$@"

echo
echo "==> what this build advertises"
# Read from the production path rather than restated here, so this cannot claim
# a capability the build does not actually offer.
cargo run --release -q -p cerebellum --example what_ships
