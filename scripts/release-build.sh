#!/usr/bin/env bash
#
# Build the module with the release attestations that have been minted.
#
# Eight identifiers gate what the computer plane may advertise and serve. Each
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

# Windows semantic actuation, reviewed under the v2 shape at 9b59170 with the
# differences from macOS recorded here as the Windows appendix. This binds only
# UIA Invoke on a uniquely resolved element (computer.click) and computer.wait;
# Windows has no per-process input path and no capture backend, so every other
# row is withheld by the advertisement rule rather than by this key.
#
# Measured on ARM64 Windows 11 from the console session, through the production
# driver: attendance verified, tree read, Close resolved uniquely with its
# alternate key, the neutral press dispatched as Invoke and accepted, after-read
# TargetGone. A duplicate id refused match_count 2 without invoking; an absent
# id refused; one Notepad resolves, two are Ambiguous by count.
#
# What differs from macOS, and why each is load-bearing:
#
# 1. Session provenance precedes everything, in this order: PROVENANCE, then
#    LIVENESS, then VISIBILITY, then RESOLUTION, then the invoke. A UIA read
#    from a service session SUCCEEDS and returns that session's own windows, so
#    an element resolved from it uniquely and correctly still names a control
#    the user cannot see. Measured: session 0 reads six service-desktop windows
#    while the console has ninety-five. The ordering is a rule, pinned by
#    other_session_refuses_actuation_before_liveness_and_before_any_invoke:
#    a service-session actuation of an element that would otherwise resolve
#    refuses by provenance with the liveness probe uncalled and the invoke
#    count zero; moving the check after liveness fails it by name.
#
# 2. Window visibility carries Unknown, never collapsed to NotVisible: a UWP
#    application has no enumerable window, and claiming absence would be false.
#    An Unknown target is actuatable only if resolution is unique; Unknown is
#    not itself a refusal.
#
# 3. The identity a caller names is the executable basename (notepad.exe), not
#    a bundle identifier, which Windows does not have. UWP applications resolve
#    by their own basename; applicationframehost.exe resolves to the host of
#    every UWP frame and is the wrong name. Two executables sharing a basename
#    in different paths resolve Ambiguous by instance count, never by path
#    preference -- the two-Notepad measurement covers that case.
#
# 4. Liveness is checked before visibility, or a dead target reads as
#    "visibility unknown": a process that has exited has no enumerable window
#    either. Found live (a Close whose after-read said unknown where the seam
#    said gone) and fixed at b326b61.
#
# 5. Refusal reasons reach the wire typed, each with its own remedy (44afafc).
#    The generic word had sent a Windows caller in the wrong session to check a
#    macOS screen-recording grant.
#
# NOT COVERED. accepted_by_platform: true from UIA Invoke means the provider's
# handler returned, not that the element did anything. The effect vocabulary
# is unexercised on Windows: the one effect witness in the record is TargetGone
# after Close, for that action alone. Nobody may read the accepted flag as
# verification. Also unmeasured: any application other than Notepad, explorer
# and Calculator, and anything under load.
export CEREBELLUM_WINDOWS_ACTUATION_REVIEW_REVISION="windows-actuation-review/v1@9b59170"

# Synthetic input: manufacturing input events rather than asking an element to
# invoke its own action. Reviewed against measurements rather than intentions --
# the review required a live end-to-end run on the served wire path as a
# prerequisite, and that run corrected the claim twice before it was granted.
#
# What it admits is type and keys. Scroll, move and drag stay withheld and this
# key is not what withholds them: per-process posting carries keyboard events
# and not pointer events, measured with a control arm, so advertisement refuses
# them for want of a delivery path. Pointer capabilities need a v2 when a path
# exists, because a new mechanism is a new containment story.
#
# The rung those rows serve is pid_structural, backed by kernel start-time
# re-verification before every post and atomically bound to each delivery. That
# claim is derived from counted witnesses rather than asserted: hoisting a check
# out of the per-post loop, or posting nothing at all, both fail it by name.
export CEREBELLUM_INPUT_REVIEW_REVISION="synthetic-input-review/v1@a39a2373"

# Attendance: who owns the schema the dispatch gate reads, and which revision.
# Bound in the same ceremony as the input review deliberately -- both are
# consumed only by the input dispatch gate, so minting them apart would leave
# one gate standing unbacked with nothing serving in the window.
export CEREBELLUM_ATTENDANCE_CONTRACT_OWNER="subc"
export CEREBELLUM_ATTENDANCE_CONTRACT_REVISION="v1"

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

# Global observed dispatch: computer.move, computer.scroll, computer.drag.
# Session-global pointer posting at the session tap, the top containment rung
# (global_none, tier 4), reviewed at subconscious 5a89716c
# (docs/reviews/global-dispatch-review-v1.md) against cerebellum 1e675685,
# from a packet run over the wire on a macOS VM under its own daemon:
#   - global_none / tier 4 on wire and journal for all three rows;
#   - focus TOCTOU: a target that is not frontmost is refused with no post;
#   - idle gate: passes after 2 s of no input, refuses at 1-9 ms after a
#     person's input;
#   - seize mid-sequence: input from another pid (hardware, and a second
#     process) stops the sequence at the next post, attributed, at 0 ms
#     detection latency against a 50 ms bound, and input after the last post
#     lets the sequence complete.
# The review records the four defects the packet found and their fixes
# (gate reading the age of its own posts; estimator dying with the
# per-dispatch driver; frontmost read at 170-260 ms per post; sleep-then-drain
# making the bound unmeetable), each with a test that reddens on the old
# shape, and the one mutation invisible to every other assertion (tap
# created after the idle read) as a failure line.
#
# Scope: macOS global-stream pointer operations only. Windows and any non-HID
# delivery path are v2 by policy; a seize the count discriminator fails to
# catch is a taxonomy change, not a tuning change.
export CEREBELLUM_GLOBAL_DISPATCH_REVIEW_REVISION="global-dispatch/v1@5a89716c"

# When a new identifier is added, leave it UNSET here until its review exists,
# rather than filling it with a placeholder. The gate rejects "placeholder",
# "tbd" and "unknown" outright, so a stand-in fails louder than absence -- but
# the reason to leave it unset is not that a stand-in would be caught. It is
# that absence is TRUE, and the module withholds the capability with a named
# reason while it is.
#
# ---------------------------------------------------------------------------

# The identifiers the compiler reads. Kept as one list so the loop below and
# the check after it cannot disagree about what exists.
readonly ATTESTATIONS=(
  CEREBELLUM_CAPTURE_REVIEW_REVISION
  CEREBELLUM_SEMANTIC_ACTUATION_REVIEW_REVISION
  CEREBELLUM_WINDOWS_ACTUATION_REVIEW_REVISION
  CEREBELLUM_RELEASE_SIGNING_TOPOLOGY_REVISION
  CEREBELLUM_INPUT_REVIEW_REVISION
  CEREBELLUM_GLOBAL_DISPATCH_REVIEW_REVISION
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
# Two siblings now: subconscious for the wire crates, commons for the
# daemon-aligned home resolvers. Each has its own declaration file with the
# same content-addressed format, and each is checked the same way, so adding
# a sibling is one line here and one file, never a second copy of the check.
check_sibling_declaration() {
  local sibling_name="$1" declaration="$2" sibling_dir drifted=""
  sibling_dir="$(cd "$(dirname "$0")/../../$sibling_name" 2>/dev/null && pwd || true)"
  if [ -z "$sibling_dir" ]; then
    echo "The $sibling_name checkout is not beside this repository." >&2
    echo "Workspace dependencies resolve through it, so there is nothing to" >&2
    echo "build against. Nothing has been produced." >&2
    exit 2
  fi
  while read -r declared_hash crate; do
    # Skip blanks and comments, so the declaration can explain what it holds.
    # A bare list of hashes reads as commit shas to everyone, which is exactly
    # the mistake that made this check compare a tree against a commit and
    # refuse every release build it was asked to approve.
    case "$declared_hash" in ""|\#*) continue ;; esac
    [ -z "$crate" ] && continue
    # Uncommitted edits are checked per declared crate, for the same reason
    # the hashes are: an edit in a sibling crate this binary does not link
    # cannot change what is compiled, and refusing over it (someone's work in
    # progress elsewhere in the sibling) blocks every release until they commit.
    if [ -n "$(git -C "$sibling_dir" status --porcelain -- "crates/$crate")" ]; then
      echo "The $sibling_name crate $crate has uncommitted changes." >&2
      echo "A recorded hash does not describe what would be compiled, so the" >&2
      echo "declaration cannot be honoured. Nothing has been produced." >&2
      exit 2
    fi
    local actual_hash
    actual_hash="$(git -C "$sibling_dir" rev-parse "HEAD:crates/$crate")"
    if [ "$actual_hash" != "$declared_hash" ]; then
      drifted="$drifted  $crate: declared $declared_hash, actual $actual_hash\n"
    fi
  done < "$declaration"
  if [ -n "$drifted" ]; then
    echo "A $sibling_name crate this binary links has changed since it was" >&2
    echo "declared:" >&2
    printf "%b" "$drifted" >&2
    echo "A path dependency records no source or checksum in Cargo.lock, so" >&2
    echo "--locked cannot see this and the binary would link code no gate has" >&2
    echo "verified. If the move is intended, update $(basename "$declaration") and" >&2
    echo "commit it, so the combination is verified before it ships." >&2
    exit 2
  fi
}
check_sibling_declaration subconscious "$(dirname "$0")/../subconscious-source.txt"
check_sibling_declaration commons "$(dirname "$0")/../commons-source.txt"

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
