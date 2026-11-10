#!/usr/bin/env bash
#
# Build the module with the release attestations that have been minted.
#
# Nine identifiers gate what the computer plane may advertise and serve. Each
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

# The semantic click path, reviewed at c8e7d2f and amended at 928cf90. It
# reviewed identifier-addressed computer.click, which vocabulary v13 retired, so
# this key admits no row in the current vocabulary. It stays bound as the record
# of that review; the element-addressed rows that replace click are a new
# semantic surface with their own, still unminted, review.
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
# differences from macOS recorded here as the Windows appendix. It reviewed UIA
# Invoke on a uniquely resolved element (computer.click, retired in vocabulary
# v13) and computer.wait. With click gone it admits no row of its own: wait
# needs no review key, and Windows has no per-process input path and no capture
# backend, so every other row is withheld by the advertisement rule rather than
# by this key.
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
# What it admits is type and keys. It never covered pointer rows: per-process
# posting carries keyboard events and not pointer events, measured with a
# control arm. Vocabulary v13 retired the old scroll, move and drag rows; their
# pointer work returns as the takeover rows, which will need the global-dispatch
# key below AND their own takeover review, because a new mechanism is a new
# containment story.
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

# Global observed dispatch: the macOS session-global pointer stream. It was
# reviewed on computer.move, computer.scroll and computer.drag, which vocabulary
# v13 retired, so it admits no row today. Its successors are the three takeover
# rows (computer.takeover_move, computer.takeover_drag,
# computer.takeover_scroll), which have no wire handler yet; when they do, they
# need this key AND their own takeover review before they are admitted.
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

# The application-state read, computer.read_state: an application's windows,
# sheets and menu bar as a text tree with element ids that persist across
# reads, the diff between reads, and the optional image of its frontmost
# window taken through capture custody. A new semantic surface, so it has its
# own review, minted in subconscious docs/reviews/app-state-review-v1.md on
# b3f42392 against ck-cerebellum ca6b54d.
export CEREBELLUM_APP_STATE_REVIEW_REVISION="app-state-review/v1@b3f42392"

# Acting on an element through accessibility: computer.press_element (AXPress
# on an element a state read numbered), computer.press_point (a point in a
# returned image, hit-tested within that image's own application and pressed
# the same way; the pointer never moves), and computer.write_text (AXValue or
# AXSelectedText written, then read back). Retained-handle actions are a new
# semantic surface, apart from reading the tree, so they have their own
# review, minted in subconscious docs/reviews/element-addressed-review-v1.md
# on b3f42392 against ck-cerebellum ca6b54d.
export CEREBELLUM_ELEMENT_ADDRESSED_REVIEW_REVISION="element-addressed-review/v1@b3f42392"

# Anything that can take the person's input focus: the takeover pointer rows,
# and the fronting bracket computer.type and computer.keys use to reach an
# application that is not frontmost (bring it forward for at most 100 ms at a
# time, post, put the previous application back, under the idle gate and the
# seize watcher). v2 adds what v1 lacked: the bracket now runs under the
# process-wide fronting lock, and an activation that lands after the call has
# replied is put back by a bounded watcher (5 s, only while the person is idle).
# Minted by SUBC on 2026-11-10 against ck-cerebellum 454cef4b (review record:
# subconscious .cortexkit/internal-docs/audits/
# 2026-11-10-takeover-dispatch-review-v2.md); v1@ada9eb93 covered abe8e3a.
# Without it, type and keys still serve a frontmost target under the input
# review above, and refuse a background one with keystrokes_need_foreground.
export CEREBELLUM_TAKEOVER_DISPATCH_REVIEW_REVISION="takeover-dispatch-review/v2@454cef4b"

# Keystrokes posted to one process through the private SkyLight route
# (SLEventPostToPid), which reaches a background Chromium or Electron app that
# the public per-process post does not wake. Fails closed: no fallback to the
# public route when the private one is missing or its authentication fails.
# Reviewed in subconscious docs/reviews/private-input-route-review-v1.md on
# b3f42392 against ck-cerebellum ca6b54d; a change to this route's code paths
# needs a new revision. Without it, type and keys use the public route only.
export CEREBELLUM_PRIVATE_INPUT_ROUTE_REVIEW_REVISION="private-input-route-review/v1@b3f42392"

# Background app use, CEREBELLUM_APP_USE_FRONTING_REVIEW_REVISION. Its scope is
# two mechanisms the takeover review above does not cover:
#   - fronting outside the keystroke bracket: foreground mode's one-way front
#     of the target before each action, and in background mode bringing an
#     application forward under the app grant alone for a press on an element
#     disabled in the background or a Command/Control/Option chord, then
#     restoring the previous application (or not, when the person switched
#     apps), with the restore held until a held key's release is confirmed;
#   - preview capture: the background-mode preview's capture of a covered
#     window's pixels, outside capture custody.
# It gates no capability row. With the takeover review it admits that
# fronting; with the capture review it admits preview capture. Once the module
# consults it, a build without it acts in foreground mode without fronting,
# refuses a press on a disabled element with element_disabled, keeps the
# takeover bracket for chords, and shows the application's icon in the preview.
# Left UNSET: its review does not exist yet.

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
# Temporary front/act/restore for takeover pointer gestures and takeover_click
# needs an independent safety review. Leave its key UNSET until that review
# approves these paths and supplies its revision. Binding the key also changes
# computer_use definition bytes. OpenCode caches those definitions until
# restart, so bind the key only at a coordinated host restart.
readonly ATTESTATIONS=(
  CEREBELLUM_TAKEOVER_POINTER_FRONTING_REVIEW_REVISION
  CEREBELLUM_CAPTURE_REVIEW_REVISION
  CEREBELLUM_SEMANTIC_ACTUATION_REVIEW_REVISION
  CEREBELLUM_WINDOWS_ACTUATION_REVIEW_REVISION
  CEREBELLUM_APP_STATE_REVIEW_REVISION
  CEREBELLUM_ELEMENT_ADDRESSED_REVIEW_REVISION
  CEREBELLUM_TAKEOVER_DISPATCH_REVIEW_REVISION
  CEREBELLUM_APP_USE_FRONTING_REVIEW_REVISION
  CEREBELLUM_PRIVATE_INPUT_ROUTE_REVIEW_REVISION
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

# Registry checksums and pinned git revisions identify the dependency source.
# Refuse external paths before building, and refuse lockfile re-resolution.
scripts/check-repo-path-deps.sh
cargo build --release --locked -p cerebellum --bin ck-cerebellum "$@"

echo
echo "==> what this build advertises"
# Read from the production path rather than restated here, so this cannot claim
# a capability the build does not actually offer.
cargo run --release -q -p cerebellum --example what_ships
