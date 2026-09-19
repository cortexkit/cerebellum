#!/usr/bin/env bash
# Build, sign, and stage ck-cerebellum for placement.
#
# WHAT THIS EXISTS TO PREVENT, and both have happened in this fleet:
#
#   A STALE ARTIFACT PUBLISHED AS A FRESH ONE. A build step can be skipped,
#   filtered by a pipe, or silently reuse a previous target directory, and the
#   bytes in the staging directory are what actually gets placed. So the gate
#   asks the ARTIFACT what it is rather than trusting that the build ran. A
#   build that did not happen cannot pass, however its output was displayed.
#
#   AD-HOC SIGNING ORPHANING TCC GRANTS. An ad-hoc signature has no stable
#   designated requirement, so macOS pins the grant to the binary's cdhash and
#   every rebuild silently revokes it -- while System Settings keeps showing
#   the toggle on, because the pane displays the record rather than whether it
#   still applies. This module needs Screen Recording and Accessibility, so it
#   is exactly the consumer signing-topology v2 was written for.
#
# The dangerous command is ABSENT here rather than present with the right flag:
# there is no `codesign --sign -` anywhere in this file, and placement is a
# plain copy, because a pin is not sticky and any later re-sign replaces it.
set -euo pipefail

cd "$(dirname "$0")/.."

HEAD_REV="$(git rev-parse HEAD)"
STAGE="$HOME/ck-stage/cerebellum-$(date -u +%Y%m%dT%H%M%SZ)"

# The fleet identity on this host, from the Apple Developer account. The
# identifier is the DEPLOYED name rather than the built one; they coincide here,
# but a rig binary carrying production's identifier would inherit or disturb
# production's TCC grant row invisibly.
IDENTITY="Apple Development: ISMET UFUK ALTINOK (7UX762GU88)"
DEPLOYED_NAME="ck-cerebellum"

# A dirty tree produces bytes that no commit describes: the rev the binary
# reports would name a commit that does not contain them. Refused here rather
# than noted, because the whole point of the artifact check below is that the
# reported rev means something.
if [ -n "$(git status --porcelain)" ]; then
  echo "REFUSING TO STAGE: the tree has uncommitted changes." >&2
  echo "The staged bytes would report a commit that does not contain them." >&2
  git status --short >&2
  exit 1
fi

# Unfiltered and unpiped: this script's refusals must reach the terminal. The
# fleet lost a refusal twice by sending it through a filter whose exit code
# replaced the script's.
./scripts/release-build.sh

mkdir -p "$STAGE"
cp target/release/"$DEPLOYED_NAME" "$STAGE/"

# The backup catalog travels with the binary. It lives in the repo because it is
# a reviewable declaration rather than generated state, and it is placed into the
# module's data directory, where the fleet's enrollment scanner looks for it. A
# catalog that stays in the repo declares nothing: an undeclared data directory
# is backed up by nobody and excluded by nobody, and its absence from a sweep
# looks the same as an oversight.
cp engram-catalog.json "$STAGE/"

codesign --force --sign "$IDENTITY" --identifier "$DEPLOYED_NAME" "$STAGE/$DEPLOYED_NAME"
codesign --verify --strict "$STAGE/$DEPLOYED_NAME"

# THE ARTIFACT GATE. Ask the signed bytes what they are, after signing, on the
# exact file that will be placed.
reported="$("$STAGE/$DEPLOYED_NAME" --version)"
reported_rev="$(printf '%s' "$reported" | grep -oE '\([0-9a-f]{40}\)' | tr -d '()' || true)"
reported_tree="$(printf '%s' "$reported" | grep -oE 'tree=[a-z]+' | cut -d= -f2 || true)"

if [ "$reported_rev" != "$HEAD_REV" ]; then
  echo >&2
  echo "REFUSING TO STAGE: the artifact reports rev '${reported_rev:-none}'," >&2
  echo "                   the tree is on $HEAD_REV." >&2
  echo "The staged bytes are not this commit. A previous build was reused, or" >&2
  echo "the build did not run. Nothing has been published." >&2
  rm -rf "$STAGE"
  exit 1
fi

if [ "$reported_tree" != "clean" ]; then
  echo >&2
  echo "REFUSING TO STAGE: the artifact was built from a ${reported_tree:-unknown} tree." >&2
  rm -rf "$STAGE"
  exit 1
fi

# THE SIGNATURE GATE, and it checks the property v2 is about rather than the
# fact that signing happened. A transitioned binary's designated requirement
# names its identifier and a certificate; an ad-hoc one names a cdhash, which
# is what dies on the next rebuild.
# codesign prints the requirement as `# designated => ...` on some paths and
# `designated => ...` on others, so both prefixes are stripped. Getting this
# wrong yields an EMPTY string, which falls to the refusing branch below and
# looks like a working gate while actually having read nothing -- a gate that
# refuses for the wrong reason passes its own test and fails the next one.
requirement="$(codesign -d -r- "$STAGE/$DEPLOYED_NAME" 2>&1 |
  sed -n -e 's/^# designated => //p' -e 's/^designated => //p')"
if [ -z "$requirement" ]; then
  echo >&2
  echo "REFUSING TO STAGE: could not read the designated requirement." >&2
  echo "Not a signature problem: codesign printed something this script does" >&2
  echo "not parse, so the identity check below would refuse without reading." >&2
  codesign -d -r- "$STAGE/$DEPLOYED_NAME" 2>&1 | head -5 >&2
  rm -rf "$STAGE"
  exit 1
fi
case "$requirement" in
  *"identifier \"$DEPLOYED_NAME\""*"certificate"*) ;;
  *)
    echo >&2
    echo "REFUSING TO STAGE: the designated requirement is not identity-based." >&2
    echo "  got: ${requirement:-<none>}" >&2
    echo "A cdhash-based requirement means TCC grants die on the next rebuild," >&2
    echo "which is the failure signing-topology v2 exists to end." >&2
    rm -rf "$STAGE"
    exit 1
    ;;
esac

# The digest sidecar, in `shasum -c` form, hashed from the bytes AT REST in the
# staging directory after signing -- never from the build output, which the
# signature step has since rewritten. Placement refuses a bare binary: the
# sidecar is what lets the placer prove the bytes it copies are the bytes
# this gate examined, without trusting this script's own printout.
(cd "$STAGE" && shasum -a 256 "$DEPLOYED_NAME" > "$DEPLOYED_NAME.sha256" \
  && shasum -a 256 -c "$DEPLOYED_NAME.sha256" >/dev/null) || {
  echo "REFUSING: could not write or verify the digest sidecar" >&2
  exit 1
}

# The fleet staging card. The placement gate reads `ck-<module>.current` to
# learn which staged artifact the owner is handing over; without it the gate
# infers the card from mtime, which nearly placed a superseded binary once.
# One line, shasum-shaped (sha256, card name, UTC stamp), overwritten on every
# stage so a superseded card is superseded here too. The card itself is copied
# beside it and its digest re-read from those bytes at rest, so the line
# describes the file the gate will open rather than the one this script built.
FLEET_STAGING="$HOME/.local/share/cortexkit/staging"
CARD="$DEPLOYED_NAME.$(printf '%s' "$HEAD_REV" | cut -c1-8)"
mkdir -p "$FLEET_STAGING"
cp "$STAGE/$DEPLOYED_NAME" "$FLEET_STAGING/$CARD"
(cd "$FLEET_STAGING" && shasum -a 256 "$CARD" > "$CARD.sha256" \
  && shasum -a 256 -c "$CARD.sha256" >/dev/null \
  && [ "$(cut -d' ' -f1 "$CARD.sha256")" = "$(cut -d' ' -f1 "$STAGE/$DEPLOYED_NAME.sha256")" ] \
  && printf '%s  %s  %s\n' "$(cut -d' ' -f1 "$CARD.sha256")" "$CARD" "$(date -u +%Y%m%dT%H%M%SZ)" > "$DEPLOYED_NAME.current") || {
  echo "REFUSING: the fleet staging card does not match the staged bytes" >&2
  exit 1
}

echo
echo "==> staged $STAGE/$DEPLOYED_NAME"
echo "    rev:         $HEAD_REV"
echo "    sha256:      $(cut -d' ' -f1 "$STAGE/$DEPLOYED_NAME.sha256")  (sidecar $DEPLOYED_NAME.sha256)"
echo "    card:        $FLEET_STAGING/$CARD  (declared in $DEPLOYED_NAME.current)"
echo "    lc_uuid:     $(dwarfdump --uuid "$STAGE/$DEPLOYED_NAME" | awk '{print $2}')"
echo "    requirement: $requirement"
echo
echo "Place engram-catalog.json into the module data directory"
echo "(~/.local/share/cortexkit/cerebellum/) alongside the binary placement, or"
echo "the browser profile is neither captured nor deliberately excluded."
echo
echo "Placement is a PLAIN COPY -- never re-sign at placement, because a"
echo "re-sign replaces the pin and invalidates the sha above. Gatekeeper"
echo "assesses each file on its own first exec, so warm the PLACED copy on the"
echo "deploy path: a multi-second first exec inside a supervisor health window"
echo "reads as a failed start."
