#!/usr/bin/env bash
# Sign the binary, then package and notarize the exact ZIP. Compute its
# checksum only after this script returns.
set -euo pipefail

binary="${1:?usage: $0 <binary> <archive>}"
archive="${2:?usage: $0 <binary> <archive>}"
: "${APP_STORE_CONNECT_API_KEY_PATH:?App Store Connect API key path is required}"
: "${APP_STORE_CONNECT_API_KEY_ID:?App Store Connect API key ID is required}"
: "${APP_STORE_CONNECT_API_ISSUER_ID:?App Store Connect API issuer ID is required}"
[[ -r "$APP_STORE_CONNECT_API_KEY_PATH" && -f "$binary" && ! -e "$archive" ]]

fail() {
  echo "$*" >&2
  exit 1
}

all_identities=$(security find-identity -v -p codesigning)
identity=$(awk -F'"' '$2 ~ /^Developer ID Application:/ { print $2 }' <<< "$all_identities")
if [[ -z "$identity" ]]; then
  fail 'No Developer ID Application identity; Apple Development cannot notarize a release.'
fi
[[ "$identity" != *$'\n'* ]] || fail 'More than one Developer ID Application identity; cannot choose a release signer.'

# The module and native host authenticate each other using the deployed name
# and Team ID 5R5846NBPW. Another valid Developer ID would notarize an unusable pair.
name=${binary##*/}
codesign --force --options runtime --timestamp --identifier "$name" --sign "$identity" "$binary"
codesign --verify --strict \
  -R="identifier \"$name\" and anchor apple generic and certificate leaf[subject.OU] = \"5R5846NBPW\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" \
  "$binary"

zip -q -j "$archive" "$binary"
result=$(xcrun notarytool submit "$archive" \
  --key "$APP_STORE_CONNECT_API_KEY_PATH" \
  --key-id "$APP_STORE_CONNECT_API_KEY_ID" \
  --issuer "$APP_STORE_CONNECT_API_ISSUER_ID" \
  --wait --output-format json)
if ! jq -e '.status == "Accepted"' <<< "$result" >/dev/null; then
  fail "Notarization did not accept $archive: $result"
fi

# A ZIP may be unstapleable. Its accepted ticket is still available online.
if ! xcrun stapler staple "$archive"; then
  echo "::warning title=staple-pending::$archive notarized but not stapled."
fi
