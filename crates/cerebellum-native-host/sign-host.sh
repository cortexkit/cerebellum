#!/usr/bin/env bash
# Development/release packaging helper, not part of the stdio relay.
set -euo pipefail

test "$(uname -s)" = Darwin
test "$#" = 2
binary="$1"
identity="$2"
test -f "$binary"

# The bridge authenticates this deployed identifier, not Cargo's package name.
codesign --force --options runtime --timestamp \
  --identifier ck-cerebellum-native-host --sign "$identity" "$binary"
codesign --verify --strict \
  -R='identifier "ck-cerebellum-native-host" and anchor apple generic and certificate leaf[subject.OU] = "5R5846NBPW"' \
  "$binary"
