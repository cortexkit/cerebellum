#!/usr/bin/env bash
# Assert every module file under a crate's src/ is declared in that crate's root.
#
# A module that exists on disk but is not declared compiles only where something
# includes it explicitly — typically a test binary via `#[path]`. That is a
# legitimate arrangement while a slice that does not own the crate root delivers
# a module, but it is indistinguishable from a module nobody ever wired up:
# dead code inside it is never reported, and nothing outside a test can call it.
#
# Deliberately test-only modules belong in EXPECTED_UNWIRED below, so the
# decision is recorded rather than inferred from an absence.

set -euo pipefail

cd "$(dirname "$0")/.."

# Modules intentionally excluded from their crate root, each with a reason.
# Format: "<crate>::<module>"
EXPECTED_UNWIRED=()

failed=0

for crate_dir in crates/*/; do
  crate="$(basename "$crate_dir")"
  root="$crate_dir/src/lib.rs"
  [ -f "$root" ] || continue

  for entry in "$crate_dir"src/*; do
    name="$(basename "$entry")"
    case "$name" in
      lib.rs | main.rs) continue ;;
    esac

    if [ -d "$entry" ]; then
      [ -f "$entry/mod.rs" ] || continue
      module="$name"
    else
      case "$name" in
        *.rs) module="${name%.rs}" ;;
        *) continue ;;
      esac
    fi

    if grep -qE "^[[:space:]]*(pub )?mod ${module};" "$root"; then
      continue
    fi

    skip=0
    for allowed in "${EXPECTED_UNWIRED[@]:-}"; do
      [ "$allowed" = "${crate}::${module}" ] && skip=1
    done
    [ "$skip" -eq 1 ] && continue

    echo "unwired module: ${crate}::${module} is not declared in ${root}"
    failed=1
  done
done

if [ "$failed" -ne 0 ]; then
  echo
  echo "Declare the module in its crate root, or add it to EXPECTED_UNWIRED in"
  echo "$0 with the reason it is deliberately test-only."
  exit 1
fi

echo "module wiring: every module under crates/*/src is declared in its crate root"
