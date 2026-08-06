#!/usr/bin/env bash
# Assert every module file under a crate's src/ is declared by its parent module.
#
# A module that exists on disk but is not declared compiles only where something
# includes it explicitly — typically a test binary via `#[path]`. That is a
# legitimate arrangement while a slice that does not own the crate root delivers
# a module, but it is indistinguishable from a module nobody ever wired up:
# dead code inside it is never reported, and nothing outside a test can call it.
#
# The walk is recursive, because the property is the same at every depth and a
# top-level-only check reports a clean tree while an undeclared module sits one
# directory down. Each file's parent is the module that must declare it:
# src/a.rs and src/a/mod.rs are declared by src/lib.rs; src/a/b.rs and
# src/a/b/mod.rs are declared by src/a/mod.rs.
#
# Deliberately test-only modules belong in EXPECTED_UNWIRED below, so the
# decision is recorded rather than inferred from an absence.

set -euo pipefail

cd "$(dirname "$0")/.."

# Modules intentionally excluded from their parent, each with a reason.
# Format: "<crate>::<path::to::module>"
EXPECTED_UNWIRED=()

failed=0

for crate_dir in crates/*/; do
  crate="$(basename "$crate_dir")"
  src="${crate_dir}src"
  [ -d "$src" ] || continue

  while IFS= read -r file; do
    relative="${file#"$src"/}"
    case "$relative" in
      lib.rs | main.rs) continue ;;
    esac

    if [ "$(basename "$relative")" = "mod.rs" ]; then
      # src/a/b/mod.rs declares module `b` inside src/a.
      module_path="$(dirname "$relative")"
    else
      module_path="${relative%.rs}"
    fi

    module="$(basename "$module_path")"
    parent_dir="$(dirname "$module_path")"

    if [ "$parent_dir" = "." ]; then
      parent="$src/lib.rs"
    else
      parent="$src/$parent_dir/mod.rs"
    fi

    # A parent that does not exist is its own defect: the directory holds
    # modules that nothing can declare.
    if [ ! -f "$parent" ]; then
      echo "unwired module: ${crate}::${module_path//\//::} has no parent module at ${parent#./}"
      failed=1
      continue
    fi

    if grep -qE "^[[:space:]]*(pub )?mod ${module};" "$parent"; then
      continue
    fi

    qualified="${crate}::${module_path//\//::}"
    skip=0
    for allowed in "${EXPECTED_UNWIRED[@]:-}"; do
      [ "$allowed" = "$qualified" ] && skip=1
    done
    [ "$skip" -eq 1 ] && continue

    echo "unwired module: ${qualified} is not declared in ${parent#./}"
    failed=1
  done < <(find "$src" -name '*.rs' | sort)
done

if [ "$failed" -ne 0 ]; then
  echo
  echo "Declare the module in its parent module, or add it to EXPECTED_UNWIRED in"
  echo "$0 with the reason it is deliberately test-only."
  exit 1
fi

echo "module wiring: every module under crates/*/src is declared by its parent"
