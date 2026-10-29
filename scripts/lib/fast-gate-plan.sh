# Shared diff planner for the fast gate and its self-tests.
# Arguments: newline-separated changed paths and cargo metadata JSON.
plan_for_files() {
  FAST_GATE_METADATA="$2" FAST_GATE_FILES="$1" python3 - <<'PY'
import json
import os
from fnmatch import fnmatchcase
from pathlib import Path
import sys

metadata = json.loads(os.environ["FAST_GATE_METADATA"])
files = [line for line in os.environ["FAST_GATE_FILES"].splitlines() if line]
if not files:
    print("refusing to plan an empty diff", file=sys.stderr)
    sys.exit(2)

root = Path.cwd().resolve()
packages = metadata["packages"]
workspace_wide = any(
    path in {"Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml"}
    or path.startswith(".cargo/")
    for path in files
)
selected_packages = set()
selected_suites = set()

# Some sources live at the repo root but are compiled into a crate with
# include_str!, so a path-containment match never selects that crate. Map them
# explicitly, or a change to the data slips past the test that parses it.
root_file_packages = {"engram-catalog.json": "cerebellum-core"}
for path in files:
    owner = root_file_packages.get(path)
    if owner:
        selected_packages.add(owner)

for package in packages:
    manifest = Path(package["manifest_path"]).resolve()
    package_root = manifest.parent
    if workspace_wide:
        selected_packages.add(package["name"])
        continue
    for relative in files:
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(package_root)
        except ValueError:
            continue
        selected_packages.add(package["name"])
        if not candidate.is_relative_to(package_root / "tests"):
            continue
        test_targets = [target for target in package["targets"] if "test" in target["kind"]]
        mapped = set()
        for target in test_targets:
            source = Path(target["src_path"]).resolve()
            if candidate == source:
                mapped.add(target["name"])
            elif source.name == "main.rs" and candidate.is_relative_to(source.parent):
                mapped.add(target["name"])
        if not mapped:
            # An unrecognized helper, fixture, or module path may be shared by
            # several test targets, so run every integration suite in its crate.
            mapped.update(target["name"] for target in test_targets)
        selected_suites.update((package["name"], suite) for suite in mapped)

# Standalone integration binaries are not part of --lib or the consolidated
# `it` target. Select them from the shipped sources they exercise, even when
# none of their test files changed. Globs are relative to cerebellum's src/;
# fnmatch's * also covers nested modules and future files in the same area.
browser_sources = (
    "browser*", "user_browser*", "cdp/*", "classification.rs", "coordinate.rs",
    "snapshot_store.rs", "network/*", "profile/*", "profile_custody/*",
    "login*", "private_content.rs", "public_suffix.rs",
)
dispatch_sources = (
    "lib.rs", "wire.rs", "tool_provider.rs", "tool_result*", "flat_tools.rs",
    "manifest.rs", "authorization.rs", "agent_grants*", "grant_enforcement.rs",
    "permission*", "call_*", "blocking_permits.rs",
    "budgets.rs", "consent*", "cingulate_client/*", "terminal_arbiter.rs",
    "turn_ended.rs",
)
lifecycle_sources = (
    "lib.rs", "main.rs", "browser_session*", "browser_launch*", "user_browser*",
    "scope_watch.rs", "consent_drain.rs", "call_record_supervisor.rs",
    "terminal_arbiter.rs", "turn_ended.rs",
)
standalone_sources = {
    "browser_own_golden": browser_sources + dispatch_sources,
    "browser_session_wire": browser_sources + dispatch_sources,
    "computer_grant_store_health": ("lib.rs", "computer_grants*", "durable_formats.rs"),
    # Conformance spans HELLO, manifests, binds, health, dispatch and live daemon
    # registration, so it has no single narrow source area. Its Linux run takes
    # about 7 s once built, small enough to protect every cerebellum src change.
    "conformance": ("*",),
    "flow_live": browser_sources + dispatch_sources + (
        "main.rs", "computer*", "scope_watch.rs", "management*",
        "launch_nonce.rs", "launch_recovery.rs", "content_named_fixture.rs",
    ),
    # Linux already runs format_floor unconditionally. Selecting its source
    # areas also exercises the platform-gated store tests in the Mac half.
    "format_floor": (
        "lib.rs", "durable_formats.rs", "computer_grants*", "browser_standing_grants.rs",
        "profile/*", "profile_custody/*", "journal*",
    ),
    "hardware_observer_health": ("lib.rs", "computer_capability/*"),
    "manifest_flag": (
        "lib.rs", "main.rs", "manifest.rs", "browser_config.rs", "flat_tools.rs",
        "content_named_fixture.rs",
    ),
    "scope_revocation_live": lifecycle_sources + (
        "management*", "agent_grants*", "authorization.rs", "browser_standing_grants.rs",
        "cingulate_client/*", "content_named_fixture.rs",
    ),
    "shutdown_endings": lifecycle_sources,
    "vault_deposit_live": (
        "lib.rs", "manifest.rs", "launch_nonce.rs", "login_capture/*",
        "content_named_fixture.rs",
    ),
}
cerebellum = next((package for package in packages if package["name"] == "cerebellum"),
                  {"targets": []})
cerebellum_tests = {
    target["name"] for target in cerebellum["targets"] if "test" in target["kind"]
}
all_cerebellum_suites = workspace_wide or "crates/cerebellum/Cargo.toml" in files
for suite, patterns in standalone_sources.items():
    if suite in cerebellum_tests and (all_cerebellum_suites or any(
        path.startswith("crates/cerebellum/src/")
        and any(fnmatchcase(path.removeprefix("crates/cerebellum/src/"), pattern)
                for pattern in patterns)
        for path in files
    )):
        selected_suites.add(("cerebellum", suite))

# The observer gauge is implemented in the macOS dependency, not in its
# cerebellum consumer. A dependency-only change must still exercise that gauge.
if "hardware_observer_health" in cerebellum_tests and any(
    path in {"crates/cerebellum-macos/src/event_tap.rs", "crates/cerebellum-macos/src/lib.rs"}
    for path in files
):
    selected_suites.add(("cerebellum", "hardware_observer_health"))

# Each crate's consolidated `it` target holds the source scans over that crate's
# shipped code. cerebellum's covers the single launch-secret reader, zero
# runtime prints, declared launch-path outcome words, the one lease clock,
# private file writes and more; cerebellum-core's keeps the crate free of plane
# identifiers. Each scan reads files under src/, so a change there can break one
# while no test file changed, and a hand-picked subset of modules misses
# whichever scan reads the changed file. So whenever a package is selected, run
# its whole `it` target. cerebellum's takes about 15 s once built, and the gate
# builds it either way.
for name in selected_packages:
    package = next(package for package in packages if package["name"] == name)
    if any(
        target["name"] == "it" and "test" in target["kind"]
        for target in package["targets"]
    ):
        selected_suites.add((name, "it"))

for name in sorted(selected_packages):
    print(f"P|{name}")
    package = next(package for package in packages if package["name"] == name)
    if any("lib" in target["kind"] for target in package["targets"]):
        print(f"L|{name}")
for package, suite in sorted(selected_suites):
    print(f"T|{package}|{suite}")
for package in packages:
    for target in package["targets"]:
        if "test" in target["kind"]:
            print(f"S|{package['name']}|{target['name']}")
for required in (
    "tool-catalog-and-schema-bytes",
    "flat-tools-fingerprints",
    "format-floor-and-journal-formats",
    "launch-secret-single-reader",
    "zero-prints",
    "module-wiring",
):
    print(f"A|{required}")
PY
}
