//! Mechanical enforcement of the plane-agnostic boundary.
//!
//! `cerebellum-core` is the substrate shared one-way by every plane's module
//! crate, so it must never couple to a plane's technology. These tests prove
//! that mechanically instead of asserting it in a comment:
//!
//! 1. [`manifest_has_no_plane_dependencies`] reads this crate's own
//!    `Cargo.toml` and fails if any browser/CDP or macOS/GUI-framework crate
//!    appears as a dependency.
//! 2. [`sources_contain_no_plane_types`] walks this crate's own `src/` and
//!    fails if any browser-plane or desktop-plane type identifier appears in
//!    the substrate's source.
//!
//! To cover a new plane, extend the explicit forbidden lists below — a new
//! dependency or type then fails the build the moment it lands.

/// Browser-plane dependency names that would couple the substrate to CDP
/// automation. Names are compared after normalizing `_`/`-` and case.
const FORBIDDEN_BROWSER_DEPS: &[&str] = &["chromiumoxide", "fantoccini", "headless-chrome"];

/// macOS/desktop-plane dependency names that would couple the substrate to a
/// GUI or desktop-automation framework.
const FORBIDDEN_DESKTOP_DEPS: &[&str] = &[
    "core-graphics",
    "core-foundation",
    "cocoa",
    "screencapturekit",
    "accessibility",
    "objc",
    "objc2",
];

/// Forbidden dependency-name prefixes: any crate whose normalized name starts
/// with one of these couples the substrate to a plane. `cdp` covers every
/// `cdp*` browser-protocol crate; the `objc` prefixes cover the objc/objc2
/// bridge family.
const FORBIDDEN_DEP_PREFIXES: &[&str] = &["cdp", "objc-", "objc2-"];

/// Browser-plane type identifiers that must never appear in the substrate.
const FORBIDDEN_BROWSER_TYPES: &[&str] =
    &["TypeTarget", "ClassificationRecord", "BrowserTypeExecutor"];

/// Desktop-plane (macOS GUI/automation) type identifiers that must never
/// appear in the substrate.
const FORBIDDEN_DESKTOP_TYPES: &[&str] = &[
    "AXUIElement",
    "CGEvent",
    "SLEventPostToPid",
    "SCStream",
    "PlatformDriver",
    "MacOs26PlatformDriver",
    "ComputerActionVocabulary",
    "CapabilityDeclaration",
    "PermissionLivenessProbe",
    "PrivateEnvelopeStartupProbe",
    "StartupCapabilityProbe",
    "FrontingSnapshot",
];

/// Identifier prefix forbidden anywhere in the substrate source: `browser_*`
/// names belong to the browser plane's surface, not the shared substrate.
const FORBIDDEN_TYPE_PREFIXES: &[&str] = &["browser_"];

/// Normalize a crate/identifier name for comparison: lowercase and treat `_`
/// and `-` as equivalent (Cargo allows either spelling for the same crate).
fn normalize(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('_', "-")
}

/// If a dependency line renames its package (`alias = { package = "real", .. }`),
/// return the real package name; the forbidden check must see through renames.
fn renamed_package(value: &str) -> Option<String> {
    let idx = value.find("package")?;
    let rest = value[idx + "package".len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = &rest[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(normalize(&rest[..end]))
}

/// Extract the package names declared as dependencies in a Cargo manifest.
///
/// Handles both declaration forms: an inline `name = ...` entry inside a
/// `[dependencies]` / `[dev-dependencies]` / `[build-dependencies]` table
/// (including target-scoped `[target.'..'.dependencies]`), and a
/// `[dependencies.name]` table header. A `package = "real"` rename is resolved
/// to the real package name so a forbidden crate cannot be hidden behind an
/// alias.
fn declared_dependency_names(manifest: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_dep_table = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            let header = header.trim();
            // A bare `[dependencies]`-style table (optionally target-scoped)
            // holds `name = ...` entries on the lines that follow it.
            in_dep_table = header == "dependencies"
                || header == "dev-dependencies"
                || header == "build-dependencies"
                || header.ends_with(".dependencies")
                || header.ends_with(".dev-dependencies")
                || header.ends_with(".build-dependencies");
            // A `[dependencies.name]` table header names the dependency itself.
            for section in ["dependencies.", "dev-dependencies.", "build-dependencies."] {
                if let Some(name) = header.strip_prefix(section) {
                    names.push(normalize(name));
                }
            }
            continue;
        }
        if !in_dep_table {
            continue;
        }
        // Inside a dependencies table, a top-level `key = value` declares a
        // dependency named `key`. Nested keys (dotted, or with interior spaces)
        // are not dependency names.
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if key.is_empty() || key.contains(' ') || key.contains('.') {
                continue;
            }
            names.push(normalize(key));
            if let Some(real) = renamed_package(value) {
                names.push(real);
            }
        }
    }
    names
}

#[test]
fn manifest_has_no_plane_dependencies() {
    let manifest = include_str!("../Cargo.toml");
    let names = declared_dependency_names(manifest);

    // Guard against a parser regression that finds nothing (which would make
    // the forbidden checks below pass vacuously). The substrate always depends
    // on the fleet wire contract, so that dependency must be detected.
    assert!(
        names.iter().any(|name| name == "subc-protocol"),
        "expected to parse cerebellum-core's dependencies, got: {names:?}"
    );

    for name in &names {
        for forbidden in FORBIDDEN_BROWSER_DEPS.iter().chain(FORBIDDEN_DESKTOP_DEPS) {
            assert_ne!(
                name, forbidden,
                "cerebellum-core must not depend on the plane crate `{forbidden}` (found `{name}`)"
            );
        }
        for prefix in FORBIDDEN_DEP_PREFIXES {
            assert!(
                !name.starts_with(prefix),
                "cerebellum-core must not depend on a `{prefix}*` plane crate (found `{name}`)"
            );
        }
    }
}

/// Recursively read and concatenate every `.rs` source file under a directory.
fn read_all_sources(dir: &std::path::Path) -> String {
    let mut combined = String::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current).expect("read source directory") {
            let path = entry.expect("read directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                combined.push_str(&std::fs::read_to_string(&path).expect("read source file"));
                combined.push('\n');
            }
        }
    }
    combined
}

#[test]
fn sources_contain_no_plane_types() {
    // Scan only `src/` (not this `tests/` file, which necessarily names the
    // forbidden identifiers in the lists above).
    let src_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = read_all_sources(&src_dir);
    assert!(
        !sources.is_empty(),
        "expected to read cerebellum-core sources under {}",
        src_dir.display()
    );

    for forbidden in FORBIDDEN_BROWSER_TYPES
        .iter()
        .chain(FORBIDDEN_DESKTOP_TYPES)
    {
        assert!(
            !sources.contains(forbidden),
            "cerebellum-core sources must not reference the plane type `{forbidden}`"
        );
    }
    for prefix in FORBIDDEN_TYPE_PREFIXES {
        assert!(
            !sources.contains(prefix),
            "cerebellum-core sources must not reference any `{prefix}*` browser-plane identifier"
        );
    }
}
