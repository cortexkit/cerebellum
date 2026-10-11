//! The acceptance-only parent identity must not enter the shipped build.

const PROBE_FEATURE: &str = "chrome-for-testing-parent-probe";

fn release_enables_probe(script: &str) -> bool {
    // Conservative by design: even an indirect feature spelling or an
    // all-features switch in the release script requires a fresh review.
    script.contains(PROBE_FEATURE) || script.contains("--all-features")
}

#[test]
fn release_build_does_not_enable_the_cft_parent_probe() {
    let script = include_str!("../../../scripts/release-build.sh");
    assert!(
        !release_enables_probe(script),
        "the release script enables the probe override"
    );
    // The compile-time exclusion consumes this very binding. It also rejects
    // a caller forwarding a probe feature through the script's "$@" arguments.
    assert!(
        script.contains("export CEREBELLUM_RELEASE_SIGNING_TOPOLOGY_REVISION=\""),
        "the release script must bind the probe exclusion before building"
    );
    let manifest = include_str!("../Cargo.toml");
    let features = manifest
        .split("[features]")
        .nth(1)
        .unwrap()
        .split("[lib]")
        .next()
        .unwrap();
    assert!(
        features.lines().any(|line| line.trim() == "default = []"),
        "probe support must not be enabled through default features"
    );
}

#[test]
fn release_feature_scan_detects_planted_overrides() {
    assert!(release_enables_probe(
        "cargo build --features cerebellum-macos/chrome-for-testing-parent-probe"
    ));
    assert!(release_enables_probe("cargo build --all-features"));
    assert!(!release_enables_probe(
        "cargo build --release --locked -p cerebellum"
    ));
}
