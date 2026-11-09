//! The helper is a picture, with no authority to post input or take focus.
use super::disclaimed_binary_paths::tokens;
use crate::support::source_scan;
use std::path::Path;

fn forbidden(source: &str) -> Vec<String> {
    let code = source_scan::shipped_code(source);
    code.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|token| {
            token.starts_with("CGEventPost")
                || matches!(
                    *token,
                    "SLEventPostToPid"
                        | "activateIgnoringOtherApps"
                        | "activate"
                        | "makeKeyAndOrderFront"
                )
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn cursor_helper_source_has_no_input_or_activation_calls() {
    let source = include_str!("../../../cerebellum-macos/src/cursor_overlay.rs");
    assert!(
        source.lines().count() > 100,
        "the helper scan must read the implementation"
    );
    assert!(
        forbidden(source).is_empty(),
        "helper calls forbidden APIs: {:?}",
        forbidden(source)
    );
    // Plant each API in the actual helper source, not a proxy file. The shared
    // scanner ignores comments and literals but retains callable selectors.
    for api in [
        "CGEventPost",
        "CGEventPostToPid",
        "SLEventPostToPid",
        "activateIgnoringOtherApps",
        "activate",
        "makeKeyAndOrderFront",
    ] {
        let planted = source.replace(
            "self.panel.orderFrontRegardless();",
            &format!("unsafe {{ objc2::msg_send![self.panel, {api}]; }}"),
        );
        assert_eq!(
            forbidden(&planted),
            [api],
            "positive control {api} was invisible"
        );
    }
    assert!(forbidden("// activate\n fn safe() { let s = \"CGEventPost\"; }").is_empty());
}

#[test]
fn cursor_capture_stays_desktop_independent_of_overlay_windows() {
    let source = include_str!("../../../cerebellum-macos/src/macos.rs");
    let code = source_scan::shipped_code(source);
    assert!(
        code.contains("initWithDesktopIndependentWindow"),
        "app capture must exclude every other window, including cursor pictures"
    );
    assert!(!code.contains("initWithDisplay_excludingWindows"));
}

fn declarations_are_gated(source: &str, declaration: &str, gate: &str) -> bool {
    let words = |source: &str| -> Vec<String> {
        tokens(source).into_iter().map(|token| token.text).collect()
    };
    let source = words(source);
    let declaration = words(declaration);
    let gate = words(gate);
    let mut found = false;
    for (index, candidate) in source.windows(declaration.len()).enumerate() {
        if candidate == declaration {
            found = true;
            if index < gate.len() || source[index - gate.len()..index] != gate {
                return false;
            }
        }
    }
    found
}

#[test]
fn single_window_capture_probe_module_and_exports_require_the_desk_probe_feature() {
    let overlay = include_str!("../../../cerebellum-macos/src/cursor_overlay.rs");
    let lib = include_str!("../../../cerebellum-macos/src/lib.rs");
    for (source, declaration, gate) in [
        (
            overlay,
            "mod capture_probe;",
            "#[cfg(feature = \"desk-probe\")]",
        ),
        (
            overlay,
            "pub use capture_probe::probe_overlay_capture_exclusion;",
            "#[cfg(feature = \"desk-probe\")]",
        ),
        (
            lib,
            "pub use cursor_overlay::probe_overlay_capture_exclusion;",
            "#[cfg(all(target_os = \"macos\", feature = \"desk-probe\"))]",
        ),
    ] {
        assert!(
            declarations_are_gated(source, declaration, gate),
            "ungated {declaration}"
        );
        // Remove the real gate and add a duplicate declaration independently:
        // either would compile probe code into builds that did not opt in.
        let unguarded = source.replace(gate, "");
        assert!(
            !declarations_are_gated(&unguarded, declaration, gate),
            "removed gate was invisible: {declaration}"
        );
        let duplicate = format!("{source}\n{declaration}");
        assert!(
            !declarations_are_gated(&duplicate, declaration, gate),
            "ungated duplicate was invisible: {declaration}"
        );
    }
}

fn display_capture_sources(directory: &Path, found: &mut Vec<String>) {
    for entry in std::fs::read_dir(directory).expect("read macOS sources") {
        let path = entry.expect("macOS source entry").path();
        if path.is_dir() {
            display_capture_sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let source = std::fs::read_to_string(&path).expect("read macOS source");
            if source.contains("initWithDisplay_excludingWindows") {
                found.push(path.to_string_lossy().into_owned());
            }
        }
    }
}

#[test]
fn display_capture_is_absent_and_the_probe_uses_production_single_window_capture() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../cerebellum-macos/src");
    let mut sources = Vec::new();
    display_capture_sources(&root, &mut sources);
    assert!(
        sources.is_empty(),
        "display capture is forbidden: {sources:?}"
    );
    let probe = source_scan::shipped_code(include_str!(
        "../../../cerebellum-macos/src/cursor_overlay/capture_probe.rs"
    ));
    assert!(
        probe.contains("capture_window("),
        "probe must use production's window capture"
    );
    // rustfmt may break a method chain across lines, so match the call with
    // whitespace removed rather than as one literal line.
    let compact: String = probe.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        compact.contains("content.windows()"),
        "probe must check the unfiltered shareable window list"
    );
    assert!(
        !probe.contains("SCScreenshotManager"),
        "probe must not implement its own capture path"
    );
    // Exercise the same recursive scan with a callable selector in a nested
    // shipped module, not just in the historically used macos.rs file.
    let planted = source_scan::scratch_directory("display-capture-scan");
    std::fs::create_dir(planted.join("nested")).unwrap();
    std::fs::write(
        planted.join("nested/escaped.rs"),
        "fn capture() { SCContentFilter::initWithDisplay_excludingWindows(); }",
    )
    .unwrap();
    let mut detected = Vec::new();
    display_capture_sources(&planted, &mut detected);
    std::fs::remove_dir_all(&planted).unwrap();
    assert_eq!(
        detected,
        [planted
            .join("nested/escaped.rs")
            .to_string_lossy()
            .into_owned()],
        "planted display capture was invisible"
    );
}

#[test]
fn cursor_helper_mode_is_selected_before_the_runtime_is_built() {
    let source = include_str!("../../src/main.rs");
    let helper_branch = source.find("arg == \"--agent-cursor\"").unwrap();
    let runtime = source.find("tokio::runtime::Builder").unwrap();
    assert!(helper_branch < runtime);
    assert!(!source.contains("#[tokio::main]"));
}

#[test]
fn cursor_avatar_work_never_runs_on_the_frame_reader() {
    let source = source_scan::shipped_code(include_str!("../../src/lib.rs"));
    let start = source.find("async fn module_loop<").unwrap();
    let end = source[start..].find("async fn send_hello(").unwrap() + start;
    let reader = &source[start..end];
    assert!(reader.contains("read_frame(read_half)"));
    for token in ["avatar", "render_tree", "fetch_and_render", "rasterize"] {
        assert!(
            !reader.contains(token),
            "avatar work on the frame reader: {token}"
        );
    }
}
