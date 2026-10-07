//! The helper is a picture, with no authority to post input or take focus.
use crate::support::source_scan;

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

#[test]
fn cursor_helper_mode_is_selected_before_the_runtime_is_built() {
    let source = include_str!("../../src/main.rs");
    let helper_branch = source.find("arg == \"--agent-cursor\"").unwrap();
    let runtime = source.find("tokio::runtime::Builder").unwrap();
    assert!(helper_branch < runtime);
    assert!(!source.contains("#[tokio::main]"));
}
