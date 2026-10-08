//! Read-only installed-app inventory measurement. Never opens an application,
//! reads its signature or windows, requests permissions, or writes a journal.
//!
//! Build locally before invoking the probe:
//! `cargo build --locked -p cerebellum-macos --example installed_apps_inventory && target/debug/examples/installed_apps_inventory`

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("installed-app inventory requires macOS");
}

#[cfg(target_os = "macos")]
fn main() {
    use std::time::{Duration, Instant};

    if std::env::args().any(|argument| argument == "--version") {
        println!("installed_apps_inventory {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let start = Instant::now();
    let inventory = cerebellum_macos::installed_applications(Duration::from_secs(2));
    println!("app_count={}", inventory.apps.len());
    println!("complete={}", inventory.complete);
    println!("elapsed_ms={}", start.elapsed().as_millis());
    println!("scan_depth=one subfolder level; never inside application bundles");
    println!("unreadable_entries={}", inventory.unreadable.len());
    for failure in &inventory.unreadable {
        println!("partial: {} | {}", failure.path.display(), failure.reason);
    }
    for target in ["Adobe Photoshop", "Calculator"] {
        let matches: Vec<_> = inventory
            .apps
            .iter()
            .filter(|app| app.name.trim().eq_ignore_ascii_case(target))
            .collect();
        println!(
            "target={target:?} unique={} matches={}",
            matches.len() == 1,
            matches.len()
        );
        for app in matches {
            println!(
                "match: {} | {} | {}",
                app.name,
                app.bundle_identifier,
                app.path.display()
            );
        }
    }
}
