//! ck-cerebellum binary entry point.
//!
//! The library (`lib.rs`) owns all module logic; this file is the thin OS entry
//! point that delegates to [`cerebellum::run_entry`] on the tokio runtime.

/// What this binary was built from, bound at compile time by `build.rs`.
///
/// Answered before anything else so it works on a binary that cannot start:
/// staging asks the bytes it is about to publish what they are, and a binary
/// that must first connect to a daemon could not answer during staging.
fn print_version() {
    println!(
        "ck-cerebellum ({}) tree={}",
        env!("CEREBELLUM_BUILD_REV"),
        env!("CEREBELLUM_BUILD_TREE")
    );
}

#[tokio::main]
async fn main() -> Result<(), cerebellum::ModuleError> {
    if std::env::args().skip(1).any(|arg| arg == "--version") {
        print_version();
        return Ok(());
    }
    cerebellum::run_entry().await
}
