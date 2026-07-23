//! ck-cerebellum binary entry point.
//!
//! The library (`lib.rs`) owns all module logic; this file is the thin OS entry
//! point that delegates to [`cerebellum::run_entry`] on the tokio runtime.

#[tokio::main]
async fn main() -> Result<(), cerebellum::ModuleError> {
    cerebellum::run_entry().await
}
