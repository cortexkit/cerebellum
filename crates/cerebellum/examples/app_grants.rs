//! List and revoke the operator's durable "always allow" app grants.
//!
//! The same listing and revoke the module serves as the management operations
//! `computer.list_app_grants` and `computer.revoke_app_grant`, run directly on
//! the grant store under the cerebellum data home. A running module reads the
//! store once when it starts, so run this while the module is stopped, or use
//! the management operations against the running module instead: a revoke
//! written here is not seen by a module that is already running, and that
//! module could write the record back.
//!
//! Records bound to another machine (restored from a backup, for instance) are
//! listed apart; they grant nothing on this machine.
//!
//! Revoking is a dry run unless `--apply` is given, so the first run shows what
//! would be removed.
//!
//! Run:
//!   cargo run -p cerebellum --example app_grants -- list
//!   cargo run -p cerebellum --example app_grants -- revoke <grantee> <bundle_identity> [--apply]

use std::process::ExitCode;
use std::sync::Arc;

use cerebellum::computer_grants::{this_machine_uuid, ComputerGrants, FilesystemGrantStorage};

fn usage() -> ExitCode {
    eprintln!(
        "usage: app_grants list\n       app_grants revoke <grantee> <bundle_identity> [--apply]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let storage = match FilesystemGrantStorage::production() {
        Ok(storage) => storage,
        Err(error) => {
            eprintln!("the grant store's location could not be resolved: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("grant store: {}", storage.path().display());
    let grants = ComputerGrants::open(Arc::new(storage), this_machine_uuid());

    let reply = match arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["list"] => grants.list(),
        ["revoke", grantee, bundle_identity] => grants.revoke(grantee, bundle_identity, true),
        ["revoke", grantee, bundle_identity, "--apply"] => {
            grants.revoke(grantee, bundle_identity, false)
        }
        _ => return usage(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&reply).unwrap_or_else(|_| reply.to_string())
    );
    if reply.get("outcome").and_then(|outcome| outcome.as_str()) == Some("would_revoke") {
        println!("dry run: nothing was written; pass --apply to revoke");
    }
    ExitCode::SUCCESS
}
