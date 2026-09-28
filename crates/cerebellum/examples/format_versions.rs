//! Print, as JSON, the highest version of each durable format this tree
//! reads and the floor file of each data tree on this host:
//! `{"supported": {"<format>": <version>, ...},
//!   "floor_paths": {"journal": "<path>", "browser": "<path>"}}`.
//!
//! Staging runs this from the tree it is about to stage and compares the
//! supported versions with the floors on the operator's disk, refusing a
//! build that could not read a record already written there. The versions
//! come from `durable_formats::readable_formats`, which takes each one from
//! the constant that format's reader checks, and the paths from the same
//! data-home resolver the module's stores use, so staging reimplements
//! neither.

use serde_json::json;

fn main() {
    let Some(floor_paths) = cerebellum::durable_formats::floor_paths() else {
        eprintln!("no absolute data home resolves on this host, so no floor can be located");
        std::process::exit(1);
    };
    let supported: std::collections::BTreeMap<&str, u64> =
        cerebellum::durable_formats::readable_formats()
            .into_iter()
            .map(|format| (format.name, format.version))
            .collect();
    println!(
        "{}",
        json!({"supported": supported, "floor_paths": floor_paths})
    );
}
