//! Print the highest version of each durable format this tree reads, as JSON:
//! `{"<format>": <version>, ...}`.
//!
//! Staging runs this from the tree it is about to stage and compares the
//! result with the format floor on the operator's disk, refusing a build that
//! could not read a record already written there. The values come from
//! `durable_formats::readable_formats`, which takes each one from the
//! constant that format's reader checks, so this cannot drift from what the
//! build actually reads.

use std::collections::BTreeMap;

fn main() {
    let versions: BTreeMap<&str, u64> = cerebellum::durable_formats::readable_formats()
        .into_iter()
        .map(|format| (format.name, format.version))
        .collect();
    println!(
        "{}",
        serde_json::to_string(&versions).expect("a map of names to numbers serializes")
    );
}
