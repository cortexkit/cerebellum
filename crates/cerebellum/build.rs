//! Bind the commit this binary was built from into the binary itself.
//!
//! Staging asks the artifact what it is and refuses to publish bytes that
//! disagree with the tree. That check is only worth anything if the answer
//! comes from the build rather than from the caller: a rev passed in as an
//! environment variable is a claim the staging script makes about itself, and
//! it stays true-looking when the build it describes did not run.
//!
//! Read here instead, so a reused target directory reports the commit it was
//! actually compiled from.

use std::path::Path;
use std::process::Command;

fn main() {
    // Rebuild when the checked-out commit moves. Without these, a rebuild after
    // a commit can reuse the cached crate and report the previous rev -- the
    // exact staleness this exists to catch, produced by the catcher.
    let git = Path::new("../../.git");
    for path in ["HEAD", "refs"] {
        let watched = git.join(path);
        if watched.exists() {
            println!("cargo:rerun-if-changed={}", watched.display());
        }
    }

    let rev = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|rev| !rev.is_empty());

    // "unknown" rather than a failed build: a source tarball with no git
    // directory is a legitimate way to build this, and it should produce a
    // binary that says it cannot name its commit. Staging refuses that value,
    // so the honest answer still cannot be published by accident.
    let rev = rev.unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=CEREBELLUM_BUILD_REV={rev}");

    // Whether the tree had uncommitted changes at build time. A clean rev is
    // not enough on its own: a dirty tree produces bytes that no commit
    // describes, and the rev it reports would name a commit that does not
    // contain them.
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false);
    println!(
        "cargo:rustc-env=CEREBELLUM_BUILD_TREE={}",
        if dirty { "dirty" } else { "clean" }
    );
}
