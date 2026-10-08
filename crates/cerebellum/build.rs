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
    //
    // Paths come from `git rev-parse --git-path`, never `../../.git/...`: in a
    // worktree `.git` is a file, so those paths do not exist, and the watch
    // either names a missing path (cargo then reruns this script on every
    // build) or silently watches nothing. Watched: HEAD, the branch it points
    // at, packed-refs (where a moved ref can live instead), and the index
    // (staging and committing both rewrite it). A missing one is never named.
    let mut watched = Vec::new();
    for name in ["HEAD", "packed-refs", "index"] {
        watched.extend(git_path(name));
    }
    if let Some(branch) = git(["symbolic-ref", "-q", "HEAD"]) {
        watched.extend(git_path(&branch));
    }
    for path in watched {
        if Path::new(&path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }

    let rev = git(["rev-parse", "HEAD"]);

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
    // `--no-optional-locks`: a plain status refreshes the index's stat cache
    // and rewrites the index, which is watched above, so every build would
    // dirty the next one and this crate would never be fresh.
    let dirty = Command::new("git")
        .args(["--no-optional-locks", "status", "--porcelain"])
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

/// One trimmed line of git output, or `None` when git fails or prints nothing.
fn git<const N: usize>(args: [&str; N]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

/// Where `name` lives for this checkout, as an absolute path, so a worktree
/// resolves into its own git directory and the shared one as git does.
fn git_path(name: &str) -> Option<String> {
    let path = git(["rev-parse", "--path-format=absolute", "--git-path", name])?;
    Some(path)
}
