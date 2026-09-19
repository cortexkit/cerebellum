//! The module keeps one lease clock, and the compiler cannot say so.
//!
//! `SystemClock`'s epoch is fixed per instance, so two of them are not
//! comparable even though both produce a `MonoInstant`. A lease stamped by one
//! reads as long expired to the other, and the types agree at every step.
//!
//! That is not hypothetical here. Two consent sites built a fresh clock instead
//! of using the module's shared one: the ask settlement that MINTS a lease, and
//! `computer.open_target` itself. The result on a running module was that
//! `open_target` answered `already_held` with ten minutes remaining while every
//! computer action refused `no_lease` -- a remedy loop, since the refusal's
//! remedy was the call that had just succeeded. It stayed invisible while the module's
//! uptime was under the grant window and was total past it, which is why every
//! live probe had passed: each one ran minutes after a restart.
//!
//! A behavioural fence cannot reach this: reproducing it needs a module whose
//! uptime already exceeds a lease, and a freshly built `Planes` is always zero
//! seconds old. So the fence is structural -- exactly one construction site on
//! the production paths, the one that builds the module's own clock.

use std::path::Path;

/// Construction sites allowed outside test code, with the reason each exists.
const ALLOWED: &[(&str, &str)] = &[(
    "src/lib.rs",
    "the module's own lease clock, built once in Planes::new and shared by Arc",
)];

#[test]
fn only_the_module_lease_clock_is_constructed_on_production_paths() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    let mut files_scanned = 0;
    for file in rust_sources(&crate_root.join("src")) {
        files_scanned += 1;
        let relative = file
            .strip_prefix(crate_root)
            .expect("sources live under the crate root")
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(&file).expect("read a crate source file");
        for (line_number, line) in production_lines(&source) {
            if line.contains("SystemClock::new()") || line.contains("SystemClock::default()") {
                found.push((relative.clone(), line_number, line.trim().to_string()));
            }
        }
    }

    assert!(
        files_scanned > 0,
        "the scan found no sources under src, so it proved nothing"
    );
    // One message for both shapes, because the remedy is the same whether the
    // extra clock appeared in a new file or beside the allowed one.
    let allowed_total = ALLOWED.len();
    let offends = found
        .iter()
        .any(|(path, _, _)| !ALLOWED.iter().any(|(allowed, _)| allowed == path))
        || found.len() != allowed_total;
    assert!(
        !offends,
        "a second clock cannot share the first one's epoch, so a lease it stamps \
         reads as expired everywhere else. Take the module's clock from \
         planes.lease_clock instead of building one here.\nallowed:\n{}\nfound:\n{}",
        ALLOWED
            .iter()
            .map(|(path, reason)| format!("  {path}: {reason}"))
            .collect::<Vec<_>>()
            .join("\n"),
        found
            .iter()
            .map(|(path, line, text)| format!("  {path}:{line}: {text}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Every `.rs` file under a directory, recursively.
fn rust_sources(directory: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![directory.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files
}

/// Lines outside every `#[cfg(test)]` module, with their 1-based numbers.
///
/// Test code builds its own clocks deliberately and that is fine: a test owns
/// the whole timeline it measures. Skipping by brace balance rather than by
/// "everything after the first test module", because this crate's largest file
/// carries production code after one test module and before the next.
fn production_lines(source: &str) -> Vec<(usize, &str)> {
    let mut kept = Vec::new();
    let mut skipping_from_depth: Option<i32> = None;
    let mut depth = 0_i32;
    let mut pending_test_module = false;
    for (index, line) in source.lines().enumerate() {
        let opens = line.matches('{').count() as i32;
        let closes = line.matches('}').count() as i32;
        if skipping_from_depth.is_none() {
            if pending_test_module && line.contains("mod ") && line.contains('{') {
                skipping_from_depth = Some(depth);
                pending_test_module = false;
                depth += opens - closes;
                continue;
            }
            if line.trim_start().starts_with("#[cfg(test)]") {
                pending_test_module = true;
                depth += opens - closes;
                continue;
            }
            kept.push((index + 1, line));
        }
        depth += opens - closes;
        if let Some(entered_at) = skipping_from_depth {
            if depth <= entered_at {
                skipping_from_depth = None;
            }
        }
    }
    kept
}

#[test]
fn the_scan_skips_test_modules_and_keeps_production_lines() {
    let source = "fn a() { let _ = SystemClock::new(); }\n\
                  #[cfg(test)]\n\
                  mod tests {\n\
                  let _ = SystemClock::new();\n\
                  }\n\
                  fn b() { let _ = SystemClock::default(); }\n";
    let kept: Vec<_> = production_lines(source)
        .into_iter()
        .filter(|(_, line)| line.contains("SystemClock"))
        .collect();

    assert_eq!(
        kept.len(),
        2,
        "the scan must keep both production lines and drop the one inside the test module: {kept:?}"
    );
    assert!(kept.iter().any(|(_, line)| line.contains("fn a()")));
    assert!(kept.iter().any(|(_, line)| line.contains("fn b()")));
}
