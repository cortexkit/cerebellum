//! Invoke one live control through the seam's own COM code and read back
//! whether anything changed.
//!
//! `invoke_accessibility_element` reports `HandlerReturned`, which means the
//! provider's invoke handler returned success and nothing more. The tree read
//! afterwards is what turns delivery into an observed effect: the probe reads
//! the target before and after, and reports whether the invoked key is still
//! present. A control whose invocation removes it (a dismiss button on a
//! banner) makes that a decisive observable; one that stays put makes the
//! before/after comparison uninformative and the probe says so.
//!
//! Usage: `live_invoke <pid> <automation_id>`
//!
//! Run it from an interactive session; see `live_accessibility` for why.

#[cfg(target_os = "windows")]
fn main() {
    use std::time::{Duration, Instant};

    use cerebellum_windows::{
        current_session_provenance, invoke_accessibility_element, read_accessibility_tree,
        AccessibilityInvokeBounds, AccessibilityReadBounds, UiaElement, UiaElementName,
    };

    let mut args = std::env::args().skip(1);
    let (Some(pid), Some(automation_id)) = (
        args.next().and_then(|raw| raw.parse::<u32>().ok()),
        args.next(),
    ) else {
        eprintln!("usage: live_invoke <pid> <automation_id>");
        std::process::exit(2);
    };

    fn count_key(element: &UiaElement, key: &str, hits: &mut usize, total: &mut usize) {
        *total += 1;
        if element.identity.automation_id.as_deref() == Some(key) {
            *hits += 1;
        }
        for child in &element.children {
            count_key(child, key, hits, total);
        }
    }
    let read = |label: &str| -> Option<(usize, usize)> {
        let bounds = AccessibilityReadBounds {
            timeout: Duration::from_millis(5_000),
            max_depth: 12,
            max_elements: 2_000,
        };
        match read_accessibility_tree(pid, bounds) {
            Ok(tree) => {
                let mut hits = 0;
                let mut total = 0;
                for root in &tree.roots {
                    count_key(root, &automation_id, &mut hits, &mut total);
                }
                println!(
                    "{label}: elements={total} matching {automation_id:?}={hits} completeness={:?}",
                    tree.completeness
                );
                Some((hits, total))
            }
            Err(failure) => {
                println!("{label}: read failed: {failure:?}");
                None
            }
        }
    };

    println!("session: {:?}", current_session_provenance());
    let Some((before_hits, before_total)) = read("before") else {
        std::process::exit(1);
    };

    let name = UiaElementName::AutomationId(automation_id.clone());
    let bounds = AccessibilityInvokeBounds {
        timeout: Duration::from_millis(5_000),
        max_depth: 12,
        max_elements: 2_000,
    };
    let started = Instant::now();
    let outcome = invoke_accessibility_element(pid, &name, bounds);
    println!("invoke took: {:?}", started.elapsed());
    match &outcome {
        Ok(outcome) => println!("invoke: {outcome:?}"),
        Err(error) => {
            println!("invoke refused: {error:?}");
            std::process::exit(1);
        }
    }

    // Give the provider a moment to apply the effect before reading back.
    std::thread::sleep(Duration::from_millis(500));
    let Some((after_hits, after_total)) = read("after") else {
        std::process::exit(1);
    };

    if before_hits == 1 && after_hits == 0 {
        println!(
            "VERDICT: the invoked control is gone ({before_total} -> {after_total} elements), so the handler did something observable"
        );
    } else if before_hits == after_hits && before_total == after_total {
        println!("VERDICT: the tree is unchanged; this key does not produce an observable this probe can read");
    } else {
        println!("VERDICT: the tree changed ({before_total} -> {after_total} elements) but the key is still present");
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("this probe invokes a Windows UI Automation element and does nothing elsewhere");
}
