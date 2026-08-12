//! Read a real application's accessibility tree.
//!
//! Read-only by construction: it inspects elements and performs no action.
//! A probe rather than a test, because it needs a granted permission and a
//! running application, so as a test it would skip in most runs.

fn main() {
    let pid: u32 = std::env::args()
        .nth(1)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or_else(|| {
            let out = std::process::Command::new("pgrep")
                .args(["-x", "Finder"])
                .output()
                .expect("pgrep runs");
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .lines()
                .next()
                .expect("Finder is running")
                .parse()
                .expect("a pid")
        });

    println!(
        "permitted: {}",
        cerebellum_macos::accessibility_is_permitted()
    );
    println!("target pid: {pid}");

    let started = std::time::Instant::now();
    match cerebellum_macos::read_accessibility_tree(pid, Default::default()) {
        Ok(tree) => {
            let complete = tree.completeness == cerebellum_macos::AxTreeCompleteness::Complete;
            let mut elements = 0usize;
            let mut with_actions = 0usize;
            let mut identified = 0usize;
            let mut depth = 0usize;
            let mut roles: std::collections::BTreeMap<String, usize> = Default::default();

            fn walk(
                e: &cerebellum_macos::AxElement,
                d: usize,
                elements: &mut usize,
                with_actions: &mut usize,
                identified: &mut usize,
                depth: &mut usize,
                roles: &mut std::collections::BTreeMap<String, usize>,
            ) {
                *elements += 1;
                *depth = (*depth).max(d);
                if !e.actions.is_empty() {
                    *with_actions += 1;
                }
                if e.identifier.is_some() {
                    *identified += 1;
                }
                if let Some(role) = &e.role {
                    roles
                        .entry(role.clone())
                        .and_modify(|n| *n += 1)
                        .or_insert(1);
                }
                for child in &e.children {
                    walk(
                        child,
                        d + 1,
                        elements,
                        with_actions,
                        identified,
                        depth,
                        roles,
                    );
                }
            }
            walk(
                &tree.root,
                0,
                &mut elements,
                &mut with_actions,
                &mut identified,
                &mut depth,
                &mut roles,
            );

            println!("read in {:?}", started.elapsed());
            println!("  complete:            {complete}   <- an incomplete tree cannot establish uniqueness, so no action may be requested against it");
            println!("  elements:            {elements}");
            println!("  max depth:           {depth}");
            println!("  advertise an action: {with_actions}");
            println!("  carry an identifier: {identified}   <- what an action can name");
            println!("  top roles:");
            let mut by_count: Vec<_> = roles.into_iter().collect();
            by_count.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            for (role, n) in by_count.into_iter().take(6) {
                println!("    {role:32} {n}");
            }
        }
        Err(error) => println!("REFUSED: {error:?}"),
    }
}
