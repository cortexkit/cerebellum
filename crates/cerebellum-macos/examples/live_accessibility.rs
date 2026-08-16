//! Read a real application's accessibility tree.
//!
//! Read-only by construction: it inspects elements and performs no action.
//! A probe rather than a test, because it needs a granted permission and a
//! running application, so as a test it would skip in most runs.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe reads a macOS accessibility tree and has nothing to run here");
}

#[cfg(target_os = "macos")]
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

    // Overridable so the probe can answer what a real application NEEDS rather
    // than only whether the shipped default happens to suit it. A refusal at the
    // default is not itself a measurement: the useful number is the budget at
    // which the same read succeeds.
    let options = cerebellum_macos::AxReadOptions {
        timeout: std::env::var("CK_AX_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| cerebellum_macos::AxReadOptions::default().timeout),
        max_depth: std::env::var("CK_AX_MAX_DEPTH")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| cerebellum_macos::AxReadOptions::default().max_depth),
        max_elements: std::env::var("CK_AX_MAX_ELEMENTS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| cerebellum_macos::AxReadOptions::default().max_elements),
    };
    println!(
        "timeout: {:?}  max_depth: {}  max_elements: {}",
        options.timeout, options.max_depth, options.max_elements
    );

    let started = std::time::Instant::now();
    match cerebellum_macos::read_accessibility_tree(pid, options) {
        Ok(tree) => {
            let complete = tree.completeness == cerebellum_macos::AxTreeCompleteness::Complete;
            let mut elements = 0usize;
            let mut with_actions = 0usize;
            let mut identified = 0usize;
            let mut depth = 0usize;
            let mut roles: std::collections::BTreeMap<String, usize> = Default::default();
            // Every identifier seen, so duplicates can be counted. The action
            // path refuses an identifier that more than one element reports, so
            // a control carrying a shared identifier is unaddressable however
            // well it advertises its action.
            let mut identifiers: std::collections::BTreeMap<String, usize> = Default::default();
            // Controls a caller would plausibly click, and the subset our
            // closed vocabulary can actually ask to act.
            let mut controls = 0usize;
            let mut controls_pressable: Vec<Option<String>> = Vec::new();
            // A candidate alternative addressing scheme, measured beside the
            // one we ship. Uniqueness is the property the action path needs;
            // AXIdentifier is only the current way of establishing it, so the
            // decision-relevant question is how many controls some OTHER key
            // separates that the identifier does not.
            let mut role_title: std::collections::BTreeMap<(String, String), usize> =
                Default::default();
            let mut controls_role_title: Vec<(String, String)> = Vec::new();
            // Whether each pressable control sits inside rendered page content.
            // A browser's tree contains both its own interface and whatever the
            // open pages happen to show, and counting them together describes
            // the web rather than the application -- every link on every page
            // lands in the denominator. Page content belongs to the browser
            // plane, which addresses it through CDP, so the computer plane's
            // reach over a browser is the OUTSIDE number.
            let mut controls_in_web: Vec<bool> = Vec::new();

            #[allow(clippy::too_many_arguments)]
            fn walk(
                e: &cerebellum_macos::AxElement,
                d: usize,
                elements: &mut usize,
                with_actions: &mut usize,
                identified: &mut usize,
                depth: &mut usize,
                roles: &mut std::collections::BTreeMap<String, usize>,
                identifiers: &mut std::collections::BTreeMap<String, usize>,
                controls: &mut usize,
                controls_pressable: &mut Vec<Option<String>>,
                role_title: &mut std::collections::BTreeMap<(String, String), usize>,
                controls_role_title: &mut Vec<(String, String)>,
                controls_in_web: &mut Vec<bool>,
                in_web: bool,
            ) {
                *elements += 1;
                *depth = (*depth).max(d);
                if !e.actions.is_empty() {
                    *with_actions += 1;
                }
                if let Some(identifier) = &e.identifier {
                    *identified += 1;
                    identifiers
                        .entry(identifier.clone())
                        .and_modify(|n| *n += 1)
                        .or_insert(1);
                }
                // Roles a person would click. Deliberately narrow: counting
                // every element that happens to advertise an action would
                // inflate the answer with containers and static text.
                let is_control = matches!(
                    e.role.as_deref(),
                    Some(
                        "AXButton"
                            | "AXMenuItem"
                            | "AXMenuBarItem"
                            | "AXCheckBox"
                            | "AXRadioButton"
                            | "AXPopUpButton"
                            | "AXLink"
                            | "AXDisclosureTriangle"
                            | "AXTab"
                    )
                );
                if is_control {
                    *controls += 1;
                    if e.actions.iter().any(|action| action == "AXPress") {
                        controls_pressable.push(e.identifier.clone());
                        let key = (
                            e.role.clone().unwrap_or_default(),
                            e.title.clone().unwrap_or_default(),
                        );
                        role_title
                            .entry(key.clone())
                            .and_modify(|n| *n += 1)
                            .or_insert(1);
                        controls_role_title.push(key);
                        controls_in_web.push(in_web);
                    }
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
                        identifiers,
                        controls,
                        controls_pressable,
                        role_title,
                        controls_role_title,
                        controls_in_web,
                        // AXWebArea is the root of one rendered document, so
                        // everything below it is page content however deeply
                        // nested. The flag only ever turns on.
                        in_web || e.role.as_deref() == Some("AXWebArea"),
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
                &mut identifiers,
                &mut controls,
                &mut controls_pressable,
                &mut role_title,
                &mut controls_role_title,
                &mut controls_in_web,
                false,
            );
            // The three conditions an element must meet TOGETHER before this
            // module will act on it: it advertises the action, it carries an
            // identifier to be named by, and no other element shares that
            // identifier. Reporting only the first would overstate reach.
            let pressable = controls_pressable.len();
            // Two unrelated reasons a pressable control cannot be acted on, kept
            // apart because they have different remedies: an element carrying NO
            // identifier might still be addressable by some other scheme we do
            // not have, whereas one SHARING an identifier is genuinely ambiguous
            // and no scheme keyed on that identifier can separate the two.
            let unnamed = controls_pressable
                .iter()
                .filter(|identifier| identifier.is_none())
                .count();
            let shared = controls_pressable
                .iter()
                .filter(|identifier| {
                    identifier.as_ref().is_some_and(|identifier| {
                        identifiers.get(identifier).is_some_and(|n| *n > 1)
                    })
                })
                .count();
            let addressable = pressable.saturating_sub(unnamed).saturating_sub(shared);
            // Same uniqueness test, different key. An empty title counts as a
            // key rather than being skipped, so controls with no title collide
            // with each other and are reported as ambiguous -- which is what
            // they would be.
            let by_role_title = controls_role_title
                .iter()
                .filter(|key| role_title.get(*key) == Some(&1))
                .count();
            // What a scheme accepting EITHER key would reach. The safety
            // property is unchanged: whichever key a caller supplies, exactly
            // one element must carry it, and a key matching two elements is
            // refused as it is today.
            // The same either-key test restricted to controls outside page
            // content, which is what the computer plane would actually serve in
            // an application that renders documents.
            let outside_web = controls_in_web.iter().filter(|in_web| !**in_web).count();
            let outside_web_addressable = controls_pressable
                .iter()
                .zip(controls_role_title.iter())
                .zip(controls_in_web.iter())
                .filter(|((identifier, key), in_web)| {
                    if **in_web {
                        return false;
                    }
                    let unique_identifier = identifier
                        .as_ref()
                        .is_some_and(|identifier| identifiers.get(identifier) == Some(&1));
                    unique_identifier || role_title.get(*key) == Some(&1)
                })
                .count();
            let by_either = controls_pressable
                .iter()
                .zip(controls_role_title.iter())
                .filter(|(identifier, key)| {
                    let unique_identifier = identifier
                        .as_ref()
                        .is_some_and(|identifier| identifiers.get(identifier) == Some(&1));
                    unique_identifier || role_title.get(*key) == Some(&1)
                })
                .count();

            println!("read in {:?}", started.elapsed());
            println!("  complete:            {complete}   <- an incomplete tree cannot establish uniqueness, so no action may be requested against it");
            println!("  elements:            {elements}");
            println!("  max depth:           {depth}");
            println!("  advertise an action: {with_actions}");
            println!("  carry an identifier: {identified}   <- what an action can name");
            println!(
                "  controls:            {controls}   <- buttons, menu items, checkboxes, links"
            );
            println!("    advertise Press:   {pressable}");
            println!("    no identifier:     {unnamed}");
            println!("    shared identifier: {shared}");
            println!("    uniquely nameable: {addressable}   <- what semantic actuation could actually act on");
            println!(
                "    unique role+title: {by_role_title}   <- the same test under a different key"
            );
            println!("    unique under EITHER: {by_either}   <- reach if a caller may name a control by either");
            println!("    outside page content: {outside_web} pressable, {outside_web_addressable} addressable   <- the application's own interface");
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
