//! What this build advertises on this machine, read from the production path.
//!
//! A probe rather than a test: the answer depends on the release identifiers
//! bound into the build and on what this host has granted, so there is no fixed
//! expectation to assert. It exists because "what does a caller actually see"
//! is answered by the manifest the module sends, and every layer below can be
//! complete while that manifest stays empty.

fn main() {
    // The browser half first, because its reachable set is the one most likely
    // to be misjudged: a capability can be implemented and proved against a
    // real browser, yet still answer unknown_method because the dispatch
    // predicate does not name it. `configured` is what a host with a browser
    // configured sees; the other column is what a host without one sees.
    // Read from the installed config rather than assumed, so this answers what
    // a caller sees ON THIS MACHINE. A browser section that is absent or
    // malformed is why an agent gets executable_missing, and that is exactly
    // the state this probe should be able to show.
    let installed = match cerebellum::browser_config::load_browser_config_file() {
        Ok(Some(config)) => {
            println!(
                "browser config:  {} (identity {})",
                config
                    .executable_path
                    .as_deref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "no executable_path".to_string()),
                config.expected_identity.as_deref().unwrap_or("none"),
            );
            config.executable_path.is_some()
        }
        Ok(None) => {
            println!("browser config:  ABSENT -- launch would refuse executable_missing");
            false
        }
        Err(error) => {
            println!("browser config:  ERROR -- {error}");
            false
        }
    };

    println!();
    println!("browser tools (this machine / a host with no browser):");
    let configured = cerebellum::browser_wire_surface(installed);
    let unconfigured = cerebellum::browser_wire_surface(false);
    for (index, (name, reachable_when_configured)) in configured.iter().enumerate() {
        let reachable_bare = unconfigured
            .get(index)
            .map(|(_, reachable)| *reachable)
            .unwrap_or(false);
        println!(
            "  {name:<24} {} / {}",
            if *reachable_when_configured {
                "reachable"
            } else {
                "REFUSED  "
            },
            if reachable_bare {
                "reachable"
            } else {
                "REFUSED"
            }
        );
    }
    println!();

    let context = cerebellum::default_computer_context();
    let evidence = cerebellum::computer_release_evidence(&context);

    println!("frozen rows:    {}", evidence.frozen_row_count);
    println!("gate-admitted:  {:?}", evidence.gate_admitted_capabilities);
    println!("advertised:     {:?}", evidence.advertised_capabilities);
    println!("scope:          {:?}", evidence.scope);
    println!();
    println!("release gates:");
    for outcome in &evidence.gate_outcomes {
        println!("  {outcome:?}");
    }
}
