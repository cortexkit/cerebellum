//! What this build advertises on this machine, read from the production path.
//!
//! A probe rather than a test: the answer depends on the release identifiers
//! bound into the build and on what this host has granted, so there is no fixed
//! expectation to assert. It exists because "what does a caller actually see"
//! is answered by the manifest the module sends, and every layer below can be
//! complete while that manifest stays empty.

fn main() {
    // The browser half first, because its reachable set is the one that has
    // been wrong twice: a capability can be implemented, proved against a real
    // browser, and still answer unknown_method because one predicate does not
    // name it. `configured` is what a host with a browser configured sees.
    println!("browser tools (configured / unconfigured):");
    let configured = cerebellum::browser_wire_surface(true);
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
