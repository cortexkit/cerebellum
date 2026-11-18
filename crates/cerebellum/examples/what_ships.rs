//! What this build advertises on this machine, read from the production path.
//!
//! A probe rather than a test: the answer depends on the release identifiers
//! bound into the build and on what this host has granted, so there is no fixed
//! expectation to assert. It exists because "what does a caller actually see"
//! is answered by the manifest the module sends, and every layer below can be
//! complete while that manifest stays empty.

fn main() {
    println!("browser tools advertised by this build (runtime prerequisites checked at use):");
    let manifest = cerebellum::manifest_for_inspection();
    for provider in manifest["provides"].as_array().into_iter().flatten() {
        for tool in provider["tools"].as_array().into_iter().flatten() {
            if let Some(name) = tool["name"]
                .as_str()
                .filter(|name| name.starts_with("browser"))
            {
                println!("  {name}");
            }
        }
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
