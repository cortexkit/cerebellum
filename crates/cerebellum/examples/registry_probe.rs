//! What does the profile registry say about a second agent identity?
//!
//! Reads the live registry on this machine and asks it, for each project id
//! given on the command line, what it would resolve to. A launch refusal names
//! only `profile_storage_unavailable`, which is the same answer for a dozen
//! causes; this prints the one the registry actually reached.

fn main() {
    let root = std::path::PathBuf::from(std::env::var("HOME").expect("HOME"))
        .join(".local/share/cortexkit/cerebellum/browser");
    if let Err(error) = std::fs::create_dir_all(&root) {
        println!("browser root creation failed: {error:?}");
        return;
    }
    let config = cerebellum::profile::RegistryConfig {
        uuid_protocol_compatible: true,
        grant_verifier_available: true,
        grant_accepted: true,
        sealing_available: true,
        ..Default::default()
    };
    let registry = match cerebellum::profile::ProfileRegistry::open_with_config(&root, config) {
        Ok(registry) => registry,
        Err(error) => {
            println!("registry open failed: {error:?}");
            return;
        }
    };
    for id in std::env::args().skip(1) {
        println!("resolve_durable({id}): {:?}", registry.resolve_durable(&id));
    }

    // The launch path opens the registry, the profile lifecycle and the custody
    // locks, and reports the same refusal whichever one fails. Name the resource
    // that failed rather than leaving it to be inferred from the outcome.
    let lifecycle_config = cerebellum::profile::RegistryConfig {
        uuid_protocol_compatible: true,
        grant_verifier_available: true,
        grant_accepted: true,
        sealing_available: true,
        ..Default::default()
    };
    match cerebellum::profile::ProfileLifecycle::open_with_config(&root, lifecycle_config) {
        Ok(_) => println!("ProfileLifecycle::open_with_config: ok"),
        Err(error) => println!("ProfileLifecycle::open_with_config: FAILED {error:?}"),
    }
    match cerebellum::profile_custody::ProfileCustodyLocks::open_filesystem(&root) {
        Ok(_) => println!("ProfileCustodyLocks::open_filesystem: ok"),
        Err(error) => println!("ProfileCustodyLocks::open_filesystem: FAILED {error:?}"),
    }
}
