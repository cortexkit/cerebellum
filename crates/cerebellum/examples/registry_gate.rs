//! Report why this machine's profile registry will or will not serve a launch.
//!
//! The launch path maps every registry failure to one outcome
//! (`profile_storage_unavailable`), so a refused launch cannot say which of
//! several unrelated conditions produced it — a missing directory, an artifact
//! that failed its digest, or a registry that does not trust the root it was
//! opened against. This reads the same inputs and names them individually.
//!
//! Written after a live launch refused with `profile_storage_unavailable` on a
//! machine whose profile directories were present and whose registry was
//! intact. The cause was a root binding mismatch, and recovering that fact from
//! the refusal alone took about twenty steps.
//!
//! ```text
//! cargo run -p cerebellum --example registry_gate [project-id]
//! ```

use std::path::PathBuf;

use cerebellum::profile::{ProfileLifecycle, RegistryConfig, REGISTRY_ARTIFACT};

fn main() {
    let home = std::env::var_os("HOME").expect("HOME");
    let root = PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("cortexkit")
        .join("cerebellum")
        .join("browser");

    println!("root: {}", root.display());
    println!("  exists:    {}", root.exists());
    println!("  directory: {}", root.is_dir());
    println!("artifact bytes: {}", REGISTRY_ARTIFACT.len());

    // The same flags the launch service sets, so this reports the launch
    // path's gate rather than a default one.
    let config = RegistryConfig {
        uuid_protocol_compatible: true,
        grant_verifier_available: true,
        grant_accepted: true,
        sealing_available: true,
        ..RegistryConfig::default()
    };

    let lifecycle = match ProfileLifecycle::open_with_config(&root, config) {
        Ok(lifecycle) => lifecycle,
        Err(error) => {
            println!("open: FAILED -- {error:?}");
            println!(
                "  VERDICT: the launch path maps this to profile_storage_unavailable and \
                 discards the reason above."
            );
            return;
        }
    };

    let registry = lifecycle.registry();
    println!("open: ok");
    println!("  artifact_enabled: {}", registry.artifact_enabled());
    println!(
        "  implementation_digest: {}",
        registry.implementation_digest()
    );

    if !registry.artifact_enabled() {
        println!(
            "  VERDICT: the gate is CLOSED, so every launch refuses before consulting any \
             session, grant, or profile state."
        );
        return;
    }

    // Resolving a durable record is the next thing that can close storage, and
    // it is where a root the registry does not trust surfaces. Any project id
    // reaches it: the binding check happens before the record lookup.
    let project = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "pj-probe".to_string());
    // A resolution is an Ok value even when it reports the registry cannot be
    // trusted, so the verdict reads the RESOLUTION rather than the Result.
    // Branching on Ok here would announce that the registry serves this root
    // while printing the sentence that says it does not.
    match registry.resolve_durable(&project) {
        Err(error) => println!("  resolve_durable({project}) FAILED: {error:?}"),
        Ok(resolution) => {
            println!("  resolve_durable({project}): {resolution:?}");
            let rendered = format!("{resolution:?}");
            if rendered.contains("UntrustworthyOrUnavailable") {
                // The verdict QUOTES the reason rather than explaining one. An
                // earlier version of this probe named a root-binding mismatch
                // in every untrusted case, and then printed that explanation
                // over a completely different reason -- a verdict that does not
                // read what it just printed, which is the defect this probe was
                // written to expose.
                println!(
                    "  VERDICT: the registry DOES NOT TRUST this root, so every launch refuses \
                     with profile_storage_unavailable -- a message about the disk, for a \
                     decision about identity. The reason above is the fact the launch path \
                     discards."
                );
                println!(
                    "  Known reasons: `managed root inode changed` means the root directory \
                     was replaced or restored; `managed root birth time changed` means it was \
                     recreated with a reused inode; `managed root canonical path changed` \
                     means it was moved; `managed root identity predates the fact-based \
                     formula` means the registry still holds the old hash-only identity and \
                     needs one rebind; `cannot report birth time` means the filesystem cannot \
                     identify the root at all. `possibly_managed_path` means profile \
                     directories exist that no record accounts for, which is refused rather \
                     than deleted on purpose."
                );
            } else {
                println!(
                    "  VERDICT: the registry serves this root. A refused launch is further \
                     along than anything this probe reads."
                );
            }
        }
    }
}
