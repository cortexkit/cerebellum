//! Keep the agent's browser from inheriting cerebellum's macOS privacy grants.
//!
//! macOS checks privacy permissions (Screen Recording, Accessibility, Input
//! Monitoring) against a process's *responsible process*, which a child
//! inherits from whoever spawned it. Spawning with the private libSystem
//! attribute `responsibility_spawnattrs_setdisclaim` makes the child its own
//! responsible process, so it holds none of the spawner's grants. That call
//! is resolved at runtime because it isn't in the public SDK headers.

/// The operation that stops the browser inheriting the module's Screen
/// Recording, Accessibility and Input Monitoring grants is missing or failed,
/// so the browser must not be launched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponsibilityDisclaimUnavailable;

/// Resolve the operation and apply it to the spawn attributes. A missing
/// symbol and a non-zero result both refuse, so the browser is never
/// launched holding the module's grants.
pub fn require_responsibility_disclaim<T>(
    resolve: impl FnOnce() -> Option<T>,
    call: impl FnOnce(T) -> i32,
) -> Result<(), ResponsibilityDisclaimUnavailable> {
    let operation = resolve().ok_or(ResponsibilityDisclaimUnavailable)?;
    if call(operation) != 0 {
        return Err(ResponsibilityDisclaimUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_symbol_refuses_launch() {
        assert_eq!(
            require_responsibility_disclaim(|| None::<()>, |_| panic!("missing operation called")),
            Err(ResponsibilityDisclaimUnavailable)
        );
    }

    #[test]
    fn failed_disclaim_refuses_launch() {
        assert_eq!(
            require_responsibility_disclaim(|| Some(()), |_| 1),
            Err(ResponsibilityDisclaimUnavailable)
        );
    }

    #[test]
    fn successful_disclaim_allows_launch() {
        assert_eq!(require_responsibility_disclaim(|| Some(()), |_| 0), Ok(()));
    }
}
