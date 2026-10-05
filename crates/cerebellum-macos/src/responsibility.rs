//! Require the runtime-resolved Darwin operation that prevents a spawned
//! browser from inheriting the launching module's macOS privacy permissions.

/// The browser must not inherit the module's Screen Recording, Accessibility,
/// or Input Monitoring permissions when responsibility cannot be disclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponsibilityDisclaimUnavailable;

/// Resolve and apply a disclaim operation before spawning. Both a missing symbol
/// and a failed operation forbid an undisclaimed launch.
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
