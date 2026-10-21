//! Which window-server window an accessibility element sits in.
//!
//! macOS has no public call that answers this. The private
//! `_AXUIElementGetWindow` of the accessibility framework answers it with the
//! window's `CGWindowID`, the same number the window-server list and screen
//! capture name a window by. It is not in the public SDK headers, so it is
//! looked up at run time. When it is missing, fails, or reports no window, the
//! window is unknown: nothing here guesses one, because a caller uses the
//! answer to decide whether an action lands in the window a person or agent
//! was shown.

/// The window number `call` reports, or `None` unless the operation was
/// found, returned success, and named a real window.
///
/// `call` returns the accessibility error code and the window number the
/// operation wrote. Zero is `kCGNullWindowID`, which names no window, so it
/// is treated like a failure.
pub(crate) fn window_number_from<T>(
    resolve: impl FnOnce() -> Option<T>,
    call: impl FnOnce(T) -> (i32, u32),
) -> Option<u32> {
    let operation = resolve()?;
    match call(operation) {
        (0, number) if number != 0 => Some(number),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_operation_names_no_window() {
        assert_eq!(
            window_number_from(|| None::<()>, |_| panic!("a missing operation was called")),
            None
        );
    }

    #[test]
    fn a_failed_call_names_no_window_even_when_it_wrote_one() {
        // kAXErrorIllegalArgument, with a stale number left in the output.
        assert_eq!(window_number_from(|| Some(()), |_| (-25_201, 77)), None);
    }

    #[test]
    fn a_null_window_id_names_no_window() {
        assert_eq!(window_number_from(|| Some(()), |_| (0, 0)), None);
    }

    #[test]
    fn a_successful_call_names_its_window() {
        assert_eq!(window_number_from(|| Some(()), |_| (0, 77)), Some(77));
    }
}
