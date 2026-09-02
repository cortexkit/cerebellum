//! What a Windows session reading can say, independent of how it is taken.
//!
//! Pure data, so the readers that consume it stay testable on any host. The
//! call that produces it is in the FFI module and is Windows-only.

/// Which Windows session this process runs in, and whether that is the console.
///
/// This exists because a UI Automation read from a NON-INTERACTIVE session
/// SUCCEEDS. Measured in a Windows 11 ARM64 guest as SYSTEM in session 0: the
/// COM stack loads, `RootElement` resolves as the desktop window class, and
/// enumerating its children returns an EMPTY COLLECTION -- while an interactive
/// console session with real windows existed at that same moment.
///
/// So nothing in an empty tree distinguishes "the target has no windows" from
/// "this process cannot see any desktop", and no accessibility call reports
/// which. The discriminator has to be established BEFORE the read and from a
/// different source, because the result is the one thing that cannot carry it.
///
/// Reported rather than judged: this seam says which session it is in and which
/// one the console is, and the caller decides what an empty tree means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProvenance {
    /// This process runs in the session currently attached to the console, so a
    /// tree read can observe a user's desktop.
    Console { session_id: u32 },
    /// This process runs in some other session -- a service session, or a
    /// disconnected or remote one. An empty tree here describes this process's
    /// visibility, not the target.
    OtherSession {
        session_id: u32,
        console_session_id: u32,
    },
    /// The console has no attached session. `WTSGetActiveConsoleSessionId`
    /// returns `0xFFFFFFFF` for this, which is a real state rather than an
    /// error: nobody is at the machine.
    NoConsoleSession { session_id: u32 },
    /// This process's own session could not be read. Kept distinct from every
    /// answer above so a failed lookup is never reported as a session number.
    Unreadable { last_error: u32 },
    /// No session reading was taken, because this build has no session to read.
    ///
    /// Not an error and not a session: the readers here are exercised over
    /// constructed sources on hosts that have no Windows sessions at all, and
    /// substituting `Unreadable` there would fabricate an operating-system
    /// error code that nothing produced.
    NotApplicable,
}

/// The sentinel `WTSGetActiveConsoleSessionId` returns when no session is
/// attached to the console.
pub(crate) const NO_ACTIVE_CONSOLE_SESSION: u32 = 0xFFFF_FFFF;

/// Compare a process's session with the console's.
///
/// Separated from the reading so the comparison is exercised on every host: the
/// two numbers come from FFI, and everything decided from them is arithmetic.
pub(crate) fn classify(session_id: u32, console_session_id: u32) -> SessionProvenance {
    if console_session_id == NO_ACTIVE_CONSOLE_SESSION {
        SessionProvenance::NoConsoleSession { session_id }
    } else if console_session_id == session_id {
        SessionProvenance::Console { session_id }
    } else {
        SessionProvenance::OtherSession {
            session_id,
            console_session_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_console_session_is_the_only_one_that_can_observe_a_desktop() {
        assert_eq!(classify(1, 1), SessionProvenance::Console { session_id: 1 });
        assert_eq!(
            classify(0, 1),
            SessionProvenance::OtherSession {
                session_id: 0,
                console_session_id: 1
            }
        );
    }

    #[test]
    fn a_failed_lookup_is_never_any_session() {
        // The trap this guards: if a failed session read were reported as
        // session 0, every service would look legitimately session-0 and an
        // empty desktop reading would be attributed to the target instead of
        // to a lookup that never happened.
        let failed = SessionProvenance::Unreadable { last_error: 5 };
        for console in [0, 1, 2, NO_ACTIVE_CONSOLE_SESSION] {
            for own in [0, 1, 2] {
                assert_ne!(classify(own, console), failed);
            }
        }
        assert_ne!(failed, SessionProvenance::NotApplicable);
    }

    #[test]
    fn an_unattached_console_is_a_state_rather_than_a_session_number() {
        // The sentinel must not be compared as an ordinary id: doing so would
        // report session 0xFFFFFFFF as the console for a machine nobody is at.
        assert_eq!(
            classify(0, NO_ACTIVE_CONSOLE_SESSION),
            SessionProvenance::NoConsoleSession { session_id: 0 }
        );
        assert_eq!(
            classify(NO_ACTIVE_CONSOLE_SESSION, NO_ACTIVE_CONSOLE_SESSION),
            SessionProvenance::NoConsoleSession {
                session_id: NO_ACTIVE_CONSOLE_SESSION
            }
        );
    }
}
