//! Top-level window owners as a reading, independent of how they are taken.
//!
//! Pure data, so a constructed list can be examined on any host. The call that
//! produces it is in the FFI module and is Windows-only.

use crate::session::SessionProvenance;

/// Why one top-level window's owning executable could not be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowOwnerUnreadable {
    /// `GetWindowThreadProcessId` did not return a thread for this window.
    ProcessIdUnreadable { last_error: u32 },
    /// No process holds this ID. Typical when the owner exited between the
    /// window enumeration and the process open.
    NoSuchProcess { pid: u32 },
    /// The process exists but this caller may not open it for a query.
    AccessDenied { pid: u32 },
    /// Windows returned an error this seam does not otherwise classify, or the
    /// image path was not valid UTF-16 (`last_error` is then 0).
    Unclassified { pid: u32, last_error: u32 },
}

/// One top-level window's owner, named or not.
///
/// An owner that cannot be opened is retained rather than dropped, so a caller
/// can see that the named list is partial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopLevelWindowOwner {
    Named {
        pid: u32,
        /// Executable basename, lowercased, so `Notepad.exe` and `notepad.exe`
        /// are one identity. Windows has no bundle identifier.
        executable_basename: String,
    },
    Unreadable(WindowOwnerUnreadable),
}

/// Whether every enumerated window's owner could be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowListCompleteness {
    Complete,
    Partial { unreadable_owners: usize },
}

/// Why top-level window enumeration itself did not produce a list.
///
/// Distinct from an empty list: `EnumWindows` failing is not "there are no
/// windows", and collapsing the two would report absence about a desktop
/// nobody inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumerateWindowsError {
    EnumerationFailed { last_error: u32 },
}

/// Top-level windows and the session that produced the reading.
///
/// Session travels WITH the list rather than as a separate call, because
/// `EnumWindows` from a non-interactive session succeeds and sees the SERVICE
/// desktop — a different, nearly empty window station. An empty named list
/// cannot be read as "that application is not running" without this field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopLevelWindowReading {
    pub session: SessionProvenance,
    pub windows: Vec<TopLevelWindowOwner>,
    pub completeness: WindowListCompleteness,
}

impl TopLevelWindowReading {
    /// Build a reading, computing completeness from the windows that are in it.
    ///
    /// Completeness is derived rather than supplied so a partial list cannot be
    /// constructed as a shorter complete one.
    pub fn from_enumerated(session: SessionProvenance, windows: Vec<TopLevelWindowOwner>) -> Self {
        let unreadable_owners = windows
            .iter()
            .filter(|window| matches!(window, TopLevelWindowOwner::Unreadable(_)))
            .count();
        let completeness = if unreadable_owners == 0 {
            WindowListCompleteness::Complete
        } else {
            WindowListCompleteness::Partial { unreadable_owners }
        };
        Self {
            session,
            windows,
            completeness,
        }
    }
}

/// The last path component of a Win32 image path, lowercased.
pub(crate) fn executable_basename(full_image_path: &str) -> String {
    full_image_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(full_image_path)
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_whose_owner_cannot_be_named_makes_the_list_partial() {
        let named = TopLevelWindowOwner::Named {
            pid: 10,
            executable_basename: "notepad.exe".into(),
        };
        let unreadable =
            TopLevelWindowOwner::Unreadable(WindowOwnerUnreadable::AccessDenied { pid: 11 });

        let partial = TopLevelWindowReading::from_enumerated(
            SessionProvenance::Console { session_id: 1 },
            vec![named.clone(), unreadable],
        );
        assert_eq!(
            partial.completeness,
            WindowListCompleteness::Partial {
                unreadable_owners: 1
            }
        );
        assert_eq!(
            partial.windows.len(),
            2,
            "the unreadable owner remains in the list rather than being dropped"
        );

        let dropped = TopLevelWindowReading::from_enumerated(
            SessionProvenance::Console { session_id: 1 },
            vec![named],
        );
        assert_eq!(dropped.completeness, WindowListCompleteness::Complete);
        assert_eq!(dropped.windows.len(), 1);
        assert_ne!(
            partial.completeness, dropped.completeness,
            "dropping the unreadable owner must not be reported as a shorter complete list"
        );
    }

    #[test]
    fn notepad_exe_casing_is_one_identity() {
        assert_eq!(
            executable_basename(r"C:\Windows\System32\Notepad.exe"),
            executable_basename(r"C:\Windows\System32\notepad.exe")
        );
        assert_eq!(
            executable_basename(r"C:\Windows\System32\Notepad.exe"),
            "notepad.exe"
        );
    }
}
