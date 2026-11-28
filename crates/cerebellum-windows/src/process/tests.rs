use super::*;

struct Evidence {
    signaled: bool,
    creation: ProcessStartTime,
}

impl ProcessEvidence for Evidence {
    fn creation(&self) -> ProcessStartTime {
        self.creation
    }

    fn signaled(&self) -> std::io::Result<bool> {
        Ok(self.signaled)
    }
}

fn denied_then_wait(signaled: bool) -> ProcessGenerationLiveness {
    let mut access_seen = Vec::new();
    let result = observe_with(42, 99, |pid, access| {
        assert_eq!(pid, 42);
        access_seen.push(access);
        if access == SYNCHRONIZE {
            Ok(Evidence {
                signaled,
                creation: ProcessStartTime::AccessDenied,
            })
        } else {
            Err(ProcessAccessFailure::AccessDenied)
        }
    });
    assert_eq!(
        access_seen,
        [SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, SYNCHRONIZE]
    );
    result
}

#[test]
fn windows_signal_on_wait_only_handle_proves_gone() {
    assert_eq!(denied_then_wait(true), ProcessGenerationLiveness::Gone);
}

#[test]
fn windows_unsignaled_wait_only_handle_is_unknown() {
    assert_eq!(denied_then_wait(false), ProcessGenerationLiveness::Unknown);
}

#[test]
fn windows_unsignaled_handle_with_failed_creation_query_is_unknown() {
    assert_eq!(
        observe_with(42, 99, |_, _| Ok(Evidence {
            signaled: false,
            creation: ProcessStartTime::Unclassified(123),
        })),
        ProcessGenerationLiveness::Unknown
    );
}

#[test]
fn windows_pid_with_a_different_creation_tick_is_gone() {
    let ProcessStartTime::Started(ticks) = current_process_creation_time() else {
        panic!("own creation FILETIME")
    };
    let pid = std::process::id();
    assert_eq!(
        observe_process_generation(pid, ticks),
        ProcessGenerationLiveness::Live
    );
    assert_eq!(
        observe_process_generation(pid, ticks + 1),
        ProcessGenerationLiveness::Gone
    );
}
