#[cfg(not(feature = "bridge-test-identities"))]
#[inline]
pub fn measure_image_check<T>(_phase: &'static str, check: impl FnOnce() -> T) -> T {
    check()
}

#[cfg(feature = "bridge-test-identities")]
pub use fixture::*;

#[cfg(feature = "bridge-test-identities")]
mod fixture {
    use std::cell::RefCell;
    use std::time::{Duration, Instant};

    #[derive(Debug)]
    pub enum ImageCheckTrace {
        Phase {
            name: &'static str,
            depth: usize,
            elapsed: Duration,
            children_elapsed: Duration,
        },
        TrustStatus {
            depth: usize,
            status: i32,
            chain_errors: u32,
        },
    }

    struct Trace {
        events: Vec<ImageCheckTrace>,
        depth: usize,
        active: Option<usize>,
    }

    thread_local! {
        static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) };
    }

    /// Buffer observations until the measured check returns so logging cannot add to its time.
    pub fn trace_image_checks<T>(check: impl FnOnce() -> T) -> (T, Vec<ImageCheckTrace>) {
        let _restore = RestoreTrace(TRACE.replace(Some(Trace {
            events: Vec::with_capacity(64),
            depth: 0,
            active: None,
        })));
        let result = check();
        (
            result,
            TRACE
                .replace(None)
                .expect("active image check trace")
                .events,
        )
    }

    struct RestoreTrace(Option<Trace>);

    impl Drop for RestoreTrace {
        fn drop(&mut self) {
            TRACE.replace(self.0.take());
        }
    }

    pub fn measure_image_check<T>(phase: &'static str, check: impl FnOnce() -> T) -> T {
        let _phase = TRACE.with_borrow_mut(|trace| {
            let trace = trace.as_mut()?;
            let index = trace.events.len();
            trace.events.push(ImageCheckTrace::Phase {
                name: phase,
                depth: trace.depth,
                elapsed: Duration::ZERO,
                children_elapsed: Duration::ZERO,
            });
            trace.depth += 1;
            Some(Phase {
                index,
                parent: trace.active.replace(index),
                started: Instant::now(),
            })
        });
        check()
    }

    struct Phase {
        index: usize,
        parent: Option<usize>,
        started: Instant,
    }

    impl Drop for Phase {
        fn drop(&mut self) {
            let duration = self.started.elapsed();
            TRACE.with_borrow_mut(|trace| {
                let trace = trace.as_mut().expect("active image check trace");
                let ImageCheckTrace::Phase { elapsed, .. } = &mut trace.events[self.index] else {
                    unreachable!("phase index must refer to a phase")
                };
                *elapsed = duration;
                if let Some(parent) = self.parent {
                    let ImageCheckTrace::Phase {
                        children_elapsed, ..
                    } = &mut trace.events[parent]
                    else {
                        unreachable!("parent index must refer to a phase")
                    };
                    *children_elapsed += duration;
                }
                trace.active = self.parent;
                trace.depth -= 1;
            });
        }
    }

    pub(in crate::browser_image) fn record_trust_status(status: i32, chain_errors: u32) {
        TRACE.with_borrow_mut(|trace| {
            if let Some(trace) = trace {
                trace.events.push(ImageCheckTrace::TrustStatus {
                    depth: trace.depth,
                    status,
                    chain_errors,
                });
            }
        });
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn image_check_trace_nests_phases_and_preserves_refusal() {
            let (result, trace) = trace_image_checks(|| {
                measure_image_check("verify", || {
                    measure_image_check("open", || Ok::<_, &str>(()))?;
                    measure_image_check("trust", || {
                        record_trust_status(-1, 0x40);
                        Err::<(), _>("refused")
                    })
                })
            });
            assert_eq!(result, Err("refused"));
            assert!(matches!(
                trace.as_slice(),
                [
                    ImageCheckTrace::Phase { name: "verify", depth: 0, elapsed: total, children_elapsed },
                    ImageCheckTrace::Phase { name: "open", depth: 1, elapsed: open, .. },
                    ImageCheckTrace::Phase { name: "trust", depth: 1, elapsed: trust, .. },
                    ImageCheckTrace::TrustStatus {
                        depth: 2,
                        status: -1,
                        chain_errors: 0x40
                    },
                ] if *children_elapsed == *open + *trust && *total >= *children_elapsed
            ));
            assert!(TRACE.with_borrow(Option::is_none));
        }
    }
}
