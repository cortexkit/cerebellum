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
        Phase(&'static str, Duration),
        TrustStatus { status: i32, chain_errors: u32 },
    }

    thread_local! {
        static TRACE: RefCell<Option<Vec<ImageCheckTrace>>> = const { RefCell::new(None) };
    }

    /// Buffer observations until the measured check returns so logging cannot add to its time.
    pub fn trace_image_checks<T>(check: impl FnOnce() -> T) -> (T, Vec<ImageCheckTrace>) {
        let _restore = RestoreTrace(TRACE.replace(Some(Vec::with_capacity(24))));
        let result = check();
        (
            result,
            TRACE.replace(None).expect("active image check trace"),
        )
    }

    struct RestoreTrace(Option<Vec<ImageCheckTrace>>);

    impl Drop for RestoreTrace {
        fn drop(&mut self) {
            TRACE.replace(self.0.take());
        }
    }

    pub fn measure_image_check<T>(phase: &'static str, check: impl FnOnce() -> T) -> T {
        let start = TRACE.with_borrow(|trace| trace.as_ref().map(|_| Instant::now()));
        let result = check();
        if let Some(start) = start {
            record(ImageCheckTrace::Phase(phase, start.elapsed()));
        }
        result
    }

    pub(in crate::browser_image) fn record_trust_status(status: i32, chain_errors: u32) {
        record(ImageCheckTrace::TrustStatus {
            status,
            chain_errors,
        });
    }

    fn record(event: ImageCheckTrace) {
        TRACE.with_borrow_mut(|trace| {
            if let Some(trace) = trace {
                trace.push(event);
            }
        });
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn image_check_trace_records_order_and_preserves_refusal() {
            let (result, trace) = trace_image_checks(|| {
                measure_image_check("open", || Ok::<_, &str>(()))?;
                measure_image_check("verify", || {
                    record_trust_status(-1, 0x40);
                    Err::<(), _>("refused")
                })
            });
            assert_eq!(result, Err("refused"));
            assert!(matches!(
                trace.as_slice(),
                [
                    ImageCheckTrace::Phase("open", _),
                    ImageCheckTrace::TrustStatus {
                        status: -1,
                        chain_errors: 0x40
                    },
                    ImageCheckTrace::Phase("verify", _)
                ]
            ));
            assert!(TRACE.with_borrow(Option::is_none));
        }
    }
}
