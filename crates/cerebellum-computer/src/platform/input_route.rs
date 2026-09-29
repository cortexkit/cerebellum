//! Privacy-preserving evidence for keyboard transport calls, never key data.
use super::process_event::{PerProcessTransport, PostCallFailure, PostCallMade};
use serde::{Deserialize, Serialize};

pub const PRIVATE_INPUT_AUTH_FAILED: &str = "private_input_auth_failed";

pub fn private_route_review_bound() -> bool {
    option_env!("CEREBELLUM_PRIVATE_INPUT_ROUTE_REVIEW_REVISION")
        .is_some_and(|revision| !revision.trim().is_empty())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteCounts {
    pub skylight: u64,
    pub public: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEvidence {
    Attached,
    Unavailable,
    #[default]
    NotApplicable,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InputRouteEvidence {
    pub routes: RouteCounts,
    pub release_routes: RouteCounts,
    pub auth: AuthEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
}

impl InputRouteEvidence {
    pub fn record(&mut self, route: PerProcessTransport, recovery: bool) {
        let counts = if recovery {
            &mut self.release_routes
        } else {
            &mut self.routes
        };
        match route {
            PerProcessTransport::PrivateSkyLight => counts.skylight += 1,
            PerProcessTransport::PublicCoreGraphics => counts.public += 1,
        }
    }
}

/// Symbol and factory availability are immutable startup-resolution facts.
/// A runtime attachment failure is an error, not evidence of an absent factory.
#[derive(Debug, Clone, Copy)]
pub struct KeyboardRoute {
    pub reviewed: bool,
    pub symbol_available: bool,
    pub factory_available: bool,
}

impl KeyboardRoute {
    pub fn selected(self) -> PerProcessTransport {
        super::process_event::keyboard_transport(self.reviewed && self.symbol_available)
    }

    pub fn post(
        self,
        recovery: bool,
        evidence: &mut InputRouteEvidence,
        private: impl FnOnce(bool) -> Result<(), PostCallFailure>,
        public: impl FnOnce() -> Result<(), PostCallFailure>,
    ) -> Result<PostCallMade, PostCallFailure> {
        let route = self.selected();
        match route {
            PerProcessTransport::PrivateSkyLight => {
                private(self.factory_available)?;
                evidence.auth = if self.factory_available {
                    AuthEvidence::Attached
                } else {
                    AuthEvidence::Unavailable
                };
            }
            PerProcessTransport::PublicCoreGraphics => {
                public()?;
                if self.reviewed && evidence.fallback_reason.is_none() {
                    evidence.fallback_reason = Some("skylight_symbol_missing".into());
                }
            }
        }
        evidence.record(route, recovery);
        Ok(PostCallMade { transport: route })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct SequenceFixture {
        evidence: InputRouteEvidence,
        recovery: bool,
        calls: usize,
        fail_at: Option<usize>,
    }

    impl super::super::process_event::PerProcessEventTransport for SequenceFixture {
        type Event = ();
        fn set_recovery(&mut self, recovery: bool) {
            self.recovery = recovery;
        }
        fn process_generation(
            &mut self,
            _: u32,
        ) -> super::super::process_event::ProcessGenerationReading {
            super::super::process_event::ProcessGenerationReading::Started(7)
        }
        fn window_server_visibility(
            &mut self,
            _: u32,
        ) -> super::super::process_event::WindowServerVisibility {
            super::super::process_event::WindowServerVisibility::Visible
        }
        fn post_to_pid(&mut self, _: u32, _: ()) -> Result<PostCallMade, PostCallFailure> {
            self.calls += 1;
            let fail = self.fail_at == Some(self.calls);
            KeyboardRoute {
                reviewed: true,
                symbol_available: true,
                factory_available: true,
            }
            .post(
                self.recovery,
                &mut self.evidence,
                |_| {
                    if fail {
                        Err(PostCallFailure::new(PRIVATE_INPUT_AUTH_FAILED))
                    } else {
                        Ok(())
                    }
                },
                || panic!("private failure must not retry publicly"),
            )
        }
    }

    #[test]
    fn failed_attach_and_cancel_preserve_release_route_counts() {
        use super::super::process_event::*;
        for fail_attach in [true, false] {
            let mut transport = SequenceFixture {
                evidence: Default::default(),
                recovery: false,
                calls: 0,
                fail_at: fail_attach.then_some(2),
            };
            let boundaries = Cell::new(0);
            let cancelled = || {
                boundaries.set(boundaries.get() + 1);
                !fail_attach && boundaries.get() == 2
            };
            let result = post_event_sequence(
                ProcessEventTarget {
                    pid: 10,
                    start_time_micros: 7,
                },
                vec![
                    SyntheticStep {
                        event: (),
                        role: SyntheticStepRole::Press,
                    },
                    SyntheticStep {
                        event: (),
                        role: SyntheticStepRole::SelfContained,
                    },
                    SyntheticStep {
                        event: (),
                        role: SyntheticStepRole::Release,
                    },
                ],
                &mut transport,
                &cancelled,
            )
            .unwrap_err();
            assert_eq!(
                result.held_state,
                HeldStateDisposition::Released { posts_returned: 1 }
            );
            assert_eq!(
                transport.evidence.routes,
                RouteCounts {
                    skylight: 1,
                    public: 0
                }
            );
            assert_eq!(
                transport.evidence.release_routes,
                RouteCounts {
                    skylight: 1,
                    public: 0
                }
            );
            if fail_attach {
                assert_eq!(
                    result.refusal,
                    ProcessEventRefusal::PostCallFailed(PostCallFailure::new(
                        PRIVATE_INPUT_AUTH_FAILED
                    ))
                );
            } else {
                assert_eq!(result.refusal, ProcessEventRefusal::Cancelled);
            }
        }
    }

    #[test]
    fn unbound_private_route_never_calls_skylight() {
        let mut evidence = InputRouteEvidence::default();
        let _ = KeyboardRoute {
            reviewed: false,
            symbol_available: true,
            factory_available: true,
        }
        .post(
            false,
            &mut evidence,
            |_| panic!("SkyLight called without review"),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(
            evidence.routes,
            RouteCounts {
                skylight: 0,
                public: 1
            }
        );
        assert_eq!(evidence.auth, AuthEvidence::NotApplicable);
        assert_eq!(evidence.fallback_reason, None);
    }

    #[test]
    fn missing_symbol_fallback_mid_sequence_keeps_both_counts() {
        let mut evidence = InputRouteEvidence::default();
        let _ = KeyboardRoute {
            reviewed: true,
            symbol_available: true,
            factory_available: false,
        }
        .post(
            false,
            &mut evidence,
            |auth| {
                assert!(!auth);
                Ok(())
            },
            || panic!("unexpected public"),
        )
        .unwrap();
        let _ = KeyboardRoute {
            reviewed: true,
            symbol_available: false,
            factory_available: false,
        }
        .post(
            false,
            &mut evidence,
            |_| panic!("missing symbol called"),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(
            evidence.routes,
            RouteCounts {
                skylight: 1,
                public: 1
            }
        );
        assert_eq!(evidence.auth, AuthEvidence::Unavailable);
        assert_eq!(
            evidence.fallback_reason.as_deref(),
            Some("skylight_symbol_missing")
        );
    }

    #[test]
    fn present_factory_attachment_failure_never_posts_or_becomes_unavailable() {
        let public_posts = Cell::new(0);
        let private_posts = Cell::new(0);
        let mut evidence = InputRouteEvidence::default();
        let result = KeyboardRoute {
            reviewed: true,
            symbol_available: true,
            factory_available: true,
        }
        .post(
            false,
            &mut evidence,
            |attach| {
                if attach {
                    Err(PostCallFailure::new(PRIVATE_INPUT_AUTH_FAILED))
                } else {
                    private_posts.set(private_posts.get() + 1);
                    Ok(())
                }
            },
            || {
                public_posts.set(public_posts.get() + 1);
                Ok(())
            },
        );
        assert_eq!(result, Err(PostCallFailure::new(PRIVATE_INPUT_AUTH_FAILED)));
        assert_eq!(private_posts.get(), 0);
        assert_eq!(public_posts.get(), 0);
        assert_eq!(evidence.routes, RouteCounts::default());
        assert_ne!(evidence.auth, AuthEvidence::Unavailable);
    }
}
