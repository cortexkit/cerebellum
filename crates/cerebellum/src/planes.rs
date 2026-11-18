use super::*;

impl Planes {
    /// Configure how agent calls open Cingulate routes and persist the cards
    /// cerebellum raised, so a later call can apply their answers.
    pub fn with_cingulate(
        mut self,
        opener: Arc<dyn cingulate_client::route::CingulateOpener>,
        store: Arc<dyn cingulate_client::desk::RegistryStore>,
    ) -> Self {
        self.consent = Arc::new(cingulate_client::desk::ConsentDesk::with_store(
            opener, store,
        ));
        self.management
            .computer_grants()
            .register_drain(&self.consent_drain);
        browser_consent::register(&self);
        login_fill_consent::register(&self);
        user_browser::register(&self);
        self
    }

    /// Build isolated planes over a scripted consent service and a private
    /// registry. No journal or grant store is opened under the operator's home.
    #[doc(hidden)]
    pub fn with_cingulate_for_test(
        health: Arc<HealthState>,
        browser_config: Option<BrowserConfig>,
        opener: Arc<dyn cingulate_client::route::CingulateOpener>,
        store: Arc<dyn cingulate_client::desk::RegistryStore>,
    ) -> Self {
        Self::with_browser_config_journaling(health, browser_config, JournalPersistence::Isolated)
            .with_cingulate(opener, store)
    }

    /// A browser config with every deadline short and no executable, for
    /// tests. A running module builds through `with_browser_config` with the
    /// config it loaded, `None` when the file names no browser.
    pub fn new(health: Arc<HealthState>) -> Self {
        Self::with_browser_config_journaling(
            health,
            Some(Self::short_test_browser_config()),
            JournalPersistence::Isolated,
        )
    }

    pub(super) fn short_test_browser_config() -> BrowserConfig {
        BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
            browser_idle_timeout_ms: 30_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 100,
        }
    }

    /// Build with a durable journal. What a running module uses.
    pub fn with_browser_config(
        health: Arc<HealthState>,
        browser_config: Option<BrowserConfig>,
    ) -> Self {
        Self::with_browser_config_journaling(health, browser_config, JournalPersistence::Durable)
    }

    /// Build with the journal written wherever the caller says.
    ///
    /// Tests take [`JournalPersistence::Isolated`]. A test that takes `Durable`
    /// writes into the operator's real audit data, which is what happened when
    /// this was a default rather than an argument.
    pub fn with_browser_config_journaling(
        health: Arc<HealthState>,
        browser_config: Option<BrowserConfig>,
        journal: JournalPersistence,
    ) -> Self {
        Self::with_browser_config_journaling_and_standing_grants(
            health,
            browser_config,
            journal,
            None,
        )
    }

    /// Like [`Self::with_browser_config_journaling`], but keeps standing
    /// browser grants in `standing` when it is given. Without it, `journal`
    /// chooses: the operator's file for a durable plane, or memory that never
    /// offers a standing answer for an isolated one. Tests pass a store to
    /// have standing answers offered, to reopen a store across a restart, or
    /// to control the store's clock.
    pub fn with_browser_config_journaling_and_standing_grants(
        health: Arc<HealthState>,
        browser_config: Option<BrowserConfig>,
        journal: JournalPersistence,
        standing: Option<Arc<browser_standing_grants::StandingBrowserGrants>>,
    ) -> Self {
        Self::with_browser_state(health, browser_config, journal, standing, None)
    }

    /// Build browser and permission services sharing the signed-in domain store;
    /// fixtures can reopen a private file without resolving the operator's data home.
    pub fn with_browser_state(
        health: Arc<HealthState>,
        browser_config: Option<BrowserConfig>,
        journal: JournalPersistence,
        standing: Option<Arc<browser_standing_grants::StandingBrowserGrants>>,
        signed_in: Option<Arc<browser_signed_in::SignedInDomains>>,
    ) -> Self {
        // The launch service picks its process launcher per platform and has
        // done since the Linux barrier landed. This wiring stayed macOS-only,
        // which left a merged Linux launcher unreachable and the refusal
        // blaming profile storage several layers away from the cause.
        //
        // Platforms without a launcher still get None: ProductionLaunchService
        // resolves one at construction, so this cannot advertise a launch it
        // cannot perform.
        let capture = Arc::new(login_capture::CaptureModule::new(
            login_capture::CaptureEnv::production(
                browser_config
                    .as_ref()
                    .map_or(30_000, |config| config.navigation_settle_deadline_ms),
            ),
        ));
        // Built before the launch service, which publishes what its startup
        // recovery kept into this plane's registry.
        // Both modes use the unified grant path. Isolation changes storage,
        // not the authorization implementation exercised by tests and probes.
        // A synthetic machine identity keeps isolated answers recordable
        // without reading the operator's identity or grant stores.
        let (computer_grants, agent_grants) = match journal {
            JournalPersistence::Durable => {
                let machine_uuid = computer_grants::this_machine_uuid();
                let grants = Arc::new(
                    agent_grants::AgentGrants::open_durable(machine_uuid.clone())
                        .unwrap_or_else(agent_grants::AgentGrants::unavailable),
                );
                computer_grants::ComputerGrants::note_durable_store_health(&grants);
                (
                    Arc::new(
                        computer_grants::ComputerGrants::in_memory()
                            .with_agent_grants(Arc::clone(&grants)),
                    ),
                    Some(grants),
                )
            }
            JournalPersistence::Isolated => (
                Arc::new(computer_grants::ComputerGrants::in_memory()),
                Some(Arc::new(agent_grants::AgentGrants::in_memory(Some(
                    "isolated-plane".into(),
                )))),
            ),
        };
        let user_grants = Arc::new(browser_standing_grants::StandingBrowserGrants::in_memory());
        let standing = standing.unwrap_or_else(|| {
            Arc::new(browser_standing_grants::StandingBrowserGrants::in_memory())
        });
        let signed_in = signed_in.unwrap_or_else(|| {
            Arc::new(match journal {
                JournalPersistence::Durable => browser_signed_in::SignedInDomains::production(),
                JournalPersistence::Isolated => browser_signed_in::SignedInDomains::default(),
            })
        });
        let management = ManagementPlane::with_computer_grants(
            Arc::new(management::PlatformResolver::new()),
            computer_grants,
        )
        .with_isolated_storage(journal == JournalPersistence::Isolated)
        .with_standing_browser_grants(standing)
        .with_signed_in_domains(Arc::clone(&signed_in));
        let management = Arc::new(match agent_grants {
            Some(grants) => management.with_agent_grants(grants),
            None => management,
        });
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let launch_service: Option<Arc<dyn browser_session::BrowserSessionLauncher>> =
            browser_config
                .clone()
                .filter(|config| {
                    config
                        .executable_path
                        .as_ref()
                        .is_some_and(|path| path.is_file())
                })
                .map(|config| {
                    // One service for route sessions and captures, so both
                    // write the one launch journal whose startup recovery
                    // reaps an orphan of either kind.
                    let service = Arc::new(
                        browser_launch_service::ProductionLaunchService::open_publishing(
                            config,
                            journal,
                            &management.launch_recovery_registry(),
                        )
                        .with_signed_in_domains(Arc::clone(&signed_in)),
                    );
                    capture.set_launcher(service.clone());
                    service as Arc<dyn browser_session::BrowserSessionLauncher>
                });
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let launch_service = None;
        let sessions = browser_session::BrowserSessions::default()
            .with_signed_in_domains(Arc::clone(&signed_in))
            .with_health(Arc::clone(&health));
        let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());
        let browser_grants = management.browser_grants();
        let browser = if let Some(config) = browser_config.as_ref() {
            Arc::new(
                BrowserPlane::with_session_gate(
                    sessions.clone(),
                    Arc::clone(&lease_clock),
                    config.navigation_settle_deadline_ms,
                )
                .with_result_schema_enforcement(
                    computer_capability::ResultSchemaEnforcement::Withhold,
                )
                .with_shared_grants(browser_grants)
                .with_journal_persistence(
                    matches!(journal, JournalPersistence::Durable),
                    journal::JournalConfig {
                        journal_retention_bytes: BROWSER_DRIVE_JOURNAL_BYTES,
                        journal_max_entry_bytes: BROWSER_DRIVE_JOURNAL_MAX_ENTRY_BYTES,
                    },
                ),
            )
        } else {
            // The action surface is unavailable without browser configuration,
            // but browser.import_login still journals its typed configuration
            // refusal on the management surface.
            Arc::new(
                BrowserPlane::new()
                    .with_result_schema_enforcement(
                        computer_capability::ResultSchemaEnforcement::Withhold,
                    )
                    .with_shared_grants(browser_grants)
                    .with_journal_persistence(
                        matches!(journal, JournalPersistence::Durable),
                        journal::JournalConfig {
                            journal_retention_bytes: BROWSER_DRIVE_JOURNAL_BYTES,
                            journal_max_entry_bytes: BROWSER_DRIVE_JOURNAL_MAX_ENTRY_BYTES,
                        },
                    ),
            )
        };
        let calls = Arc::new(match journal {
            JournalPersistence::Durable => {
                journal::call_records::CallRecords::open_durable(wall_clock_ms())
            }
            JournalPersistence::Isolated => journal::call_records::CallRecords::in_memory(),
        });
        let routes = Arc::new(RouteBindings {
            display: Arc::new(tool_display::Records::with_events(Arc::clone(
                &calls.events,
            ))),
            ..Default::default()
        });
        let _ = calls.display.set(Arc::downgrade(&routes.display));
        let egress_deadlines = Arc::new(ConnectionDeadlines {
            display: Arc::clone(&routes.display),
            ..Default::default()
        });
        #[cfg(target_os = "macos")]
        let global_dispatch_review_revision =
            compiled_release_inputs().global_dispatch_review_revision;
        #[cfg(target_os = "macos")]
        let takeover_dispatch_review_revision =
            compiled_release_inputs().takeover_dispatch_review_revision;
        Self {
            health,
            agent_data: Arc::new(match journal {
                JournalPersistence::Durable => crate::agent_data::Participant::production(),
                JournalPersistence::Isolated => crate::agent_data::Participant::in_memory(),
            }),
            private_content: Arc::new(match journal {
                JournalPersistence::Durable => private_content::PrivateContent::production(),
                JournalPersistence::Isolated => private_content::PrivateContent::in_memory(),
            }),
            image_handles: Arc::new(image_handles::ImageHandles::default()),
            signed_in,
            routes,
            browser,
            browser_config,
            runtime_browser: None,
            sessions,
            user_browser: user_browser_bridge::UserBrowserBridge::with_user_grants(user_grants),
            lease_clock,
            launch_service,
            management,
            consent: Arc::new(cingulate_client::desk::ConsentDesk::new(Arc::new(
                consent_drain::UnconfiguredCingulate,
            ))),
            consent_drain: Arc::new(consent_drain::ConsentDrain::default()),
            user_browser_cards: Arc::default(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            computer: computer_capability::computer_audit(journal).map(|audit| {
                // One idle estimator for the plane's lifetime: it exists to
                // remember the previous sequence's posts, which a per-dispatch
                // driver cannot do.
                #[cfg(target_os = "macos")]
                let user_idle = Arc::new(std::sync::Mutex::new(
                    cerebellum_computer::dispatch::UserIdleEstimator::new(),
                ));
                Arc::new(
                    computer_capability::ComputerPlane::with_synthetic_driver(
                        audit,
                        // Built fresh per dispatch: each platform driver caches
                        // accessibility trees, and a stale cache may name a process
                        // generation that is gone. Synthetic requests declare no
                        // post-condition, so their effects remain indeterminate.
                        move || {
                            let driver =
                                computer_capability::NativeComputerPlatformDriver::default()
                                    .without_expected_post_condition();
                            #[cfg(target_os = "macos")]
                            let driver = driver
                                .with_global_dispatch_review_revision(
                                    global_dispatch_review_revision.clone(),
                                )
                                .with_takeover_dispatch_review_revision(
                                    takeover_dispatch_review_revision.clone(),
                                )
                                .with_takeover_pointer_fronting_review_revision(
                                    compiled_release_inputs()
                                        .takeover_pointer_fronting_review_revision,
                                )
                                .with_shared_user_idle(user_idle.clone());
                            driver
                        },
                    )
                    .with_launch_history(match journal {
                        JournalPersistence::Durable => {
                            open_app_history::LaunchHistory::production()
                        }
                        JournalPersistence::Isolated => {
                            open_app_history::LaunchHistory::in_memory()
                        }
                    })
                    // The fronting bracket is served only by a build carrying
                    // its review; without it a background target is refused.
                    .with_fronting_bracket_admitted(fronting_bracket_admitted(
                        &compiled_release_inputs(),
                    ))
                    .with_takeover_pointer_fronting_admitted(takeover_pointer_fronting_admitted(
                        &compiled_release_inputs(),
                    ))
                    // Fronting outside that bracket needs the app-use review
                    // as well; without it every such front is unavailable.
                    .with_app_use_fronting_admitted(app_use_fronting_admitted(
                        &compiled_release_inputs(),
                    ))
                    // The plane's one preview worker captures with the
                    // platform's capture, and only when the capture review
                    // and the app-use review both bind; otherwise every
                    // preview shows the application's icon.
                    .with_native_preview_capture(preview_capture_admitted(
                        &compiled_release_inputs(),
                    )),
                )
            }),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            computer_admitted: Arc::new(
                computer_release_evidence(&default_computer_context())
                    .gate_admitted_capabilities
                    .into_iter()
                    .collect(),
            ),
            #[cfg(test)]
            route_test_handler: None,
            #[cfg(test)]
            cursor_for_test: None,
            #[cfg(all(test, target_os = "macos"))]
            computer_for_test: None,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            cancellations: RequestCancellations::default(),
            operator_confirm: Arc::default(),
            run_calls: codemode::RunCalls::default(),
            browser_resumes: Arc::default(),
            browser_queue: Arc::new(call_queue::ConversationQueue::default()),
            capture,
            calls,
            call_record_workers: Arc::new(CallRecordWorkers::default()),
            egress_deadlines,
            scopes: Arc::new(scope_watch::ScopeRevocation::default()),
            #[cfg(test)]
            consent_test: None,
        }
    }
}

impl Clone for Planes {
    fn clone(&self) -> Self {
        Self {
            #[cfg(test)]
            route_test_handler: self.route_test_handler.clone(),
            #[cfg(test)]
            cursor_for_test: self.cursor_for_test.clone(),
            #[cfg(all(test, target_os = "macos"))]
            computer_for_test: self.computer_for_test.clone(),
            health: Arc::clone(&self.health),
            private_content: Arc::clone(&self.private_content),
            agent_data: Arc::clone(&self.agent_data),
            image_handles: Arc::clone(&self.image_handles),
            signed_in: Arc::clone(&self.signed_in),
            cancellations: self.cancellations.clone(),
            operator_confirm: self.operator_confirm.clone(),
            run_calls: self.run_calls.clone(),
            browser_queue: self.browser_queue.clone(),
            draining: self.draining.clone(),
            browser_resumes: Arc::clone(&self.browser_resumes),
            drain_signal: Arc::clone(&self.drain_signal),
            drain_notice: self.drain_notice.clone(),
            routes: Arc::clone(&self.routes),
            browser: Arc::clone(&self.browser),
            browser_config: self.browser_config.clone(),
            runtime_browser: self.runtime_browser.clone(),
            sessions: self.sessions.clone(),
            user_browser: self.user_browser.clone(),
            lease_clock: Arc::clone(&self.lease_clock),
            launch_service: self.launch_service.clone(),
            management: Arc::clone(&self.management),
            consent: Arc::clone(&self.consent),
            consent_drain: Arc::clone(&self.consent_drain),
            user_browser_cards: Arc::clone(&self.user_browser_cards),
            #[cfg(test)]
            consent_test: self.consent_test.clone(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            computer: self.computer.clone(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            computer_admitted: Arc::clone(&self.computer_admitted),
            capture: Arc::clone(&self.capture),
            calls: Arc::clone(&self.calls),
            call_record_workers: Arc::clone(&self.call_record_workers),
            egress_deadlines: Arc::clone(&self.egress_deadlines),
            scopes: Arc::clone(&self.scopes),
        }
    }
}

/// Adds the image handle a screenshot reply's bytes are resolvable by, for a
/// capture made on the route described by `facts`.
///
/// A route without a scope stamp gets no handle, and the field is omitted: the
/// resolver authorizes by scope, so nothing could ever fetch those bytes. A
/// reply whose image is missing or unreadable is left as it is.
impl Planes {
    /// The screenshot handle store, exposed so the wire fixtures can inspect it
    /// and resolve against it. Fixtures mint through
    /// `mint_image_handle_for_test`; production mints through
    /// `mint_image_handle`.
    pub fn image_handle_store(&self) -> &image_handles::ImageHandles {
        &self.image_handles
    }
}
