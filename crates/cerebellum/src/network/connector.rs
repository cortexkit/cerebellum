//! Enforcing connector model for browser-originated requests.
//!
//! This module models the ordering boundary at which destination-request and
//! multiplexed-stream bytes may be committed. Every request is attributed to a
//! custody-verified child and an open target before policy or transport work;
//! top-level requests additionally carry one immutable authorization decision.

use super::address_policy::{AddressClass, AddressPolicy, AddressPolicyError};
use super::url::{CanonicalUrl, TransitionTarget, TransitionTargetCache, UrlParseError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

pub const TEST_PLAN_SCHEMA: &str = "ck-browser-connector-test-plan/v1";
pub const CONNECTOR_TEST_PLAN_FIXTURE: &[u8] =
    include_bytes!("../../resources/b1_s4_connector-test-plan.json");

pub const REQUIREMENTS: &[&str] = &[
    "NET-ADDRESS-CANONICALIZATION",
    "NET-ADDRESS-CLASSIFICATION",
    "NET-ALLOWED-CANDIDATE-SELECTION",
    "NET-BYPASS-SUITE",
    "NET-CONNECTOR-DNS",
    "NET-CUSTODY-ARGS",
    "NET-CUSTODY-BINARY",
    "NET-DNS-CHANGE-RECHECK",
    "NET-DOWNLOAD-BLOCK",
    "NET-EXACT-PEER-BINDING",
    "NET-NO-DIRECT-FALLBACK",
    "NET-REDIRECT-RECHECK",
    "NET-REQUEST-CLASS-COVERAGE",
    "NET-RETRY-RECHECK",
    "NET-SUBRESOURCE-RECORD-ONLY",
    "NET-TOPLEVEL-ORIGIN-GATE",
    "NET-TRANSPORT-COALESCING",
    "NET-TRANSPORT-REUSE",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorTestPlan {
    pub cases: Vec<TestPlanCase>,
    pub schema: String,
    pub test_plan_revision: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestPlanCase {
    pub case_id: String,
    pub requirement_ids: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestPlanError {
    InvalidJson,
    NonCanonical,
    UnknownOrMissingField,
    InvalidField(&'static str),
    MissingRequirement(&'static str),
}
impl ConnectorTestPlan {
    pub fn parse(bytes: &[u8]) -> Result<Self, TestPlanError> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| TestPlanError::InvalidJson)?;
        if super::address_policy::canonical_json_bytes(&value) != bytes {
            return Err(TestPlanError::NonCanonical);
        }
        let plan: Self =
            serde_json::from_value(value).map_err(|_| TestPlanError::UnknownOrMissingField)?;
        plan.validate()?;
        Ok(plan)
    }
    pub fn parse_pinned(bytes: &[u8], expected_sha256: &str) -> Result<Self, TestPlanError> {
        if !super::address_policy::valid_digest(expected_sha256) {
            return Err(TestPlanError::InvalidField("digest"));
        }
        let plan = Self::parse(bytes)?;
        if plan.digest() != expected_sha256 {
            return Err(TestPlanError::InvalidField("digest"));
        }
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), TestPlanError> {
        if self.schema != TEST_PLAN_SCHEMA
            || self.test_plan_revision.is_empty()
            || self.test_plan_revision.len() > 256
            || matches!(
                self.test_plan_revision.to_ascii_lowercase().as_str(),
                "placeholder" | "tbd" | "unknown"
            )
        {
            return Err(TestPlanError::InvalidField("schema"));
        }
        let mut previous = None;
        let mut covered = BTreeSet::new();
        for case in &self.cases {
            if case.case_id.is_empty()
                || case.case_id.len() > 256
                || previous.is_some_and(|old: &str| old.as_bytes() >= case.case_id.as_bytes())
            {
                return Err(TestPlanError::InvalidField("cases"));
            }
            previous = Some(case.case_id.as_str());
            let mut local = BTreeSet::new();
            let mut requirement_previous = None;
            if case.requirement_ids.is_empty() {
                return Err(TestPlanError::InvalidField("requirement_ids"));
            }
            for requirement in &case.requirement_ids {
                if !REQUIREMENTS.contains(&requirement.as_str())
                    || !local.insert(requirement.clone())
                    || requirement_previous
                        .is_some_and(|old: &str| old.as_bytes() >= requirement.as_bytes())
                {
                    return Err(TestPlanError::InvalidField("requirement_ids"));
                }
                requirement_previous = Some(requirement.as_str());
                covered.insert(requirement.as_str());
            }
        }
        for requirement in REQUIREMENTS {
            if !covered.contains(requirement) {
                return Err(TestPlanError::MissingRequirement(requirement));
            }
        }
        if !self.cases.iter().any(|case| {
            case.requirement_ids
                .contains(&"NET-CUSTODY-BINARY".to_string())
                && case
                    .requirement_ids
                    .contains(&"NET-NO-DIRECT-FALLBACK".to_string())
        }) {
            return Err(TestPlanError::InvalidField("cases"));
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        super::address_policy::canonical_json_bytes(
            &serde_json::to_value(self).expect("test plan serializes"),
        )
    }
    pub fn digest(&self) -> String {
        super::address_policy::sha256_hex(&self.canonical_bytes())
    }
}
pub fn connector_test_plan() -> Result<ConnectorTestPlan, TestPlanError> {
    ConnectorTestPlan::parse(CONNECTOR_TEST_PLAN_FIXTURE)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestClass {
    TopLevelNavigation,
    FrameNavigation,
    Script,
    Stylesheet,
    Image,
    Media,
    FetchXhr,
    Worker,
    ServiceWorker,
    WebSocketHandshake,
    EventSource,
    Prefetch,
    Download,
    Redirect,
    Retry,
}
impl RequestClass {
    pub const fn is_top_level(self) -> bool {
        matches!(
            self,
            Self::TopLevelNavigation | Self::Redirect | Self::Retry
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributionSource {
    Module,
    PageSupplied,
    UnknownTarget,
    Ambiguous,
    Late,
}

/// Identity facts supplied by module-owned process, target, frame, and context
/// observations. Renderer-supplied assertions cannot construct valid attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAttribution {
    process_id: u64,
    generation: u64,
    context_id: String,
    target_id: String,
    pub request_class: RequestClass,
    source: AttributionSource,
}
impl RequestAttribution {
    pub fn module_controlled(
        process_id: u64,
        generation: u64,
        context_id: impl Into<String>,
        target_id: impl Into<String>,
        request_class: RequestClass,
    ) -> Self {
        Self {
            process_id,
            generation,
            context_id: context_id.into(),
            target_id: target_id.into(),
            request_class,
            source: AttributionSource::Module,
        }
    }
    pub fn page_supplied(request_class: RequestClass) -> Self {
        Self {
            process_id: 0,
            generation: 0,
            context_id: String::new(),
            target_id: String::new(),
            request_class,
            source: AttributionSource::PageSupplied,
        }
    }
    pub fn unknown_target(
        process_id: u64,
        generation: u64,
        context_id: impl Into<String>,
        request_class: RequestClass,
    ) -> Self {
        Self {
            process_id,
            generation,
            context_id: context_id.into(),
            target_id: String::new(),
            request_class,
            source: AttributionSource::UnknownTarget,
        }
    }
    pub fn ambiguous(
        process_id: u64,
        generation: u64,
        context_id: impl Into<String>,
        target_id: impl Into<String>,
        request_class: RequestClass,
    ) -> Self {
        Self {
            process_id,
            generation,
            context_id: context_id.into(),
            target_id: target_id.into(),
            request_class,
            source: AttributionSource::Ambiguous,
        }
    }
    pub fn late(
        process_id: u64,
        generation: u64,
        context_id: impl Into<String>,
        target_id: impl Into<String>,
        request_class: RequestClass,
    ) -> Self {
        Self {
            process_id,
            generation,
            context_id: context_id.into(),
            target_id: target_id.into(),
            request_class,
            source: AttributionSource::Late,
        }
    }
    pub fn process_id(&self) -> u64 {
        self.process_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn context_id(&self) -> &str {
        &self.context_id
    }
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    pub fn source(&self) -> &AttributionSource {
        &self.source
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDecision {
    pub decision_id: String,
    pub authorized_origins: Vec<String>,
}
impl AuthorizationDecision {
    pub fn new(
        decision_id: impl Into<String>,
        authorized_origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            decision_id: decision_id.into(),
            authorized_origins: authorized_origins.into_iter().map(Into::into).collect(),
        }
    }
    fn covers(&self, origin: &str) -> bool {
        self.authorized_origins.iter().any(|value| value == origin)
    }
}

#[derive(Debug, Clone)]
pub struct NetworkRequest {
    request_id: String,
    target: Arc<CanonicalUrl>,
    attribution: Option<RequestAttribution>,
    pub request_class: RequestClass,
    authorization_decision_id: Option<String>,
    transport: TransportUse,
    attempt: usize,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportUse {
    Fresh,
    Reuse(String),
    Coalesce(String),
}
impl NetworkRequest {
    pub fn new(
        request_id: impl Into<String>,
        target: Arc<CanonicalUrl>,
        attribution: Option<RequestAttribution>,
        request_class: RequestClass,
        authorization_decision_id: Option<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            target,
            attribution,
            request_class,
            authorization_decision_id,
            transport: TransportUse::Fresh,
            attempt: 0,
        }
    }
    pub fn from_url(
        cache: &mut TransitionTargetCache,
        request_id: impl Into<String>,
        raw_url: &str,
        attribution: Option<RequestAttribution>,
        request_class: RequestClass,
        authorization_decision_id: Option<String>,
    ) -> Result<Self, UrlParseError> {
        let target = cache.parse_once(raw_url)?;
        Ok(Self::new(
            request_id,
            target,
            attribution,
            request_class,
            authorization_decision_id,
        ))
    }
    pub fn from_transition_target(
        request_id: impl Into<String>,
        target: &TransitionTarget,
        attribution: Option<RequestAttribution>,
        request_class: RequestClass,
        authorization_decision_id: Option<String>,
    ) -> Self {
        Self::new(
            request_id,
            target.shared_url(),
            attribution,
            request_class,
            authorization_decision_id,
        )
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn target(&self) -> &CanonicalUrl {
        &self.target
    }
    pub fn shared_target(&self) -> Arc<CanonicalUrl> {
        Arc::clone(&self.target)
    }
    pub fn attribution(&self) -> Option<&RequestAttribution> {
        self.attribution.as_ref()
    }
    pub fn authorization_decision_id(&self) -> Option<&str> {
        self.authorization_decision_id.as_deref()
    }
    pub fn attempt(&self) -> usize {
        self.attempt
    }
    pub fn retry(&self) -> Self {
        let mut retry = self.clone();
        retry.attempt += 1;
        retry
    }
    pub fn reuse_transport(mut self, transport_id: impl Into<String>) -> Self {
        self.transport = TransportUse::Reuse(transport_id.into());
        self
    }
    pub fn coalesce_transport(mut self, transport_id: impl Into<String>) -> Self {
        self.transport = TransportUse::Coalesce(transport_id.into());
        self
    }
    pub fn transport_use(&self) -> &TransportUse {
        &self.transport
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildIdentity {
    pub process_id: u64,
    pub generation: u64,
    pub custody_digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorAdmission {
    child: ChildIdentity,
}
impl ConnectorAdmission {
    pub fn new(child: ChildIdentity) -> Self {
        Self { child }
    }
    pub fn child(&self) -> &ChildIdentity {
        &self.child
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectorConfig {
    pub direct_fallback: bool,
    pub browser_owned_dns: bool,
    pub unmanaged_quic: bool,
    pub extension_transports: bool,
    pub direct_sockets: bool,
    pub proxy_bypass: bool,
    pub unmanaged_remote_debugging: bool,
    pub loopback_exemption: bool,
}
impl ConnectorConfig {
    fn safe(self) -> bool {
        !self.direct_fallback
            && !self.browser_owned_dns
            && !self.unmanaged_quic
            && !self.extension_transports
            && !self.direct_sockets
            && !self.proxy_bypass
            && !self.unmanaged_remote_debugging
            && !self.loopback_exemption
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassPath {
    ProxyBypass,
    BrowserOwnedDns,
    UnmanagedQuic,
    ExtensionTransport,
    DirectSocket,
    UnmanagedRemoteDebugging,
    LoopbackExemption,
    BrowserArgumentInjection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverError {
    OperationalFailure,
    ProtocolFailure,
    Incomplete,
}
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str) -> Result<Vec<String>, ResolverError>;
}
#[derive(Debug, Default)]
pub struct StaticResolver {
    answers: RwLock<BTreeMap<String, Vec<String>>>,
    failures: RwLock<BTreeSet<String>>,
    revision: AtomicU64,
}
impl StaticResolver {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&self, host: impl Into<String>, answers: Vec<String>) {
        if let Ok(mut values) = self.answers.write() {
            values.insert(host.into().to_ascii_lowercase(), answers);
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn fail(&self, host: impl Into<String>) {
        if let Ok(mut values) = self.failures.write() {
            values.insert(host.into().to_ascii_lowercase());
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }
}
impl Resolver for StaticResolver {
    fn resolve(&self, host: &str) -> Result<Vec<String>, ResolverError> {
        if self
            .failures
            .read()
            .ok()
            .is_some_and(|values| values.contains(&host.to_ascii_lowercase()))
        {
            return Err(ResolverError::OperationalFailure);
        }
        Ok(self
            .answers
            .read()
            .ok()
            .and_then(|values| values.get(&host.to_ascii_lowercase()).cloned())
            .unwrap_or_default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorError {
    DirectFallbackBlocked,
    BypassPathBlocked,
    MissingAdmission,
    AdmissionMismatch,
    InvalidAuthorizationDecision,
    Unattributed,
    UnknownTarget,
    AmbiguousAttribution,
    LateAttribution,
    PageSuppliedAttribution,
    RequestClassMismatch,
    MissingContext,
    SchemeNotAllowed {
        scheme: String,
    },
    AddressNotAllowed {
        address_class: AddressClass,
    },
    ResolverFailure,
    MalformedResolverCandidate,
    MissingAuthorizationDecision,
    AmbiguousAuthorizationDecision,
    AuthorizationDecisionNotFound,
    OriginScope {
        attempted_origin: String,
        granted_origins: Vec<String>,
    },
    TransportNotFound,
    TransportPeerNotAllowed,
    TransportHostNotAllowed,
    TransportOriginNotAllowed,
    CertificateCoalescingDenied,
    AddressPolicy(AddressPolicyError),
}
impl fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ConnectorError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentKind {
    DestinationRequest,
    MultiplexedStream,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedTraffic {
    pub request_id: String,
    pub transport_id: String,
    pub peer: IpAddr,
    pub kind: CommitmentKind,
    pub attempt: usize,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPeer {
    pub address: IpAddr,
    pub address_class: Option<AddressClass>,
}
#[derive(Debug, Clone)]
struct Transport {
    child: ChildIdentity,
    peer: IpAddr,
    scheme: String,
    hosts: BTreeSet<String>,
    origins: BTreeSet<String>,
    certificate_hosts: BTreeSet<String>,
}
impl Transport {
    fn accepts(&self, url: &CanonicalUrl) -> bool {
        self.scheme == url.scheme()
            && self.hosts.contains(url.host())
            && self.origins.contains(&url.origin())
            && self.child.process_id != 0
    }
}

pub struct Connector<R: Resolver + ?Sized> {
    policy: AddressPolicy,
    resolver: Arc<R>,
    config: ConnectorConfig,
    admission: Option<ConnectorAdmission>,
    decisions: BTreeMap<String, AuthorizationDecision>,
    transports: BTreeMap<String, Transport>,
    next_transport: u64,
    destination_request_commits: u64,
    stream_commits: u64,
}
impl<R: Resolver + ?Sized> Connector<R> {
    pub fn new(policy: AddressPolicy, resolver: Arc<R>) -> Self {
        Self::with_config(policy, resolver, ConnectorConfig::default())
            .expect("default connector configuration is safe")
    }
    pub fn with_config(
        policy: AddressPolicy,
        resolver: Arc<R>,
        config: ConnectorConfig,
    ) -> Result<Self, ConnectorError> {
        if !config.safe() {
            return Err(ConnectorError::BypassPathBlocked);
        }
        Ok(Self {
            policy,
            resolver,
            config,
            admission: None,
            decisions: BTreeMap::new(),
            transports: BTreeMap::new(),
            next_transport: 1,
            destination_request_commits: 0,
            stream_commits: 0,
        })
    }
    pub fn policy(&self) -> &AddressPolicy {
        &self.policy
    }
    pub fn config(&self) -> ConnectorConfig {
        self.config
    }
    pub fn admit(&mut self, admission: ConnectorAdmission) {
        // The supplied admission remains process-bound even when it contains
        // malformed data; later validation prevents that data from authorizing
        // a request or transport.
        self.admission = Some(admission);
    }
    pub fn revoke_admission(&mut self) {
        self.admission = None;
        self.transports.clear();
    }
    pub fn register_decision(
        &mut self,
        decision: AuthorizationDecision,
    ) -> Result<(), ConnectorError> {
        if !(1..=256).contains(&decision.decision_id.len())
            || self.decisions.contains_key(&decision.decision_id)
            || decision.authorized_origins.len() > 256
        {
            return Err(ConnectorError::InvalidAuthorizationDecision);
        }
        let mut seen = BTreeSet::new();
        for origin in &decision.authorized_origins {
            if origin.len() > 4096 || !seen.insert(origin) {
                return Err(ConnectorError::InvalidAuthorizationDecision);
            }
            if origin != "null" {
                let parsed = CanonicalUrl::parse(origin)
                    .map_err(|_| ConnectorError::InvalidAuthorizationDecision)?;
                if !parsed.is_http() || parsed.origin() != *origin {
                    return Err(ConnectorError::InvalidAuthorizationDecision);
                }
            }
        }
        self.decisions
            .insert(decision.decision_id.clone(), decision);
        Ok(())
    }
    pub fn direct_socket_attempt(&self) -> Result<(), ConnectorError> {
        Err(ConnectorError::DirectFallbackBlocked)
    }
    /// All alternate browser egress mechanisms fail before they can reach the
    /// destination-request or multiplexed-stream commitment counters.
    pub fn bypass_attempt(&self, _path: BypassPath) -> Result<(), ConnectorError> {
        Err(ConnectorError::BypassPathBlocked)
    }
    pub fn destination_request_commits(&self) -> u64 {
        self.destination_request_commits
    }
    pub fn stream_commits(&self) -> u64 {
        self.stream_commits
    }
    pub fn total_committed_bytes(&self) -> u64 {
        self.destination_request_commits + self.stream_commits
    }
    pub fn transport_count(&self) -> usize {
        self.transports.len()
    }
    pub fn resolve_allowed(&self, target: &CanonicalUrl) -> Result<ResolvedPeer, ConnectorError> {
        if !target.is_http() {
            return Err(ConnectorError::SchemeNotAllowed {
                scheme: target.scheme().to_string(),
            });
        }
        if let Some(literal) = target.literal_address() {
            let literal = super::address_policy::canonical_address_for_connector(literal);
            return self.policy.classify(literal).map_or(
                Ok(ResolvedPeer {
                    address: literal,
                    address_class: None,
                }),
                |class| {
                    Err(ConnectorError::AddressNotAllowed {
                        address_class: class,
                    })
                },
            );
        }
        let candidates = self
            .resolver
            .resolve(target.host())
            .map_err(|_| ConnectorError::ResolverFailure)?;
        if candidates.is_empty() {
            return Err(ConnectorError::ResolverFailure);
        }
        let mut rejected = None;
        for candidate in candidates {
            let address = match candidate.parse::<IpAddr>() {
                Ok(value) => value,
                Err(_) => {
                    rejected.get_or_insert(AddressClass::Unspecified);
                    continue;
                }
            };
            if let Some(class) = self.policy.classify(address) {
                rejected.get_or_insert(class);
            } else {
                return Ok(ResolvedPeer {
                    address: super::address_policy::canonical_address_for_connector(address),
                    address_class: None,
                });
            }
        }
        Err(ConnectorError::AddressNotAllowed {
            address_class: rejected.unwrap_or(AddressClass::Unspecified),
        })
    }
    pub fn commit_request(
        &mut self,
        request: &NetworkRequest,
    ) -> Result<CommittedTraffic, ConnectorError> {
        self.commit(request, CommitmentKind::DestinationRequest)
    }
    pub fn commit_stream(
        &mut self,
        request: &NetworkRequest,
    ) -> Result<CommittedTraffic, ConnectorError> {
        self.commit(request, CommitmentKind::MultiplexedStream)
    }
    fn commit(
        &mut self,
        request: &NetworkRequest,
        kind: CommitmentKind,
    ) -> Result<CommittedTraffic, ConnectorError> {
        self.validate_attribution(request)?;
        self.validate_admission(request)?;
        if !request.target.is_http() {
            return Err(ConnectorError::SchemeNotAllowed {
                scheme: request.target.scheme().to_string(),
            });
        }
        let (peer, existing_transport_id) = match &request.transport {
            TransportUse::Fresh => {
                let peer = self.resolve_allowed(&request.target)?;
                (peer.address, None)
            }
            TransportUse::Reuse(id) => {
                let transport = self
                    .transports
                    .get(id)
                    .ok_or(ConnectorError::TransportNotFound)?;
                self.validate_existing_transport(transport, request)?;
                (transport.peer, Some(id.clone()))
            }
            TransportUse::Coalesce(id) => {
                let transport = self
                    .transports
                    .get(id)
                    .ok_or(ConnectorError::TransportNotFound)?;
                self.validate_coalescing(transport, request)?;
                (transport.peer, Some(id.clone()))
            }
        };
        // A top-level decision is checked after address policy but before a
        // transport is bound, so an unauthorized transition leaves no socket
        // binding or destination-request state behind.
        self.validate_transition_authority(request)?;
        let transport_id =
            existing_transport_id.unwrap_or_else(|| self.open_transport(request, peer));
        let committed = CommittedTraffic {
            request_id: request.request_id.clone(),
            transport_id,
            peer,
            kind,
            attempt: request.attempt,
        };
        match kind {
            CommitmentKind::DestinationRequest => self.destination_request_commits += 1,
            CommitmentKind::MultiplexedStream => self.stream_commits += 1,
        }
        Ok(committed)
    }
    fn validate_admission(&self, request: &NetworkRequest) -> Result<(), ConnectorError> {
        let expected = self
            .admission
            .as_ref()
            .ok_or(ConnectorError::MissingAdmission)?;
        if expected.child.process_id == 0
            || expected.child.generation == 0
            || !super::address_policy::valid_digest(&expected.child.custody_digest)
        {
            return Err(ConnectorError::AdmissionMismatch);
        }
        let attribution = request
            .attribution
            .as_ref()
            .ok_or(ConnectorError::Unattributed)?;
        if attribution.process_id != expected.child.process_id
            || attribution.generation != expected.child.generation
        {
            return Err(ConnectorError::AdmissionMismatch);
        }
        Ok(())
    }
    fn validate_attribution(&self, request: &NetworkRequest) -> Result<(), ConnectorError> {
        let attribution = request
            .attribution
            .as_ref()
            .ok_or(ConnectorError::Unattributed)?;
        if attribution.request_class != request.request_class {
            return Err(ConnectorError::RequestClassMismatch);
        }
        match attribution.source {
            AttributionSource::Module => {
                if attribution.context_id.is_empty() {
                    return Err(ConnectorError::MissingContext);
                }
                if attribution.target_id.is_empty() {
                    return Err(ConnectorError::UnknownTarget);
                }
                Ok(())
            }
            AttributionSource::PageSupplied => Err(ConnectorError::PageSuppliedAttribution),
            AttributionSource::UnknownTarget => Err(ConnectorError::UnknownTarget),
            AttributionSource::Ambiguous => Err(ConnectorError::AmbiguousAttribution),
            AttributionSource::Late => Err(ConnectorError::LateAttribution),
        }
    }
    fn validate_transition_authority(
        &self,
        request: &NetworkRequest,
    ) -> Result<(), ConnectorError> {
        if !request.request_class.is_top_level() {
            return Ok(());
        }
        let decision_id = request
            .authorization_decision_id
            .as_deref()
            .ok_or(ConnectorError::MissingAuthorizationDecision)?;
        let decision = self
            .decisions
            .get(decision_id)
            .ok_or(ConnectorError::AuthorizationDecisionNotFound)?;
        let origin = request.target.origin();
        if !decision.covers(&origin) {
            return Err(ConnectorError::OriginScope {
                attempted_origin: origin,
                granted_origins: decision.authorized_origins.clone(),
            });
        }
        Ok(())
    }
    fn open_transport(&mut self, request: &NetworkRequest, peer: IpAddr) -> String {
        let id = format!("transport-{}", self.next_transport);
        self.next_transport += 1;
        let mut hosts = BTreeSet::new();
        hosts.insert(request.target.host().to_string());
        let mut origins = BTreeSet::new();
        origins.insert(request.target.origin());
        self.transports.insert(
            id.clone(),
            Transport {
                child: self
                    .admission
                    .as_ref()
                    .expect("admission validated")
                    .child
                    .clone(),
                peer,
                scheme: request.target.scheme().to_string(),
                hosts,
                origins,
                certificate_hosts: BTreeSet::new(),
            },
        );
        id
    }
    fn validate_existing_transport(
        &self,
        transport: &Transport,
        request: &NetworkRequest,
    ) -> Result<(), ConnectorError> {
        if !same_child(
            &transport.child,
            self.admission
                .as_ref()
                .expect("admission validated")
                .child(),
        ) {
            return Err(ConnectorError::AdmissionMismatch);
        }
        if self.policy.classify(transport.peer).is_some() {
            return Err(ConnectorError::TransportPeerNotAllowed);
        }
        if !transport.accepts(&request.target) {
            return Err(ConnectorError::TransportHostNotAllowed);
        }
        Ok(())
    }
    fn validate_coalescing(
        &self,
        transport: &Transport,
        request: &NetworkRequest,
    ) -> Result<(), ConnectorError> {
        if !transport.certificate_hosts.contains(request.target.host()) {
            return Err(ConnectorError::CertificateCoalescingDenied);
        }
        self.validate_existing_transport(transport, request)
    }
    /// Add a certificate-authorized host without adding it to the transport's
    /// validated host/origin sets. Coalescing remains fail-closed until the host
    /// was independently validated by a request, so this operation cannot widen
    /// origin authority.
    pub fn record_certificate_host(
        &mut self,
        transport_id: &str,
        host: impl Into<String>,
    ) -> Result<(), ConnectorError> {
        let transport = self
            .transports
            .get_mut(transport_id)
            .ok_or(ConnectorError::TransportNotFound)?;
        transport
            .certificate_hosts
            .insert(host.into().to_ascii_lowercase());
        Ok(())
    }
}
fn same_child(left: &ChildIdentity, right: &ChildIdentity) -> bool {
    left.process_id == right.process_id
        && left.generation == right.generation
        && left.custody_digest == right.custody_digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::address_policy::fixture as policy_fixture;

    fn connector() -> (Connector<StaticResolver>, Arc<StaticResolver>) {
        let resolver = Arc::new(StaticResolver::new());
        resolver.set(
            "public.example",
            vec!["10.0.0.1".into(), "93.184.216.34".into()],
        );
        let mut connector = Connector::new(policy_fixture().unwrap(), Arc::clone(&resolver));
        connector.admit(ConnectorAdmission::new(ChildIdentity {
            process_id: 7,
            generation: 1,
            custody_digest: "a".repeat(64),
        }));
        connector
            .register_decision(AuthorizationDecision::new(
                "decision-1",
                ["https://public.example"],
            ))
            .unwrap();
        (connector, resolver)
    }
    fn request(class: RequestClass, decision: Option<&str>) -> NetworkRequest {
        let target = Arc::new(CanonicalUrl::parse("https://public.example/").unwrap());
        NetworkRequest::new(
            "request-1",
            target,
            Some(RequestAttribution::module_controlled(
                7, 1, "context", "target", class,
            )),
            class,
            decision.map(str::to_string),
        )
    }

    #[test]
    fn policy_and_authorization_complete_before_bytes() {
        let (mut connector, _) = connector();
        let denied = request(RequestClass::TopLevelNavigation, None);
        assert_eq!(
            connector.commit_request(&denied),
            Err(ConnectorError::MissingAuthorizationDecision)
        );
        assert_eq!(connector.total_committed_bytes(), 0);
        let allowed = request(RequestClass::TopLevelNavigation, Some("decision-1"));
        assert_eq!(
            connector.commit_request(&allowed).unwrap().peer.to_string(),
            "93.184.216.34"
        );
        assert_eq!(connector.total_committed_bytes(), 1);
    }

    #[test]
    fn attribution_and_forbidden_candidates_are_blocked_without_bytes() {
        let (mut connector, resolver) = connector();
        let unattributed = NetworkRequest::new(
            "request-1",
            Arc::new(CanonicalUrl::parse("https://public.example/").unwrap()),
            None,
            RequestClass::Image,
            None,
        );
        assert_eq!(
            connector.commit_request(&unattributed),
            Err(ConnectorError::Unattributed)
        );
        resolver.set("public.example", vec!["127.0.0.1".into()]);
        assert_eq!(
            connector.commit_request(&request(RequestClass::Image, None)),
            Err(ConnectorError::AddressNotAllowed {
                address_class: AddressClass::Loopback
            })
        );
        assert_eq!(connector.total_committed_bytes(), 0);
    }

    #[test]
    fn retries_reuse_the_same_parsed_target() {
        let mut cache = TransitionTargetCache::new();
        let first = NetworkRequest::from_url(
            &mut cache,
            "r1",
            "https://public.example/a",
            None,
            RequestClass::Retry,
            Some("d".into()),
        );
        let first = first.unwrap();
        let retry = first.retry();
        assert!(Arc::ptr_eq(&first.target, &retry.target));
        assert_eq!(cache.parse_count(), 1);
    }
}
