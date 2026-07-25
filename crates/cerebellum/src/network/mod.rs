//! Browser-plane network safety primitives.
//!
//! The module is intentionally side-effect free at its policy boundaries. The
//! connector records a commitment only after custody attribution, scheme and
//! address policy, transport checks, and, for top-level transitions, one
//! immutable authorization decision all pass.

pub mod address_policy;
pub mod connector;
pub mod url;

pub use address_policy::{
    fixture as address_policy_fixture, fixture_digest as address_policy_fixture_digest,
    AddressClass, AddressPolicy, AddressPolicyArtifact, AddressPolicyError, PolicyClassLists,
    ADDRESS_POLICY_FIXTURE, ADDRESS_POLICY_SCHEMA,
};
pub use connector::{
    connector_test_plan, AttributionSource, AuthorizationDecision, BypassPath, ChildIdentity,
    CommitmentKind, CommittedTraffic, Connector, ConnectorAdmission, ConnectorConfig,
    ConnectorError, ConnectorTestPlan, NetworkRequest, RequestAttribution, RequestClass,
    ResolvedPeer, Resolver, ResolverError, StaticResolver, TestPlanCase, TransportUse,
    CONNECTOR_TEST_PLAN_FIXTURE, REQUIREMENTS, TEST_PLAN_SCHEMA,
};
pub use url::{
    parse_canonical_url, parse_url, CanonicalUrl, TransitionTarget, TransitionTargetCache,
    UrlParseError,
};

/// A small release-facing validation bundle. Registration validates the
/// immutable address-policy fixture and connector test plan without opening a
/// browser or contacting a resolver.
pub fn validate_s4_fixtures() -> Result<(AddressPolicy, ConnectorTestPlan), String> {
    let policy = address_policy_fixture().map_err(|error| error.to_string())?;
    let plan = connector_test_plan().map_err(|error| format!("{error:?}"))?;
    Ok((policy, plan))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_fixtures_are_parseable_and_complete() {
        let (policy, plan) = validate_s4_fixtures().unwrap();
        assert_eq!(policy.artifact().schema, ADDRESS_POLICY_SCHEMA);
        assert_eq!(plan.schema, TEST_PLAN_SCHEMA);
        assert_eq!(policy.digest().len(), 64);
        assert_eq!(plan.digest().len(), 64);
    }
}
