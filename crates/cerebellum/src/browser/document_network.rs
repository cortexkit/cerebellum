//! Connected-peer evidence belongs to a document, not a DNS name or a grant.

use std::{net::IpAddr, sync::OnceLock};

use crate::network::{address_policy, AddressPolicy};

/// Ephemeral evidence copied with committed document identities, never stored
/// in a grant or exposed as a tool result.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DocumentNetwork {
    pub remote_ip_address: Option<IpAddr>,
    pub private_origin_seen: bool,
}

impl DocumentNetwork {
    pub fn is_public(self, origin: &str) -> bool {
        crate::browser_standing_grants::origin_is_public(origin)
            && match self.remote_ip_address {
                Some(address) => address_is_public(address),
                // Chrome supplies no peer for synthetic service-worker documents.
                // Durable public profiles can encounter those on their first load;
                // asking on every such page would turn ordinary public browsing
                // into site consent. Retain the name-only rule unless this context
                // has seen the origin on a private peer. Residual: worker-served
                // content under a public name never seen private remains public.
                // Frames are never paused to observe their peer addresses. A first-ever
                // private out-of-process iframe can remain unknown if its response arrived
                // before its session was tracked, and keeps the name rule.
                None => !self.private_origin_seen,
            }
    }
}

pub(super) fn address_is_public(address: IpAddr) -> bool {
    static POLICY: OnceLock<AddressPolicy> = OnceLock::new();
    POLICY
        .get_or_init(|| address_policy::fixture().expect("checked-in address policy is valid"))
        .allows(address)
}
