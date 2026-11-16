//! Route requests on sockets already bound by a self claim.
//! The daemon supplies the principal from that binding, not from route fields.

use subc_protocol::{scope::ScopeSelector, BindIdentity, RouteTarget};

pub(crate) fn open(
    target: RouteTarget,
    identity: &BindIdentity,
    scope: Option<&ScopeSelector>,
) -> Vec<u8> {
    let mut body = serde_json::json!({"op":"route.open", "target":target, "identity":identity});
    if let Some(scope) = scope {
        body["scope"] = serde_json::to_value(scope).expect("scope serializes");
    }
    serde_json::to_vec(&body).expect("route request serializes")
}
