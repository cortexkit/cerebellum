use super::*;
use crate::browser::document_network::{address_is_public, DocumentNetwork};

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    /// Observe even between explicit navigation operations: a renderer can
    /// replace either the page or an embedded document on its own.
    pub(super) fn observe_document_peer(&mut self, event: &CdpEvent) {
        let Some(session) = event.session_id.as_deref().filter(|session| {
            self.attachment
                .as_ref()
                .is_some_and(|a| a.session_id == *session)
                || self.frame_sessions.values().any(|s| s == *session)
        }) else {
            return;
        };
        if event.method != "Network.responseReceived" {
            return;
        }
        let Some(params) = event
            .params
            .as_ref()
            .filter(|p| p.get("type").and_then(Value::as_str) == Some("Document"))
        else {
            return;
        };
        let (Some(frame), Some(loader), Some(response)) = (
            params.get("frameId").and_then(Value::as_str),
            params
                .get("loaderId")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty()),
            params.get("response"),
        ) else {
            return;
        };
        let Some(address) = response
            .get("remoteIPAddress")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        else {
            return;
        };
        self.document_peers
            .retain(|(_, known_frame, known_loader), _| {
                known_frame != frame || known_loader != loader
            });
        self.document_peers
            .insert((session.into(), frame.into(), loader.into()), address);
        if !address_is_public(address) {
            if let Some(origin) = response
                .get("url")
                .and_then(Value::as_str)
                .and_then(classification::canonical_origin_from_url)
            {
                self.private_peer_origins.insert(origin);
            }
        }
    }

    pub(super) fn document_network(
        &self,
        session: &str,
        frame: &str,
        loader: &str,
        origin: &str,
    ) -> DocumentNetwork {
        let lookup = |session: &str| {
            self.document_peers
                .get(&(session.into(), frame.into(), loader.into()))
                .copied()
        };
        DocumentNetwork {
            // A document can receive its response before moving to another
            // renderer. Frame and loader identity survive that session change;
            // each response came from the main page or an attached iframe session.
            remote_ip_address: lookup(session).or_else(|| {
                self.document_peers
                    .iter()
                    .find_map(|((_, known_frame, known_loader), address)| {
                        (known_frame == frame && known_loader == loader).then_some(*address)
                    })
            }),
            private_origin_seen: classification::canonical_origin_from_url(origin)
                .is_some_and(|origin| self.private_peer_origins.contains(&origin)),
        }
    }
}

#[cfg(test)]
#[path = "peers_tests.rs"]
mod tests;
