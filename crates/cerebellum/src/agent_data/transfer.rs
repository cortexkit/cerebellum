//! Engram's authenticated cut metadata bounds and identifies the marks bytes.

use super::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Item {
    #[serde(rename = "sessionRef")]
    pub session_ref: String,
    pub stream: String,
    #[serde(rename = "endOffset")]
    pub end_offset: u64,
    pub digest: String,
}

fn session_ref(agent: &str, cut: &str) -> String {
    door::hex(&Sha256::digest(
        format!("cerebellum-marks:{agent}:{cut}").as_bytes(),
    ))[..32]
        .into()
}

impl Participant {
    pub(super) async fn upload(
        &self,
        payload: &Payload,
        cut: &str,
        step: Step,
    ) -> Result<Item, ErrorBody> {
        let bytes = serde_json::to_vec(payload).map_err(unavailable)?;
        let item = Item {
            session_ref: session_ref(&payload.agent_id, cut),
            stream: STREAM.into(),
            end_offset: bytes.len() as u64,
            digest: door::hex(&Sha256::digest(&bytes)),
        };
        let door = self.door()?;
        let mut offset = 0;
        for chunk in bytes.chunks(32 * 1024) {
            let end = offset + chunk.len() as u64;
            match door.call("session.admit", json!({"sessionRef":item.session_ref,"fromOffset":offset,"bytes":door::hex(chunk)})).await {
                Ok(reply) if reply["durableOffset"].as_u64() == Some(end) => {}
                Err(e) if e.code.as_str() == "offset_mismatch" && e.detail.as_ref().and_then(|d| d["expectedOffset"].as_u64()).is_some_and(|n| n >= end && n <= item.end_offset) => {
                    let reply = door.call("session.read", json!({"sessionRef":item.session_ref,"fromOffset":offset,"limit":chunk.len()})).await.map_err(unavailable)?;
                    if reply["bytes"].as_str() != Some(door::hex(chunk).as_str()) {
                        return Err(detailed(RefusalCode::InvalidState, "admitted marks prefix differs", json!({"step":step})));
                    }
                }
                other => return Err(unavailable(other)),
            }
            offset = end;
        }
        let cover = door
            .call("session.cover", json!({"sessionRef":item.session_ref}))
            .await
            .map_err(unavailable)?;
        if cover["durableOffset"].as_u64() != Some(item.end_offset)
            || cover["cloudOffset"].as_u64().unwrap_or(0) < item.end_offset
        {
            return Err(unavailable("marks stream is not covered in the cloud yet"));
        }
        Ok(item)
    }

    pub(super) async fn download(
        &self,
        agent: &str,
        cut: &str,
    ) -> Result<(Option<Item>, Payload), ErrorBody> {
        let door = self.door()?;
        let metadata = door
            .call("cut.read", json!({"cutId":cut}))
            .await
            .map_err(|_| error(RefusalCode::CutNotReady, "marks cut is not readable"))?;
        #[derive(Deserialize)]
        struct Cut {
            items: Vec<Item>,
        }
        let metadata: Cut = serde_json::from_value(metadata).map_err(unavailable)?;
        let mut matching = metadata
            .items
            .into_iter()
            .filter(|i| i.session_ref == session_ref(agent, cut) && i.stream == STREAM);
        // The source writes no record for an agent with nothing marked, so
        // that a computer without cerebellum can still receive that agent.
        // A sealed cut with no record therefore means an empty mark set.
        let Some(item) = matching.next() else {
            return Ok((
                None,
                Payload {
                    v: 1,
                    agent_id: agent.to_owned(),
                    sources: Default::default(),
                },
            ));
        };
        if matching.next().is_some() || item.end_offset > 256 * 1024 || item.end_offset == 0 {
            return Err(error(
                RefusalCode::DigestMismatch,
                "invalid marks cut metadata",
            ));
        }
        let mut bytes = Vec::new();
        let mut offset = 0;
        while offset < item.end_offset {
            let limit = (item.end_offset - offset).min(32 * 1024);
            let reply = door.call("session.read", json!({"sessionRef":item.session_ref,"fromOffset":offset,"limit":limit,"cutId":cut})).await.map_err(|_| error(RefusalCode::CutNotReady, "marks cut bytes are not readable"))?;
            if reply["fromOffset"].as_u64() != Some(offset)
                || reply["endOffset"].as_u64() != Some(offset + limit)
                || reply["streamEnd"].as_u64() != Some(item.end_offset)
                || reply["digest"].as_str() != Some(item.digest.as_str())
            {
                return Err(error(
                    RefusalCode::DigestMismatch,
                    "cut read metadata differs",
                ));
            }
            let chunk = door::unhex(
                reply["bytes"]
                    .as_str()
                    .ok_or_else(|| error(RefusalCode::DigestMismatch, "cut read has no bytes"))?,
            )?;
            if chunk.len() as u64 != limit {
                return Err(error(RefusalCode::DigestMismatch, "short marks read"));
            }
            bytes.extend(chunk);
            offset += limit;
        }
        if door::hex(&Sha256::digest(&bytes)) != item.digest {
            return Err(error(RefusalCode::DigestMismatch, "marks cut hash differs"));
        }
        let payload: Payload = serde_json::from_slice(&bytes).map_err(|_| {
            detailed(
                RefusalCode::IncompatibleVersion,
                "unsupported marks payload",
                json!({"found":"unknown","required":FORMAT}),
            )
        })?;
        if payload.v != 1 {
            return Err(detailed(
                RefusalCode::IncompatibleVersion,
                "unsupported marks payload version",
                json!({"found":payload.v.to_string(),"required":"1"}),
            ));
        }
        if payload.agent_id != agent {
            return Err(error(
                RefusalCode::DigestMismatch,
                "marks payload belongs to another agent",
            ));
        }
        Ok((Some(item), payload))
    }
}
