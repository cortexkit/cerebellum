//! The backup module's authenticated cut metadata bounds and identifies the marks bytes.

use super::*;
use cortexkit_role_agent_data::errors::{DigestMismatchDetail, ParticipantFailedDetail};
use sha2::{Digest, Sha256};

const READ_PAGE_BYTES: u64 = 32 * 1024;
const MAX_MARKS_BYTES: u64 = 256 * 1024;

#[derive(Clone, Serialize)]
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

fn cut_not_ready() -> ErrorBody {
    error(RefusalCode::CutNotReady, "marks cut bytes are not readable")
}

fn read_refusal(op: Op, refusal: ErrorBody) -> ErrorBody {
    // Only the import operation may abort a move over an unreadable cut. The
    // agent-data contract allows the diverged check to answer cut_not_ready
    // (retry) but not participant_failed or digest_mismatch.
    if op != Op::Import {
        return cut_not_ready();
    }
    let code = refusal.code.as_str();
    match code {
        "verify_failed" => ErrorBody::with_digest_mismatch_detail(
            DigestMismatchDetail::new("session_door:verify_failed"),
            "session door could not verify the marks cut",
        ),
        "invalid_request"
        | "caller_forbidden"
        | "stream_label_too_long"
        | "record_too_large"
        | "response_too_large"
        | "offset_out_of_range"
        | "below_floor"
        | "cut_not_published"
        | "cut_takeover_closed"
        | "cut_range_not_local"
        | "cut_item_missing" => ErrorBody::with_participant_failed_detail(
            ParticipantFailedDetail::new(format!("session_door:{code}")),
            "session door cannot serve the marks cut",
        ),
        // Everything else retries: the door's temporary refusals (unavailable,
        // lease_unavailable, cut_import_pending), the not_found an older
        // session door still returns for a missing cut, and codes newer than
        // this list.
        _ => cut_not_ready(),
    }
}

fn integrity_refusal(op: Op, message: impl Into<String>) -> ErrorBody {
    let code = if op == Op::Import {
        RefusalCode::DigestMismatch
    } else {
        RefusalCode::CutNotReady
    };
    error(code, message)
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
        op: Op,
        agent: &str,
        cut: &str,
    ) -> Result<(Option<Item>, Payload), ErrorBody> {
        let door = self.door().map_err(|_| cut_not_ready())?;
        let session = session_ref(agent, cut);
        let read_page = |offset, limit| {
            door.call(
                "session.read",
                json!({"sessionRef":session,"fromOffset":offset,"limit":limit,"cutId":cut}),
            )
        };
        let mut reply = match read_page(0, READ_PAGE_BYTES).await {
            Ok(reply) => reply,
            // The source writes no item for an unmarked agent. Once the first
            // page has identified an item, a later missing item is a refusal.
            Err(e) if e.code.as_str() == "cut_item_missing" => {
                return Ok((
                    None,
                    Payload {
                        v: 1,
                        agent_id: agent.to_owned(),
                        sources: Default::default(),
                    },
                ));
            }
            Err(e) => return Err(read_refusal(op, e)),
        };
        let end_offset = reply["streamEnd"]
            .as_u64()
            .filter(|end| (1..=MAX_MARKS_BYTES).contains(end))
            .ok_or_else(|| integrity_refusal(op, "invalid marks cut length"))?;
        let digest = reply["digest"]
            .as_str()
            .ok_or_else(|| integrity_refusal(op, "marks cut has no digest"))?
            .to_owned();
        let mut bytes = Vec::with_capacity(end_offset as usize);
        let mut offset = 0;
        loop {
            let page_len = (end_offset - offset).min(READ_PAGE_BYTES);
            if reply["fromOffset"].as_u64() != Some(offset)
                || reply["endOffset"].as_u64() != Some(offset + page_len)
                || reply["streamEnd"].as_u64() != Some(end_offset)
                || reply["digest"].as_str() != Some(digest.as_str())
            {
                return Err(integrity_refusal(op, "cut read metadata differs"));
            }
            let chunk = door::unhex(
                reply["bytes"]
                    .as_str()
                    .ok_or_else(|| integrity_refusal(op, "cut read has no bytes"))?,
            )
            .map_err(|e| integrity_refusal(op, e.message))?;
            if chunk.len() as u64 != page_len {
                return Err(integrity_refusal(op, "marks read length differs"));
            }
            bytes.extend(chunk);
            offset += page_len;
            if offset == end_offset {
                break;
            }
            reply = read_page(offset, (end_offset - offset).min(READ_PAGE_BYTES))
                .await
                .map_err(|e| read_refusal(op, e))?;
        }
        if door::hex(&Sha256::digest(&bytes)) != digest {
            return Err(integrity_refusal(op, "marks cut hash differs"));
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
            return Err(integrity_refusal(
                op,
                "marks payload belongs to another agent",
            ));
        }
        let item = Item {
            session_ref: session,
            stream: STREAM.into(),
            end_offset,
            digest,
        };
        Ok((Some(item), payload))
    }
}
