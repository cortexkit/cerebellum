//! The primary registration transport owns the authority for outbound sockets.
//! A channel-launched process must bind each consumer with a fresh self claim;
//! failure to obtain or present one never permits a direct/nonce fallback.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use subc_protocol::claim::{
    Claim, ClaimMintReply, ClaimMintRequest, ClaimPresentReply, ClaimPresentRequest, ClaimPurpose,
    ClaimRateLimitedDetail,
};
use subc_protocol::{Frame, FrameType};
use subc_transport::{read_frame, write_frame};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::scope_watch::{ControlAnswer, ControlRequests};

pub(crate) trait ModuleStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ModuleStream for T {}
pub(crate) type Stream = Box<dyn ModuleStream>;

// Scope requests start at 2^40; operator confirmation starts at 2^63.
const FIRST_CLAIM_CORR: u64 = 1 << 48;
static OWNER: OnceLock<ControlRequests> = OnceLock::new();
static LIVE: AtomicBool = AtomicBool::new(false);

pub(crate) struct RegistrationLease;
impl Drop for RegistrationLease {
    fn drop(&mut self) {
        LIVE.store(false, Ordering::Release);
    }
}

/// Called only by the production entry point, before config probes or helpers.
/// subc-os validates the handoff and sets close-on-exec before it returns.
pub(crate) fn take_before_any_spawn() -> Result<Option<Stream>, crate::ModuleError> {
    let channel = subc_client_rs::registration::adopt_channel()
        .map_err(|error| crate::ModuleError::Message(format!("registration channel: {error}")))?;
    let Some(channel) = channel else {
        return Ok(None);
    };
    OWNER
        .set(ControlRequests::starting_at(FIRST_CLAIM_CORR))
        .map_err(|_| crate::ModuleError::Message("registration owner already installed".into()))?;
    Ok(Some(Box::new(channel)))
}

pub(crate) fn connect(
    writer: &mpsc::Sender<Frame>,
) -> Result<RegistrationLease, crate::ModuleError> {
    if let Some(owner) = OWNER.get() {
        owner.connect(writer);
        subc_client_rs::registration::install_claim_minter(Arc::new(Minter))
            .map_err(|error| crate::ModuleError::Message(format!("claim minter: {error}")))?;
        LIVE.store(true, Ordering::Release);
    }
    Ok(RegistrationLease)
}

struct Minter;

#[subc_client_rs::async_trait]
impl subc_client_rs::registration::ClaimMinter for Minter {
    async fn mint(
        &self,
        request: ClaimMintRequest,
    ) -> Result<ClaimMintReply, subc_client_rs::registration::ClaimError> {
        use subc_client_rs::registration::ClaimError as SdkError;
        if !LIVE.load(Ordering::Acquire) {
            return Err(SdkError::Unavailable);
        }
        mint_reply(
            OWNER.get().ok_or(SdkError::Unavailable)?,
            request,
            Duration::from_secs(3),
        )
        .await
    }
}

pub(crate) fn deliver(corr: u64, answer: &ControlAnswer) -> bool {
    OWNER
        .get()
        .is_some_and(|owner| owner.deliver(corr, answer.clone()))
}

/// Errors name the failed step, never a bearer value or a daemon reply body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    MintUnavailable,
    MintRefused,
    MintMalformed,
    PresentFailed,
}

/// Authenticate an outbound socket only when the process owns a channel.
pub(crate) async fn bind_consumer<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    deadline: Duration,
) -> Result<(), ClaimError> {
    if !subc_os::registration_channel::supervised() {
        return Ok(());
    }
    if !LIVE.load(Ordering::Acquire) {
        return Err(ClaimError::MintUnavailable);
    }
    bind_with_owner(
        stream,
        OWNER.get().ok_or(ClaimError::MintUnavailable)?,
        deadline,
    )
    .await
}

async fn bind_with_owner<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    owner: &ControlRequests,
    deadline: Duration,
) -> Result<(), ClaimError> {
    let claim = mint(owner, deadline).await?;
    let request = Frame::build(
        FrameType::Request,
        crate::control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&ClaimPresentRequest::new(claim))
            .map_err(|_| ClaimError::PresentFailed)?,
    )
    .map_err(|_| ClaimError::PresentFailed)?;
    tokio::time::timeout(deadline, async {
        write_frame(stream, &request)
            .await
            .map_err(|_| ClaimError::PresentFailed)?;
        let reply = read_frame(stream)
            .await
            .map_err(|_| ClaimError::PresentFailed)?
            .ok_or(ClaimError::PresentFailed)?;
        if (
            reply.header.ty,
            reply.header.channel,
            reply.header.epoch,
            reply.header.corr,
        ) != (FrameType::Response, 0, 0, 1)
        {
            return Err(ClaimError::PresentFailed);
        }
        serde_json::from_slice::<ClaimPresentReply>(&reply.body)
            .map_err(|_| ClaimError::PresentFailed)?;
        Ok(())
    })
    .await
    .map_err(|_| ClaimError::PresentFailed)?
}

async fn mint(owner: &ControlRequests, deadline: Duration) -> Result<Claim, ClaimError> {
    mint_reply(
        owner,
        ClaimMintRequest::new(ClaimPurpose::SelfConnection),
        deadline,
    )
    .await
    .map(|reply| reply.claim)
    .map_err(|error| match error {
        subc_client_rs::registration::ClaimError::Unavailable
        | subc_client_rs::registration::ClaimError::Timeout => ClaimError::MintUnavailable,
        subc_client_rs::registration::ClaimError::Refused { .. } => ClaimError::MintRefused,
        _ => ClaimError::MintMalformed,
    })
}

async fn mint_reply(
    owner: &ControlRequests,
    request: ClaimMintRequest,
    deadline: Duration,
) -> Result<ClaimMintReply, subc_client_rs::registration::ClaimError> {
    use subc_client_rs::registration::ClaimError as SdkError;
    let end = tokio::time::Instant::now() + deadline;
    loop {
        let remaining = end.saturating_duration_since(tokio::time::Instant::now());
        let answer = owner
            .request_connected(&request, remaining)
            .await
            .ok_or(SdkError::Unavailable)?;
        match answer {
            ControlAnswer::Response(body) => {
                return serde_json::from_value::<ClaimMintReply>(body)
                    .map_err(|_| SdkError::Protocol)
            }
            ControlAnswer::Error(body)
                if body["code"] == subc_protocol::error_codes::CLAIM_RATE_LIMITED =>
            {
                let delay: ClaimRateLimitedDetail = serde_json::from_value(body["detail"].clone())
                    .map_err(|_| SdkError::Protocol)?;
                let retry = Duration::from_millis(delay.retry_after_ms);
                if retry >= end.saturating_duration_since(tokio::time::Instant::now()) {
                    return Err(SdkError::Timeout);
                }
                tokio::time::sleep(retry).await;
            }
            ControlAnswer::Error(body) => {
                return Err(SdkError::Refused {
                    code: body["code"].as_str().ok_or(SdkError::Protocol)?.to_owned(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests;
