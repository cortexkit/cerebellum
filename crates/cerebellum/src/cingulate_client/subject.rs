//! What each kind of card is about, as the one string the desk files it
//! under (`RaisedCard::subject`).
//!
//! A call that needs a card first looks for an open one this session raised
//! about the same subject (`ConsentDesk::open_card_for`) and waits on it
//! rather than putting a second card to the person. So two calls asking the
//! same thing must build the same string, and calls asking different things
//! must never: each kind has exactly one function here, and every flow builds
//! its subject through it.
//!
//! Each subject is a JSON array whose first element names the family, so
//! subjects of different kinds never collide (a takeover and a profile
//! re-identification are both keyed by the conversation alone) and the parts
//! can be read back, as the next-call drain does for login cards after a
//! restart. Both website-access kinds share one family on purpose: a
//! navigate that needs the same origins as an open `open_grant` card joins
//! that card instead of raising its own.

use serde_json::{json, Value};

use crate::computer_grants::LoginCapability;

fn encode(parts: Value) -> String {
    parts.to_string()
}

/// Browser site access, asked in the call or ahead: the conversation and the
/// origins, sorted so the same origins asked in another order are the same
/// card.
fn website(conversation_key: &str, origins: &[String]) -> String {
    let mut origins = origins.to_vec();
    origins.sort();
    encode(json!(["website", conversation_key, origins]))
}

/// `CardKind::WebsiteAccessInCall`. The same string as
/// [`website_access_in_advance`] for the same conversation and origins.
pub fn website_access_in_call(conversation_key: &str, origins: &[String]) -> String {
    website(conversation_key, origins)
}

/// `CardKind::WebsiteAccessInAdvance`. The same string as
/// [`website_access_in_call`] for the same conversation and origins.
pub fn website_access_in_advance(conversation_key: &str, origins: &[String]) -> String {
    website(conversation_key, origins)
}

/// `CardKind::AppControl`: one app in one conversation.
pub fn app_control(conversation_key: &str, bundle_identity: &str) -> String {
    encode(json!(["app", conversation_key, bundle_identity]))
}

/// `CardKind::Takeover`: the whole computer, in one conversation.
pub fn takeover(conversation_key: &str) -> String {
    encode(json!(["takeover", conversation_key]))
}

fn capability_name(capability: LoginCapability) -> &'static str {
    match capability {
        LoginCapability::ImportLogin => "import_login",
        LoginCapability::CaptureLogin => "capture_login",
    }
}

fn login(conversation_key: &str, capability: LoginCapability, parameters: &str) -> String {
    encode(json!([
        "login",
        conversation_key,
        capability_name(capability),
        parameters
    ]))
}

/// `CardKind::LoginImport`: one `browser.import_login` call, by its exact
/// parameters, in one conversation.
pub fn login_import(conversation_key: &str, parameters: &str) -> String {
    login(conversation_key, LoginCapability::ImportLogin, parameters)
}

/// `CardKind::LoginCapture`: one `browser.capture_login` call, by its exact
/// parameters, in one conversation.
pub fn login_capture(conversation_key: &str, parameters: &str) -> String {
    login(conversation_key, LoginCapability::CaptureLogin, parameters)
}

/// The parts of a login card's subject, read back from the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSubject {
    pub conversation_key: String,
    pub capability: LoginCapability,
    pub parameters: String,
}

/// Read a subject built by [`login_import`] or [`login_capture`] back into
/// its parts. `None` for any other subject.
pub fn login_parts(subject: &str) -> Option<LoginSubject> {
    let parts: Vec<String> = serde_json::from_str(subject).ok()?;
    let [family, conversation_key, capability, parameters] = <[String; 4]>::try_from(parts).ok()?;
    if family != "login" {
        return None;
    }
    let capability = match capability.as_str() {
        "import_login" => LoginCapability::ImportLogin,
        "capture_login" => LoginCapability::CaptureLogin,
        _ => return None,
    };
    Some(LoginSubject {
        conversation_key,
        capability,
        parameters,
    })
}

/// `CardKind::ProfileReidentification`: one conversation's re-identification
/// of the managed profile root.
pub fn profile_reidentification(conversation_key: &str) -> String {
    encode(json!(["profile_reidentification", conversation_key]))
}

/// `CardKind::StuckProfileClearance`: one stuck launch of one project's
/// browser profile, by its launch sequence.
pub fn stuck_profile_clearance(agent_project_id: &str, sequence: u64) -> String {
    encode(json!([
        "stuck_profile_clearance",
        agent_project_id,
        sequence
    ]))
}

/// `CardKind::UserBrowserSite`: one site in the person's own browser.
pub fn user_browser_site(origin: &str) -> String {
    encode(json!(["user_browser_site", origin]))
}
