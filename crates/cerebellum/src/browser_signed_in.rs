//! Login facts for the agent's browser profiles, not cookie or page inspection.
//!
//! A profile is keyed by its agent project and durable/disposable profile name.
//! Records are monotonic: signing out does not erase a previously observed login.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use cerebellum_core::format_floor::{DurableFormat, FormatFloor};
use serde::{Deserialize, Serialize};

pub const SIGNED_IN_FORMAT: DurableFormat = DurableFormat::new("browser-signed-in-domains", 1);
const FILE_NAME: &str = "signed-in-domains.json";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignedInCoverage {
    Complete,
    Incomplete,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFacts {
    domains: BTreeSet<String>,
    signed_in_coverage: SignedInCoverage,
    profile_uuid: Option<String>,
}

#[derive(Debug, Default)]
pub struct LoginJournalEvidence {
    pub domains: BTreeSet<String>,
}

impl LoginJournalEvidence {
    pub fn from_export(export: &str, agent: &str, profile: &str, uuid: &str) -> Self {
        let mut evidence = Self::default();
        for row in export
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        {
            let identity = &row["identity"];
            if identity["agent_project_id"].as_str() != Some(agent)
                || identity["profile_uuid"]
                    .as_str()
                    .is_some_and(|known| known != uuid)
            {
                continue;
            }
            let matches_profile = if profile == "default" {
                identity["profile_name"].as_str() == Some("default")
            } else {
                profile
                    .strip_prefix("disposable:")
                    .is_some_and(|context| identity["conversation_key"].as_str() == Some(context))
            };
            if !matches_profile {
                continue;
            }
            let origin = if (row["capability"] == "browser.present"
                && row["payload"]["outcome"] == "login_observed")
                || (row["capability"] == "browser.import_login"
                    && row["payload"]["outcome"] == "transferred")
            {
                row["payload"]["origin"].as_str()
            } else {
                None
            };
            if let Some(domain) = origin.and_then(SignedInDomains::domain) {
                evidence.domains.insert(domain);
            }
        }
        evidence
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u64,
    profiles: BTreeMap<String, BTreeMap<String, ProfileFacts>>,
    #[serde(skip)]
    seeded_legacy: BTreeSet<(String, String, String)>,
}

/// Shared by authorization, the login handoff and the install-time grant check.
/// An unreadable store makes typing require consent rather than guessing signed out.
#[derive(Debug)]
pub struct SignedInDomains {
    path: Option<PathBuf>,
    floor: FormatFloor,
    state: Mutex<Result<State, String>>,
}

impl Default for SignedInDomains {
    fn default() -> Self {
        Self {
            path: None,
            floor: FormatFloor::isolated(),
            state: Mutex::new(Ok(State {
                version: SIGNED_IN_FORMAT.version,
                profiles: BTreeMap::new(),
                seeded_legacy: BTreeSet::new(),
            })),
        }
    }
}

impl SignedInDomains {
    /// Opening a missing store creates neither the file nor its format floor.
    pub fn open(path: PathBuf) -> Self {
        let state = match fs::read(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(State {
                version: SIGNED_IN_FORMAT.version,
                profiles: BTreeMap::new(),
                seeded_legacy: BTreeSet::new(),
            }),
            Err(error) => Err(error.to_string()),
            Ok(bytes) => (|| {
                let value: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                if value["version"].as_u64() != Some(SIGNED_IN_FORMAT.version) {
                    return Err("unsupported signed-in domains version".into());
                }
                let state: State = serde_json::from_value(value).map_err(|e| e.to_string())?;
                if state
                    .profiles
                    .values()
                    .flat_map(|profiles| profiles.values())
                    .flat_map(|facts| facts.domains.iter())
                    .any(|domain| {
                        crate::public_suffix::registrable_domain(domain).as_deref() != Some(domain)
                    })
                {
                    return Err("invalid signed-in domain".into());
                }
                Ok(state)
            })(),
        };
        Self {
            floor: FormatFloor::governing(&path),
            path: Some(path),
            state: Mutex::new(state),
        }
    }

    pub fn with_format_floor(mut self, floor: FormatFloor) -> Self {
        self.floor = floor;
        self
    }

    pub fn production() -> Self {
        match cerebellum_core::platform_dirs::data_home() {
            Some(home) => Self::open(
                cerebellum_core::format_floor::module_directory(&home)
                    .join("browser")
                    .join(FILE_NAME),
            ),
            None => Self {
                state: Mutex::new(Err("no absolute data home".into())),
                ..Self::default()
            },
        }
    }

    /// Use the domain-grant PSL matcher, including private suffix boundaries.
    pub(crate) fn domain(origin: &str) -> Option<String> {
        let canonical = crate::classification::canonical_grant_origin(origin)?;
        let (_, authority) = canonical.split_once("://")?;
        let host = authority.split(':').next()?;
        if authority.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        crate::public_suffix::registrable_domain(host)
    }

    pub fn profile_name(identity: &cerebellum_core::identity::RouteIdentity) -> String {
        match identity.profile_disposition {
            cerebellum_core::identity::ProfileDisposition::Disposable => {
                format!("disposable:{}", identity.conversation_key)
            }
            _ => "default".to_string(),
        }
    }

    /// Old registry and journal formats cannot prove complete login history.
    /// Only an observed creation of a new empty profile starts complete.
    pub fn initialize_profile(
        &self,
        agent: &str,
        profile: &str,
        uuid: &str,
        fresh: bool,
    ) -> Result<(), String> {
        let mut locked = self
            .state
            .lock()
            .map_err(|_| "signed-in domains lock poisoned".to_string())?;
        let state = locked.as_mut().map_err(|error| error.clone())?;
        let profiles = state.profiles.entry(agent.to_string()).or_default();
        let coverage = if fresh {
            SignedInCoverage::Complete
        } else {
            SignedInCoverage::Incomplete
        };
        match profiles.get_mut(profile) {
            Some(facts)
                if !fresh
                    && facts
                        .profile_uuid
                        .as_deref()
                        .is_none_or(|known| known == uuid) =>
            {
                facts.profile_uuid = Some(uuid.to_string());
            }
            _ => {
                profiles.insert(
                    profile.to_string(),
                    ProfileFacts {
                        domains: BTreeSet::new(),
                        signed_in_coverage: coverage,
                        profile_uuid: Some(uuid.to_string()),
                    },
                );
            }
        }
        if let Err(error) = self.save(state) {
            *locked = Err(error.clone());
            return Err(error);
        }
        Ok(())
    }

    pub fn contains_profile(&self, agent: &str, profile: &str) -> bool {
        match self.state.lock() {
            Ok(locked) => match locked.as_ref() {
                Ok(state) => state
                    .profiles
                    .get(agent)
                    .is_some_and(|profiles| profiles.contains_key(profile)),
                Err(_) => true,
            },
            Err(_) => true,
        }
    }

    pub(crate) fn needs_legacy_seed(&self, agent: &str, profile: &str) -> Option<String> {
        let locked = self.state.lock().ok()?;
        let state = locked.as_ref().ok()?;
        let facts = state.profiles.get(agent)?.get(profile)?;
        let uuid = facts.profile_uuid.as_ref()?;
        (facts.signed_in_coverage == SignedInCoverage::Incomplete
            && !state
                .seeded_legacy
                .contains(&(agent.into(), profile.into(), uuid.clone())))
        .then(|| uuid.clone())
    }

    pub(crate) fn seed_legacy(
        &self,
        agent: &str,
        profile: &str,
        uuid: &str,
        evidence: LoginJournalEvidence,
    ) -> Result<(), String> {
        let mut locked = self
            .state
            .lock()
            .map_err(|_| "signed-in domains lock poisoned".to_string())?;
        let state = locked.as_mut().map_err(|error| error.clone())?;
        let Some(facts) = state
            .profiles
            .get_mut(agent)
            .and_then(|profiles| profiles.get_mut(profile))
        else {
            return Ok(());
        };
        if facts.profile_uuid.as_deref() != Some(uuid)
            || facts.signed_in_coverage == SignedInCoverage::Complete
        {
            return Ok(());
        }
        facts.domains.extend(evidence.domains);
        state
            .seeded_legacy
            .insert((agent.into(), profile.into(), uuid.into()));
        if let Err(error) = self.save(state) {
            *locked = Err(error.clone());
            return Err(error);
        }
        Ok(())
    }

    pub fn is_signed_in(&self, agent: &str, profile: &str, origin: &str) -> bool {
        let Some(domain) = Self::domain(origin) else {
            return true;
        };
        match self.state.lock() {
            Ok(state) => match state.as_ref() {
                Ok(state) => state
                    .profiles
                    .get(agent)
                    .and_then(|profiles| profiles.get(profile))
                    .is_none_or(|facts| {
                        facts.signed_in_coverage == SignedInCoverage::Incomplete
                            || facts.domains.contains(&domain)
                    }),
                Err(_) => true,
            },
            Err(_) => true,
        }
    }

    /// Called only for an observed handoff login or a successful login import.
    pub fn record(&self, agent: &str, profile: &str, origin: &str) -> Result<(), String> {
        let Some(domain) = Self::domain(origin) else {
            return Ok(());
        };
        let mut locked = self
            .state
            .lock()
            .map_err(|_| "signed-in domains lock poisoned".to_string())?;
        let state = locked.as_mut().map_err(|error| error.clone())?;
        if !state
            .profiles
            .entry(agent.to_string())
            .or_default()
            .entry(profile.to_string())
            .or_insert_with(|| ProfileFacts {
                domains: BTreeSet::new(),
                signed_in_coverage: SignedInCoverage::Incomplete,
                profile_uuid: None,
            })
            .domains
            .insert(domain)
        {
            return Ok(());
        }
        if let Err(error) = self.save(state) {
            // A failed write is not evidence that the profile is signed out.
            *locked = Err(error.clone());
            return Err(error);
        }
        Ok(())
    }

    fn save(&self, state: &State) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        self.floor
            .raise(SIGNED_IN_FORMAT)
            .map_err(|e| e.to_string())?;
        let directory = path
            .parent()
            .ok_or("signed-in domains path has no parent")?;
        cerebellum_core::private_fs::create_dir_all(directory).map_err(|e| e.to_string())?;
        let temporary = directory.join(format!(
            ".{FILE_NAME}.{}.{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let written = (|| -> Result<(), String> {
            let bytes = serde_json::to_vec(state).map_err(|e| e.to_string())?;
            let mut file = cerebellum_core::private_fs::create_new_file(&temporary)
                .map_err(|e| e.to_string())?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
            drop(file);
            fs::rename(&temporary, path).map_err(|e| e.to_string())?;
            File::open(directory)
                .and_then(|file| file.sync_all())
                .map_err(|e| e.to_string())
        })();
        if written.is_err() {
            let _ = fs::remove_file(temporary);
        }
        written
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_domains_use_private_psl_boundaries_and_ignore_ports() {
        let store = SignedInDomains::default();
        store
            .initialize_profile("agent", "default", "new-agent-profile", true)
            .unwrap();
        store
            .initialize_profile("other-agent", "default", "new-other-profile", true)
            .unwrap();
        store
            .record("agent", "default", "https://app.alice.github.io:8443")
            .unwrap();
        assert!(store.is_signed_in("agent", "default", "http://other.alice.github.io"));
        assert!(!store.is_signed_in("agent", "default", "https://bob.github.io"));
        assert!(!store.is_signed_in("other-agent", "default", "https://alice.github.io"));
        store
            .record("agent", "default", "http://login.example.co.uk")
            .unwrap();
        assert!(store.is_signed_in("agent", "default", "https://account.example.co.uk"));
    }

    #[test]
    fn an_unreadable_login_store_requires_consent_and_is_not_overwritten() {
        let scratch = cortexkit_test_support::ScratchDir::new("signed-in-domains-corrupt");
        let path = scratch.join(FILE_NAME);
        fs::write(&path, b"corrupt").unwrap();
        let store = SignedInDomains::open(path.clone());
        assert!(store.is_signed_in("agent", "default", "https://example.com"));
        assert!(store
            .record("agent", "default", "https://example.com")
            .is_err());
        assert_eq!(fs::read(path).unwrap(), b"corrupt");
    }
}
