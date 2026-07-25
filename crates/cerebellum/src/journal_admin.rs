//! The journal administration surface (Spec B2A, slice S10).
//!
//! `cerebellum.journal.*` consists of `export`, `purge`, `retention.get`,
//! `retention.set`, and `status` on the [`ManagementSurface`]. The family is
//! never exposed as `browser.*` and is unavailable until BOTH family-level
//! registration bindings are compatible: the concrete operation-schema binding
//! and the daemon-owned administrative authorization-predicate binding.
//!
//! Authorization is evaluated only from daemon-attested principal facts. An
//! operation is dispatched only for a first-party principal that satisfies the
//! bound predicate; every `mcp:*` principal, every first-party principal that
//! does not satisfy the predicate, and every forged caller-supplied role or
//! authorization field is denied before operation-specific parsing, export
//! snapshot creation, purge, retention mutation, or status disclosure.
//!
//! Missing serialization-fit inputs affect ONLY `retention.set`, and only after
//! the family gates pass: the other four operations remain available under
//! compatible bindings.

use crate::journal::store::{JournalStatus, JournalStore, PurgeReport};
use crate::journal::{JournalConfig, JournalError, EXPORT_FORMAT_VERSION};

/// The expected operation-schema binding identifier for `cerebellum.journal.*`.
pub const JOURNAL_ADMIN_OPERATION_SCHEMA_ID: &str = "ck-browser-journal-admin/v1";

/// The expected daemon-owned authorization-predicate binding identifier.
pub const JOURNAL_ADMIN_AUTH_PREDICATE_ID: &str = "ck-browser-journal-admin-auth/v1";

/// The export encoding reported by the `export` operation.
pub const JOURNAL_EXPORT_ENCODING: &str = "utf-8-ndjson-rfc8785";

/// A manifest-bound schema binding: an identifier and a concrete revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaBinding {
    pub identifier: String,
    pub revision: String,
}

/// The two family-level administration registration bindings.
///
/// Both must be present and compatible for the family to be registered and
/// externally available. Neither may be omitted when administration is enabled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdminRegistration {
    /// The concrete operation-schema binding.
    pub operation_schema: Option<SchemaBinding>,
    /// The daemon-owned administrative authorization-predicate binding.
    pub authorization_predicate: Option<SchemaBinding>,
}

impl AdminRegistration {
    /// A registration with both bindings present and compatible.
    pub fn compatible(operation_revision: &str, predicate_revision: &str) -> Self {
        Self {
            operation_schema: Some(SchemaBinding {
                identifier: JOURNAL_ADMIN_OPERATION_SCHEMA_ID.to_string(),
                revision: operation_revision.to_string(),
            }),
            authorization_predicate: Some(SchemaBinding {
                identifier: JOURNAL_ADMIN_AUTH_PREDICATE_ID.to_string(),
                revision: predicate_revision.to_string(),
            }),
        }
    }

    /// Whether both bindings are present and compatible: each identifier matches
    /// the expected value and carries a concrete (non-empty) revision.
    pub fn is_compatible(&self) -> bool {
        let op_ok = self.operation_schema.as_ref().is_some_and(|b| {
            b.identifier == JOURNAL_ADMIN_OPERATION_SCHEMA_ID && !b.revision.is_empty()
        });
        let auth_ok = self.authorization_predicate.as_ref().is_some_and(|b| {
            b.identifier == JOURNAL_ADMIN_AUTH_PREDICATE_ID && !b.revision.is_empty()
        });
        op_ok && auth_ok
    }
}

/// Daemon-attested principal facts for administration authorization.
///
/// The predicate is evaluated only from these daemon-attested facts; it never
/// accepts a caller-supplied role, principal-kind, authorization, or
/// administration field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminPrincipal {
    /// The canonical principal projection.
    pub principal: String,
    /// Whether the daemon attests this principal as first-party. Every `mcp:*`
    /// principal is not first-party.
    pub first_party: bool,
    /// Whether the daemon-attested principal satisfies the bound administrative
    /// authorization predicate.
    pub satisfies_predicate: bool,
    /// A caller-supplied role or authorization field, if any. The presence of
    /// such a field is a forgery attempt and is denied; no implementation may
    /// equate `not mcp:*` or a caller-supplied label with administrator
    /// authority.
    pub caller_supplied_role: Option<String>,
}

impl AdminPrincipal {
    /// A first-party administrator satisfying the bound predicate.
    pub fn administrator(principal: &str) -> Self {
        Self {
            principal: principal.to_string(),
            first_party: true,
            satisfies_predicate: true,
            caller_supplied_role: None,
        }
    }
}

/// Serialization-fit inputs consumed ONLY by `retention.set`.
///
/// These are the B2B profile-fact maxima and other computed serialization-fit
/// inputs required to validate a proposed retention maximum. Their absence
/// makes ONLY `retention.set` unavailable; `export`, `purge`, `retention.get`,
/// and `status` do not consume them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SerializationFit {
    /// The maximum request-entry size over every enabled capability
    /// (`computed_max_entry_bytes`); must fit the proposed maximum entry size.
    pub computed_max_entry_bytes: Option<u64>,
    /// The maximum policy-event size (`computed_max_policy_event_bytes`); must
    /// fit the proposed maximum entry size.
    pub computed_max_policy_event_bytes: Option<u64>,
}

/// A failure of a journal administration operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminError {
    /// The family is not registered: one or both registration bindings are
    /// missing or incompatible. The entire five-operation family is unavailable.
    FamilyUnavailable,
    /// Authorization was denied before operation-specific parsing or data
    /// disclosure.
    Denied,
    /// The serialization-fit inputs required by `retention.set` are missing or
    /// incompatible. Affects ONLY `retention.set`.
    SerializationFitUnavailable,
    /// An operation-specific constraint failed (ordering, positivity, active
    /// capacity, or a proposed maximum that cannot represent a reachable
    /// representation).
    Constraint(JournalError),
}

/// The success result of the `export` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportResult {
    pub format_version: String,
    pub encoding: String,
    pub bytes_utf8: String,
}

/// The `cerebellum.journal.*` management surface.
///
/// Holds the family-level registration bindings and the `retention.set`-only
/// serialization-fit inputs. Each operation authorizes the principal first and
/// then delegates to the S7 [`JournalStore`].
#[derive(Debug, Clone)]
pub struct ManagementSurface {
    registration: AdminRegistration,
    serialization_fit: Option<SerializationFit>,
}

impl ManagementSurface {
    /// Build a management surface from the registration bindings and the
    /// `retention.set`-only serialization-fit inputs (absent until bound).
    pub fn new(
        registration: AdminRegistration,
        serialization_fit: Option<SerializationFit>,
    ) -> Self {
        Self {
            registration,
            serialization_fit,
        }
    }

    /// Whether the family is registered (both bindings compatible).
    pub fn is_registered(&self) -> bool {
        self.registration.is_compatible()
    }

    /// Authorize the principal against the family gates and the bound predicate.
    fn authorize(&self, principal: &AdminPrincipal) -> Result<(), AdminError> {
        // Family gate: both bindings must be compatible. Until then the entire
        // family is unavailable.
        if !self.registration.is_compatible() {
            return Err(AdminError::FamilyUnavailable);
        }
        // A forged caller-supplied role or authorization field is denied before
        // any operation-specific parsing or disclosure.
        if principal.caller_supplied_role.is_some() {
            return Err(AdminError::Denied);
        }
        // The predicate is evaluated only from daemon-attested facts: the
        // principal must be first-party AND satisfy the bound predicate.
        if !principal.first_party || !principal.satisfies_predicate {
            return Err(AdminError::Denied);
        }
        Ok(())
    }

    /// `export`: the point-in-time export snapshot.
    pub fn export(
        &self,
        principal: &AdminPrincipal,
        store: &JournalStore,
    ) -> Result<ExportResult, AdminError> {
        self.authorize(principal)?;
        Ok(ExportResult {
            format_version: EXPORT_FORMAT_VERSION.to_string(),
            encoding: JOURNAL_EXPORT_ENCODING.to_string(),
            bytes_utf8: store.export(),
        })
    }

    /// `purge`: atomically remove finalized exportable entries and clear the
    /// oversize flag.
    pub fn purge(
        &self,
        principal: &AdminPrincipal,
        store: &mut JournalStore,
    ) -> Result<PurgeReport, AdminError> {
        self.authorize(principal)?;
        Ok(store.purge())
    }

    /// `retention.get`: the active retention configuration.
    pub fn retention_get(
        &self,
        principal: &AdminPrincipal,
        store: &JournalStore,
    ) -> Result<JournalConfig, AdminError> {
        self.authorize(principal)?;
        Ok(store.retention_get())
    }

    /// `retention.set`: atomically validate and commit a new retention
    /// configuration.
    ///
    /// After the family gates pass, this operation ALONE requires the
    /// serialization-fit inputs: if they are absent the operation is
    /// unavailable while the other four remain available. Every applicable
    /// computed maximum must fit the proposed maximum entry size before the S7
    /// active-capacity and ordering checks run.
    pub fn retention_set(
        &self,
        principal: &AdminPrincipal,
        store: &mut JournalStore,
        proposed: JournalConfig,
    ) -> Result<JournalConfig, AdminError> {
        self.authorize(principal)?;
        // Serialization-fit inputs affect ONLY retention.set, and only after the
        // family gates pass.
        let fit = self
            .serialization_fit
            .ok_or(AdminError::SerializationFitUnavailable)?;
        if let Some(max_entry) = fit.computed_max_entry_bytes {
            if max_entry > proposed.journal_max_entry_bytes {
                return Err(AdminError::Constraint(JournalError::internal_failure()));
            }
        }
        if let Some(max_policy) = fit.computed_max_policy_event_bytes {
            if max_policy > proposed.journal_max_entry_bytes {
                return Err(AdminError::Constraint(JournalError::internal_failure()));
            }
        }
        store
            .retention_set(proposed)
            .map_err(AdminError::Constraint)
    }

    /// `status`: the journal status snapshot.
    pub fn status(
        &self,
        principal: &AdminPrincipal,
        store: &JournalStore,
    ) -> Result<JournalStatus, AdminError> {
        self.authorize(principal)?;
        Ok(store.status())
    }
}
