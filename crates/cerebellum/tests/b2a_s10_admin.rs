//! S10 acceptance tests: the journal administration surface.
//!
//! Covers the two family-level registration gates, per-operation authorization
//! (first-party predicate, `mcp:*` denial, forged caller-role denial) before any
//! parsing or disclosure, and the split where missing serialization-fit inputs
//! disable ONLY `retention.set`.

use cerebellum::journal::store::JournalStore;
use cerebellum::journal::JournalConfig;
use cerebellum::journal_admin::{
    AdminError, AdminPrincipal, AdminRegistration, ManagementSurface, SerializationFit,
};

fn store() -> JournalStore {
    JournalStore::new(JournalConfig {
        journal_retention_bytes: 1_000_000,
        journal_max_entry_bytes: 100_000,
    })
    .unwrap()
}

fn registered_surface() -> ManagementSurface {
    ManagementSurface::new(
        AdminRegistration::compatible("1", "1"),
        Some(SerializationFit {
            computed_max_entry_bytes: Some(100_000),
            computed_max_policy_event_bytes: Some(50_000),
        }),
    )
}

fn admin() -> AdminPrincipal {
    AdminPrincipal::administrator("direct:admin")
}

#[test]
fn family_unavailable_until_both_bindings_compatible() {
    // Missing the authorization-predicate binding: the whole family is
    // unavailable, even for an administrator.
    let mut registration = AdminRegistration::compatible("1", "1");
    registration.authorization_predicate = None;
    let surface = ManagementSurface::new(registration, None);
    let store = store();
    assert_eq!(
        surface.export(&admin(), &store).unwrap_err(),
        AdminError::FamilyUnavailable
    );
    assert_eq!(
        surface.status(&admin(), &store).unwrap_err(),
        AdminError::FamilyUnavailable
    );

    // Missing the operation-schema binding: likewise unavailable.
    let mut registration = AdminRegistration::compatible("1", "1");
    registration.operation_schema = None;
    let surface = ManagementSurface::new(registration, None);
    assert_eq!(
        surface.retention_get(&admin(), &store).unwrap_err(),
        AdminError::FamilyUnavailable
    );
}

#[test]
fn denied_principal_creates_no_snapshot_and_mutates_nothing() {
    let surface = registered_surface();
    let mut store = store();
    let before = surface.status(&admin(), &store).unwrap();

    // An ordinary first-party principal that does not satisfy the predicate.
    let unauthorized = AdminPrincipal {
        principal: "direct:user".to_string(),
        first_party: true,
        satisfies_predicate: false,
        caller_supplied_role: None,
    };
    assert_eq!(
        surface.export(&unauthorized, &store).unwrap_err(),
        AdminError::Denied
    );
    assert_eq!(
        surface.purge(&unauthorized, &mut store).unwrap_err(),
        AdminError::Denied
    );
    assert_eq!(
        surface
            .retention_set(
                &unauthorized,
                &mut store,
                JournalConfig {
                    journal_retention_bytes: 2_000_000,
                    journal_max_entry_bytes: 100_000,
                }
            )
            .unwrap_err(),
        AdminError::Denied
    );

    // An mcp:* principal is not first-party and is denied even if the predicate
    // bit is set: no implementation may equate `not mcp:*` with authority.
    let mcp = AdminPrincipal {
        principal: "mcp:subc-mcp".to_string(),
        first_party: false,
        satisfies_predicate: true,
        caller_supplied_role: None,
    };
    assert_eq!(
        surface.status(&mcp, &store).unwrap_err(),
        AdminError::Denied
    );

    // A forged caller-supplied role field is denied before any disclosure.
    let forged = AdminPrincipal {
        principal: "direct:admin".to_string(),
        first_party: true,
        satisfies_predicate: true,
        caller_supplied_role: Some("admin".to_string()),
    };
    assert_eq!(
        surface.export(&forged, &store).unwrap_err(),
        AdminError::Denied
    );

    // Nothing was mutated and no snapshot was created: status is unchanged.
    let after = surface.status(&admin(), &store).unwrap();
    assert_eq!(before, after);
}

#[test]
fn missing_serialization_fit_disables_only_retention_set() {
    // Compatible bindings but NO serialization-fit inputs.
    let surface = ManagementSurface::new(AdminRegistration::compatible("1", "1"), None);
    let mut store = store();

    // export, purge, retention.get, and status remain available.
    assert!(surface.export(&admin(), &store).is_ok());
    assert!(surface.retention_get(&admin(), &store).is_ok());
    assert!(surface.status(&admin(), &store).is_ok());
    assert!(surface.purge(&admin(), &mut store).is_ok());

    // retention.set ALONE is unavailable.
    assert_eq!(
        surface
            .retention_set(
                &admin(),
                &mut store,
                JournalConfig {
                    journal_retention_bytes: 2_000_000,
                    journal_max_entry_bytes: 100_000,
                }
            )
            .unwrap_err(),
        AdminError::SerializationFitUnavailable
    );
}

#[test]
fn retention_set_rejects_proposed_maximum_below_computed_fit() {
    let surface = registered_surface();
    let mut store = store();
    // The proposed maximum entry size cannot represent the computed request-entry
    // maximum: rejected, configuration unchanged.
    let err = surface
        .retention_set(
            &admin(),
            &mut store,
            JournalConfig {
                journal_retention_bytes: 1_000_000,
                journal_max_entry_bytes: 50_000,
            },
        )
        .unwrap_err();
    assert!(matches!(err, AdminError::Constraint(_)));
    assert_eq!(store.retention_get().journal_max_entry_bytes, 100_000);
}

#[test]
fn authorized_administrator_runs_all_five_operations() {
    let surface = registered_surface();
    let mut store = store();
    assert!(surface.export(&admin(), &store).is_ok());
    assert!(surface.purge(&admin(), &mut store).is_ok());
    assert!(surface.retention_get(&admin(), &store).is_ok());
    assert!(surface
        .retention_set(
            &admin(),
            &mut store,
            JournalConfig {
                journal_retention_bytes: 2_000_000,
                journal_max_entry_bytes: 100_000,
            }
        )
        .is_ok());
    assert!(surface.status(&admin(), &store).is_ok());
    // The retention.set committed the new values.
    assert_eq!(store.retention_get().journal_retention_bytes, 2_000_000);
}
