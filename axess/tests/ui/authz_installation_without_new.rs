// What a `require_authz!` gate decides with is built by
// `AuthzInstallation::new`, which refuses a policy store that reads
// `context` when no context provider comes with it. The value cannot be
// written out by its parts, so no installation exists that skipped the check.
use std::sync::Arc;

use axess::authz::{AuthzInstallation, PolicyStore, RequestEntityProvider};

fn unchecked(
    store: Arc<PolicyStore>,
    entities: Arc<dyn RequestEntityProvider>,
) -> AuthzInstallation {
    AuthzInstallation {
        store,
        entities,
        context: None,
    }
}

fn main() {}
