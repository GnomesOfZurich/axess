# Axess Example: Cedar Policy Authorization

This example demonstrates the Axess authorization layer in isolation — no database, no sessions, no authentication. It shows how to use Cedar policies for access control in an Axum application.

## Scenario

A simple document management system with three authorization patterns:

### RBAC (role-based access control)

| User  | Role   | Can view | Can edit | Can delete |
|-------|--------|----------|----------|------------|
| alice | admin  | all      | all      | all (with MFA) |
| bob   | viewer | all      | —        | —          |
| carol | editor | all      | all      | —          |

### ReBAC (relationship-based access control)

Document owners can always view and edit their own documents, regardless of role. Bob is a viewer but owns `doc-3`, so he can edit it.

### ABAC (attribute-based access control)

Deleting a document requires MFA verification. Even admins get a 403 without `?mfa=true`. This is enforced by a Cedar `forbid` policy that checks `context.mfa_verified`.

## Running

```sh
cargo run -p axess-example-authz
```

The server listens on `http://127.0.0.1:3000`.

## Test requests

```sh
# Bob can view any document (viewer role):
curl http://localhost:3000/users/bob/documents/doc-1

# Bob cannot edit (viewer role, not the owner):
curl -X POST http://localhost:3000/users/bob/documents/doc-2/edit
# → 403

# Bob CAN edit doc-3 (he owns it — ReBAC):
curl -X POST http://localhost:3000/users/bob/documents/doc-3/edit
# → 200

# Carol can edit any document (editor role):
curl -X POST http://localhost:3000/users/carol/documents/doc-2/edit

# Alice can delete, but only with MFA (ABAC):
curl -X DELETE "http://localhost:3000/users/alice/documents/doc-1?mfa=false"
# → 403

curl -X DELETE "http://localhost:3000/users/alice/documents/doc-1?mfa=true"
# → 200

# UI capability hints — what can bob do with doc-1?
curl http://localhost:3000/users/bob/documents/doc-1/permissions
# → {"document_id":"doc-1","can_view":true,"can_edit":false,"can_delete":false}

# Batch check — bob's permissions across all documents:
curl http://localhost:3000/users/bob/capabilities
```

## Project structure

```
src/
  main.rs        — Axum router, startup, AuthzStore construction
  provider.rs    — AuthzEntityProvider implementation (in-memory)
  handlers.rs    — Route handlers using require(), is_permitted(), batch_check()
policies/
  app.cedar      — Cedar policy rules (RBAC + ReBAC + ABAC)
  app.cedarschema.json — Cedar entity type and action schema
```

## Key concepts

### `AuthzStore`

Created once at startup. Holds the compiled Cedar policies, the entity provider, and the Cedar namespace. Stored in `Arc` in Axum state.

```rust
let policy_store = Arc::new(PolicyStore::from_text(policy_text, schema_json)?);
let provider = Arc::new(DocEntityProvider::new(data, "DocApp"));
let authz = Arc::new(AuthzStore::new(policy_store, provider, "DocApp"));
authz.validate()?; // catch schema mismatches at startup
```

### `AuthzEntityProvider`

Your application implements this trait to teach Axess how to build Cedar entity graphs from your data. The provider loads users, roles, and resources from your database (or in this example, from memory) and constructs Cedar `Entity` values with attributes and parent relationships.

### `AuthzSession`

Created per-request from the store. Provides `require()` (hard 403), `is_permitted()` (boolean), and `batch_check()` (multiple checks in one call).

```rust
let authz = state.authz.for_user_id(&user_id)?;
authz.require("EditDocument", &doc_id).await?; // → Ok(()) or Err(AuthzDenied)
```

### ABAC context

For policies that check request-level attributes (MFA status, IP address), use `for_user_id_with_context()`:

```rust
let ctx = StandardRequestContext::new(mfa_verified, ip_address);
let authz = state.authz.for_user_id_with_context(&user_id, ctx)?;
authz.require("DeleteDocument", &doc_id).await?;
```

## License

MIT
