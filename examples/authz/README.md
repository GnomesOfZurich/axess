# Axess Example: Cedar Policy Authorization

Demonstrates the Axess authorization layer in isolation. No database, no sessions, no authentication. Pure Cedar Policy evaluation with RBAC, ReBAC, and ABAC in a single application.

If you want to understand how Cedar policies work with Axess before integrating authentication, start here.

## Scenario

A document management system with three users and three authorization patterns working together.

### RBAC (role-based)

| User | Role | View | Edit | Delete |
|------|------|------|------|--------|
| alice | admin | all | all | all (with MFA) |
| bob | viewer | all | no | no |
| carol | editor | all | all | no |

### ReBAC (relationship-based)

Document owners can always view and edit their own documents, regardless of role. Bob is a viewer but owns `doc-3`, so he can edit it.

### ABAC (attribute-based)

Deleting a document requires MFA verification. Even admins get a 403 without `?mfa=true`. This is enforced by a Cedar `forbid` policy that checks `context.mfa_verified`.

## Running

```sh
cargo run -p axess-example-authz
```

The server starts on [http://127.0.0.1:3000](http://127.0.0.1:3000).

## Test requests

```sh
# Bob can view any document (viewer role)
curl http://localhost:3000/users/bob/documents/doc-1

# Bob cannot edit doc-2 (viewer, not the owner)
curl -X POST http://localhost:3000/users/bob/documents/doc-2/edit
# 403

# Bob CAN edit doc-3 (he owns it, ReBAC)
curl -X POST http://localhost:3000/users/bob/documents/doc-3/edit
# 200

# Carol can edit any document (editor role)
curl -X POST http://localhost:3000/users/carol/documents/doc-2/edit

# Alice can delete, but only with MFA (ABAC)
curl -X DELETE "http://localhost:3000/users/alice/documents/doc-1?mfa=false"
# 403

curl -X DELETE "http://localhost:3000/users/alice/documents/doc-1?mfa=true"
# 200

# What can Bob do with doc-1?
curl http://localhost:3000/users/bob/documents/doc-1/permissions
# {"document_id":"doc-1","can_view":true,"can_edit":false,"can_delete":false}

# Bob's permissions across all documents
curl http://localhost:3000/users/bob/capabilities
```

## Project structure

```
src/
  main.rs        Axum router, AuthzStore setup, startup
  provider.rs    AuthzEntityProvider (in-memory users, roles, documents)
  handlers.rs    Route handlers using require(), is_permitted(), batch_check()
policies/
  app.cedar              Cedar policy rules (RBAC + ReBAC + ABAC)
  app.cedarschema.json   Entity type and action schema
```

## Key patterns

**AuthzStore.** Created once at startup. Holds the compiled Cedar policies, entity provider, and Cedar namespace. Passed via `Arc` in Axum state.

```rust
let policy_store = Arc::new(PolicyStore::from_text(policy_text, schema_json)?);
let provider = Arc::new(DocEntityProvider::new(data, "DocApp"));
let authz = Arc::new(AuthzStore::new(policy_store, provider, "DocApp"));
authz.validate()?; // catch schema mismatches at startup, not at request time
```

**AuthzEntityProvider.** Your application implements this trait to build Cedar entity graphs from your data. The provider loads users, roles, and resources and constructs Cedar `Entity` values with attributes and parent relationships.

**AuthzSession.** Created per-request from the store. Three methods:
- `require(action, resource)` returns `Ok(())` or `Err(AuthzDenied)` (403)
- `is_permitted(action, resource)` returns a boolean (for UI capability hints)
- `batch_check(checks)` evaluates multiple (action, resource) pairs in one call

**ABAC context.** For policies that check request-level attributes (MFA status, IP address), use `for_user_id_with_context()`:

```rust
let ctx = StandardRequestContext::new(mfa_verified, ip_address);
let authz = state.authz.for_user_id_with_context(&user_id, ctx)?;
authz.require("DeleteDocument", &doc_id).await?;
```

## License

MIT OR Apache-2.0
