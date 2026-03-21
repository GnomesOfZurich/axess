// Valkey session store — reimplementation pending.
//
// The old implementation used `tower-sessions` which has been removed.
// A new `ValkeySessionStore` implementing `crate::session::store::SessionStore`
// will be added here when the `valkey` feature is used.

compile_error!(
    "The `valkey` feature is enabled but the ValkeySessionStore has not been \
     reimplemented yet after the tower-sessions removal. Use `MemorySessionStore` \
     or `SqliteSessionStore` for now."
);
