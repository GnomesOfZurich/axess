-- Consecutive wrong guesses per tenant, user and client address, for the
-- throttle beside the lockout. `address` is the empty string for the
-- account-only key. Rows older than twice the longest delay are swept on
-- every record, so the table holds only keys that still throttle.
CREATE TABLE login_throttle (
    tenant_id       TEXT    NOT NULL,
    user_id         TEXT    NOT NULL,
    address         TEXT    NOT NULL DEFAULT '',
    failures        INTEGER NOT NULL DEFAULT 0,
    last_failure_at TEXT    NOT NULL,
    PRIMARY KEY (tenant_id, user_id, address)
);
CREATE INDEX login_throttle_last_failure ON login_throttle (last_failure_at);
