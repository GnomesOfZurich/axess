-- One passkey credential id belongs to one account within a tenant. The
-- registration claims the id here, with one conditional insert, before it
-- stores the passkey in `factor_configs`; the primary key is what makes two
-- registrations racing for one id have one winner.
CREATE TABLE fido2_credential_claims (
    tenant_id     TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    PRIMARY KEY (tenant_id, credential_id)
);
