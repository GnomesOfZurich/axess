-- Why a refresh token was revoked, and when. Only the reuse of a token that
-- was rotated out is a theft signal; a logout or a cap eviction is not.
-- NULL (rows revoked before these columns existed) reads as 'rotated', the
-- strictest reading: reuse revokes the whole family.
ALTER TABLE refresh_tokens ADD COLUMN revoked_reason TEXT;
ALTER TABLE refresh_tokens ADD COLUMN revoked_at TEXT;
