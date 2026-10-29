-- When the last failed attempt was recorded. The lockout is derived from
-- `failed_attempts` and this time, so it expires on its own and needs no
-- job to flip `status`.
ALTER TABLE users ADD COLUMN last_failed_at TEXT;
