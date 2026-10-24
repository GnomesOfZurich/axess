-- When the user last authenticated, carried from parent to child on every
-- refresh-token rotation. NULL (rows written before this column) reads as
-- the row's own `issued_at`.
ALTER TABLE refresh_tokens ADD COLUMN authn_time TEXT;
