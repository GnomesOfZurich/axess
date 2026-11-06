-- What put a user in a non-nominal status, as the `StatusCause` the caller
-- gave `suspend_user`, encoded as JSON (`"Administrative"`, `"Lockout"`,
-- `{"Other":"billing"}`). The status column says the state; this column says
-- by what, so a reader never infers an operator's hold from the reason text.
-- NULL (rows written before the column existed) reads by the status: a
-- suspension as an unspecified cause, which no eligibility check admits.
ALTER TABLE users ADD COLUMN status_cause TEXT;
