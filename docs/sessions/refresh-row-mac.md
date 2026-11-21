# Design: a MAC over the security-relevant refresh-token fields

Status: a design, not built. It changes what a stored refresh-token row holds,
so it waits for one decision, stated at the end.

## The gap

A refresh-token row stores the token's hash and, beside it in plain columns,
the fields that decide what the token may do: the user and tenant it belongs
to, when it expires, whether it is revoked, its rotation family, the device it
is bound to and the time the user last proved who they are. The hash is of a
256-bit random token (keyed with the pepper when one is configured), so a
reader of the table cannot forge a token. The
other columns are not authenticated. A party that can write the table can
extend `expires_at`, clear `revoked`, move a token to another family or device,
or move `authn_time` forward, and the library trusts the row.

## The design

Store a tag in the row and verify it whenever the row is read to make a decision:

- The tag is HMAC-SHA256 under a key derived from the pepper (a separate
  derivation label, so the tag key and the token-hash key are different keys),
  over a length-prefixed encoding of: the token id, user id, tenant id, token
  hash, issued-at, expires-at, family id, device id and last-authenticated
  time. It is written by every operation that writes those fields: issuing a
  token, and rotating one, which stores the child.
- `revoked`, `revoked_reason` and `revoked_at` are not inside the tag, because
  revoking is a write to the row, not a delete, and the store does it in bulk:
  `revoke_family` and `revoke_device_tokens` must each mark every matching
  row in one statement (a conditional `UPDATE` in SQL), and with the flag
  tagged that statement would have to recompute each row's tag. So the tag
  does not catch a cleared flag. Nor does the family-reuse rule, which
  revokes the family on the first reuse of a rotated-out token: it reads the
  same flag, and a token whose flag was cleared reads as live. This design
  leaves that case open.
- A row whose tag does not verify is refused by name and counted, and the
  family is revoked, as a reused token's is.
- The pepper is required for the tag, so a deployment without one gets the
  existing behaviour and a warning that rows are unauthenticated.

The column is nullable, so a store needs one added column and no rewrite. Durable refresh-token stores are the adopter's own (the workspace has the memory store and the example's), so the column is a change to the adopter's schema.

## The decision this needs

Rows written before the upgrade have no tag. Two ways to cross it:

1. **Dual read for one release.** An untagged row is accepted and tagged the
   next time it is rotated. Until then it stays unauthenticated.
2. **Refuse untagged rows at once.** Every refresh token issued before the
   upgrade stops working and its user signs in again.

The first is the quiet upgrade; the second closes the gap on deployment. The
choice, and the window for the first, is the owner's.
