# Design: a MAC over the security-relevant refresh-token fields

Status: a design, not built. It changes what a stored refresh-token row holds,
so it waits for one decision, stated at the end.

## The gap

A refresh-token row stores the token's hash and, beside it in plain columns,
the fields that decide what the token may do: the user and tenant it belongs
to, when it expires, whether it is revoked, its rotation family, the device it
is bound to and the time the user last proved who they are. The hash is keyed
with the configured pepper, so a reader of the table cannot forge a token. The
other columns are not authenticated. A party that can write the table can
extend `expires_at`, clear `revoked`, move a token to another family or device,
or move `authn_time` forward, and the library trusts the row.

## The design

Store a tag next to the row and verify it whenever the row is read to decide
something:

- The tag is HMAC-SHA256 under a key derived from the pepper (a separate
  derivation label, so the tag key and the token-hash key are different keys),
  over a length-prefixed encoding of: the token id, user id, tenant id, token
  hash, issued-at, expires-at, family id, device id and last-authenticated
  time. It is written by every operation that writes those fields (issue,
  rotate, family revoke).
- `revoked` is not inside the tag, because revoking is a legitimate write by
  anything that can delete rows. A cleared flag is still caught: a token that
  verifies is only usable while the revocation record that removed it is
  absent, and the family-reuse rule revokes the family on the first reuse of a
  rotated-out token.
- A row whose tag does not verify is refused by name and counted, and the
  family is revoked, as a reused token's is.
- The pepper is required for the tag, so a deployment without one gets the
  existing behaviour and a warning that rows are unauthenticated.

The column is nullable, so the stores need one added column and no rewrite.

## The decision this needs

Rows written before the upgrade have no tag. Two ways to cross it:

1. **Dual read for one release.** An untagged row is accepted and tagged the
   next time it is rotated. Until then it stays unauthenticated.
2. **Refuse untagged rows at once.** Every refresh token issued before the
   upgrade stops working and its user signs in again.

The first is the quiet upgrade, the second closes the gap on deployment. The
choice, and the window for the first, is the owner's.
