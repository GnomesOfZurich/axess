# Design: absolute times in the sealed session blob

Status: a design, not built. It changes what a stored session row holds, so
it waits for one decision, stated at the end.

## The gap

A session row is one sealed blob. The seal authenticates the row's identity
(the session's key) as additional authenticated data, so a blob cannot be moved
to another row. It does not authenticate when the row expires: the idle expiry
lives outside the seal, in the row's expiry column or the key's expiry. What
the sealed data does hold is the time of authentication, from which the layer
already enforces the absolute age cap (seven days by default), and the time of
the last write. A party that can write the store, or restore an old backup of it, can therefore do either of two things, and the blob still opens: extend a row's idle life (up to that cap for an authenticated session) by rewriting the expiry beside an untouched blob, or put back a blob that was revoked and deleted.

## The design

Add two absolute instants to the sealed envelope and enforce them when the blob
is opened:

- `created_at` and `expires_at`, in epoch seconds, written by `SessionCodec`
  when it seals and bound into the additional authenticated data beside the
  row id (the id, then the two times, each length-prefixed so two different
  triples cannot share one byte string).
- On load, the codec derives the additional authenticated data from the row
  id and the two times it read from the blob header, opens the blob under it,
  and then refuses the session when `expires_at` is not after the codec's
  clock. The expiry column and the key's expiry stay as a cleanup hint; the
  sealed value is the one that decides.
- A save that extends the session (the idle window slides) seals a new blob
  with the new `expires_at`; `created_at` never changes after the first seal,
  so a lifetime cap for sessions that never authenticate can be checked
  against it, as the age cap is checked against the time of authentication
  today.

The blob header grows by sixteen bytes and carries a format marker, as the
row-binding format did. The codec's existing marker logic tells the formats
apart.

## The decision this needs

Blobs sealed today have no times. Two ways to cross the upgrade:

1. **Dual read for one release.** The codec reads a blob without the new
   marker under the row-id-only additional authenticated data, treats the
   row's expiry column as the expiry, and re-seals it in the new format the
   next time the row is written. For that release the gap stays open for rows
   that were not yet rewritten. No user signs in again.
2. **Refuse old blobs at once.** Every session sealed before the upgrade reads
   as a decryption failure and its user signs in again. The gap closes the
   moment the release is deployed.

Session rows take the second way today: a session blob is read in the
current sealed form only, and `LegacyBlobs` (`AcceptUntil` for a window,
`Reject` by default) applies to device rows and factor secrets, not to
sessions. The first way would be new code for this one upgrade. The owner chooses the way and, for the first, the length of the window.
