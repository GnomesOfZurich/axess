//! Conformance checks for [`SessionStore::update_if_revision`], for how a
//! session store addresses its rows by [`SessionKey`], for what it must hand
//! back as it was saved, for the passkey
//! credential-id claim of a [`FactorStore`], and for what an
//! [`AuditQuery`](crate::authn::store::AuditQuery) answers of a row it
//! cannot read ([`assert_unreadable_rows_contract`]), for the stores the
//! crate ships and for an adopter's own.

use crate::authn::ids::{TenantId, UserId};
use crate::authn::store::{FactorStore, Fido2CredentialClaim};
use crate::session::{
    data::SessionData,
    id::{SessionId, SessionKey},
    store::{ConditionalUpdate, SessionStore},
};
use std::time::Duration;

mod unreadable_rows;

pub use unreadable_rows::assert_unreadable_rows_contract;

/// Exercise the compare-and-swap contract of a session store and panic with a
/// message naming the broken rule:
///
/// - a write against the stored revision is `Written` and replaces the data;
/// - a write against any other revision is `Conflict` and changes nothing;
/// - of two writers holding the same revision exactly one is `Written`;
/// - a deleted row, and a key never stored, are `Gone`.
///
/// It then runs [`assert_key_binding_contract`],
/// [`assert_key_addressing_contract`] and [`assert_stored_state_contract`],
/// so one call holds a store to all four.
///
/// # Panics
///
/// On the first rule the store breaks, or on a store error.
pub async fn assert_update_if_revision_contract<S: SessionStore>(store: &S) {
    let ttl = Duration::from_secs(60);
    let id = SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
    let outcome = |r: Result<ConditionalUpdate, S::Error>| r.expect("update_if_revision errored");

    let stored = SessionData {
        revision: 3,
        ..SessionData::default()
    };
    store.save(&id, &stored, ttl).await.expect("save");
    let next = SessionData {
        revision: 4,
        custom: serde_json::json!({"k": 1}),
        ..SessionData::default()
    };

    assert_eq!(
        outcome(store.update_if_revision(&id, 9, &next, ttl).await),
        ConditionalUpdate::Conflict,
        "a write against another revision must conflict"
    );
    let unchanged = store.load(&id).await.expect("load").expect("row");
    assert_eq!(unchanged.revision, 3, "a conflict must write nothing");
    assert!(unchanged.custom.get("k").is_none());

    assert_eq!(
        outcome(store.update_if_revision(&id, 3, &next, ttl).await),
        ConditionalUpdate::Written,
        "a write against the stored revision must be written"
    );
    let written = store.load(&id).await.expect("load").expect("row");
    assert_eq!(written.revision, 4);
    assert_eq!(written.custom, serde_json::json!({"k": 1}));

    assert_eq!(
        outcome(store.update_if_revision(&id, 3, &next, ttl).await),
        ConditionalUpdate::Conflict,
        "a second writer holding the old revision must conflict"
    );

    // Each writer moves the revision on, as the session layer does.
    let racing = SessionData {
        revision: 5,
        ..next.clone()
    };
    let (a, b) = tokio::join!(
        store.update_if_revision(&id, 4, &racing, ttl),
        store.update_if_revision(&id, 4, &racing, ttl)
    );
    let mut results = [outcome(a), outcome(b)];
    results.sort_by_key(|r| *r == ConditionalUpdate::Conflict);
    assert_eq!(
        results,
        [ConditionalUpdate::Written, ConditionalUpdate::Conflict],
        "of two writers on one revision exactly one may write"
    );

    store.delete(&id).await.expect("delete");
    assert_eq!(
        outcome(store.update_if_revision(&id, 4, &next, ttl).await),
        ConditionalUpdate::Gone,
        "a deleted row is gone"
    );
    let never = SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
    assert_eq!(
        outcome(store.update_if_revision(&never, 0, &next, ttl).await),
        ConditionalUpdate::Gone,
        "a key never stored is gone"
    );

    assert_key_binding_contract(store).await;
    assert_key_addressing_contract(store).await;
    assert_stored_state_contract(store).await;
}

/// Exercise what a session store owes a session bound to a device key, and
/// panic with a message naming the broken rule:
///
/// - a bound row comes back bound to the same key, made for the same
///   person (its `owner`);
/// - a rotation ([`SessionStore::cycle`] and
///   [`SessionStore::cycle_if_revision`]) delivers the binding under the new
///   key and leaves nothing under the old one;
/// - a compare-and-swap against a stale revision leaves the stored binding
///   as it was.
///
/// A store that drops the binding turns a session held to a key into a
/// bearer session without a sign, which is why
/// [`assert_update_if_revision_contract`] runs this too.
///
/// # Panics
///
/// On the first rule the store breaks, or on a store error.
pub async fn assert_key_binding_contract<S: SessionStore>(store: &S) {
    use crate::device_key::{KeyThumbprint, SessionKeyBinding};
    use crate::session::store::CycleOutcome;

    let ttl = Duration::from_secs(60);
    let binding = SessionKeyBinding {
        owner: "00000000-0000-4000-8000-0000000000b1"
            .parse()
            .expect("a user id"),
        tenant_id: "00000000-0000-4000-8000-0000000000a1"
            .parse()
            .expect("a tenant id"),
        device_id: "00000000-0000-4000-8000-0000000000d1"
            .parse()
            .expect("a device id"),
        thumbprint: KeyThumbprint::from_bytes([0x5a; 32]),
        bound_at: axess_clock::Timestamp::from_unix_seconds(1_800_000_000)
            .expect("a valid instant"),
    };
    let bound = SessionData {
        revision: 1,
        key_binding: Some(binding),
        ..SessionData::default()
    };
    let binding_of = |row: Option<SessionData>| row.and_then(|row| row.key_binding);
    let first = SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
    store.save(&first, &bound, ttl).await.expect("save");
    assert_eq!(
        binding_of(store.load(&first).await.expect("load")),
        Some(binding),
        "a bound row must come back bound to the same key"
    );

    let second = SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
    let rotated = store
        .cycle(&first, &second, &bound, ttl, true)
        .await
        .expect("cycle");
    assert_eq!(rotated, CycleOutcome::Rotated, "a live row rotates");
    assert_eq!(
        binding_of(store.load(&second).await.expect("load")),
        Some(binding),
        "a rotation must deliver the binding under the new key"
    );
    assert!(
        store.load(&first).await.expect("load").is_none(),
        "a rotation must leave nothing under the old key"
    );

    let third = SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
    let rotated = store
        .cycle_if_revision(&second, &third, &bound, ttl, true, 1)
        .await
        .expect("cycle_if_revision");
    assert_eq!(rotated, CycleOutcome::Rotated, "the read revision rotates");
    assert_eq!(
        binding_of(store.load(&third).await.expect("load")),
        Some(binding),
        "a conditional rotation must deliver the binding under the new key"
    );

    let unbound = SessionData {
        revision: 2,
        ..SessionData::default()
    };
    let swapped = store
        .update_if_revision(&third, 9, &unbound, ttl)
        .await
        .expect("update_if_revision");
    assert_eq!(
        swapped,
        ConditionalUpdate::Conflict,
        "a stale revision conflicts"
    );
    assert_eq!(
        binding_of(store.load(&third).await.expect("load")),
        Some(binding),
        "a write that conflicted must leave the stored binding as it was"
    );
    store.delete(&third).await.expect("delete");
}

/// Exercise how a session store addresses its rows, and panic with a
/// message naming the broken rule. A store names a session by the whole of
/// its [`SessionKey`] and by nothing else:
///
/// - a session saved under a key loads under that key, and under no other:
///   not the key of another id, not the key with one bit flipped in its
///   last byte or in its first (a store that keys by a prefix or a suffix of
///   the text cannot tell those apart), and not the key of the id made of
///   the key's first sixteen bytes;
/// - [`SessionStore::update`], [`SessionStore::update_if_revision`] and
///   [`SessionStore::delete`] on such another key find no row and leave the
///   session as it was;
/// - [`SessionStore::cycle`] and [`SessionStore::cycle_if_revision`] leave
///   nothing under the old key and the session under the new one;
/// - a second session, under a key of its own, is untouched by all of it;
/// - a store that lists ([`SessionStore::find_sessions_for_user`] answers
///   `Ok`) returns the keys the sessions were saved under.
///
/// The check sees what a store answers, not what it holds. That a store
/// holds no value a cookie could carry needs no check: no method of
/// [`SessionStore`] receives a session id, and [`SessionData`] holds none.
/// [`assert_update_if_revision_contract`] runs this too.
///
/// # Panics
///
/// On the first rule the store breaks, or on a store error.
pub async fn assert_key_addressing_contract<S: SessionStore>(store: &S) {
    use crate::session::data::AuthState;
    use crate::session::store::CycleOutcome;

    let ttl = Duration::from_secs(60);
    let fresh_key = || SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
    let flipped = |key: &SessionKey, byte: usize| {
        let mut bytes = *key.as_bytes();
        bytes[byte] ^= 1;
        SessionKey::from_bytes(bytes)
    };
    let marked = |mark: &str, revision: u64| SessionData {
        revision,
        custom: serde_json::json!({ "mark": mark }),
        ..SessionData::default()
    };
    let mark_of = |row: Option<SessionData>| {
        row.and_then(|row| {
            row.custom
                .get("mark")
                .and_then(|m| m.as_str().map(String::from))
        })
    };

    // The session under test, and a bystander that nothing below names.
    let key = fresh_key();
    let bystander = fresh_key();
    store
        .save(&key, &marked("one", 1), ttl)
        .await
        .expect("save");
    store
        .save(&bystander, &marked("bystander", 1), ttl)
        .await
        .expect("save");
    assert_eq!(
        mark_of(store.load(&key).await.expect("load")).as_deref(),
        Some("one"),
        "a session must load under the key it was saved under"
    );

    let mut first_half = [0u8; 16];
    first_half.copy_from_slice(&key.as_bytes()[..16]);
    let others = [
        ("the key of another id", fresh_key()),
        (
            "the key with a bit of its last byte flipped",
            flipped(&key, 31),
        ),
        (
            "the key with a bit of its first byte flipped",
            flipped(&key, 0),
        ),
        (
            "the key of the id made of the key's first sixteen bytes",
            SessionKey::of(&SessionId::from_bytes(first_half)),
        ),
    ];
    for (what, other) in &others {
        assert!(
            store.load(other).await.expect("load").is_none(),
            "a session must not load under {what}"
        );
        assert!(
            !store
                .update(other, &marked("stray", 2), ttl)
                .await
                .expect("update"),
            "an update under {what} must find no row"
        );
        assert_eq!(
            store
                .update_if_revision(other, 1, &marked("stray", 2), ttl)
                .await
                .expect("update_if_revision"),
            ConditionalUpdate::Gone,
            "a conditional update under {what} must find no row"
        );
        store.delete(other).await.expect("delete");
        assert_eq!(
            mark_of(store.load(&key).await.expect("load")).as_deref(),
            Some("one"),
            "a write or a delete under {what} must leave the session as it was"
        );
        assert!(
            store.load(other).await.expect("load").is_none(),
            "an update under {what} must store nothing there"
        );
    }

    // A rotation moves the session from one whole key to another.
    let second = fresh_key();
    assert_eq!(
        store
            .cycle(&key, &second, &marked("two", 2), ttl, true)
            .await
            .expect("cycle"),
        CycleOutcome::Rotated,
        "a live row rotates"
    );
    assert!(
        store.load(&key).await.expect("load").is_none(),
        "a rotation must leave nothing under the old key"
    );
    assert_eq!(
        mark_of(store.load(&second).await.expect("load")).as_deref(),
        Some("two"),
        "a rotation must store the session under the new key"
    );
    let third = fresh_key();
    assert_eq!(
        store
            .cycle_if_revision(&second, &third, &marked("three", 3), ttl, true, 2)
            .await
            .expect("cycle_if_revision"),
        CycleOutcome::Rotated,
        "the read revision rotates"
    );
    assert!(
        store.load(&second).await.expect("load").is_none(),
        "a conditional rotation must leave nothing under the old key"
    );
    assert_eq!(
        mark_of(store.load(&third).await.expect("load")).as_deref(),
        Some("three"),
        "a conditional rotation must store the session under the new key"
    );
    // A rotation from a key that holds nothing, when the old row is
    // required, writes nothing under the new key.
    let unborn = fresh_key();
    assert_eq!(
        store
            .cycle(
                &flipped(&third, 31),
                &unborn,
                &marked("stray", 4),
                ttl,
                true
            )
            .await
            .expect("cycle"),
        CycleOutcome::SessionGone,
        "a rotation from the key with a bit of its last byte flipped must find no row"
    );
    assert!(
        store.load(&unborn).await.expect("load").is_none(),
        "a rotation that found no row must store nothing"
    );
    assert_eq!(
        mark_of(store.load(&third).await.expect("load")).as_deref(),
        Some("three"),
        "a rotation from another key must leave the session as it was"
    );
    assert_eq!(
        mark_of(store.load(&bystander).await.expect("load")).as_deref(),
        Some("bystander"),
        "a session nothing named must be untouched"
    );

    // A store that lists names each session by the key it was saved under.
    let user = UserId::new(&axess_rng::SystemRng);
    let tenant = TenantId::new(&axess_rng::SystemRng);
    let listed = SessionData {
        auth_state: AuthState::Identifying {
            user_id: user,
            tenant_id: tenant,
        },
        ..marked("listed", 1)
    };
    let (one, other) = (fresh_key(), fresh_key());
    store.save(&one, &listed, ttl).await.expect("save");
    store.save(&other, &listed, ttl).await.expect("save");
    if let Ok(found) = store.find_sessions_for_user(&user, 10).await {
        let mut found: Vec<SessionKey> = found.into_iter().map(|(key, _)| key).collect();
        found.sort();
        let mut saved = vec![one, other];
        saved.sort();
        assert_eq!(
            found, saved,
            "a store that lists must return the keys the sessions were saved under"
        );
    }

    for key in [third, bystander, one, other] {
        store.delete(&key).await.expect("delete");
    }
}

/// Exercise what a session store must hand back as it was saved for the
/// session layer to end a session once and to judge its age, and panic with
/// a message naming the broken rule. Each of these rows comes back equal
/// from [`SessionStore::save`], [`SessionStore::update_if_revision`],
/// [`SessionStore::cycle`] and [`SessionStore::cycle_if_revision`]:
///
/// - a row that carries an ending claim ([`SessionData::ending`]) keeps it:
///   the claim is what lets exactly one of several requests end a session,
///   so a store that drops it lets two of them end it, each with an audit
///   row;
/// - a session in a step-up keeps its flow
///   ([`AuthFlow::StepUp`](crate::session::data::AuthFlow::StepUp)) and
///   the login time the flow carries: without it the pending state is a
///   login, which no registry check and no age cap holds;
/// - a signed-in session keeps its `signed_in_at` apart from its
///   `authn_time`: the absolute age cap counts from the first, a recency
///   check reads the second;
/// - every row keeps its schema `version`.
///
/// [`assert_update_if_revision_contract`] runs this too.
///
/// # Panics
///
/// On the first rule the store breaks, or on a store error.
pub async fn assert_stored_state_contract<S: SessionStore>(store: &S) {
    use crate::authn::factor::{FactorKind, FactorStep};
    use crate::session::data::{AuthState, EndingClaim};
    use crate::session::layer::SessionEndReason;
    use crate::session::store::CycleOutcome;

    let ttl = Duration::from_secs(60);
    let at = |secs: i64| axess_clock::Timestamp::from_unix_seconds(secs).expect("a valid instant");
    let signed_in = AuthState::Authenticated {
        user_id: UserId::new(&axess_rng::SystemRng),
        tenant_id: TenantId::new(&axess_rng::SystemRng),
        authn_time: at(1_800_000_600),
        signed_in_at: at(1_800_000_000),
        factors_completed: vec![(FactorKind::Password, at(1_800_000_000))],
        impersonator: None,
        ldap_groups: None,
        assurance: Vec::new(),
    };
    let mut stepping_up = signed_in.clone();
    assert!(
        stepping_up.begin_step_up(vec![FactorStep::Required(FactorKind::Totp)]),
        "a signed-in state opens a step-up"
    );
    let claim = EndingClaim {
        since: at(1_800_000_900),
        reason: SessionEndReason::AgeCap,
    };
    let rows = [
        (
            "an ending claim",
            SessionData {
                auth_state: signed_in.clone(),
                ending: Some(claim),
                ..SessionData::default()
            },
        ),
        (
            "a step-up's flow",
            SessionData {
                auth_state: stepping_up,
                ..SessionData::default()
            },
        ),
        (
            "a signed-in session's login time",
            SessionData {
                auth_state: signed_in,
                ..SessionData::default()
            },
        ),
    ];

    for (what, row) in rows {
        let at_revision = |revision: u64| SessionData {
            revision,
            ..row.clone()
        };
        let kept = |how: &str, back: Option<SessionData>, sent: &SessionData| {
            let back = back.unwrap_or_else(|| panic!("a row written by {how} must load"));
            assert_eq!(
                back.ending, sent.ending,
                "a store must keep {what} through {how}: the ending claim differs"
            );
            assert_eq!(
                back.auth_state, sent.auth_state,
                "a store must keep {what} through {how}: the state differs"
            );
            assert_eq!(
                back.version, sent.version,
                "a store must keep {what} through {how}: the schema version differs"
            );
        };

        let first = SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
        store
            .save(&first, &at_revision(1), ttl)
            .await
            .expect("save");
        kept(
            "save",
            store.load(&first).await.expect("load"),
            &at_revision(1),
        );

        assert_eq!(
            store
                .update_if_revision(&first, 1, &at_revision(2), ttl)
                .await
                .expect("update_if_revision"),
            ConditionalUpdate::Written,
            "a write against the stored revision must be written"
        );
        kept(
            "update_if_revision",
            store.load(&first).await.expect("load"),
            &at_revision(2),
        );

        let second = SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
        assert_eq!(
            store
                .cycle(&first, &second, &at_revision(3), ttl, true)
                .await
                .expect("cycle"),
            CycleOutcome::Rotated,
            "a live row rotates"
        );
        kept(
            "cycle",
            store.load(&second).await.expect("load"),
            &at_revision(3),
        );

        let third = SessionKey::of(&SessionId::new(&axess_rng::SystemRng));
        assert_eq!(
            store
                .cycle_if_revision(&second, &third, &at_revision(4), ttl, true, 3)
                .await
                .expect("cycle_if_revision"),
            CycleOutcome::Rotated,
            "the read revision rotates"
        );
        kept(
            "cycle_if_revision",
            store.load(&third).await.expect("load"),
            &at_revision(4),
        );
        store.delete(&third).await.expect("delete");
    }
}

/// Exercise the passkey credential-id claim of a factor store and panic with
/// a message naming the broken rule. `first` and `second` are two users of
/// `tenant` that the store takes claims for. The check claims two ids whose
/// bytes start with `axess-claim-contract-`, and releases them before and
/// after, so it can run again on a store that keeps its rows.
///
/// - a claim on a free id is `Claimed`, and so is the holder's own claim
///   made again;
/// - another user's claim is refused with `HeldBy` naming the holder, in the
///   answer of the refused claim itself;
/// - a release by a user who does not hold the claim changes nothing;
/// - once the holder releases, the other user's claim is `Claimed`, and the
///   first user is then told the new holder;
/// - of two users claiming one id at the same time exactly one is `Claimed`
///   and the other is told that user.
///
/// A store that keeps no passkeys and refuses every claim does not meet
/// these rules and has no use for the check.
///
/// # Panics
///
/// On the first rule the store breaks, or on a store error.
pub async fn assert_fido2_claim_contract<S: FactorStore>(
    store: &S,
    tenant: &TenantId,
    first: &UserId,
    second: &UserId,
) {
    const HELD: &[u8] = b"axess-claim-contract-held";
    const RACED: &[u8] = b"axess-claim-contract-raced";
    for id in [HELD, RACED] {
        release(store, tenant, first, id).await;
        release(store, tenant, second, id).await;
    }

    assert_eq!(
        claim(store, tenant, first, HELD).await,
        Fido2CredentialClaim::Claimed,
        "a claim on a free id must be claimed"
    );
    assert_eq!(
        claim(store, tenant, first, HELD).await,
        Fido2CredentialClaim::Claimed,
        "the holder's own claim, made again, must be claimed"
    );
    assert_eq!(
        claim(store, tenant, second, HELD).await,
        Fido2CredentialClaim::HeldBy(*first),
        "a refused claim must name the user who holds the id, in its own answer"
    );
    release(store, tenant, second, HELD).await;
    assert_eq!(
        claim(store, tenant, second, HELD).await,
        Fido2CredentialClaim::HeldBy(*first),
        "a release by a user who does not hold the claim must change nothing"
    );
    release(store, tenant, first, HELD).await;
    assert_eq!(
        claim(store, tenant, second, HELD).await,
        Fido2CredentialClaim::Claimed,
        "an id its holder released must be free for another user"
    );
    assert_eq!(
        claim(store, tenant, first, HELD).await,
        Fido2CredentialClaim::HeldBy(*second),
        "after a release and a new claim the refusal must name the new holder"
    );

    let racing = tokio::join!(
        claim(store, tenant, first, RACED),
        claim(store, tenant, second, RACED)
    );
    let told = match racing {
        (Fido2CredentialClaim::Claimed, Fido2CredentialClaim::HeldBy(holder)) => (holder, *first),
        (Fido2CredentialClaim::HeldBy(holder), Fido2CredentialClaim::Claimed) => (holder, *second),
        other => panic!(
            "of two users claiming one id exactly one must be claimed and the other \
             told who holds it: {other:?}"
        ),
    };
    assert_eq!(
        told.0, told.1,
        "the loser of two racing claims must be told the winner"
    );

    for id in [HELD, RACED] {
        release(store, tenant, first, id).await;
        release(store, tenant, second, id).await;
    }
}

async fn claim<S: FactorStore>(
    store: &S,
    tenant: &TenantId,
    user: &UserId,
    id: &[u8],
) -> Fido2CredentialClaim {
    store
        .claim_fido2_credential(tenant, user, id)
        .await
        .expect("claim_fido2_credential errored")
}

async fn release<S: FactorStore>(store: &S, tenant: &TenantId, user: &UserId, id: &[u8]) {
    store
        .release_fido2_credential(tenant, user, id)
        .await
        .expect("release_fido2_credential errored");
}

mod factor_swap;
pub use factor_swap::{RACING_SWAPS, assert_compare_and_save_factor_contract};

#[cfg(test)]
mod tests;
