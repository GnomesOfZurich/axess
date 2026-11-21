//! Properties of the proof cookie and the offer, over generated inputs.

use super::*;
use crate::session::id::SessionId;
use axess_clock::SignedDuration;
use axess_clock::testing::MockClock;
use axess_clock::testing::Shift;
use proptest::prelude::*;

fn keys(seed: u8) -> KeyCookieKeys {
    KeyCookieKeys {
        current: [seed; 32],
        previous: None,
    }
}

fn proven(tenant: u8, device: u8, thumbprint: [u8; 32]) -> ProvenKey {
    ProvenKey {
        tenant: crate::authn::ids::testing::tenant(&format!("tenant-{tenant}")),
        device: crate::authn::ids::testing::device(&format!("device-{device}")),
        thumbprint: KeyThumbprint::from_bytes(thumbprint),
    }
}

proptest! {
    /// A proof cookie is accepted exactly while the clock is inside its
    /// window, and then as the key it was minted for.
    #[test]
    fn a_proof_is_accepted_exactly_inside_its_window(
        tenant in 0u8..4,
        device in 0u8..4,
        thumbprint in any::<[u8; 32]>(),
        ttl in 1i64..7200,
        grace in 0i64..600,
        elapsed in 0i64..10_000,
    ) {
        let start = MockClock::reference_time();
        let key = proven(tenant, device, thumbprint);
        let value = mint_proof(&keys(1), &key, axess_clock::Until::At(start.plus(SignedDuration::seconds(ttl))));
        let read = read_proof(
            &keys(1),
            &value,
            start.plus(SignedDuration::seconds(elapsed)),
            std::time::Duration::from_secs(grace.unsigned_abs()),
        );
        if elapsed < ttl + grace {
            prop_assert_eq!(read, Some(key));
        } else {
            prop_assert_eq!(read, None);
        }
    }

    /// Changing any one character of a proof cookie makes it prove nothing,
    /// or, where the change is to another spelling of the same value, the
    /// same key and never another.
    #[test]
    fn a_changed_proof_never_proves_another_key(
        thumbprint in any::<[u8; 32]>(),
        position in any::<prop::sample::Index>(),
        replacement in "[A-Za-z0-9._-]",
    ) {
        let now = MockClock::reference_time();
        let key = proven(1, 1, thumbprint);
        let value = mint_proof(&keys(1), &key, axess_clock::Until::At(now.plus(SignedDuration::seconds(600))));
        let at = position.index(value.len());
        let mut changed = value.clone();
        changed.replace_range(at..=at, &replacement);
        let read = read_proof(&keys(1), &changed, now, std::time::Duration::ZERO);
        prop_assert!(read.is_none() || read == Some(key));
        if changed != value {
            // A proof minted under one key is nothing under another.
            prop_assert_eq!(read_proof(&keys(2), &changed, now, std::time::Duration::ZERO), None);
        }
    }

    /// Whatever a client sends as a proof cookie or as an offer, reading it
    /// returns and proves nothing.
    #[test]
    fn arbitrary_text_proves_nothing(text in ".{0,400}") {
        let now = MockClock::reference_time();
        prop_assert_eq!(read_proof(&keys(1), &text, now, std::time::Duration::from_secs(30)), None);
        let rng = crate::testing::mock_random::MockRng::new(3);
        let session = SessionKey::of(&SessionId::new(&rng));
        let key = proven(1, 1, [7; 32]);
        prop_assert!(!offer_holds(&keys(1), &text, &session, &key.tenant, &key.device, now));
    }

    /// An offer holds for the session, tenant and device it was made for,
    /// until its expiry, and for no other combination.
    #[test]
    fn an_offer_holds_only_for_what_it_was_made_for(
        tenant in 0u8..3,
        device in 0u8..3,
        other_tenant in 0u8..3,
        other_device in 0u8..3,
        same_session in any::<bool>(),
        ttl in 1i64..900,
        elapsed in 0i64..2000,
    ) {
        let start = MockClock::reference_time();
        let rng = crate::testing::mock_random::MockRng::new(9);
        let (session, another) = (
            SessionKey::of(&SessionId::new(&rng)),
            SessionKey::of(&SessionId::new(&rng)),
        );
        let made_for = proven(tenant, device, [0; 32]);
        let asked_for = proven(other_tenant, other_device, [0; 32]);
        let offer = mint_offer(
            &keys(1),
            &session,
            &made_for.tenant,
            &made_for.device,
            axess_clock::Until::At(start.plus(SignedDuration::seconds(ttl))),
        );
        let holds = offer_holds(
            &keys(1),
            &offer,
            if same_session { &session } else { &another },
            &asked_for.tenant,
            &asked_for.device,
            start.plus(SignedDuration::seconds(elapsed)),
        );
        let expected = same_session
            && tenant == other_tenant
            && device == other_device
            && elapsed < ttl;
        prop_assert_eq!(holds, expected);
    }
}
