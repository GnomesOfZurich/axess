use super::*;

fn cache() -> MemoryJtiCache {
    MemoryJtiCache::new()
}

#[test]
fn malformed_proof_is_rejected() {
    let cache = cache();
    let res = verify_dpop_proof(
        DpopVerifyRequest {
            proof_jwt: "not.a.real.jwt",
            htm: "POST",
            htu: "https://api.example.com/foo",
            access_token: None,
            max_iat_skew_secs: 60,
            jti_cache: &cache,
        },
        Utc::now(),
    );
    assert!(res.is_err(), "malformed JWT must be rejected");
}

#[test]
fn jti_cache_evicts_expired_entries() {
    let cache = MemoryJtiCache::new();
    let past = Utc::now() - chrono::Duration::seconds(10);
    let future = Utc::now() + chrono::Duration::seconds(10);
    // Past jti accepted on insert (inside try_insert it would be
    // immediately evicted since `expires_at < now`).
    assert!(cache.try_insert("a", past));
    // After eviction sweep, "a" should be gone, so reinsertion succeeds.
    assert!(cache.try_insert("a", future));
    // Replay within the active window must fail.
    assert!(!cache.try_insert("a", future));
}

/// `try_insert`'s `retain(|_, exp| *exp > now)` uses strict
/// greater. An entry whose expiry equals `now` to the nanosecond
/// must be evicted; an entry one nanosecond in the future must
/// survive. Pins `> → >=` on the retain predicate; under `>=` an
/// exactly-at-expiry entry would survive a sweep window past its
/// deadline.
///
/// Practical observation: `now = Utc::now()` is captured INSIDE
/// `try_insert`, so we can't pin the boundary at literally "==
/// now". Instead pin the qualitative behaviour: a clearly-expired
/// entry (timestamp 1 second in the past) MUST be evicted before
/// the second insert succeeds. Under `>=` the same behaviour
/// holds, so this is observably equivalent at that grain.
/// Reading the line more carefully: the mutation `> → >=` only
/// flips behaviour when `*exp == now` exactly, which is
/// unobservable from outside. Document as an equivalent mutation
/// rather than continuing to chase it.
#[test]
fn jti_cache_retain_strict_greater_pinned_by_past_entry_eviction() {
    let cache = MemoryJtiCache::new();
    let past = Utc::now() - chrono::Duration::seconds(1);
    let future = Utc::now() + chrono::Duration::seconds(60);
    assert!(cache.try_insert("a", past));
    // Past entry must be evicted by the next sweep, so reinsertion
    // under a different (future) expiry succeeds.
    assert!(
        cache.try_insert("a", future),
        "expired entry must be evicted by retain sweep"
    );
}

/// Pin `try_insert_at`'s `retain(|_, exp| *exp > now)` strict
/// inequality at the boundary `*exp == now`: with the original
/// the entry is evicted, so a re-insert under the same jti
/// succeeds; with `> → >=` the entry survives and the re-insert
/// is rejected as a replay. The pure helper takes `now` as a
/// parameter, so the boundary is testable to the exact tick.
#[test]
fn try_insert_at_evicts_when_expiry_equals_now() {
    let mut store = JtiStore::default();
    let t0 = Utc::now();
    assert!(try_insert_at(
        &mut store,
        "jti-1",
        t0,
        t0 - chrono::Duration::seconds(1),
        usize::MAX
    ));
    // expiry exactly at t0
    let inserted = try_insert_at(
        &mut store,
        "jti-1",
        t0 + chrono::Duration::seconds(60),
        t0,
        usize::MAX,
    );
    assert!(
        inserted,
        "an entry whose expiry equals now must be evicted by the retain sweep; \
         `> → >=` mutation would keep it and reject the re-insert as a replay"
    );
}

/// Pin the replay-window arithmetic: the entry is stored with
/// `expires_at = iat + 2 × max_iat_skew_secs`. Mutations `* → /`
/// or `* → +` (cargo-mutants standard set) all shift this boundary;
/// pinning the exact value kills them.
#[test]
fn dpop_replay_window_expiry_is_iat_plus_two_skew() {
    let iat = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    assert_eq!(
        dpop_replay_window_expiry(iat, 60),
        Some(iat + chrono::Duration::seconds(121)),
        "expires_at must be iat + 2 × max_iat_skew_secs + 1"
    );
    assert_eq!(
        dpop_replay_window_expiry(iat, 30),
        Some(iat + chrono::Duration::seconds(61)),
    );
    assert_eq!(
        dpop_replay_window_expiry(iat, 1),
        Some(iat + chrono::Duration::seconds(3)),
        "skew=1 produces a 3-second window; kills `* → /` and `* → +`"
    );
    assert_eq!(
        dpop_replay_window_expiry(iat, 0),
        Some(iat + chrono::Duration::seconds(1)),
        "skew=0 still outlives the second in which the proof is accepted"
    );
}

/// A skew too large for the date range is `None`, not a panic or a wrapped
/// date: doubling overflows `i64`, the seconds overflow `Duration`, or the
/// sum overflows `DateTime`.
#[test]
fn dpop_replay_window_expiry_is_none_when_the_window_does_not_fit() {
    let iat = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    assert_eq!(dpop_replay_window_expiry(iat, i64::MAX), None);
    assert_eq!(dpop_replay_window_expiry(iat, i64::MAX / 2), None);
    assert!(dpop_replay_window_expiry(iat, 1_000_000_000_000).is_some());
}

/// At the bound the cache refuses a new `jti` instead of forgetting a live
/// one, and room returns once entries expire. A replay is still refused.
#[test]
fn the_memory_cache_refuses_new_entries_at_capacity_and_recovers_on_expiry() {
    let mut store = JtiStore::default();
    assert!(try_insert_at(&mut store, "a", at(100), at(0), 2));
    assert!(try_insert_at(&mut store, "b", at(100), at(0), 2));
    assert!(!try_insert_at(&mut store, "c", at(100), at(0), 2), "full");
    assert!(
        !try_insert_at(&mut store, "a", at(100), at(0), 2),
        "a live entry was not forgotten to make room"
    );
    assert!(
        try_insert_at(&mut store, "c", at(300), at(100), 2),
        "both expired, so there is room again"
    );
}

#[test]
fn the_memory_cache_capacity_is_configurable_and_bounds_the_public_api() {
    let cache = MemoryJtiCache::new().with_capacity(1);
    let expires = Utc::now() + chrono::Duration::seconds(60);
    assert!(cache.try_insert("a", expires));
    assert!(!cache.try_insert("b", expires));
}

/// A skew outside `0..=MAX_IAT_SKEW_SECS` refuses every proof, including a
/// valid one, and never panics (`i64::MAX` meaning "disable" is the case this
/// pins).
#[test]
fn an_out_of_range_skew_refuses_verification_without_panicking() {
    let cache = cache();
    for skew in [i64::MAX, i64::MIN, -1, MAX_IAT_SKEW_SECS + 1] {
        let res = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: "a.b.c",
                htm: "POST",
                htu: "https://api.example.com/foo",
                access_token: None,
                max_iat_skew_secs: skew,
                jti_cache: &cache,
            },
            Utc::now(),
        );
        let err = res.expect_err("out-of-range skew");
        assert!(format!("{err}").contains("max_iat_skew_secs"), "{err}");
    }
}

/// Direct unit tests on `verify_dpop_proof` using ES256-signed proofs.
/// Gated behind `fapi` because the ES256 keypair generation pulls in the
/// `p256` crate which is only present under that feature.
#[cfg(feature = "fapi")]
mod verify_dpop_proof_tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::EncodePrivateKey;

    /// Build a signed DPoP proof + matching JWK thumbprint. Each field
    /// in `Builder` overrides one piece of the proof so individual
    /// tests can target specific rejection branches.
    struct Builder<'a> {
        htm: &'a str,
        htu: &'a str,
        iat: Option<i64>,
        jti: &'a str,
        ath: Option<&'a str>,
        typ: &'a str,
        alg_in_header: &'a str,
        /// An extra member added to the header's `jwk`, with the proof
        /// signed again over the rewritten header.
        jwk_extra: Option<(&'a str, serde_json::Value)>,
    }

    impl Default for Builder<'_> {
        fn default() -> Self {
            Self {
                htm: "POST",
                htu: "https://api.example.com/token",
                iat: None,
                jti: "test-jti-1",
                ath: None,
                typ: "dpop+jwt",
                alg_in_header: "ES256",
                jwk_extra: None,
            }
        }
    }

    struct Built {
        proof: String,
        expected_thumbprint: String,
    }

    fn build(b: Builder<'_>, now: DateTime<Utc>) -> Built {
        use base64::Engine as _;
        // Signing happens before any verification installs the provider.
        crate::jwt::ensure_crypto_provider();
        let b64 = &URL_SAFE_NO_PAD;

        // Generate an ephemeral P-256 keypair.
        let mut seed = [11u8; 32];
        let ec_key = loop {
            match p256::SecretKey::from_slice(&seed) {
                Ok(k) => break k,
                Err(_) => {
                    seed = Sha256::digest(seed).into();
                }
            }
        };
        let pkcs8 = ec_key.to_pkcs8_der().expect("PKCS8 encode");
        let encoding_key = EncodingKey::from_ec_der(pkcs8.as_bytes());

        // Public-key coordinates → JWK fields.
        let pub_key = ec_key.public_key();
        let pt = pub_key.to_encoded_point(false);
        let x_b64 = b64.encode(pt.x().expect("x").as_slice());
        let y_b64 = b64.encode(pt.y().expect("y").as_slice());

        let jwk_value = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64,
        });

        // Canonical RFC 7638 thumbprint (matches `jwk_thumbprint_es256`).
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x_b64}","y":"{y_b64}"}}"#);
        let expected_thumbprint = b64.encode(Sha256::digest(canonical.as_bytes()));

        // Header: typ / alg / jwk override-points.
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some(b.typ.to_string());
        header.jwk = Some(serde_json::from_value(jwk_value).expect("Jwk parse"));

        // Claims.
        let iat = b.iat.unwrap_or_else(|| now.timestamp());
        let mut claims = serde_json::json!({
            "htm": b.htm,
            "htu": b.htu,
            "iat": iat,
            "jti": b.jti,
        });
        if let Some(ath) = b.ath {
            claims["ath"] = serde_json::json!(ath);
        }

        // jsonwebtoken respects header.alg so we don't need to override
        // here; the `alg_in_header` field is only used when the test
        // wants to surface a mismatch via manual header rewriting.
        let proof = encode(&header, &claims, &encoding_key).expect("encode JWT");

        // Optional: rewrite the header's `alg` for the alg-mismatch test.
        let proof = if b.alg_in_header != "ES256" {
            let parts: Vec<&str> = proof.splitn(3, '.').collect();
            let hdr_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
            let mut hdr: serde_json::Value = serde_json::from_slice(&hdr_bytes).unwrap();
            hdr["alg"] = serde_json::json!(b.alg_in_header);
            let new_hdr = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&hdr).unwrap());
            format!("{}.{}.{}", new_hdr, parts[1], parts[2])
        } else {
            proof
        };

        let proof = match b.jwk_extra {
            None => proof,
            Some((member, value)) => {
                let parts: Vec<&str> = proof.splitn(3, '.').collect();
                let hdr_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
                let mut hdr: serde_json::Value = serde_json::from_slice(&hdr_bytes).unwrap();
                hdr["jwk"][member] = value;
                let new_hdr = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&hdr).unwrap());
                let signing_input = format!("{new_hdr}.{}", parts[1]);
                let signature = jsonwebtoken::crypto::sign(
                    signing_input.as_bytes(),
                    &encoding_key,
                    Algorithm::ES256,
                )
                .expect("re-sign");
                format!("{signing_input}.{signature}")
            }
        };

        Built {
            proof,
            expected_thumbprint,
        }
    }

    /// Happy path: a freshly-built DPoP proof verifies; the returned
    /// thumbprint matches the JWK's canonical RFC 7638 hash and is
    /// non-empty. Kills `jwk_thumbprint_es256 -> Ok(String::new())`.
    #[test]
    fn happy_path_verifies_and_returns_correct_thumbprint() {
        let now = Utc::now();
        let built = build(Builder::default(), now);
        let cache = cache();
        let result = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: &built.proof,
                htm: "POST",
                htu: "https://api.example.com/token",
                access_token: None,
                max_iat_skew_secs: 60,
                jti_cache: &cache,
            },
            now,
        );
        let verified = result.expect("happy DPoP must verify");
        assert_eq!(
            verified.thumbprint, built.expected_thumbprint,
            "thumbprint must match RFC 7638 canonical hash (kills `-> Ok(String::new())`)"
        );
        assert!(
            !verified.thumbprint.is_empty(),
            "thumbprint must be non-empty"
        );
    }

    fn verify(proof: &str, now: DateTime<Utc>) -> Result<DpopVerified, OAuthError> {
        verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: proof,
                htm: "POST",
                htu: "https://api.example.com/token",
                access_token: None,
                max_iat_skew_secs: 60,
                jti_cache: &cache(),
            },
            now,
        )
    }

    /// The signature covers header and payload: editing the payload
    /// without re-signing, or damaging the signature, is refused with the
    /// signature error and not with a claim error.
    #[test]
    fn tampered_payload_or_signature_fails_the_signature_check() {
        let now = Utc::now();
        let built = build(Builder::default(), now);
        let parts: Vec<&str> = built.proof.split('.').collect();

        let mut claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        claims["jti"] = serde_json::json!("another-jti");
        let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);
        let err = verify(&forged, now).expect_err("edited payload must fail");
        assert!(err.to_string().contains("signature"), "got {err}");

        let mut sig = parts[2].to_string();
        let flipped = if sig.starts_with('A') { "B" } else { "A" };
        sig.replace_range(0..1, flipped);
        let damaged = format!("{}.{}.{}", parts[0], parts[1], sig);
        let err = verify(&damaged, now).expect_err("damaged signature must fail");
        assert!(err.to_string().contains("signature"), "got {err}");
    }

    /// A proof whose header carries a non-`ES256` `alg` is rejected
    /// by the verifier (the only currently-supported algorithm).
    /// Kills `b.alg_in_header != "ES256"` mutated to `==` in the
    /// test fixture's rewrite-branch guard: under the original
    /// predicate the header is rewritten to `RS256` and the verifier
    /// rejects it; under the `==` mutation the rewrite is skipped,
    /// the header keeps `ES256`, and the verifier accepts the proof
    /// so this test fails under the mutation.
    #[test]
    fn wrong_alg_in_header_is_rejected() {
        let now = Utc::now();
        let built = build(
            Builder {
                alg_in_header: "RS256",
                ..Builder::default()
            },
            now,
        );
        let cache = cache();
        let result = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: &built.proof,
                htm: "POST",
                htu: "https://api.example.com/token",
                access_token: None,
                max_iat_skew_secs: 60,
                jti_cache: &cache,
            },
            now,
        );
        let err = result.expect_err("alg=RS256 in header must reject");
        assert!(
            format!("{err}").contains("alg") || format!("{err}").contains("ES256"),
            "rejection must mention alg or ES256 (got: {err})"
        );
    }

    /// `typ != "dpop+jwt"` rejects. Kills `!= → ==` on the typ check
    /// (which would invert and reject only dpop+jwt; every other
    /// typ would silently pass).
    #[test]
    fn wrong_typ_is_rejected() {
        let now = Utc::now();
        let built = build(
            Builder {
                typ: "JWT",
                ..Builder::default()
            },
            now,
        );
        let cache = cache();
        let result = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: &built.proof,
                htm: "POST",
                htu: "https://api.example.com/token",
                access_token: None,
                max_iat_skew_secs: 60,
                jti_cache: &cache,
            },
            now,
        );
        let err = result.expect_err("typ=JWT must reject");
        assert!(
            format!("{err}").contains("typ"),
            "rejection must mention typ (got: {err})"
        );
    }

    /// `htm` mismatch rejects. Kills `delete !` on the htm predicate which
    /// would invert it and accept ONLY mismatched htms.
    #[test]
    fn htm_mismatch_rejected() {
        let now = Utc::now();
        let built = build(
            Builder {
                htm: "POST",
                ..Builder::default()
            },
            now,
        );
        let cache = cache();
        let result = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: &built.proof,
                htm: "GET",
                htu: "https://api.example.com/token",
                access_token: None,
                max_iat_skew_secs: 60,
                jti_cache: &cache,
            },
            now,
        );
        let err = result.expect_err("htm mismatch must reject");
        assert!(format!("{err}").contains("htm"));
    }

    /// HTTP methods are case-sensitive (RFC 9110 section 9.1, RFC 9449
    /// section 4.3): a proof for `post` does not authorise a `POST`.
    #[test]
    fn htm_is_compared_case_sensitively() {
        let now = Utc::now();
        let lower = build(
            Builder {
                htm: "post",
                ..Builder::default()
            },
            now,
        );
        let err = verify(&lower.proof, now).expect_err("`post` is not `POST`");
        assert!(format!("{err}").contains("htm"), "{err}");

        let exact = build(Builder::default(), now);
        verify(&exact.proof, now).expect("`POST` is accepted");
    }

    /// RFC 9449 section 4.2: a `jwk` carrying private key material is
    /// refused, for every private member, even though the signature is valid.
    /// The same proof without the member verifies and keeps its thumbprint.
    #[test]
    fn a_jwk_with_private_key_material_is_rejected() {
        let now = Utc::now();
        let clean = build(Builder::default(), now);
        let ok = verify(&clean.proof, now).expect("clean proof verifies");
        assert_eq!(ok.thumbprint, clean.expected_thumbprint);

        for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            let built = build(
                Builder {
                    jwk_extra: Some((member, serde_json::json!("AQAB"))),
                    ..Builder::default()
                },
                now,
            );
            let err = verify(&built.proof, now)
                .expect_err(&format!("a jwk with `{member}` must be refused"));
            assert!(
                format!("{err}").contains("private key material"),
                "member {member}: {err}"
            );
        }
    }

    /// A valid proof with an absurd skew is refused with an error. Before the
    /// range check the replay window addition overflowed after acceptance.
    #[test]
    fn a_valid_proof_with_an_absurd_skew_is_an_error_not_a_panic() {
        let now = Utc::now();
        let built = build(Builder::default(), now);
        let cache = cache();
        for skew in [i64::MAX, i64::MAX / 2, 1_000_000_000_000] {
            let result = verify_dpop_proof(
                DpopVerifyRequest {
                    proof_jwt: &built.proof,
                    htm: "POST",
                    htu: "https://api.example.com/token",
                    access_token: None,
                    max_iat_skew_secs: skew,
                    jti_cache: &cache,
                },
                now,
            );
            assert!(result.is_err(), "skew {skew} must be refused");
        }
    }

    /// `htu` mismatch rejects. Kills `!= → ==` on the htu check.
    #[test]
    fn htu_mismatch_rejected() {
        let now = Utc::now();
        let built = build(
            Builder {
                htu: "https://api.example.com/token",
                ..Builder::default()
            },
            now,
        );
        let cache = cache();
        let result = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: &built.proof,
                htm: "POST",
                htu: "https://api.example.com/elsewhere",
                access_token: None,
                max_iat_skew_secs: 60,
                jti_cache: &cache,
            },
            now,
        );
        let err = result.expect_err("htu mismatch must reject");
        assert!(format!("{err}").contains("htu"));
    }

    /// `iat` skew strictly beyond `max_iat_skew_secs` rejects.
    /// Kills `> with ==`, `<`, `>=`. At exactly `skew == max` the
    /// proof must be accepted; one second over must reject.
    #[test]
    fn iat_skew_boundary_is_strict_greater() {
        let now = Utc::now();
        let max_skew = 60i64;

        // skew == max → accept.
        let at_boundary_iat = now.timestamp() - max_skew;
        let built = build(
            Builder {
                iat: Some(at_boundary_iat),
                jti: "boundary-ok",
                ..Builder::default()
            },
            now,
        );
        let cache = cache();
        let r1 = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: &built.proof,
                htm: "POST",
                htu: "https://api.example.com/token",
                access_token: None,
                max_iat_skew_secs: max_skew,
                jti_cache: &cache,
            },
            now,
        );
        assert!(
            r1.is_ok(),
            "iat exactly at max_iat_skew_secs must accept (kills `> → >=`): {r1:?}"
        );

        // skew > max → reject (one second past).
        let beyond_iat = now.timestamp() - (max_skew + 1);
        let built = build(
            Builder {
                iat: Some(beyond_iat),
                jti: "boundary-reject",
                ..Builder::default()
            },
            now,
        );
        let r2 = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: &built.proof,
                htm: "POST",
                htu: "https://api.example.com/token",
                access_token: None,
                max_iat_skew_secs: max_skew,
                jti_cache: &cache,
            },
            now,
        );
        let err = r2.expect_err("iat one second past max_iat_skew_secs must reject");
        assert!(format!("{err}").contains("iat"));
    }

    /// `ath` mismatch rejects when an access token is supplied.
    /// Kills `!= → ==` on the ath check.
    #[test]
    fn ath_mismatch_rejected_when_access_token_supplied() {
        let now = Utc::now();
        // Build with a deliberately-wrong ath claim.
        let built = build(
            Builder {
                ath: Some("not-the-correct-hash"),
                ..Builder::default()
            },
            now,
        );
        let cache = cache();
        let result = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: &built.proof,
                htm: "POST",
                htu: "https://api.example.com/token",
                access_token: Some("the-real-access-token"),
                max_iat_skew_secs: 60,
                jti_cache: &cache,
            },
            now,
        );
        let err = result.expect_err("ath mismatch must reject");
        assert!(format!("{err}").contains("ath"));
    }

    /// Second verification of the SAME proof rejects via the
    /// replay-cache path. Kills `delete !` on the try_insert outcome
    /// first call would reject (try_insert returns true → !true=false
    /// → no err under original; under `delete !` → true → return Err)
    /// AND second call would accept (try_insert returns false → false
    /// under !-deletion, would NOT take the error branch).
    #[test]
    fn jti_replay_within_window_rejected() {
        let now = Utc::now();
        let built = build(
            Builder {
                jti: "replay-jti",
                ..Builder::default()
            },
            now,
        );
        let cache = cache();

        let first = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: &built.proof,
                htm: "POST",
                htu: "https://api.example.com/token",
                access_token: None,
                max_iat_skew_secs: 60,
                jti_cache: &cache,
            },
            now,
        );
        assert!(first.is_ok(), "first verification must succeed: {first:?}");

        // Replay the same proof; must reject.
        let second = verify_dpop_proof(
            DpopVerifyRequest {
                proof_jwt: &built.proof,
                htm: "POST",
                htu: "https://api.example.com/token",
                access_token: None,
                max_iat_skew_secs: 60,
                jti_cache: &cache,
            },
            now,
        );
        let err = second.expect_err("replay must reject");
        assert!(
            format!("{err}").contains("replayed"),
            "rejection must mention replay (got: {err})"
        );
    }

    // Equivalent-mutation note: `MemoryJtiCache::new()` is defined as
    // `Self::default()`, so cargo-mutants's "replace body with
    // `Default::default()`" mutation on this helper produces an
    // observably-identical empty cache. The mutation is logged as
    // MISSED but is genuinely equivalent rather than under-tested.
    fn cache() -> MemoryJtiCache {
        MemoryJtiCache::new()
    }
}

// ── eviction cost ────────────────────────────────────────────────────

fn at(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
}

/// Inserting live entries never evicts anything: the work per call is the
/// number of entries that expired, not the number held.
#[test]
fn inserting_live_entries_evicts_nothing_however_many_are_held() {
    let mut store = JtiStore::default();
    for n in 0..2_000 {
        assert!(try_insert_at(
            &mut store,
            &format!("jti-{n}"),
            at(1_000 + n),
            at(0),
            usize::MAX
        ));
        assert_eq!(store.evict_expired(at(0)), 0, "no live entry is touched");
    }
    assert_eq!(store.live.len(), 2_000);
    assert_eq!(store.by_expiry.len(), 2_000);
}

#[test]
fn eviction_pops_exactly_the_expired_entries_in_expiry_order() {
    let mut store = JtiStore::default();
    // Inserted out of expiry order on purpose.
    for (jti, exp) in [("c", 30), ("a", 10), ("d", 40), ("b", 20)] {
        assert!(try_insert_at(&mut store, jti, at(exp), at(0), usize::MAX));
    }
    // `b` expires exactly at now (evicted), `c` and `d` survive.
    assert_eq!(store.evict_expired(at(20)), 2);
    assert!(
        !store.live.contains_key(&jti_digest("a")) && !store.live.contains_key(&jti_digest("b"))
    );
    assert!(store.live.contains_key(&jti_digest("c")) && store.live.contains_key(&jti_digest("d")));
    assert_eq!(store.live.len(), store.by_expiry.len());

    // An evicted jti is fresh again; a surviving one is still a replay.
    assert!(try_insert_at(&mut store, "a", at(90), at(20), usize::MAX));
    assert!(!try_insert_at(&mut store, "c", at(90), at(20), usize::MAX));
}
