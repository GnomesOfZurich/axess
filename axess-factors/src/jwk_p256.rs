//! A P-256 public key given as a JWK by whoever sent it.
//!
//! Two verifiers read a key the sender chose: the DPoP proof verifier and the
//! device-key proof verifier. Both hold it to the same rules before a key is
//! built from it, and both name it by the same RFC 7638 thumbprint, so the
//! rules live here once.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Members of a JWK that hold private key material (RFC 7517 §4, RFC 7518
/// §6): an EC or OKP `d`, the RSA `p`, `q`, `dp`, `dq`, `qi` and `oth`, and a
/// symmetric `k`. A key that travels in a proof is public.
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Why a JWK was refused. The verifier that asked puts its own words around
/// it; none of the sender's text is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JwkRefusal {
    /// The value is not a JSON object.
    NotAnObject,
    /// The key carries a member that holds private key material.
    PrivateMaterial,
    /// A member is missing or is not what a P-256 public key has.
    Member {
        /// The member's name.
        member: &'static str,
        /// What it must be.
        why: &'static str,
    },
}

/// A key that travels in a proof is public. A JWK that carries the private
/// half has handed it to everyone who can read the request.
pub(crate) fn refuse_private_members(jwk: &serde_json::Value) -> Result<(), JwkRefusal> {
    let members = jwk.as_object().ok_or(JwkRefusal::NotAnObject)?;
    if PRIVATE_JWK_MEMBERS
        .iter()
        .any(|member| members.contains_key(*member))
    {
        return Err(JwkRefusal::PrivateMaterial);
    }
    Ok(())
}

/// The coordinates of an EC P-256 public key given as a JWK: `kty` must be
/// `EC`, `crv` `P-256`, and `x` and `y` base64url without padding of exactly
/// 32 bytes each. Anything else is refused naming the member.
pub(crate) fn coordinates(jwk: &serde_json::Value) -> Result<([u8; 32], [u8; 32]), JwkRefusal> {
    if jwk.get("kty").and_then(|v| v.as_str()) != Some("EC") {
        return Err(JwkRefusal::Member {
            member: "kty",
            why: "must be `EC`",
        });
    }
    if jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256") {
        return Err(JwkRefusal::Member {
            member: "crv",
            why: "must be `P-256`",
        });
    }
    let coordinate = |member: &'static str| -> Result<[u8; 32], JwkRefusal> {
        let refuse = |why: &'static str| JwkRefusal::Member { member, why };
        let text = jwk
            .get(member)
            .and_then(|v| v.as_str())
            .ok_or_else(|| refuse("must be a string"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| refuse("must be base64url without padding"))?;
        bytes.try_into().map_err(|_| refuse("must be 32 bytes"))
    };
    Ok((coordinate("x")?, coordinate("y")?))
}

/// The unpadded base64url of one coordinate: the one spelling a key has,
/// however its sender wrote it.
pub(crate) fn coordinate_text(coordinate: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(coordinate)
}

/// The public JWK of a P-256 key, with exactly the four members of an EC
/// public key.
#[cfg(feature = "key-proof")]
pub(crate) fn public_jwk(x: &[u8; 32], y: &[u8; 32]) -> serde_json::Value {
    let mut members = serde_json::Map::new();
    members.insert("crv".to_string(), "P-256".into());
    members.insert("kty".to_string(), "EC".into());
    members.insert("x".to_string(), coordinate_text(x).into());
    members.insert("y".to_string(), coordinate_text(y).into());
    serde_json::Value::Object(members)
}

/// The RFC 7638 JWK thumbprint of a P-256 key: the SHA-256 of its required
/// members, `crv`, `kty`, `x` and `y` in that order, as compact JSON.
pub(crate) fn thumbprint(x: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    // RFC 7638 fixes the member order, so the text is written out rather
    // than left to a map's ordering: with `serde_json`'s `preserve_order`
    // on somewhere in the build, a map keeps the order it was filled in.
    // The two coordinates are base64url, which needs no JSON escaping.
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        coordinate_text(x),
        coordinate_text(y)
    );
    Sha256::digest(canonical.as_bytes()).into()
}

/// [`thumbprint`] as the unpadded base64url text a `cnf.jkt` claim carries.
#[cfg(feature = "oauth")]
pub(crate) fn thumbprint_text(x: &[u8; 32], y: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(thumbprint(x, y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key() -> serde_json::Value {
        json!({
            "kty": "EC", "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
            "y": URL_SAFE_NO_PAD.encode([2u8; 32]),
        })
    }

    /// The thumbprint is RFC 7638's for every pair of coordinates: SHA-256
    /// of the JSON with exactly `crv`, `kty`, `x`, `y` in that order and no
    /// whitespace, written here without the code under test. It depends on
    /// the coordinates alone, and no two of the pairs share one.
    #[test]
    fn the_thumbprint_is_the_rfc_7638_digest_for_every_key() {
        let mut seen = std::collections::HashSet::new();
        let mut seed: [u8; 32] = Sha256::digest(b"coordinates").into();
        for _ in 0..64 {
            let x: [u8; 32] = Sha256::digest(seed).into();
            let y: [u8; 32] = Sha256::digest(x).into();
            seed = y;
            let canonical = format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                URL_SAFE_NO_PAD.encode(x),
                URL_SAFE_NO_PAD.encode(y)
            );
            let expected: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
            assert_eq!(thumbprint(&x, &y), expected);
            assert_ne!(thumbprint(&y, &x), expected, "the order of the two matters");
            assert!(seen.insert(expected), "two keys shared a thumbprint");
        }
    }

    #[test]
    fn a_well_formed_key_yields_its_coordinates() {
        assert_eq!(coordinates(&key()), Ok(([1u8; 32], [2u8; 32])));
        assert_eq!(refuse_private_members(&key()), Ok(()));
    }

    #[test]
    fn each_member_is_held_to_its_rule() {
        let cases: [(&str, serde_json::Value, &str, &str); 7] = [
            ("kty", json!("RSA"), "kty", "must be `EC`"),
            ("crv", json!("P-384"), "crv", "must be `P-256`"),
            ("x", json!(7), "x", "must be a string"),
            ("x", json!("***"), "x", "must be base64url without padding"),
            (
                "x",
                json!(URL_SAFE_NO_PAD.encode([1u8; 31])),
                "x",
                "must be 32 bytes",
            ),
            (
                "y",
                json!(URL_SAFE_NO_PAD.encode([1u8; 33])),
                "y",
                "must be 32 bytes",
            ),
            ("y", serde_json::Value::Null, "y", "must be a string"),
        ];
        for (member, value, named, why) in cases {
            let mut jwk = key();
            jwk[member] = value;
            assert_eq!(
                coordinates(&jwk),
                Err(JwkRefusal::Member { member: named, why }),
                "{member}"
            );
        }
    }

    #[test]
    fn every_private_member_is_refused_and_a_non_object_too() {
        for member in PRIVATE_JWK_MEMBERS {
            let mut jwk = key();
            jwk[member] = json!("AA");
            assert_eq!(
                refuse_private_members(&jwk),
                Err(JwkRefusal::PrivateMaterial),
                "{member}"
            );
        }
        assert_eq!(
            refuse_private_members(&json!("a string")),
            Err(JwkRefusal::NotAnObject)
        );
    }

    /// The thumbprint is the RFC 7638 one: SHA-256 over the four members in
    /// lexicographic order, with no whitespace.
    #[test]
    fn the_thumbprint_hashes_the_canonical_members() {
        let (x, y) = ([1u8; 32], [2u8; 32]);
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            URL_SAFE_NO_PAD.encode(x),
            URL_SAFE_NO_PAD.encode(y)
        );
        let expected: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        assert_eq!(thumbprint(&x, &y), expected);
        assert_ne!(thumbprint(&x, &y), thumbprint(&y, &x));
    }

    /// The text form is the base64url of the same digest.
    #[cfg(feature = "oauth")]
    #[test]
    fn the_thumbprint_text_is_the_digest_in_base64url() {
        let (x, y) = ([1u8; 32], [2u8; 32]);
        assert_eq!(
            thumbprint_text(&x, &y),
            URL_SAFE_NO_PAD.encode(thumbprint(&x, &y))
        );
    }

    /// The JWK written for a key reads back as the same key.
    #[cfg(feature = "key-proof")]
    #[test]
    fn the_public_jwk_round_trips() {
        let jwk = public_jwk(&[9u8; 32], &[8u8; 32]);
        assert_eq!(coordinates(&jwk), Ok(([9u8; 32], [8u8; 32])));
        assert_eq!(jwk.as_object().map(|m| m.len()), Some(4));
    }
}
