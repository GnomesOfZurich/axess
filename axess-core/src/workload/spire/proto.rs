//! The messages of the SPIFFE Workload API, read and written by hand.
//!
//! The service is `SpiffeWorkloadAPI`, declared with no protobuf package, so
//! a method's path is `/SpiffeWorkloadAPI/<Method>`. The method names and
//! the field numbers below are those of `workloadapi.proto`, the service
//! definition section 3 of the SPIFFE Workload API standard points to. The
//! fake agent in `crate::testing::spire_agent` writes the same field numbers
//! in its own encoders, so the tests show that the two agree, and tests hold
//! the method names and the metadata key to their literal values. The
//! standard's third profile, for WIT-SVIDs, is optional and is not read
//! here. No test runs against a SPIRE agent.
//! An unknown field is skipped, as protobuf requires, so a message from a
//! newer agent still reads.
//!
//! Responses are decoded into the `Raw*` types here, which hold what the
//! agent sent and nothing more. Whether an SVID is one this workload accepts
//! is decided in [`super::svid`].

use serde_json::{Map, Number, Value};
use zeroize::Zeroizing;

use super::wire::{Field, Reader, WireError, put_bytes};

/// `FetchX509SVID`: server-streaming.
pub(crate) const FETCH_X509_SVID: &str = "FetchX509SVID";
/// `FetchX509Bundles`: server-streaming.
pub(crate) const FETCH_X509_BUNDLES: &str = "FetchX509Bundles";
/// `FetchJWTSVID`: unary.
pub(crate) const FETCH_JWT_SVID: &str = "FetchJWTSVID";
/// `FetchJWTBundles`: server-streaming.
pub(crate) const FETCH_JWT_BUNDLES: &str = "FetchJWTBundles";
/// `ValidateJWTSVID`: unary.
pub(crate) const VALIDATE_JWT_SVID: &str = "ValidateJWTSVID";

/// The most SVIDs one response may carry. An agent returns one SVID per
/// registration entry that matches the workload; a response with more than
/// this is refused rather than read.
pub(crate) const MAX_SVIDS: usize = 64;
/// The most trust domains one bundle map may carry.
pub(crate) const MAX_BUNDLES: usize = 256;
/// The most revocation lists one response may carry.
pub(crate) const MAX_CRLS: usize = 256;
/// How deep objects and lists may nest in the claims of a validated token,
/// the claims object itself counting as the first level.
pub(crate) const MAX_CLAIM_DEPTH: usize = 16;

/// Why a response could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProtoError {
    /// The bytes are not a protobuf message.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// A known field arrived with another wire type than its declaration.
    #[error("field `{0}` has the wrong wire type")]
    WrongType(&'static str),
    /// A string field is not UTF-8.
    #[error("field `{0}` is not valid UTF-8")]
    NotUtf8(&'static str),
    /// A repeated field or a map has more entries than the limit.
    #[error("more than {max} entries in `{field}`")]
    TooMany {
        /// The field that overflowed.
        field: &'static str,
        /// The limit.
        max: usize,
    },
    /// The claims nest deeper than [`MAX_CLAIM_DEPTH`].
    #[error("the claims nest deeper than {0} levels")]
    TooDeep(usize),
    /// A claim holds a number JSON cannot carry (NaN or an infinity).
    #[error("a claim holds a number that is not finite")]
    NotFinite,
}

/// One `X509SVID` as the agent sent it.
pub(crate) struct RawX509Svid {
    /// `spiffe_id`: the SPIFFE ID the SVID was issued for.
    pub(crate) spiffe_id: String,
    /// `x509_svid`: the certificate chain, DER certificates end to end, leaf
    /// first.
    pub(crate) cert_chain: Vec<u8>,
    /// `x509_svid_key`: the private key, PKCS#8 DER, unencrypted.
    pub(crate) private_key: Zeroizing<Vec<u8>>,
    /// `bundle`: the trust domain's X.509 authorities, DER end to end.
    pub(crate) bundle: Vec<u8>,
    /// `hint`: the operator's name for this SVID among several.
    pub(crate) hint: String,
}

/// One `X509SVIDResponse`.
pub(crate) struct RawX509SvidResponse {
    /// `svids`, in the agent's order; the first is the default.
    pub(crate) svids: Vec<RawX509Svid>,
    /// `crl`: revocation lists, DER.
    pub(crate) crls: Vec<Vec<u8>>,
    /// `federated_bundles`: trust domain to its authorities, DER end to end.
    pub(crate) federated_bundles: Vec<(String, Vec<u8>)>,
}

/// One `X509BundlesResponse` or `JWTBundlesResponse`: both are a map from a
/// trust domain to its bundle, the former with revocation lists beside it.
pub(crate) struct RawBundles {
    /// `crl`: revocation lists, DER. Always empty for JWT bundles.
    pub(crate) crls: Vec<Vec<u8>>,
    /// `bundles`: trust domain to bundle bytes (DER end to end, or a JWKS).
    pub(crate) bundles: Vec<(String, Vec<u8>)>,
}

/// One `JWTSVID`.
pub(crate) struct RawJwtSvid {
    /// `spiffe_id`.
    pub(crate) spiffe_id: String,
    /// `svid`: the token, in compact serialization.
    pub(crate) token: Zeroizing<String>,
    /// `hint`.
    pub(crate) hint: String,
}

/// One `ValidateJWTSVIDResponse`.
pub(crate) struct RawValidation {
    /// `spiffe_id`: the identity the agent read from the token it accepted.
    pub(crate) spiffe_id: String,
    /// `claims`: the token's claims, from a `google.protobuf.Struct`.
    pub(crate) claims: Map<String, Value>,
}

/// `JWTSVIDRequest`: the audiences the token is for, and optionally which of
/// the workload's identities it should carry.
pub(crate) fn encode_jwt_svid_request(audiences: &[String], spiffe_id: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    for audience in audiences {
        put_bytes(&mut out, 1, audience.as_bytes());
    }
    if let Some(spiffe_id) = spiffe_id {
        put_bytes(&mut out, 2, spiffe_id.as_bytes());
    }
    out
}

/// `ValidateJWTSVIDRequest`: the audience the validator is, and the token.
/// The message holds the token, so it wipes itself when dropped.
pub(crate) fn encode_validate_jwt_svid_request(audience: &str, token: &str) -> Zeroizing<Vec<u8>> {
    // Sized up front: a buffer that grew would leave the token behind in
    // the allocation it outgrew.
    let mut out = Zeroizing::new(Vec::with_capacity(audience.len() + token.len() + 24));
    put_bytes(&mut out, 1, audience.as_bytes());
    put_bytes(&mut out, 2, token.as_bytes());
    out
}

/// Decode an `X509SVIDResponse`.
pub(crate) fn decode_x509_svid_response(message: &[u8]) -> Result<RawX509SvidResponse, ProtoError> {
    let mut response = RawX509SvidResponse {
        svids: Vec::new(),
        crls: Vec::new(),
        federated_bundles: Vec::new(),
    };
    let mut reader = Reader::new(message);
    while let Some((number, field)) = reader.next_field()? {
        match number {
            1 => {
                bounded(response.svids.len(), "svids", MAX_SVIDS)?;
                response
                    .svids
                    .push(decode_x509_svid(bytes(field, "svids")?)?);
            }
            2 => {
                bounded(response.crls.len(), "crl", MAX_CRLS)?;
                response.crls.push(bytes(field, "crl")?.to_vec());
            }
            3 => {
                bounded(
                    response.federated_bundles.len(),
                    "federated_bundles",
                    MAX_BUNDLES,
                )?;
                response.federated_bundles.push(decode_bundle_entry(
                    bytes(field, "federated_bundles")?,
                    "federated_bundles",
                )?);
            }
            _ => {}
        }
    }
    Ok(response)
}

fn decode_x509_svid(message: &[u8]) -> Result<RawX509Svid, ProtoError> {
    let mut svid = RawX509Svid {
        spiffe_id: String::new(),
        cert_chain: Vec::new(),
        private_key: Zeroizing::new(Vec::new()),
        bundle: Vec::new(),
        hint: String::new(),
    };
    let mut reader = Reader::new(message);
    while let Some((number, field)) = reader.next_field()? {
        match number {
            1 => svid.spiffe_id = string(field, "spiffe_id")?,
            2 => svid.cert_chain = bytes(field, "x509_svid")?.to_vec(),
            3 => svid.private_key = Zeroizing::new(bytes(field, "x509_svid_key")?.to_vec()),
            4 => svid.bundle = bytes(field, "bundle")?.to_vec(),
            5 => svid.hint = string(field, "hint")?,
            _ => {}
        }
    }
    Ok(svid)
}

/// Decode an `X509BundlesResponse`: `crl` is field 1 and `bundles` field 2.
pub(crate) fn decode_x509_bundles_response(message: &[u8]) -> Result<RawBundles, ProtoError> {
    let mut response = RawBundles {
        crls: Vec::new(),
        bundles: Vec::new(),
    };
    let mut reader = Reader::new(message);
    while let Some((number, field)) = reader.next_field()? {
        match number {
            1 => {
                bounded(response.crls.len(), "crl", MAX_CRLS)?;
                response.crls.push(bytes(field, "crl")?.to_vec());
            }
            2 => {
                bounded(response.bundles.len(), "bundles", MAX_BUNDLES)?;
                response
                    .bundles
                    .push(decode_bundle_entry(bytes(field, "bundles")?, "bundles")?);
            }
            _ => {}
        }
    }
    Ok(response)
}

/// Decode a `JWTBundlesResponse`: `bundles` is field 1.
pub(crate) fn decode_jwt_bundles_response(message: &[u8]) -> Result<RawBundles, ProtoError> {
    let mut response = RawBundles {
        crls: Vec::new(),
        bundles: Vec::new(),
    };
    let mut reader = Reader::new(message);
    while let Some((number, field)) = reader.next_field()? {
        if number == 1 {
            bounded(response.bundles.len(), "bundles", MAX_BUNDLES)?;
            response
                .bundles
                .push(decode_bundle_entry(bytes(field, "bundles")?, "bundles")?);
        }
    }
    Ok(response)
}

/// One entry of a `map<string, bytes>`: the key is field 1, the value 2.
fn decode_bundle_entry(message: &[u8], map: &'static str) -> Result<(String, Vec<u8>), ProtoError> {
    let mut key = String::new();
    let mut value = Vec::new();
    let mut reader = Reader::new(message);
    while let Some((number, field)) = reader.next_field()? {
        match number {
            1 => key = string(field, map)?,
            2 => value = bytes(field, map)?.to_vec(),
            _ => {}
        }
    }
    Ok((key, value))
}

/// Decode a `JWTSVIDResponse`.
pub(crate) fn decode_jwt_svid_response(message: &[u8]) -> Result<Vec<RawJwtSvid>, ProtoError> {
    let mut svids = Vec::new();
    let mut reader = Reader::new(message);
    while let Some((number, field)) = reader.next_field()? {
        if number == 1 {
            bounded(svids.len(), "svids", MAX_SVIDS)?;
            svids.push(decode_jwt_svid(bytes(field, "svids")?)?);
        }
    }
    Ok(svids)
}

fn decode_jwt_svid(message: &[u8]) -> Result<RawJwtSvid, ProtoError> {
    let mut svid = RawJwtSvid {
        spiffe_id: String::new(),
        token: Zeroizing::new(String::new()),
        hint: String::new(),
    };
    let mut reader = Reader::new(message);
    while let Some((number, field)) = reader.next_field()? {
        match number {
            1 => svid.spiffe_id = string(field, "spiffe_id")?,
            2 => svid.token = Zeroizing::new(string(field, "svid")?),
            3 => svid.hint = string(field, "hint")?,
            _ => {}
        }
    }
    Ok(svid)
}

/// Decode a `ValidateJWTSVIDResponse`.
pub(crate) fn decode_validate_jwt_svid_response(
    message: &[u8],
) -> Result<RawValidation, ProtoError> {
    let mut validation = RawValidation {
        spiffe_id: String::new(),
        claims: Map::new(),
    };
    let mut reader = Reader::new(message);
    while let Some((number, field)) = reader.next_field()? {
        match number {
            1 => validation.spiffe_id = string(field, "spiffe_id")?,
            2 => validation.claims = decode_struct(bytes(field, "claims")?, 0)?,
            _ => {}
        }
    }
    Ok(validation)
}

/// A `google.protobuf.Struct`: `map<string, Value> fields = 1`.
fn decode_struct(message: &[u8], depth: usize) -> Result<Map<String, Value>, ProtoError> {
    if depth >= MAX_CLAIM_DEPTH {
        return Err(ProtoError::TooDeep(MAX_CLAIM_DEPTH));
    }
    let mut fields = Map::new();
    let mut reader = Reader::new(message);
    while let Some((number, field)) = reader.next_field()? {
        if number != 1 {
            continue;
        }
        let mut key = String::new();
        let mut value = Value::Null;
        let mut entry = Reader::new(bytes(field, "claims")?);
        while let Some((number, field)) = entry.next_field()? {
            match number {
                1 => key = string(field, "claims")?,
                2 => value = decode_value(bytes(field, "claims")?, depth)?,
                _ => {}
            }
        }
        fields.insert(key, value);
    }
    Ok(fields)
}

/// A `google.protobuf.Value`: a oneof of null (1), number (2), string (3),
/// bool (4), struct (5) and list (6). The last member written wins. A
/// struct or a list inside it is one level deeper than `depth`.
fn decode_value(message: &[u8], depth: usize) -> Result<Value, ProtoError> {
    let mut value = Value::Null;
    let mut reader = Reader::new(message);
    while let Some((number, field)) = reader.next_field()? {
        value = match (number, field) {
            (1, Field::Varint(_)) => Value::Null,
            (2, Field::Fixed64(bits)) => number_value(f64::from_bits(bits))?,
            (3, Field::Bytes(text)) => Value::String(utf8(text, "claims")?),
            (4, Field::Varint(flag)) => Value::Bool(flag != 0),
            (5, Field::Bytes(nested)) => Value::Object(decode_struct(nested, depth + 1)?),
            (6, Field::Bytes(nested)) => Value::Array(decode_list(nested, depth + 1)?),
            (1..=6, _) => return Err(ProtoError::WrongType("claims")),
            _ => value,
        };
    }
    Ok(value)
}

/// A `google.protobuf.ListValue`: `repeated Value values = 1`.
fn decode_list(message: &[u8], depth: usize) -> Result<Vec<Value>, ProtoError> {
    if depth >= MAX_CLAIM_DEPTH {
        return Err(ProtoError::TooDeep(MAX_CLAIM_DEPTH));
    }
    let mut values = Vec::new();
    let mut reader = Reader::new(message);
    while let Some((number, field)) = reader.next_field()? {
        if number == 1 {
            values.push(decode_value(bytes(field, "claims")?, depth)?);
        }
    }
    Ok(values)
}

/// A protobuf double as a JSON number. A `Struct` has no integer, so `exp`
/// and `iat` arrive as doubles; a whole number that a double holds exactly
/// is given back as an integer, which is what a claim reader expects.
fn number_value(number: f64) -> Result<Value, ProtoError> {
    /// 2^53: every whole number below it is exact in a double.
    const EXACT: f64 = 9_007_199_254_740_992.0;
    if !number.is_finite() {
        return Err(ProtoError::NotFinite);
    }
    if number.fract() == 0.0 && number.abs() < EXACT {
        return Ok(Value::Number(Number::from(number as i64)));
    }
    Number::from_f64(number)
        .map(Value::Number)
        .ok_or(ProtoError::NotFinite)
}

fn bytes<'a>(field: Field<'a>, name: &'static str) -> Result<&'a [u8], ProtoError> {
    match field {
        Field::Bytes(value) => Ok(value),
        _ => Err(ProtoError::WrongType(name)),
    }
}

fn string(field: Field<'_>, name: &'static str) -> Result<String, ProtoError> {
    utf8(bytes(field, name)?, name)
}

fn utf8(value: &[u8], name: &'static str) -> Result<String, ProtoError> {
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| ProtoError::NotUtf8(name))
}

fn bounded(len: usize, field: &'static str, max: usize) -> Result<(), ProtoError> {
    if len >= max {
        return Err(ProtoError::TooMany { field, max });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
