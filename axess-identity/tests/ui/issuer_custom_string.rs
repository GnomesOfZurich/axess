// `Issuer::Custom` holds a `CustomLabel`, not a string: a label that
// `Issuer::custom` would refuse cannot be written out by hand.
use axess_identity::Issuer;

fn main() {
    let _ = Issuer::Custom("oauth".to_string());
}
