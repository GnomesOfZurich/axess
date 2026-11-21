// The field of `CustomLabel` is private: the only way to a label is
// `Issuer::custom`, which checks the format and refuses a built-in name.
use axess_identity::{CustomLabel, Issuer};

fn main() {
    let _ = Issuer::Custom(CustomLabel("oauth".to_string()));
}
