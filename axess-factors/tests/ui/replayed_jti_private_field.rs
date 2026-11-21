// `ReplayedJti`'s field is private: only `JtiReplayError::already_used`,
// which escapes and cuts the key, builds one.
use axess_factors::jwt::verifier::ReplayedJti;

fn main() {
    let _ = ReplayedJti(String::from("the key as the token wrote it"));
}
