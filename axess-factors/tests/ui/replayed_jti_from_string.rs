// `JtiReplayError::AlreadyUsed` holds a `ReplayedJti`, not a string: a key
// as the token wrote it cannot be put there by hand.
use axess_factors::jwt::verifier::JtiReplayError;

fn main() {
    let _ = JtiReplayError::AlreadyUsed(String::from("the key as the token wrote it"));
}
