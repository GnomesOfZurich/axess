//! A build without `local-idp-rsa` has no RSA keys: the fixture refuses
//! every RSA algorithm by naming the feature, and generates no key.

use super::*;

#[test]
fn an_rsa_algorithm_is_refused_by_naming_the_feature() {
    for algorithm in [Algorithm::RS256, Algorithm::RS384, Algorithm::RS512] {
        let Err(refused) =
            LocalIdpFixture::try_with_algorithm("https://idp.example.org", algorithm)
        else {
            panic!("{algorithm:?} built a fixture without `local-idp-rsa`");
        };
        assert!(
            matches!(refused, LocalIdpKeyError::UnsupportedAlgorithm(_)),
            "{algorithm:?}: {refused:?}"
        );
        let message = refused.to_string();
        assert!(message.contains("local-idp-rsa"), "{message}");
        assert!(message.contains(&format!("{algorithm:?}")), "{message}");
    }
}

#[test]
#[should_panic(expected = "local-idp-rsa")]
fn with_algorithm_panics_by_naming_the_feature() {
    let _ = LocalIdpFixture::with_algorithm("https://idp.example.org", Algorithm::RS256);
}
