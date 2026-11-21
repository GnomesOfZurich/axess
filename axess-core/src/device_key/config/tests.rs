use super::*;

fn config() -> DeviceKeyConfig {
    DeviceKeyConfig::new("https://app.example")
}

fn refused(config: DeviceKeyConfig) -> &'static str {
    config.validate().expect_err("refused").setting
}

#[test]
fn the_defaults_are_accepted_and_are_the_documented_ones() {
    let c = config();
    assert_eq!(c.validate(), Ok(()));
    assert_eq!(c.policy(), KeyBindingPolicy::Prefer);
    assert_eq!(c.proof_ttl(), Duration::from_secs(600));
    assert_eq!(c.acceptance_grace(), Duration::from_secs(30));
    assert_eq!(c.challenge_ttl(), Duration::from_secs(1200));
    assert_eq!(c.registration_window(), Duration::from_secs(120));
    assert_eq!(c.origin(), Some("https://app.example"));
    assert_eq!(
        c.registration_url("https://app.example"),
        "https://app.example/axess/device-key"
    );
    assert_eq!(
        c.refresh_url("https://app.example"),
        "https://app.example/axess/device-key/refresh"
    );
    assert_eq!(c.proof_cookie_name(), "__Host-axess_device_proof");
    assert_eq!(c.registration_path(), "/axess/device-key");
    assert_eq!(c.refresh_path(), "/axess/device-key/refresh");
    assert!(c.secure());
    let local = DeviceKeyConfig::insecure_for_local_development("http://localhost:3000");
    assert_eq!(local.validate(), Ok(()));
    assert!(!local.secure());
    assert_eq!(local.proof_cookie_name(), "axess_device_proof");
}

#[test]
fn each_setter_sets_what_its_accessor_reads() {
    let secs = Duration::from_secs;
    let c = config()
        .with_policy(KeyBindingPolicy::Require)
        .with_proof_ttl(secs(300))
        .with_acceptance_grace(secs(10))
        .with_challenge_ttl(secs(900))
        .with_registration_window(secs(60))
        .with_registration_path("/keys")
        .with_refresh_path("/keys/refresh")
        .with_proof_cookie_name("__Host-proof");
    assert_eq!(c.validate(), Ok(()));
    assert_eq!(c.policy(), KeyBindingPolicy::Require);
    assert_eq!(
        config().with_policy(KeyBindingPolicy::Off).policy(),
        KeyBindingPolicy::Off
    );
    assert_eq!(c.proof_ttl(), secs(300));
    assert_eq!(c.acceptance_grace(), secs(10));
    assert_eq!(c.challenge_ttl(), secs(900));
    assert_eq!(c.registration_window(), secs(60));
    assert_eq!(c.registration_path(), "/keys");
    assert_eq!(c.refresh_path(), "/keys/refresh");
    assert_eq!(c.proof_cookie_name(), "__Host-proof");
    assert_eq!(
        c.registration_url("https://a.example"),
        "https://a.example/keys"
    );
    assert_eq!(
        c.refresh_url("https://a.example"),
        "https://a.example/keys/refresh"
    );
}

/// A cookie name of 64 characters is accepted and one of 65 refused.
#[test]
fn the_cookie_name_bound_is_inclusive() {
    assert_eq!(
        config().with_proof_cookie_name("n".repeat(64)).validate(),
        Ok(())
    );
    assert_eq!(
        refused(config().with_proof_cookie_name("n".repeat(65))),
        "proof_cookie_name"
    );
}

#[test]
fn each_bound_is_inclusive_and_one_step_past_it_is_refused_by_name() {
    let secs = Duration::from_secs;
    assert_eq!(config().with_proof_ttl(secs(60)).validate(), Ok(()));
    assert_eq!(refused(config().with_proof_ttl(secs(59))), "proof_ttl");
    assert_eq!(
        config()
            .with_proof_ttl(secs(3600))
            .with_challenge_ttl(secs(7200))
            .validate(),
        Ok(())
    );
    assert_eq!(
        refused(
            config()
                .with_proof_ttl(secs(3601))
                .with_challenge_ttl(secs(7200))
        ),
        "proof_ttl"
    );
    assert_eq!(config().with_acceptance_grace(secs(300)).validate(), Ok(()));
    assert_eq!(
        refused(config().with_acceptance_grace(secs(301))),
        "acceptance_grace"
    );
    // 600 s of proof and 30 s of grace: 630 is refused, 631 accepted.
    assert_eq!(
        refused(config().with_challenge_ttl(secs(630))),
        "challenge_ttl"
    );
    assert_eq!(config().with_challenge_ttl(secs(631)).validate(), Ok(()));
    assert_eq!(config().with_challenge_ttl(secs(86_400)).validate(), Ok(()));
    assert_eq!(
        refused(config().with_challenge_ttl(secs(86_401))),
        "challenge_ttl"
    );
    assert_eq!(
        config().with_registration_window(secs(10)).validate(),
        Ok(())
    );
    assert_eq!(
        refused(config().with_registration_window(secs(9))),
        "registration_window"
    );
    assert_eq!(
        config().with_registration_window(secs(900)).validate(),
        Ok(())
    );
    assert_eq!(
        refused(config().with_registration_window(secs(901))),
        "registration_window"
    );
}

#[test]
fn origins_paths_and_cookie_names_are_checked() {
    for origin in [
        "http://app.example",
        "app.example",
        "https://",
        "https://app.example/",
        "https://app.example/x",
        "https://user@app.example",
        "https://app.example?x",
        "https://app.example#x",
        "https://app .example",
    ] {
        assert_eq!(refused(DeviceKeyConfig::new(origin)), "origin", "{origin}");
    }
    assert_eq!(
        refused(DeviceKeyConfig::insecure_for_local_development(
            "ftp://localhost"
        )),
        "origin"
    );
    assert_eq!(
        refused(config().with_registration_path("axess")),
        "registration_path"
    );
    for path in ["/a\"b", "/a\\b"] {
        assert_eq!(
            refused(config().with_registration_path(path)),
            "registration_path",
            "{path:?}"
        );
    }
    assert_eq!(
        config().with_registration_path("/a-b_c.d~e/f").validate(),
        Ok(())
    );
    for path in [
        "/a?b",
        "/a#b",
        "/a b",
        "/a\u{7f}",
        "/a\"b",
        "/a\\b",
        "/caf\u{e9}",
        "/a\tb",
    ] {
        assert_eq!(
            refused(config().with_refresh_path(path)),
            "refresh_path",
            "{path:?}"
        );
    }
    assert_eq!(
        refused(config().with_refresh_path("/axess/device-key")),
        "refresh_path"
    );
    assert_eq!(
        refused(config().with_proof_cookie_name("")),
        "proof_cookie_name"
    );
    assert_eq!(
        refused(config().with_proof_cookie_name("a b")),
        "proof_cookie_name"
    );
    assert_eq!(
        refused(
            DeviceKeyConfig::insecure_for_local_development("http://localhost")
                .with_proof_cookie_name("__Host-proof")
        ),
        "proof_cookie_name"
    );
}
