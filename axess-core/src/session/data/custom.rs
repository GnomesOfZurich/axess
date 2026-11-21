//! The session's custom bag: the keys the library keeps in it, what a
//! login carries across, and the size cap every write applies.

/// Custom key under which the login service stamps the flow in flight. The
/// transition to `Authenticated` keeps it: the registration step that follows
/// reads it to check the credentials did not change meanwhile.
pub(crate) const LOGIN_FLOW_KEY: &str = "axess.login.flow";

/// Custom key under which a step-up begun for a named FIDO2 ceremony keeps
/// it, for the challenge the step's `prepare_factor` issues. A new login
/// removes it and the transition to `Authenticated` drops it (it is not one
/// of the keys [`retain_across_login`] keeps), so it never outlives its
/// step-up.
pub(crate) const STEP_UP_CEREMONY_KEY: &str = "axess.step_up.ceremony";

/// Drop the pre-login contents of the custom bag when a session becomes
/// authenticated, keeping the key the login service owns (the flow in
/// flight) and the keys the application registered to be carried across.
///
/// State an anonymous visitor could put in a session (a cart, a locale, a
/// planted value) must not ride into the authenticated session, so the
/// default keeps nothing else.
pub(crate) fn retain_across_login(custom: &mut serde_json::Value, preserved: &[String]) {
    match custom {
        serde_json::Value::Object(map) => {
            map.retain(|key, _| key == LOGIN_FLOW_KEY || preserved.iter().any(|p| p == key));
        }
        other => *other = serde_json::Value::default(),
    }
}

/// Length in bytes of `value` serialized as compact JSON, counted without
/// building the string.
pub(crate) fn json_byte_len(value: &serde_json::Value) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    // A `Value` always serializes, so the error arm is unreachable; a count of
    // zero is the same fallback the size check has always used.
    if serde_json::to_writer(&mut count, value).is_err() {
        return 0;
    }
    count.0
}

/// Clear a custom bag that exceeds `max_bytes` serialized (zero is no cap).
/// Every write of a session applies it, so data loaded or merged
/// from a concurrent write cannot be stored oversized.
pub(crate) fn cap_custom(custom: &mut serde_json::Value, max_bytes: usize) {
    if max_bytes == 0 {
        return;
    }
    let custom_size = json_byte_len(custom);
    if custom_size > max_bytes {
        tracing::warn!(
            custom_size,
            max = max_bytes,
            "session custom data exceeds size limit; clearing custom data"
        );
        *custom = serde_json::Value::default();
    }
}
