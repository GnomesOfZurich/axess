use super::*;
use crate::device::store::MemoryDeviceStore;
use chrono::TimeZone;

fn ids() -> (TenantId, UserId, DeviceId) {
    (
        crate::authn::ids::testing::tenant("tenant-1"),
        crate::authn::ids::testing::user("user-1"),
        crate::authn::ids::testing::device("device-1"),
    )
}

fn now_at(h: u32, m: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, h, m, 0).unwrap()
}

fn fingerprint(byte: u8) -> FingerprintHash {
    FingerprintHash::from_bytes([byte; 32])
}

/// Pin: ensure_device on an empty store creates an Unknown device
/// using new_id_fn; subsequent ensure_device for the same
/// fingerprint returns the same id (idempotent on the find path).
#[tokio::test]
async fn ensure_device_creates_then_finds() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (t, u, expected_id) = ids();
    let fp = fingerprint(7);
    let now = now_at(10, 0);

    let created = svc
        .ensure_device(&t, Some(&u), fp, now, || expected_id)
        .await
        .unwrap();
    assert_eq!(created, expected_id, "first call must use new_id_fn");

    // Confirm Device is at Unknown.
    let device = svc.store.load(&t, &created).await.unwrap().unwrap();
    assert_eq!(device.trust_level, DeviceTrustLevel::Unknown);
    assert_eq!(device.fingerprint_hash, fp);
    assert_eq!(device.first_seen_at, now);
    assert_eq!(device.last_seen_at, now);

    // Second call with same fingerprint: must find, NOT create.
    let later = now_at(11, 0);
    let found = svc
        .ensure_device(&t, Some(&u), fp, later, || {
            panic!("new_id_fn must not be called on the find path")
        })
        .await
        .unwrap();
    assert_eq!(
        found, expected_id,
        "second call must return the existing id"
    );
}

/// Pin: existing-device path bumps last_seen_at via record_sighting.
#[tokio::test]
async fn ensure_device_existing_bumps_last_seen() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (t, u, id) = ids();
    let fp = fingerprint(1);

    let created_at = now_at(10, 0);
    let _ = svc
        .ensure_device(&t, Some(&u), fp, created_at, || id)
        .await
        .unwrap();

    let later = now_at(12, 30);
    let _ = svc
        .ensure_device(&t, Some(&u), fp, later, || id)
        .await
        .unwrap();

    let device = svc.store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(
        device.last_seen_at, later,
        "second sighting must bump last_seen_at"
    );
    assert_eq!(
        device.first_seen_at, created_at,
        "first_seen_at must remain pinned to creation moment"
    );
}

/// Pin: promote_on_authn transitions Unknown → Seen.
#[tokio::test]
async fn promote_unknown_transitions_to_seen() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (t, u, id) = ids();
    let _ = svc
        .ensure_device(&t, Some(&u), fingerprint(2), now_at(10, 0), || id)
        .await
        .unwrap();

    let after_login = now_at(10, 5);
    let new_level = svc
        .promote_on_authn(&t, &id, after_login)
        .await
        .unwrap()
        .expect("device exists");
    assert_eq!(new_level, DeviceTrustLevel::Seen);

    let device = svc.store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(device.trust_level, DeviceTrustLevel::Seen);
    assert_eq!(
        device.last_seen_at, after_login,
        "promotion path must also bump last_seen_at"
    );
}

/// Pin: Seen → Seen on subsequent authn, last_seen bumped.
#[tokio::test]
async fn promote_seen_is_noop_but_bumps_last_seen() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (t, u, id) = ids();
    let _ = svc
        .ensure_device(&t, Some(&u), fingerprint(3), now_at(10, 0), || id)
        .await
        .unwrap();
    // Take it to Seen first.
    let _ = svc.promote_on_authn(&t, &id, now_at(10, 5)).await.unwrap();

    // Now another authn; should stay Seen, bump last_seen.
    let later = now_at(11, 0);
    let level = svc
        .promote_on_authn(&t, &id, later)
        .await
        .unwrap()
        .expect("present");
    assert_eq!(level, DeviceTrustLevel::Seen);
    let device = svc.store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(device.last_seen_at, later);
}

/// Pin: Trusted stays Trusted; never demoted by promote_on_authn.
#[tokio::test]
async fn promote_trusted_stays_trusted() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (t, u, id) = ids();
    let _ = svc
        .ensure_device(&t, Some(&u), fingerprint(4), now_at(10, 0), || id)
        .await
        .unwrap();
    // Manually elevate to Trusted via the underlying store.
    svc.store
        .set_trust_level(&t, &id, DeviceTrustLevel::Trusted, now_at(10, 1))
        .await
        .unwrap();

    let level = svc
        .promote_on_authn(&t, &id, now_at(11, 0))
        .await
        .unwrap()
        .expect("present");
    assert_eq!(
        level,
        DeviceTrustLevel::Trusted,
        "Trusted devices must not be demoted by promote_on_authn"
    );
}

/// Pin: Revoked stays Revoked; promote_on_authn never re-elevates.
/// Also: last_seen is NOT bumped on the revoked path (the device
/// is conceptually retired; touching last_seen would defeat sweep
/// thresholds).
#[tokio::test]
async fn promote_revoked_never_re_elevates_or_bumps() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (t, u, id) = ids();
    let _ = svc
        .ensure_device(&t, Some(&u), fingerprint(5), now_at(10, 0), || id)
        .await
        .unwrap();
    svc.store
        .set_trust_level(&t, &id, DeviceTrustLevel::Revoked, now_at(10, 1))
        .await
        .unwrap();
    let last_seen_before = svc.store.load(&t, &id).await.unwrap().unwrap().last_seen_at;

    let level = svc
        .promote_on_authn(&t, &id, now_at(11, 0))
        .await
        .unwrap()
        .expect("present");
    assert_eq!(
        level,
        DeviceTrustLevel::Revoked,
        "Revoked devices must remain Revoked"
    );
    let device = svc.store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(
        device.last_seen_at, last_seen_before,
        "Revoked path must NOT bump last_seen_at"
    );
}

/// Pin: promote_on_authn returns None when the device_id doesn't
/// resolve: defensive against caller bugs that pass stale ids.
#[tokio::test]
async fn promote_unknown_id_returns_none() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (t, _u, id) = ids();
    let result = svc.promote_on_authn(&t, &id, now_at(10, 0)).await.unwrap();
    assert!(
        result.is_none(),
        "absent device_id must yield Ok(None), not error"
    );
}

// ── promote_if_authenticated (FactorOutcome composition) ──────────

/// Pin: composition helper fires promote only on `Authenticated`.
#[tokio::test]
async fn promote_if_authenticated_fires_only_on_authenticated_arm() {
    use crate::authn::factor::FactorKind;

    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let (t, u, id) = ids();
    let _ = svc
        .ensure_device(&t, Some(&u), fingerprint(8), now_at(10, 0), || id)
        .await
        .unwrap();

    // FactorRequired → no-op, returns Ok(None).
    let outcome = FactorOutcome::FactorRequired(FactorKind::Totp);
    let r = svc
        .promote_if_authenticated(&outcome, &t, &id, now_at(10, 1))
        .await
        .unwrap();
    assert!(r.is_none(), "FactorRequired must not promote");
    let after_required = svc.store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(
        after_required.trust_level,
        DeviceTrustLevel::Unknown,
        "no promote → still Unknown"
    );

    // InvalidCredential → no-op.
    let r = svc
        .promote_if_authenticated(&FactorOutcome::InvalidCredential, &t, &id, now_at(10, 2))
        .await
        .unwrap();
    assert!(r.is_none(), "InvalidCredential must not promote");

    // Locked → no-op.
    let r = svc
        .promote_if_authenticated(
            &FactorOutcome::Locked { until: None },
            &t,
            &id,
            now_at(10, 3),
        )
        .await
        .unwrap();
    assert!(r.is_none(), "Locked must not promote");

    // Authenticated → fires promote, returns Some(Seen).
    let r = svc
        .promote_if_authenticated(&FactorOutcome::Authenticated, &t, &id, now_at(10, 4))
        .await
        .unwrap();
    assert_eq!(r, Some(DeviceTrustLevel::Seen));
    let after_auth = svc.store.load(&t, &id).await.unwrap().unwrap();
    assert_eq!(after_auth.trust_level, DeviceTrustLevel::Seen);
}

/// Capturing sink for device-event emission tests. Local to the
/// lifecycle module so the events module's own test fixture can
/// stay test-private there.
struct LifecycleCaptureSink {
    events: std::sync::Mutex<Vec<crate::authn::event::AuthEvent>>,
}
impl LifecycleCaptureSink {
    fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }
}
impl crate::device::events::DeviceEventSink for std::sync::Arc<LifecycleCaptureSink> {
    fn emit<'a>(
        &'a self,
        event: crate::authn::event::AuthEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let me = self.clone();
        Box::pin(async move {
            me.events.lock().unwrap().push(event);
        })
    }
}

/// Pin: `ensure_device` emits `DeviceFirstSeen` on the
/// create path and stays silent on the find path (the sighting is
/// not itself an audit-worthy event; sightings are aggregate-rate
/// telemetry, not row-level audit).
#[tokio::test]
async fn ensure_device_emits_device_first_seen_on_create_only() {
    use crate::authn::event::AuthEventType;

    let sink = std::sync::Arc::new(LifecycleCaptureSink::new());
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new()).with_event_sink(sink.clone());
    let (t, u, id) = ids();
    let fp = fingerprint(7);

    // Create path; must emit one DeviceFirstSeen event.
    let _ = svc
        .ensure_device(&t, Some(&u), fp, now_at(10, 0), || id)
        .await
        .unwrap();
    {
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1, "create path emits exactly one event");
        assert_eq!(events[0].event_type, AuthEventType::DeviceFirstSeen);
        assert_eq!(events[0].device_id.as_ref(), Some(&id));
        assert_eq!(events[0].user_id.as_ref(), Some(&u));
        assert_eq!(events[0].tenant_id.as_ref(), Some(&t));
    }

    // Second call with same fingerprint; must NOT emit a new event.
    let _ = svc
        .ensure_device(&t, Some(&u), fp, now_at(11, 0), || id)
        .await
        .unwrap();
    let events = sink.events.lock().unwrap();
    assert_eq!(
        events.len(),
        1,
        "find path must NOT emit DeviceFirstSeen; sightings are not audit events"
    );
}

/// Pin: ensure_device works for guest sessions (user = None).
/// The stored Device row carries user_id = None until authn
/// completes and the application updates it.
#[tokio::test]
async fn ensure_device_supports_guest_sessions() {
    let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
    let t = crate::authn::ids::testing::tenant("tenant-1");
    let id = crate::authn::ids::testing::device("dev-guest");
    let fp = fingerprint(9);
    let _ = svc
        .ensure_device(&t, None, fp, now_at(10, 0), || id)
        .await
        .unwrap();
    let device = svc.store.load(&t, &id).await.unwrap().unwrap();
    assert!(
        device.user_id.is_none(),
        "guest sighting must store user_id = None"
    );
}

// ── WebAuthn binding tests ─────────────────────────────────────

#[cfg(feature = "fido2")]
mod webauthn_binding {
    use super::*;
    use crate::device::types::{AttestationClass, DeviceBinding};

    /// Helper: create a device via the lifecycle service and return ids.
    async fn setup_device() -> (
        DeviceLifecycleService<MemoryDeviceStore>,
        TenantId,
        UserId,
        DeviceId,
    ) {
        let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
        let (t, u, id) = ids();
        let _ = svc
            .ensure_device(&t, Some(&u), fingerprint(10), now_at(10, 0), || id)
            .await
            .unwrap();
        (svc, t, u, id)
    }

    /// Pin: bind_webauthn_credential adds a WebAuthn binding to the device.
    #[tokio::test]
    async fn bind_adds_webauthn_binding() {
        let (svc, t, _u, id) = setup_device().await;

        let added = svc
            .bind_webauthn_credential(
                &t,
                &id,
                "cred-abc".into(),
                AttestationClass::Basic,
                now_at(10, 5),
            )
            .await
            .unwrap();
        assert!(added, "first bind must return true");

        let device = svc.store().load(&t, &id).await.unwrap().unwrap();
        assert_eq!(device.bindings.len(), 1);
        match &device.bindings[0] {
            DeviceBinding::WebAuthn {
                credential_id,
                attestation_class,
                bound_at,
                last_used_at,
            } => {
                assert_eq!(credential_id, "cred-abc");
                assert_eq!(*attestation_class, AttestationClass::Basic);
                assert_eq!(*bound_at, now_at(10, 5));
                assert_eq!(*last_used_at, now_at(10, 5));
            }
            other => panic!("expected WebAuthn binding, got {other:?}"),
        }
    }

    /// Pin: duplicate credential_id is idempotent: returns false, no second binding.
    #[tokio::test]
    async fn bind_deduplicates_same_credential() {
        let (svc, t, _u, id) = setup_device().await;

        let first = svc
            .bind_webauthn_credential(
                &t,
                &id,
                "cred-dup".into(),
                AttestationClass::None,
                now_at(10, 1),
            )
            .await
            .unwrap();
        assert!(first);

        let second = svc
            .bind_webauthn_credential(
                &t,
                &id,
                "cred-dup".into(),
                AttestationClass::AttCa,
                now_at(10, 2),
            )
            .await
            .unwrap();
        assert!(!second, "duplicate bind must return false");

        let device = svc.store().load(&t, &id).await.unwrap().unwrap();
        assert_eq!(
            device.bindings.len(),
            1,
            "dedup must not add a second binding"
        );
    }

    /// Pin: bind returns false for a nonexistent device_id.
    #[tokio::test]
    async fn bind_returns_false_for_missing_device() {
        let svc = DeviceLifecycleService::new(MemoryDeviceStore::new());
        let t = crate::authn::ids::testing::tenant("t");
        let absent = crate::authn::ids::testing::device("ghost");

        let result = svc
            .bind_webauthn_credential(
                &t,
                &absent,
                "cred-x".into(),
                AttestationClass::None,
                now_at(10, 0),
            )
            .await
            .unwrap();
        assert!(!result);
    }

    /// Pin: record_webauthn_usage updates last_used_at on the matching binding.
    #[tokio::test]
    async fn usage_updates_last_used_at() {
        let (svc, t, _u, id) = setup_device().await;
        svc.bind_webauthn_credential(
            &t,
            &id,
            "cred-use".into(),
            AttestationClass::Basic,
            now_at(10, 0),
        )
        .await
        .unwrap();

        svc.record_webauthn_usage(&t, &id, "cred-use", now_at(12, 0))
            .await
            .unwrap();

        let device = svc.store().load(&t, &id).await.unwrap().unwrap();
        match &device.bindings[0] {
            DeviceBinding::WebAuthn { last_used_at, .. } => {
                assert_eq!(*last_used_at, now_at(12, 0), "last_used_at must be updated");
            }
            other => panic!("expected WebAuthn binding, got {other:?}"),
        }
    }

    /// Pin: record_webauthn_usage is a no-op for nonexistent device or credential.
    #[tokio::test]
    async fn usage_noop_for_missing_device_or_credential() {
        let (svc, t, _u, id) = setup_device().await;

        // No binding exists yet; should be silent no-op.
        svc.record_webauthn_usage(&t, &id, "no-such-cred", now_at(11, 0))
            .await
            .unwrap();

        // Device doesn't exist.
        let ghost = crate::authn::ids::testing::device("ghost");
        svc.record_webauthn_usage(&t, &ghost, "cred-x", now_at(11, 0))
            .await
            .unwrap();
    }

    /// Pin: bind emits DeviceBindingAdded audit event.
    #[tokio::test]
    async fn bind_emits_device_binding_added_event() {
        use crate::authn::event::AuthEventType;

        let sink = std::sync::Arc::new(LifecycleCaptureSink::new());
        let svc =
            DeviceLifecycleService::new(MemoryDeviceStore::new()).with_event_sink(sink.clone());
        let (t, u, id) = ids();
        let _ = svc
            .ensure_device(&t, Some(&u), fingerprint(11), now_at(10, 0), || id)
            .await
            .unwrap();

        // Clear the DeviceFirstSeen event from ensure_device.
        sink.events.lock().unwrap().clear();

        svc.bind_webauthn_credential(
            &t,
            &id,
            "cred-evt".into(),
            AttestationClass::Basic,
            now_at(10, 5),
        )
        .await
        .unwrap();

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 1, "bind must emit exactly one event");
        assert_eq!(events[0].event_type, AuthEventType::DeviceBindingAdded);
        assert_eq!(events[0].device_id.as_ref(), Some(&id));
        assert_eq!(events[0].user_id.as_ref(), Some(&u));
    }

    /// Pin: multiple different credentials can coexist on the same device.
    #[tokio::test]
    async fn multiple_credentials_on_same_device() {
        let (svc, t, _u, id) = setup_device().await;

        svc.bind_webauthn_credential(
            &t,
            &id,
            "cred-1".into(),
            AttestationClass::Basic,
            now_at(10, 1),
        )
        .await
        .unwrap();
        svc.bind_webauthn_credential(
            &t,
            &id,
            "cred-2".into(),
            AttestationClass::AttCa,
            now_at(10, 2),
        )
        .await
        .unwrap();

        let device = svc.store().load(&t, &id).await.unwrap().unwrap();
        assert_eq!(device.bindings.len(), 2);
    }

    /// line 365 `==` → `!=` in `record_webauthn_usage`:
    /// the credential-id match must update ONLY the matching
    /// binding. Mutation flips the comparator so we touch every
    /// other binding instead. Setup with two WebAuthn credentials
    /// and observe which `last_used_at` advanced.
    #[tokio::test]
    async fn record_webauthn_usage_updates_only_matching_credential() {
        let (svc, t, _u, id) = setup_device().await;
        let bind_time = now_at(10, 0);
        svc.bind_webauthn_credential(&t, &id, "cred-A".into(), AttestationClass::Basic, bind_time)
            .await
            .unwrap();
        svc.bind_webauthn_credential(&t, &id, "cred-B".into(), AttestationClass::Basic, bind_time)
            .await
            .unwrap();

        let usage_time = now_at(11, 30);
        svc.record_webauthn_usage(&t, &id, "cred-A", usage_time)
            .await
            .unwrap();

        let device = svc.store().load(&t, &id).await.unwrap().unwrap();
        let mut a_last_used: Option<DateTime<Utc>> = None;
        let mut b_last_used: Option<DateTime<Utc>> = None;
        for b in &device.bindings {
            if let DeviceBinding::WebAuthn {
                credential_id,
                last_used_at,
                ..
            } = b
            {
                if credential_id == "cred-A" {
                    a_last_used = Some(*last_used_at);
                } else if credential_id == "cred-B" {
                    b_last_used = Some(*last_used_at);
                }
            }
        }
        assert_eq!(
            a_last_used,
            Some(usage_time),
            "cred-A must have its last_used_at advanced"
        );
        assert_eq!(
            b_last_used,
            Some(bind_time),
            "cred-B must NOT be touched (mutation `!=` would touch it)"
        );
    }
}
