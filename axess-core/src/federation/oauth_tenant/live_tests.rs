//! The live registry: a set answers the provider it replaced, a remove the
//! provider it removed, and a pair is refused only when an entry other than
//! the one being set holds it.

use super::live::PairHeldElsewhere;
use super::*;
use crate::authn::factor::FederatedProvider;
use crate::authn::ids::testing::tenant;
use axess_factors::oauth::MockOAuthProvider;

/// A provider named `name` for `(issuer, client_id)`.
fn provider(name: &str, issuer: &str, client_id: &str) -> Arc<dyn OAuthProvider> {
    Arc::new(
        MockOAuthProvider::new(name)
            .with_issuer(issuer)
            .with_client_id(client_id),
    )
}

/// The kind a set names when the test is not about kinds.
fn custom() -> FederatedProvider {
    FederatedProvider::Custom("sso".into())
}

/// The issuer of `provider`, which tells two test providers apart.
fn issuer_of(provider: &Arc<dyn OAuthProvider>) -> Option<String> {
    provider.issuer().map(str::to_string)
}

/// A first set answers no provider; setting the same entry again answers the
/// one it replaced, and the entry holds the new one.
#[test]
fn a_set_answers_the_provider_it_replaced() {
    let live = LiveTenantOAuthProviders::new();
    let first = live
        .set(
            tenant("acme"),
            "sso".into(),
            provider("sso", "https://one.example", "client-1"),
            custom(),
        )
        .expect("the pair is free");
    assert!(first.is_none(), "nothing was replaced");

    let replaced = live
        .set(
            tenant("acme"),
            "sso".into(),
            provider("sso", "https://two.example", "client-1"),
            custom(),
        )
        .expect("the entry's own pair is not held elsewhere")
        .expect("the first provider was replaced");
    assert_eq!(
        issuer_of(&replaced.0).as_deref(),
        Some("https://one.example")
    );
    let held = live.get(&tenant("acme"), "sso").expect("held");
    assert_eq!(issuer_of(&held).as_deref(), Some("https://two.example"));
}

/// A remove answers the provider it removed, and nothing once it is gone.
#[test]
fn a_remove_answers_the_provider_it_removed() {
    let live = LiveTenantOAuthProviders::new();
    live.set(
        tenant("acme"),
        "sso".into(),
        provider("sso", "https://one.example", "client-1"),
        custom(),
    )
    .expect("the pair is free");

    let removed = live
        .remove(&tenant("acme"), "sso")
        .expect("the provider was there");
    assert_eq!(
        issuer_of(&removed.0).as_deref(),
        Some("https://one.example")
    );
    assert!(live.get(&tenant("acme"), "sso").is_none());
    assert!(live.is_empty());
    assert!(live.remove(&tenant("acme"), "sso").is_none());
}

/// Two entries with pairs of their own both hold, and setting an entry again
/// over its own pair is not a pair held elsewhere.
#[test]
fn entries_with_their_own_pairs_and_an_entrys_own_pair_go_through() {
    let live = LiveTenantOAuthProviders::new();
    live.set(
        tenant("acme"),
        "sso".into(),
        provider("sso", "https://one.example", "client-1"),
        custom(),
    )
    .expect("the pair is free");
    live.set(
        tenant("beta"),
        "sso".into(),
        provider("sso", "https://two.example", "client-2"),
        custom(),
    )
    .expect("another pair is free");
    live.set(
        tenant("acme"),
        "corp".into(),
        provider("corp", "https://one.example", "client-3"),
        custom(),
    )
    .expect("the same issuer under another client id is another pair");
    live.set(
        tenant("acme"),
        "sso".into(),
        provider("sso", "https://one.example", "client-1"),
        custom(),
    )
    .expect("an entry's own pair is not held elsewhere");
    assert_eq!(live.len(), 3);
}

/// A pair another tenant's entry holds, or this tenant's under another name,
/// is refused, nothing is set and the generation does not move.
#[test]
fn a_pair_another_entry_holds_is_refused_and_nothing_moves() {
    let live = LiveTenantOAuthProviders::new();
    live.set(
        tenant("acme"),
        "sso".into(),
        provider("sso", "https://one.example", "client-1"),
        custom(),
    )
    .expect("the pair is free");
    let generation = live.generation();

    let other_tenant = live.set(
        tenant("beta"),
        "sso".into(),
        provider("sso", "https://one.example", "client-1"),
        custom(),
    );
    assert_eq!(other_tenant.err(), Some(PairHeldElsewhere));
    let other_name = live.set(
        tenant("acme"),
        "copy".into(),
        provider("copy", "https://one.example", "client-1"),
        custom(),
    );
    assert_eq!(other_name.err(), Some(PairHeldElsewhere));

    assert!(live.get(&tenant("beta"), "sso").is_none());
    assert!(live.get(&tenant("acme"), "copy").is_none());
    assert_eq!(live.generation(), generation);
}

/// The pair a provider names is its issuer and client id, in that order.
#[test]
fn a_providers_pair_is_its_issuer_and_client_id() {
    let named = provider("sso", "https://one.example", "client-1");
    assert_eq!(pair_of(&*named), Some(("https://one.example", "client-1")));
}

/// An entry's kind is the one its set named; a set again names it anew, a
/// name with no entry is `Custom(name)`, and a remove answers the kind with
/// the provider.
#[tokio::test]
async fn an_entrys_kind_is_the_one_its_set_named() {
    let live = LiveTenantOAuthProviders::new();
    live.set(
        tenant("acme"),
        "sso".into(),
        provider("sso", "https://one.example", "client-1"),
        FederatedProvider::Microsoft,
    )
    .expect("the pair is free");
    assert_eq!(
        live.provider_kind(&tenant("acme"), "sso").await,
        FederatedProvider::Microsoft
    );
    assert_eq!(
        live.provider_kind(&tenant("beta"), "sso").await,
        FederatedProvider::Custom("sso".into()),
        "another tenant's name of the same spelling has no entry"
    );
    let (_, was) = live
        .set(
            tenant("acme"),
            "sso".into(),
            provider("sso", "https://one.example", "client-1"),
            FederatedProvider::Google,
        )
        .expect("the entry's own pair")
        .expect("an entry was replaced");
    assert_eq!(was, FederatedProvider::Microsoft);
    assert_eq!(
        live.provider_kind(&tenant("acme"), "sso").await,
        FederatedProvider::Google
    );
    let (_, removed) = live.remove(&tenant("acme"), "sso").expect("removed");
    assert_eq!(removed, FederatedProvider::Google);
    assert_eq!(
        live.provider_kind(&tenant("acme"), "sso").await,
        FederatedProvider::Custom("sso".into())
    );
}
