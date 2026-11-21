//! A type with a stable wire name displays as that name: `{}` in a log
//! line or an error is the string `as_str` returns, for every variant.

use axess_core::authn::factor::FederatedProvider;

#[test]
fn a_federated_provider_displays_as_its_tag() {
    for (provider, tag) in [
        (FederatedProvider::Github, "github"),
        (FederatedProvider::Google, "google"),
        (FederatedProvider::Microsoft, "microsoft"),
        (FederatedProvider::Custom("acme-sso".into()), "acme-sso"),
    ] {
        assert_eq!(provider.to_string(), tag);
        assert_eq!(provider.to_string(), provider.as_str());
    }
}

#[cfg(feature = "device")]
#[test]
fn a_device_pii_category_displays_as_its_stable_string() {
    use axess_core::device::pii::DevicePiiCategory;
    for (category, name) in [
        (DevicePiiCategory::DisplayName, "display_name"),
        (DevicePiiCategory::UserAgentString, "user_agent_string"),
        (DevicePiiCategory::AcceptLanguage, "accept_language"),
        (DevicePiiCategory::IpAddress, "ip_address"),
        (DevicePiiCategory::ScreenMetrics, "screen_metrics"),
        (DevicePiiCategory::Other, "other"),
    ] {
        assert_eq!(category.to_string(), name);
        assert_eq!(category.to_string(), category.as_str());
    }
}
