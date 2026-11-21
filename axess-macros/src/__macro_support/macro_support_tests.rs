//! Tests of the entity ids the gate builds from a template, and of the context-provider check.

use super::*;

const GUARDED_SCHEMA: &str = r#"{"App": {"entityTypes": {"User": {}, "Doc": {}},
    "actions": {"View": {"appliesTo": {"principalTypes": ["User"],
    "resourceTypes": ["Doc"], "context": {"type": "Record",
    "attributes": {"mfa": {"type": "Boolean", "required": false}}}}}}}}"#;

#[test]
fn a_missing_context_provider_is_refused_only_when_policies_read_the_context() {
    let guarded = axess_core::authz::PolicyStore::from_text(
        "permit(principal, action, resource) when { context has mfa && context.mfa };",
        GUARDED_SCHEMA,
    )
    .unwrap();
    let plain = axess_core::authz::PolicyStore::from_text(
        "permit(principal, action, resource);",
        GUARDED_SCHEMA,
    )
    .unwrap();

    assert!(!refuse_without_context_provider(&plain, "View"));
    assert!(refuse_without_context_provider(&guarded, "View"));
    assert!(refuse_without_context_provider(&guarded, "View"));
}

/// What the expansion of `require_authz!` reads from the request: the
/// installation, and nothing beside it. A second read (a policy store, a
/// provider) would be a second way to install one, apart from the value
/// whose constructor checks them against each other.
#[test]
fn the_gate_reads_the_installation_and_no_other_extension() {
    let source = include_str!("../authz_macro.rs");
    let expansion = &source[source
        .find("macro_rules! require_authz")
        .expect("the macro is defined in this file")..];
    let reads: Vec<&str> = expansion
        .match_indices(".get::<")
        .map(|(at, open)| {
            let rest = &expansion[at + open.len()..];
            &rest[..rest.find(">()").expect("a typed read is closed")]
        })
        .collect();
    assert_eq!(reads, ["$crate::__authz::AuthzInstallation"]);
    // The expansion names no type it could read on its own either.
    for gone in [
        "PolicyStore",
        "RequestEntityProvider",
        "RequestContextProvider",
    ] {
        assert!(
            !expansion.contains(&format!("__authz::{gone}")),
            "the expansion names {gone}"
        );
    }
}

#[test]
fn unicode_escape_in_user_id_stays_data() {
    let p = params(&[("id", "x")]);
    let (principal, _, _) = build_uids("App", "Read", "Doc:{id}", &p, r"al\u{69}ce", "t1").unwrap();
    assert_eq!(principal.id().unescaped(), r"al\u{69}ce");
    assert_ne!(principal.id().unescaped(), "alice");
}

#[test]
fn quote_and_escape_in_path_param_stay_data() {
    let p = params(&[("id", r#"a" } \u{41}"#)]);
    let (_, _, resource) = build_uids("App", "Read", "Doc:{id}", &p, "u1", "t1").unwrap();
    assert_eq!(resource.id().unescaped(), r#"a" } \u{41}"#);
    assert_eq!(resource.type_name().to_string(), "App::Doc");
}

/// A colon in a single value is refused, not read as a type boundary: a
/// value under a template's only placeholder may hold neither `:` nor
/// `/`, the separators templates of several placeholders use.
#[test]
fn colon_in_param_is_refused_not_moved_into_the_type() {
    let p = params(&[("id", "Admin:1")]);
    let err = build_uids("App", "Read", "Doc:{id}", &p, "u1", "t1").unwrap_err();
    assert!(err.to_string().contains("`/` or `:`"), "{err}");
    let p = params(&[("id", "Admin-1")]);
    let (_, _, resource) = build_uids("App", "Read", "Doc:{id}", &p, "u1", "t1").unwrap();
    assert_eq!(resource.type_name().to_string(), "App::Doc");
    assert_eq!(resource.id().unescaped(), "Admin-1");
}

#[test]
fn namespaced_type_keeps_its_whole_namespace() {
    let p = params(&[("id", "d1")]);
    let (_, _, r) = build_uids("MyApp", "Read", "Sub::Document:{id}", &p, "u1", "t1").unwrap();
    assert_eq!(r.type_name().to_string(), "MyApp::Sub::Document");
    assert_eq!(r.id().unescaped(), "d1");
}

#[test]
fn two_level_namespace_argument_is_kept() {
    let p = params(&[("id", "d1")]);
    let (principal, action, r) =
        build_uids("MyApp::Sub", "Read", "Document:{id}", &p, "u1", "t1").unwrap();
    assert_eq!(r.type_name().to_string(), "MyApp::Sub::Document");
    assert_eq!(principal.type_name().to_string(), "MyApp::Sub::User");
    assert_eq!(action.type_name().to_string(), "MyApp::Sub::Action");
}

#[test]
fn path_value_with_double_colon_or_quote_cannot_change_the_type() {
    // A value that names a type holds `:` and is refused before any
    // entity is built.
    for value in ["Admin::Root", r#"x"::A::"y"#, "A::B:C", "::"] {
        let p = params(&[("id", value)]);
        assert!(
            build_uids("App", "Read", "Doc:{id}", &p, "u1", "t1").is_err(),
            "{value}"
        );
    }
    // A quote alone is data in the id, under the attribute's type.
    let value = r#"x"A"y"#;
    let p = params(&[("id", value)]);
    let (_, _, r) = build_uids("App", "Read", "Doc:{id}", &p, "u1", "t1").unwrap();
    assert_eq!(r.type_name().to_string(), "App::Doc");
    assert_eq!(r.id().unescaped(), value);
}

#[test]
fn placeholder_in_the_type_position_is_refused() {
    let p = params(&[("kind", "Admin"), ("id", "1")]);
    assert!(build_uids("App", "Read", "{kind}:{id}", &p, "u1", "t1").is_err());
    assert!(build_uids("App", "Read", "Pre{kind}:{id}", &p, "u1", "t1").is_err());
    assert!(build_uids("App", "Read", "Doc:{id}", &p, "u1", "t1").is_ok());
}

#[test]
fn parameterless_template_builds_from_the_attribute_alone() {
    let (_, _, r) =
        build_uids("App", "Manage", "Platform:global", &params(&[]), "u1", "t1").unwrap();
    assert_eq!(r.type_name().to_string(), "App::Platform");
    assert_eq!(r.id().unescaped(), "global");
}

#[test]
fn const_check_accepts_literal_types_and_ids_with_placeholders() {
    const _: () = assert_resource_type_is_literal("Doc:{id}");
    const _: () = assert_resource_type_is_literal("Sub::Doc:{id}");
    const _: () = assert_resource_type_is_literal("Platform:global");
    assert_eq!(type_id_separator("A::B:c"), Some(4));
    assert_eq!(type_id_separator("A::B"), None);
}

#[test]
fn unknown_placeholder_is_refused() {
    assert!(build_uids("App", "Read", "Doc:{id}", &params(&[]), "u1", "t1").is_err());
}

#[test]
fn template_without_colon_is_refused() {
    assert!(build_uids("App", "Read", "Doc", &params(&[]), "u1", "t1").is_err());
}

#[test]
fn session_placeholders_come_from_the_session_not_the_route() {
    let p = params(&[("id", "d1"), ("$tenant", "evil")]);
    let (_, _, r) = build_uids("App", "Read", "Doc:{$tenant}/{id}", &p, "u1", "t1").unwrap();
    assert_eq!(r.id().unescaped(), "t1/d1");
    let (_, _, r) = build_uids(
        "App",
        "Read",
        "Doc:{$tenant}:{$user}",
        &params(&[]),
        "u1",
        "t1",
    )
    .unwrap();
    assert_eq!(r.id().unescaped(), "t1:u1");
}

/// Two request values joined by a literal can be re-split by the caller,
/// so the template is refused.
#[test]
fn two_path_placeholders_in_one_id_are_refused() {
    let p = params(&[("a", "x/y"), ("b", "z")]);
    assert!(build_uids("App", "Read", "Doc:{a}/{b}", &p, "u1", "t1").is_err());
    // Under one placeholder the separator is refused too, so the two
    // templates can never render one id; a value without it renders.
    assert!(build_uids("App", "Read", "Doc:{a}", &p, "u1", "t1").is_err());
    let p = params(&[("a", "x-y")]);
    assert!(build_uids("App", "Read", "Doc:{a}", &p, "u1", "t1").is_ok());
}

#[test]
fn const_check_counts_only_path_placeholders() {
    const _: () = assert_one_path_placeholder("Doc:{id}");
    const _: () = assert_one_path_placeholder("Doc:{$tenant}/{id}");
    const _: () = assert_one_path_placeholder("Platform:global");
}

fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

#[test]
fn substitutes_single_placeholder() {
    let p = params(&[("id", "abc-123")]);
    assert_eq!(interpolate_path_params("Ledger:{id}", &p), "Ledger:abc-123");
}

#[test]
fn substitutes_multiple_placeholders() {
    let p = params(&[("tenant", "t1"), ("id", "x")]);
    assert_eq!(interpolate_path_params("Doc:{tenant}/{id}", &p), "Doc:t1/x");
}

#[test]
fn leaves_unknown_placeholder_literal() {
    let p = params(&[]);
    assert_eq!(
        interpolate_path_params("Ledger:{id}", &p),
        "Ledger:{id}",
        "missing key should leave placeholder literal so Cedar parse fails loudly"
    );
}

#[test]
fn handles_no_placeholders() {
    let p = params(&[]);
    assert_eq!(interpolate_path_params("Platform", &p), "Platform");
}

#[test]
fn handles_unmatched_open_brace() {
    let p = params(&[]);
    assert_eq!(
        interpolate_path_params("Bad:{unterm", &p),
        "Bad:{unterm",
        "unmatched '{{' preserved literally"
    );
}
