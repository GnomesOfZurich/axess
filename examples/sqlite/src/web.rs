pub mod app;
pub mod auth;
pub mod protected;

use axess::csrf::CsrfToken;

/// Minimal HTML escaper for form-value interpolation. Only handles the
/// characters that break out of attribute or text context: `&`, `<`, `>`,
/// `"`, `'`. Sufficient for the fixture's static templates; not a general
/// HTML sanitizer.
pub(crate) fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Render the hidden `_csrf` input the CSRF middleware expects on
/// state-changing form submissions.
pub(crate) fn csrf_hidden_input(csrf: &CsrfToken) -> String {
    format!(
        r#"<input type="hidden" name="_csrf" value="{}">"#,
        html_escape(csrf.as_str())
    )
}
