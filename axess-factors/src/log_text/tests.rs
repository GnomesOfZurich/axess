//! The re-export is the identity crate's predicate, not a copy of it.

use super::*;

/// Every character gets the same answer from the re-export as from the
/// identity crate, and text the same escape and cut: a copy that drifted
/// from the one predicate fails here.
#[test]
fn the_re_export_answers_as_the_identity_crate_does() {
    for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
        assert_eq!(
            escapes(c),
            axess_identity::log_text::escapes(c),
            "U+{:04X}",
            u32::from(c)
        );
    }
    let text = format!(
        "a\nb\u{202E}c\u{200B}d\u{FEFF}e\u{3164}f{}",
        "é".repeat(100)
    );
    assert_eq!(
        log_safe(&text, 64),
        axess_identity::log_text::log_safe(&text, 64)
    );
}
