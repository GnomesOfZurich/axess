//! The escape and the bounded cut of text made safe for a log line.

use super::*;

#[test]
fn log_safe_reads_no_more_than_it_keeps_and_cuts_on_a_boundary() {
    let text = "é".repeat(100_000);
    let safe = log_safe(&text, 101);
    assert!(safe.len() <= 101, "{}", safe.len());
    assert!(safe.ends_with("..."));
    assert_eq!(log_safe("short", 101), "short");
    assert_eq!(log_safe("a\nb", 101), "a\\nb");
    // A text that fits only before it is escaped is cut after.
    let lines = "\n".repeat(60);
    let safe = log_safe(&lines, 100);
    assert!(safe.len() <= 100 && safe.ends_with("..."), "{safe}");
}

#[test]
fn a_text_of_exactly_the_bound_is_kept_whole() {
    let text = "a".repeat(100);
    assert_eq!(log_safe(&text, 100), text);
    let longer = "a".repeat(101);
    let safe = log_safe(&longer, 100);
    assert_eq!(safe.len(), 100);
    assert!(safe.ends_with("..."));
}

#[test]
fn a_bound_below_the_cut_mark_still_marks_the_cut() {
    assert_eq!(log_safe("abcdef", 0), "...");
}

/// A cut that falls inside a character moves back to the character's
/// start, so the result is text and stays within the bound.
#[test]
fn a_cut_inside_a_character_moves_back_to_its_start() {
    let text = "é".repeat(400);

    let safe = log_safe(&text, 100);

    assert_eq!(safe, format!("{}...", "é".repeat(48)));
}

/// Each character of `class` is written as its escape, and the text around
/// it is kept as it was.
fn assert_escaped(class: &[char]) {
    for &c in class {
        let safe = log_safe(&format!("a{c}b"), 512);
        assert_eq!(
            safe,
            format!("a{}b", c.escape_default()),
            "U+{:04X}",
            c as u32
        );
        assert!(!safe.contains(c), "U+{:04X} passed raw", c as u32);
        assert!(escapes(c), "U+{:04X}", c as u32);
    }
}

#[test]
fn the_bidirectional_controls_are_escaped() {
    assert_escaped(&[
        '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
        '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ]);
}

#[test]
fn the_zero_width_characters_are_escaped() {
    assert_escaped(&['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}']);
}

#[test]
fn the_byte_order_mark_is_escaped() {
    assert_escaped(&['\u{FEFF}']);
}

#[test]
fn the_hangul_fillers_are_escaped() {
    assert_escaped(&['\u{115F}', '\u{1160}', '\u{3164}', '\u{FFA0}']);
}

#[test]
fn the_line_separators_and_control_characters_are_escaped() {
    assert_escaped(&['\u{2028}', '\u{2029}', '\n', '\u{1b}', '\u{7f}', '\u{85}']);
}

/// Visible characters next to the classes pass raw: the predicate names
/// ranges, and a letter, a sign or a space is the text as it was.
#[test]
fn the_visible_neighbours_of_the_classes_pass_raw() {
    for c in [
        '\u{061B}', '\u{2010}', '\u{2027}', '\u{2030}', '\u{2070}', '\u{FEFE}', '\u{115E}',
        '\u{1161}', '\u{3163}', '\u{3165}', '\u{FF9F}', '\u{FFA1}', '\u{e9}', ' ', 'z',
    ] {
        assert!(!escapes(c), "U+{:04X}", c as u32);
        assert_eq!(
            log_safe(&c.to_string(), 512),
            c.to_string(),
            "U+{:04X}",
            c as u32
        );
    }
}
