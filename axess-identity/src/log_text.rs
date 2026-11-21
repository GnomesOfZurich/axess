//! Text from a remote party or a request, made safe for a log line or an
//! error message.
//!
//! The one predicate of the workspace for what such text must not carry
//! raw: [`escapes`] names the control characters, the line and paragraph
//! separators, the bidirectional controls, the zero-width characters, the
//! byte order mark and the Hangul fillers, and [`log_safe`] writes each as
//! its escape and bounds the result. Every axess crate that puts outside
//! text into a log line or an error uses these two, so the classes are
//! decided in one place; the same classes are what an identifier may not
//! hold.

use std::ops::RangeInclusive;

/// Marks a cut made by [`log_safe`].
const CUT: &str = "...";

/// The Unicode line and paragraph separators, which end a line as a line
/// break does.
const LINE_SEPARATORS: RangeInclusive<char> = '\u{2028}'..='\u{2029}';

/// The bidirectional formatting characters: the Arabic letter mark, the
/// left-to-right and right-to-left marks, the embeddings and overrides and
/// the isolates. Each reorders the text after it as a terminal or a log
/// viewer shows it, so a value can make a line read otherwise than it is.
const BIDI_CONTROLS: [RangeInclusive<char>; 4] = [
    '\u{061C}'..='\u{061C}',
    '\u{200E}'..='\u{200F}',
    '\u{202A}'..='\u{202E}',
    '\u{2066}'..='\u{2069}',
];

/// The zero-width space, non-joiner and joiner, and the word joiner: shown
/// as nothing, they split or join what an operator reads, or searches for.
const ZERO_WIDTH: [RangeInclusive<char>; 2] = ['\u{200B}'..='\u{200D}', '\u{2060}'..='\u{2060}'];

/// The byte order mark, shown as nothing inside a line.
const BYTE_ORDER_MARK: RangeInclusive<char> = '\u{FEFF}'..='\u{FEFF}';

/// The Hangul choseong and jungseong fillers, the Hangul filler and the
/// halfwidth Hangul filler: letters that are drawn as blank space.
const BLANK_FILLERS: [RangeInclusive<char>; 3] = [
    '\u{115F}'..='\u{1160}',
    '\u{3164}'..='\u{3164}',
    '\u{FFA0}'..='\u{FFA0}',
];

/// Whether [`log_safe`] writes `c` as an escape: a control character, a
/// line or paragraph separator, a bidirectional formatting character, a
/// zero-width character, the byte order mark or a Hangul filler. Named by
/// these ranges and not by the compiler's Unicode tables, so the answer is
/// the same on every toolchain.
pub fn escapes(c: char) -> bool {
    c.is_control()
        || LINE_SEPARATORS.contains(&c)
        || BYTE_ORDER_MARK.contains(&c)
        || [BIDI_CONTROLS.as_slice(), &ZERO_WIDTH, &BLANK_FILLERS]
            .iter()
            .any(|class| class.iter().any(|range| range.contains(&c)))
}

/// Text from a remote party, made safe for an error message that is meant
/// for a log line: a control character (a line break, an escape sequence),
/// the Unicode line and paragraph separators, and the characters that
/// reorder a line or hide in it (bidirectional controls, zero-width
/// characters, the byte order mark, the Hangul fillers; see [`escapes`])
/// are written as escapes, so one response cannot forge a log line, make it
/// read otherwise than it is or rewrite the terminal, and the result is cut
/// to at most `max_bytes` bytes with `...` marking the cut. No more of
/// `text` is read than the cut can keep, so a long text costs no more than
/// a short one.
pub fn log_safe(text: &str, max_bytes: usize) -> String {
    // Escaping never shortens a character, so this prefix holds every
    // character the cut can keep, and runs past the cut whenever the text
    // does.
    let read = text.floor_char_boundary(max_bytes.saturating_add(4));
    let mut out = escaped(&text[..read]);
    if read == text.len() && out.len() <= max_bytes {
        return out;
    }
    let end = out.floor_char_boundary(max_bytes.saturating_sub(CUT.len()));
    out.truncate(end);
    out.push_str(CUT);
    out
}

/// `text` with every character [`escapes`] names written as an escape.
fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if escapes(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests;
