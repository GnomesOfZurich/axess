//! How the encryption key is held in memory.

use super::*;
use zeroize::Zeroizing;

/// The key is a `Zeroizing` buffer, which wipes itself when the last handle
/// to it is dropped. The key type has no `Drop` of its own to keep in step
/// with its fields: taking the buffer out of it compiles only while it has
/// none.
#[test]
fn the_encryption_key_is_held_in_a_zeroizing_buffer() {
    let EncryptionKey(held) = EncryptionKey::new(&crate::testing::test_key(7));
    let held: &Zeroizing<[u8; 32]> = &held;
    assert_eq!(**held, crate::testing::test_key(7));
}
