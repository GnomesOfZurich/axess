// `axess::testing` is gated on the `testing` feature; this program is built
// against `axess` without it and must not compile.
fn main() {
    let key = axess::testing::test_key;
}
