//! The quickstart in both READMEs shows the sealed session store, never the
//! unsealed one, so an adopter who copies it manages a key from the start.

fn quickstart_store_line(readme: &str) -> &str {
    readme
        .lines()
        .find(|l| l.contains("SqliteSessionStore::") && l.contains("let session_store"))
        .expect("the quickstart builds a session store")
}

#[test]
fn both_readmes_quickstart_seals_the_session_store() {
    for (name, readme) in [
        ("README.md", include_str!("../../README.md")),
        ("axess/README.md", include_str!("../README.md")),
    ] {
        let line = quickstart_store_line(readme);
        assert!(
            line.contains("SqliteSessionStore::new(pool.clone(), SessionCrypto::new("),
            "{name}: {line}"
        );
        assert!(!readme.contains("::plaintext("), "{name} names plaintext");
    }
}
