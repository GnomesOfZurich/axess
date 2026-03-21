#![allow(dead_code)] // Available for future integration tests.

use std::sync::Once;
use tracing::Level;
use tracing_subscriber;

static INIT: Once = Once::new();

pub fn init_tracing() {
    INIT.call_once(|| {
        // Use tracing-subscriber for test output
        let _ = tracing_subscriber::fmt()
            .with_max_level(Level::INFO)
            .with_test_writer()
            .try_init();
    });
}
