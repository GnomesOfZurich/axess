use std::sync::Once;
use tracing::Level;
use tracing_subscriber::{self, util::SubscriberInitExt};

static INIT: Once = Once::new();

pub(crate) fn init_tracing() {
    INIT.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::INFO)
            .finish();
        subscriber.init();
    });

    // INIT.call_once(|| {
    //     tracing_subscriber::fmt()
    //         .with_env_filter(
    //             tracing_subscriber::EnvFilter::try_from_default_env()
    //                 .unwrap_or_else(|_| "info".into()),
    //         )
    //         .init();
    // });
}
