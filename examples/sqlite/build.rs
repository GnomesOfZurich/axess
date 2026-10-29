//! `sqlx::migrate!()` embeds the migration files at compile time, and cargo
//! does not know the macro reads them. Without this line an edited or removed
//! migration leaves a stale embedded copy in the build, so a test that should
//! notice the change keeps passing against the old schema.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
