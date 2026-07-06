//! HTTP command-line client.
//!
//! Foundation executable: prints build identity and exits.
//! Runtime functionality is added in the implementation plan.

fn main() {
    println!(
        "{} {} (foundation; runtime not implemented)",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
}
