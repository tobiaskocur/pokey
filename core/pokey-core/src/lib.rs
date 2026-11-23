//! Core of Pokey, a macOS EDR agent: signed rule bundles, the structural schema
//! language (compiler + fuel-limited interpreter) and the scan engine used by
//! the inspector.

pub mod bundle;
pub mod engine;
pub mod policy;
pub mod schema;

/// Engine version implemented by this build. Bundles declare `min_engine`;
/// a bundle with `min_engine > ENGINE_VERSION` is rejected.
pub const ENGINE_VERSION: u32 = 1;
