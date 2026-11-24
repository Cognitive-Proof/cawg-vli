//! The vLEI trust chain for the testbed.
//!
//! [`tel`] implements the KERI 1.0 transaction event log that production
//! vLEI credentials use (`vcp` / `iss` / `rev`, no backers), which the Rust
//! KERI stack no longer provides.

pub mod chain;
pub mod credential;
pub mod schema;
pub mod tel;
