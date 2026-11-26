//! Windows and Linux provider transport and client identity in the Rust core
//! (docs/implementation/desktop-approval-spec.md, D-2 to D-5). Compiled on
//! the desktop targets (macOS only for the tests on the development host;
//! the macOS app keeps its native Swift transport). Phones never build it.
pub mod hello;
pub mod identity;
pub mod protect;
pub mod recovery;
pub mod rules;
pub mod service;
pub mod store;
pub mod transport;
