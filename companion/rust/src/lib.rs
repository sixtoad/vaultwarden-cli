pub mod api;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub mod desktop;
// The generator names a lint introduced after our Rust 1.88 MSRV.
#[allow(unknown_lints)]
mod frb_generated;
pub mod installation;
pub mod lifecycle;
pub mod provider;
