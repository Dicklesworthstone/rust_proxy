//! E2E test entry point for rust_proxy.
//!
//! This file serves as the test binary entry point and imports
//! all E2E test modules.

mod common;

#[path = "e2e/basic_operations.rs"]
mod basic_operations;

#[path = "e2e/load_balancing.rs"]
mod load_balancing;
