//! E2E test entry point for rust_proxy.
//!
//! This file serves as the test binary entry point and imports
//! all E2E test modules.

mod common;

#[path = "e2e/basic_operations.rs"]
mod basic_operations;

#[path = "e2e/load_balancing.rs"]
mod load_balancing;

#[path = "e2e/daemon_path.rs"]
mod daemon_path;

#[path = "e2e/routing_and_failover.rs"]
mod routing_and_failover;
