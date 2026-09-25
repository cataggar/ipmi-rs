//! ipmi-rs-core: a pure-rust, sans-IO IPMI library.
//!
//! This library provides data structures for the requests and responses
//! defined in the IPMI spec, and primitives for interacting with an IPMI connection.

pub mod app;

pub mod chassis;

pub mod connection;

/// Opt-in, identity-checked vendor-specific IPMI commands.
pub mod oem;

pub mod dcmi;

pub mod node_manager;

pub mod storage;

pub mod sensor_event;

pub mod transport;

pub mod hpm;

#[cfg(feature = "group-extensions")]
mod group_extension;

#[cfg(feature = "group-extensions")]
pub mod picmg;

#[cfg(feature = "group-extensions")]
pub mod vita;

#[cfg(test)]
mod tests;
