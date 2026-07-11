//! Bounded edge inputs, durable local admission and HTTP forwarding.

pub mod config;
pub mod contracts;
mod dns;
pub mod http;
pub mod input;
pub mod runtime;
pub mod spool;
pub mod tls;
mod worker;
