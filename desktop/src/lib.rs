//! SyncMob core library (desktop module).
//!
//! The crate is deliberately split so that the GUI binary is a thin shell on
//! top of an audit-friendly core:
//!
//! * [`security`] — long term identity, at-rest key protection, trust store,
//!   fingerprints / short authentication strings.
//! * [`net`] — discovery, Noise handshake, framed encrypted transport.
//! * [`proto`] — wire message definitions shared with the Android module.
//! * [`engine`] — orchestration (peer table, sessions, transfers) exposing a
//!   command/event API to any front-end.
//!
//! Nothing in `security`, `net`, `proto` or `engine` depends on the GUI.

pub mod config;
pub mod engine;
pub mod net;

pub mod proto;
pub mod security;
pub mod util;

pub use engine::{Engine, EngineEvent};
