//! Signal envelope v1 and coverage report v1.
//!
//! This crate is the Rust side of the frozen contract in `schemas/`. It makes no OS calls, so the
//! in-guest collector (Collector C) links exactly these types.
//!
//! # Why the types are shaped the way they are
//!
//! The schema enforces three rules with `if`/`then` blocks. Rust can enforce the same rules in the
//! type system, which is stronger: a violation stops being a validation failure at the far end of a
//! WebSocket and becomes a compile error.
//!
//! * A `path` exists **iff** the image was readable. See [`ImagePath`].
//! * A hash or signer cannot exist without a readable image. See [`Signature`].
//! * A signal's `code` cannot disagree with its `detail`. See [`Observation`].
//!
//! That last one is why you build a [`Signal`] from an [`Observation`] rather than filling in a
//! struct: `code`, `scope` and the collector-side `tier` are all derived from the variant.
//!
//! # The invariants that are not types
//!
//! Two rules live in the sampler, not here, and are restated because nothing in this crate can
//! catch a violation:
//!
//! * `seq` is contiguous per `collector_instance_id`. **A gap means dropped samples** and must
//!   surface as reduced coverage, never be smoothed over.
//! * Absence never means good news — a missing signal, an unknown enum member and a dropped sample
//!   all degrade to "unknown", never to "clean".

pub mod coverage;
pub mod detail;
pub mod envelope;

pub use coverage::{Capability, CapabilityKey, CapabilityState, CoverageReason, CoverageReport};
pub use detail::{DetailS1, DetailS2, DetailS3, DetailS5, DetailS6, Observation};
pub use envelope::{
    AudioDevice, DeviceKind, Emission, Envelope, ImagePath, MessageType, ProbeErrorKind, SampleMeta, SessionEvent,
    Signal, Signature, Subject, Timestamp, TitleState, WindowRef,
};

/// Wire version this build produces. A consumer accepts `1.x` and hard-rejects `2.x`.
pub const SCHEMA_VERSION: &str = "1.0";

/// `<family>/<semver>`. The family vocabulary is open; consumers must not infer capability from it.
pub const COLLECTOR_ID: &str = concat!("host-agent/", env!("CARGO_PKG_VERSION"));
