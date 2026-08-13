//! The coverage report — what this collector can and cannot see.
//!
//! This is the half of the contract that stops the other half from lying. A degraded collector and
//! a genuinely clean machine both produce an empty signal list; they render identically and mean
//! opposite things. "Nothing flagged" is only meaningful next to a coverage line.
//!
//! Two rules the types enforce:
//!
//! * The shorthand string form exists only for `full` and `not_applicable`. Every degraded state
//!   must carry a machine-readable [`CapabilityReason`], so "denied, and nobody said why" cannot be
//!   expressed. See [`Capability`]'s custom `Serialize`.
//! * [`CapabilityMethod::Probed`] means the collector *called the API and looked at the result*.
//!   Anything else must render as unverified in the panel. "Measured, not assumed" is only true if
//!   the wire can tell the difference — so [`Capability::probed`] is the only constructor that
//!   produces it.

use std::collections::BTreeMap;

use serde::{Serialize, Serializer};
use uuid::Uuid;

use crate::envelope::Timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// Probed and works completely.
    Full,
    /// Works, with a stated limit. Must carry a reason.
    Partial,
    /// The platform or the user refused. **Fixable by the candidate** — which is the whole reason
    /// it is distinct from [`Unsupported`](Self::Unsupported).
    Denied,
    /// This OS build or this collector has no such capability. Not fixable, and must never be
    /// rendered with a "grant permission" prompt.
    Unsupported,
    /// Meaningless for this collector — an in-guest collector and `host_machine`, for instance.
    NotApplicable,
    Unknown,
}

impl CapabilityState {
    /// Whether the shorthand string form is permitted. Only the two states that need no excuse.
    fn is_shorthandable(self) -> bool {
        matches!(self, Self::Full | Self::NotApplicable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityMethod {
    /// The collector actually called the API at startup and looked at the result. The only method
    /// the spec accepts for the core capabilities.
    Probed,
    /// Asserted from build configuration or platform version.
    Declared,
    /// Derived from another probe's outcome.
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityReason {
    PermissionNotGranted,
    PermissionRevoked,
    PermissionNotRequested,
    AccessDenied,
    ApiUnavailable,
    OsVersionTooOld,
    EntitlementMissing,
    NotImplemented,
    CollectorScope,
    PolicyDisabled,
    ProbeFailed,
    ProbeTimeout,
    DegradedPolling,
    HardwareAbsent,
    NotProbedYet,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageReason {
    Handshake,
    PermissionChanged,
    DeviceChanged,
    ProbeFailure,
    ProbeRecovered,
    PeriodicRecheck,
    CollectorUpgraded,
    Requested,
    Other,
}

/// Capability keys. Open vocabulary — this enum exists so two independent implementations of the
/// contract choose the same names, not to constrain them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityKey {
    S1Processes,
    S2Signature,
    S3MicOwner,
    S5CaptureExcluded,
    S6WindowTitles,
    /// Gates S2 rather than S1: an image you cannot read is an image you cannot hash. Its own key
    /// because that distinction decides whether tier 1 can ever fire.
    ProcessPaths,
    /// `not_applicable` for a host agent — it *is* the host. The in-guest collector reports this
    /// as its blind spot, which is why A and C pair.
    HostMachine,
    RealtimeEvents,
}

impl CapabilityKey {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::S1Processes => "S1_processes",
            Self::S2Signature => "S2_signature",
            Self::S3MicOwner => "S3_mic_owner",
            Self::S5CaptureExcluded => "S5_capture_excluded",
            Self::S6WindowTitles => "S6_window_titles",
            Self::ProcessPaths => "process_paths",
            Self::HostMachine => "host_machine",
            Self::RealtimeEvents => "realtime_events",
        }
    }

    /// Which signal codes this capability gates, so a consumer need not parse the key name. Parsing
    /// `S6_window_titles` into `S6` by string prefix works by luck, and `process_paths` and
    /// `host_machine` have no code at all.
    fn signals(self) -> &'static [&'static str] {
        match self {
            Self::S1Processes => &["S1"],
            Self::S2Signature => &["S2"],
            Self::S3MicOwner => &["S3"],
            Self::S5CaptureExcluded => &["S5"],
            Self::S6WindowTitles => &["S6"],
            Self::ProcessPaths => &["S2"],
            Self::HostMachine | Self::RealtimeEvents => &[],
        }
    }
}

#[derive(Debug, Clone)]
pub struct Capability {
    pub key: CapabilityKey,
    pub state: CapabilityState,
    pub method: CapabilityMethod,
    pub reason: Option<CapabilityReason>,
    pub detail: Option<String>,
    /// The Win32/CoreAudio entry point actually called, so a coverage answer can be audited against
    /// the code that produced it.
    pub platform_api: Option<&'static str>,
    pub checked_at: Option<Timestamp>,
    /// Quantified limits — e.g. `{"processes_total": 324, "paths_unreadable": 180}`. This is where
    /// the real numbers go rather than into prose.
    pub limits: BTreeMap<String, u64>,
}

impl Capability {
    /// The collector called the API and it worked completely.
    pub fn probed(key: CapabilityKey, platform_api: &'static str) -> Self {
        Self {
            key,
            state: CapabilityState::Full,
            method: CapabilityMethod::Probed,
            reason: None,
            detail: None,
            platform_api: Some(platform_api),
            checked_at: Some(Timestamp::now()),
            limits: BTreeMap::new(),
        }
    }

    /// The collector called the API and it did not work, or worked only partly. A reason is
    /// mandatory at the type level, because it is mandatory on the wire.
    pub fn degraded(
        key: CapabilityKey,
        state: CapabilityState,
        reason: CapabilityReason,
        platform_api: &'static str,
    ) -> Self {
        debug_assert!(
            !matches!(state, CapabilityState::Full),
            "degraded() with state=Full — use probed()"
        );
        Self {
            key,
            state,
            method: CapabilityMethod::Probed,
            reason: Some(reason),
            detail: None,
            platform_api: Some(platform_api),
            checked_at: Some(Timestamp::now()),
            limits: BTreeMap::new(),
        }
    }

    /// Meaningless for this collector. A host agent *is* the host machine, so it cannot observe one.
    pub fn not_applicable(key: CapabilityKey) -> Self {
        Self {
            key,
            state: CapabilityState::NotApplicable,
            method: CapabilityMethod::Declared,
            reason: None,
            detail: None,
            platform_api: None,
            checked_at: None,
            limits: BTreeMap::new(),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_limit(mut self, name: &str, value: u64) -> Self {
        self.limits.insert(name.to_string(), value);
        self
    }

    /// True when the report may use the bare-string form: a good state, nothing to explain, and no
    /// quantified limits worth carrying.
    fn shorthandable(&self) -> bool {
        self.state.is_shorthandable()
            && self.reason.is_none()
            && self.detail.is_none()
            && self.limits.is_empty()
            && self.method != CapabilityMethod::Probed
    }
}

impl Serialize for Capability {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        if self.shorthandable() {
            return match self.state {
                CapabilityState::Full => s.serialize_str("full"),
                _ => s.serialize_str("not_applicable"),
            };
        }

        let mut m = s.serialize_map(None)?;
        m.serialize_entry("state", &self.state)?;
        m.serialize_entry("method", &self.method)?;
        if let Some(r) = &self.reason {
            m.serialize_entry("reason", r)?;
        }
        if let Some(d) = &self.detail {
            m.serialize_entry("detail", d)?;
        }
        let signals = self.key.signals();
        if !signals.is_empty() {
            m.serialize_entry("signals", signals)?;
        }
        if let Some(api) = self.platform_api {
            m.serialize_entry("platform_api", api)?;
        }
        if let Some(t) = &self.checked_at {
            m.serialize_entry("checked_at", t)?;
        }
        if !self.limits.is_empty() {
            m.serialize_entry("limits", &self.limits)?;
        }
        m.end()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Platform {
    pub os: &'static str,
    pub os_version: Option<String>,
    pub os_build: Option<String>,
    pub arch: &'static str,
    pub locale: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageReport {
    pub schema_version: &'static str,
    #[serde(rename = "type")]
    pub message_type: &'static str,
    pub collector_id: &'static str,
    pub collector_instance_id: Uuid,
    pub session_id: Uuid,
    /// Shares the envelope's `seq` space so the relative order of a coverage change and the samples
    /// around it is provable.
    pub seq: u64,
    pub ts: Timestamp,
    pub reason: CoverageReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes_seq: Option<u64>,
    pub platform: Platform,
    pub capabilities: BTreeMap<String, Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl CoverageReport {
    pub fn new(
        session_id: Uuid,
        collector_instance_id: Uuid,
        seq: u64,
        reason: CoverageReason,
        platform: Platform,
        capabilities: Vec<Capability>,
    ) -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION,
            message_type: "coverage_report",
            collector_id: crate::COLLECTOR_ID,
            collector_instance_id,
            session_id,
            seq,
            ts: Timestamp::now(),
            reason,
            supersedes_seq: None,
            platform,
            capabilities: capabilities
                .into_iter()
                .map(|c| (c.key.as_str().to_string(), c))
                .collect(),
            notes: None,
        }
    }
}
