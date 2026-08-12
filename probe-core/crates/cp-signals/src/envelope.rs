//! The envelope, its header, and the subject/window/device value types.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Serialize, Serializer};
use uuid::Uuid;

use crate::detail::Observation;

/// UTC, `Z`-suffixed, millisecond precision. Offsets are not accepted by the schema: evidence
/// timelines get compared across collectors in different timezones and offset arithmetic is where
/// that goes wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp(pub DateTime<Utc>);

impl Timestamp {
    pub fn now() -> Self {
        Self(Utc::now())
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_rfc3339_opts(SecondsFormat::Millis, true))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    SignalSample,
    SessionEvent,
}

/// Snapshot vs delta. Getting this wrong is unrecoverable in the other direction — a consumer that
/// reads a delta stream as snapshots silently interprets "absent" as "gone", so a consumer without
/// delta support must **reject the session** rather than degrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Emission {
    Snapshot,
    Delta,
}

// ---------------------------------------------------------------------------------------------
// Subject
// ---------------------------------------------------------------------------------------------

/// Whether the process image path was readable, and if so what it was.
///
/// Modelled as one value rather than a `path: Option<String>` beside a `path_state: enum`, because
/// the two can disagree and the schema spends an `if`/`then` block forbidding it. Here they cannot.
///
/// The distinction between [`AccessDenied`](Self::AccessDenied) and [`Exited`](Self::Exited) is
/// load-bearing: the first is a permanent capability limit (a protected process — S2 can *never*
/// hash it), the second is a one-cycle race. Collapsing them into `null` loses the difference the
/// whole S2 coverage story turns on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImagePath {
    /// `OpenProcess` + `QueryFullProcessImageName` succeeded.
    Readable(String),
    /// `OpenProcess` returned ERROR_ACCESS_DENIED. Expect this for every session-0 service when
    /// running non-elevated — on a real machine that was 180 of 324 processes.
    AccessDenied,
    /// The subject legitimately has no image path.
    NotApplicable,
    /// The process died between enumeration and resolution.
    Exited,
    Unknown,
}

impl ImagePath {
    fn wire(&self) -> (Option<&str>, &'static str) {
        match self {
            Self::Readable(p) => (Some(p.as_str()), "readable"),
            Self::AccessDenied => (None, "access_denied"),
            Self::NotApplicable => (None, "not_applicable"),
            Self::Exited => (None, "exited"),
            Self::Unknown => (None, "unknown"),
        }
    }

    pub fn is_readable(&self) -> bool {
        matches!(self, Self::Readable(_))
    }
}

/// Authenticode result. The variants carrying a hash are only constructible from a readable image
/// (see [`Subject::with_signature`]), so a producer cannot invent a hash for a file it could not
/// open — which is exactly what the schema's `if`/`then` rules forbid at the far end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// S2 has not run for this subject yet. The default: hashing is lazy and bounded.
    NotChecked,
    /// S2 cannot run — no readable image.
    Unavailable,
    Unsigned { sha256: String },
    Valid { signer: String, sha256: String },
    Invalid { signer: Option<String>, sha256: String },
}

impl Signature {
    fn wire(&self) -> (Option<&str>, &'static str, Option<&str>) {
        match self {
            Self::NotChecked => (None, "not_checked", None),
            Self::Unavailable => (None, "unavailable", None),
            Self::Unsigned { sha256 } => (None, "unsigned", Some(sha256)),
            Self::Valid { signer, sha256 } => (Some(signer), "valid", Some(sha256)),
            Self::Invalid { signer, sha256 } => {
                (signer.as_deref(), "invalid", Some(sha256))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub pid: u32,
    pub name: Option<String>,
    pub path: ImagePath,
    pub signature: Signature,
    pub start_ts: Option<Timestamp>,
    pub has_window: Option<bool>,
    pub parent_pid: Option<u32>,
    pub elevated: Option<bool>,
}

impl Subject {
    pub fn new(pid: u32, name: Option<String>, path: ImagePath) -> Self {
        let signature = if path.is_readable() {
            Signature::NotChecked
        } else {
            // No readable image, so S2 can never run for this subject. Encoded at construction so
            // it cannot be forgotten at emission.
            Signature::Unavailable
        };
        Self {
            pid,
            name,
            path,
            signature,
            start_ts: None,
            has_window: None,
            parent_pid: None,
            elevated: None,
        }
    }

    /// Attach an S2 result. Rejected — silently, by clamping to [`Signature::Unavailable`] — if the
    /// image was not readable, because a hash of an unreadable file did not come from that file.
    pub fn with_signature(mut self, sig: Signature) -> Self {
        self.signature = if self.path.is_readable() {
            sig
        } else {
            Signature::Unavailable
        };
        self
    }

    pub fn with_has_window(mut self, has_window: bool) -> Self {
        self.has_window = Some(has_window);
        self
    }

    pub fn with_start_ts(mut self, ts: Timestamp) -> Self {
        self.start_ts = Some(ts);
        self
    }
}

impl Serialize for Subject {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let (path, path_state) = self.path.wire();
        let (signer, sig_state, sha256) = self.signature.wire();

        let mut m = s.serialize_map(None)?;
        m.serialize_entry("pid", &self.pid)?;
        m.serialize_entry("name", &self.name)?; // required, nullable
        m.serialize_entry("path", &path)?; // required, nullable
        m.serialize_entry("path_state", path_state)?;
        m.serialize_entry("signature_state", sig_state)?;
        m.serialize_entry("signer", &signer)?;
        m.serialize_entry("sha256", &sha256)?;
        if let Some(ts) = &self.start_ts {
            m.serialize_entry("start_ts", ts)?;
        }
        if let Some(v) = self.has_window {
            m.serialize_entry("has_window", &v)?;
        }
        if let Some(v) = self.parent_pid {
            m.serialize_entry("parent_pid", &v)?;
        }
        if let Some(v) = self.elevated {
            m.serialize_entry("elevated", &v)?;
        }
        m.end()
    }
}

// ---------------------------------------------------------------------------------------------
// Window and device value types
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TitleState {
    /// Read successfully and non-empty.
    Captured,
    /// Read successfully; the window genuinely has no title.
    Empty,
    /// The OS refused. macOS Accessibility denied — reserved, unreachable on Windows.
    NotPermitted,
    /// Withheld by policy before leaving the machine.
    Redacted,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowRef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub title: Option<String>,
    pub title_state: TitleState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visible: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_screen: Option<bool>,
}

impl WindowRef {
    /// Titles only, never contents (NG3). An empty title is a fact, not a missing value.
    pub fn new(hwnd: isize, title: Option<String>, visible: bool) -> Self {
        let (title, title_state) = match title {
            Some(t) if !t.is_empty() => (Some(t), TitleState::Captured),
            Some(_) => (None, TitleState::Empty),
            None => (None, TitleState::Unavailable),
        };
        Self {
            id: Some(format!("hwnd:0x{hwnd:08x}")),
            title,
            title_state,
            visible: Some(visible),
            on_screen: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Physical,
    Virtual,
    Loopback,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AudioDevice {
    /// **Never the raw endpoint id.** The MMDevice string embeds a per-machine GUID that is a
    /// cross-session hardware fingerprint; this is `HMAC-SHA256(native_id, key = session_id)`
    /// truncated to 32 hex. A producer shipping a raw endpoint id fails schema validation.
    pub id: String,
    pub id_scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub kind: DeviceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

impl AudioDevice {
    pub fn session_scoped(id: String, name: Option<String>, kind: DeviceKind) -> Self {
        Self {
            id,
            id_scope: "session",
            name,
            kind,
            is_default: None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Signal
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub code: &'static str,
    /// The collector's **local** triage hint, never a verdict, never aggregated into a score
    /// (NG4 / EU AI Act Annex III). The server's rules engine is authoritative because the tool
    /// database updates centrally and a collector's copy is always stale.
    ///
    /// This collector ships no tool database, so it never emits tier 1.
    pub tier: u8,
    pub scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    pub detail: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_observed_ts: Option<Timestamp>,
}

impl From<Observation> for Signal {
    fn from(o: Observation) -> Self {
        o.into_signal()
    }
}

// ---------------------------------------------------------------------------------------------
// Sample metadata
// ---------------------------------------------------------------------------------------------

/// The coverage principle applied per sample: a scan whose window sweep threw is not a clean scan,
/// and `signals: []` only means "I looked and saw nothing" when `complete` is true.
#[derive(Debug, Clone, Serialize)]
pub struct SampleMeta {
    pub emission: Emission,
    pub complete: bool,
    /// Whole milliseconds. The only `type: number` in the contract — see `schemas/README.md` §6 on
    /// why producers should keep it integral: it is the sole float that would enter the evidence
    /// chain, and ES6 double formatting is the part of RFC 8785 implementations most often wrong.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_interval_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub unreadable_counts: std::collections::BTreeMap<String, u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub probe_errors: Vec<ProbeError>,
}

impl SampleMeta {
    pub fn snapshot(scan_duration_ms: u64, poll_interval_ms: u32) -> Self {
        Self {
            emission: Emission::Snapshot,
            complete: true,
            scan_duration_ms: Some(scan_duration_ms),
            poll_interval_ms: Some(poll_interval_ms),
            truncated: None,
            unreadable_counts: Default::default(),
            probe_errors: Vec::new(),
        }
    }

    /// Record a probe failure. This is the only place `complete` becomes false — a partial scan
    /// must never present as a clean one.
    pub fn record_error(
        &mut self,
        code: &'static str,
        kind: ProbeErrorKind,
        message: impl Into<String>,
    ) {
        self.complete = false;
        self.probe_errors.push(ProbeError {
            code,
            kind,
            platform_status: None,
            message: Some(message.into()),
        });
    }

    pub fn count_unreadable(&mut self, key: &str, n: u32) {
        if n > 0 {
            *self.unreadable_counts.entry(key.to_string()).or_insert(0) += n;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeErrorKind {
    PermissionDenied,
    ApiFailure,
    Timeout,
    NotSupported,
    Internal,
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeError {
    /// The signal code this probe serves, or `*` for a cross-cutting failure.
    pub code: &'static str,
    pub kind: ProbeErrorKind,
    /// Raw HRESULT / errno, diagnostic only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_status: Option<String>,
    /// Human-readable and non-authoritative. **Must not contain a file path, a window title, or any
    /// other candidate data** — a diagnostic string is not an exemption from NG3, and these travel
    /// the same wire as everything else.
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Session events
// ---------------------------------------------------------------------------------------------

/// Lifecycle events share the connection and the `seq` counter with samples, but are a distinct
/// message type carrying **no tier**. Giving "candidate declined monitoring" a risk tier is exactly
/// the verdict this product refuses to render.
#[derive(Debug, Clone, Serialize)]
pub struct SessionEvent {
    pub code: &'static str,
    pub initiator: &'static str,
    /// Explicit rather than derived from `code`, so an older pipeline receiving a *future* terminal
    /// event still closes the session instead of waiting on a heartbeat that never comes.
    pub terminal: bool,
    pub occurred_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl SessionEvent {
    pub fn consent_granted() -> Self {
        Self::candidate("consent_granted", false)
    }

    /// A supported outcome, not an error. The panel shows "candidate declined monitoring" and the
    /// interview proceeds; what that means is the customer's decision.
    pub fn consent_declined() -> Self {
        Self::candidate("consent_declined", true)
    }

    /// Ending the session cleanly and saying so is correct behaviour. "Quit at minute 14" is
    /// information, not a failure.
    pub fn candidate_quit() -> Self {
        Self::candidate("candidate_quit", true)
    }

    fn candidate(code: &'static str, terminal: bool) -> Self {
        Self {
            code,
            initiator: "candidate",
            terminal,
            occurred_at: Timestamp::now(),
            message: None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Envelope {
    pub schema_version: &'static str,
    #[serde(rename = "type")]
    pub message_type: MessageType,
    pub collector_id: &'static str,
    /// One continuous run of one collector process. `seq` is monotonic within *this*, not within
    /// the session — the enterprise tier runs two collectors under one `session_id`, and crash
    /// recovery legitimately restarts `seq` at 1.
    pub collector_instance_id: Uuid,
    pub session_id: Uuid,
    pub seq: u64,
    pub ts: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signals: Option<Vec<Signal>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_meta: Option<SampleMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<SessionEvent>,
}

impl Envelope {
    pub fn sample(
        session_id: Uuid,
        collector_instance_id: Uuid,
        seq: u64,
        signals: Vec<Signal>,
        sample_meta: SampleMeta,
    ) -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION,
            message_type: MessageType::SignalSample,
            collector_id: crate::COLLECTOR_ID,
            collector_instance_id,
            session_id,
            seq,
            ts: Timestamp::now(),
            uptime_ms: None,
            signals: Some(signals),
            sample_meta: Some(sample_meta),
            event: None,
        }
    }

    pub fn event(
        session_id: Uuid,
        collector_instance_id: Uuid,
        seq: u64,
        event: SessionEvent,
    ) -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION,
            message_type: MessageType::SessionEvent,
            collector_id: crate::COLLECTOR_ID,
            collector_instance_id,
            session_id,
            seq,
            ts: Timestamp::now(),
            uptime_ms: None,
            signals: None,
            sample_meta: None,
            event: Some(event),
        }
    }
}
