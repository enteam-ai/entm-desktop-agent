//! Per-signal `detail` payloads, and the [`Observation`] enum that binds each one to its code.
//!
//! The schema types `detail` by conditional dispatch (`if`/`then` per code) rather than `oneOf`, so
//! an unknown `S11` still validates and an older pipeline forwards it intact. On the producing side
//! the risk is the mirror image: emitting `code: "S5"` beside an S3-shaped detail. [`Observation`]
//! makes that unrepresentable — you construct the variant, and the code comes with it.

use serde::Serialize;

use crate::envelope::{AudioDevice, Signal, Subject, WindowRef};

#[derive(Debug, Clone, Serialize)]
pub struct DetailS1 {
    pub present: bool,
    pub has_window: bool,
    pub window_count: u32,
    pub session_kind: &'static str,
}

/// S3 — the microphone session owner. One of the two signals the product exists for.
///
/// `holds_microphone` stays a boolean *and* carries the device, rather than being overloaded into a
/// nullable device string. S7 (virtual audio devices) is "is the mic owner attached to a
/// non-physical endpoint" and needs something to correlate on; without `device` here, S7 forces a
/// schema v2 the day it ships.
#[derive(Debug, Clone, Serialize)]
pub struct DetailS3 {
    /// **Possession, not activity.** True when the process owns a non-expired capture session, per
    /// the contract. Whether it is capturing *right now* is [`Self::session_state`].
    ///
    /// The distinction is load-bearing: a VAD-gated or push-to-talk assistant goes inactive between
    /// utterances while still owning the stream and the endpoint. Deriving this from "active" would
    /// make the same observation flap between tiers at the poll rate, and flicker in the panel.
    pub holds_microphone: bool,
    /// Owns at least one top-level window — **including hidden ones**, which is what the schema
    /// defines this field to mean. Do not narrow it; use [`Self::has_visible_window`] instead.
    pub has_window: bool,
    /// The actual tell. An audio assistant renders nothing the candidate can see but must open the
    /// microphone to listen, so "holds the mic **and** shows no visible UI" is its signature.
    ///
    /// Separate from [`Self::has_window`] because `EnumWindows` returns hidden top-level windows and
    /// almost every tray application owns several — measured on one machine, 235 of 268 top-level
    /// windows were invisible, and 47 of 60 window-owning processes owned only invisible ones. A
    /// tray-resident assistant therefore looks windowed unless visibility is tested.
    pub has_visible_window: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<AudioDevice>,
    /// A session lingers `inactive` after a tool stops listening, so reporting "listening now" from
    /// mere presence would be a lie. R7 measures how long that lingering lasts.
    pub session_state: &'static str,
    /// The `S_OK` (0) / `S_FALSE` (1) inversion that HANDOFF §4 flags as the likely interop bug.
    /// If system sounds start appearing as findings, this is where to look.
    pub is_system_sounds: bool,
    /// True when the process already held the mic before the collector started. Detection lag is
    /// meaningless for these, and the panel must not imply it caught something starting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_existing: Option<bool>,
    /// `"capture"` or `"render"`. A loopback-capturing tool (recording the *interviewer*, e.g. via a
    /// desktop-SDK loopback client) opens its session on a **render** endpoint, not a capture one —
    /// this is the eRender pass, and the only way that tool's process becomes visible at all.
    ///
    /// WASAPI exposes no session property that tells a loopback capture apart from ordinary
    /// playback, so a `render` row is context, never a mic-possession claim. Always construct it
    /// through [`Self::render_session`], which is the only path that can produce one, rather than
    /// setting this field directly — that constructor is what keeps `holds_microphone` from ever
    /// being true here, which the schema's `allOf` also enforces at the wire.
    pub endpoint_flow: &'static str,
}

impl DetailS3 {
    /// The only constructor that can produce an `endpoint_flow: "render"` row, and it is the only
    /// one that forces `holds_microphone: false` — see the field's own doc for why that pairing is
    /// load-bearing rather than incidental.
    pub fn render_session(
        has_window: bool,
        has_visible_window: bool,
        device: Option<AudioDevice>,
        session_state: &'static str,
        is_system_sounds: bool,
        pre_existing: Option<bool>,
    ) -> Self {
        Self {
            holds_microphone: false,
            has_window,
            has_visible_window,
            device,
            session_state,
            is_system_sounds,
            pre_existing,
            endpoint_flow: "render",
        }
    }
}

/// S5 — a window flagged to hide from screen capture.
///
/// Structurally rename-proof: the exclusion flag *is* the feature the overlay tools sell, so they
/// cannot stop setting it. Cheap, too — `GetWindowDisplayAffinity` succeeded on every top-level
/// window on a real machine, non-elevated, with zero failures.
#[derive(Debug, Clone, Serialize)]
pub struct DetailS5 {
    pub capture_excluded: bool,
    pub affinity_raw: Option<u32>,
    /// `WDA_NONE` | `WDA_MONITOR` | `WDA_EXCLUDEFROMCAPTURE` | `WDA_UNKNOWN_<n>`. Only
    /// `WDA_EXCLUDEFROMCAPTURE` is the overlay signature; `WDA_MONITOR` is the older, weaker flag
    /// and must not be reported as the same thing.
    pub affinity_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<WindowRef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetailS6 {
    pub is_foreground: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<WindowRef>,
}

/// S2 — the verification result. The hash and signer strings themselves live on [`Subject`]
/// (every signal carries them, not just this one); this says how much that verification is worth.
///
/// This collector ships no tool database, so [`Observation::tier`] never reads this above 3 — the
/// central tool-database match against `subject.sha256` is the server's job. What this signal earns
/// is the join key: a rename defeats `subject.name`, and `sha256` is the half that survives it.
#[derive(Debug, Clone, Serialize)]
pub struct DetailS2 {
    pub verified: Option<bool>,
    pub chain_trusted: Option<bool>,
    pub revocation_checked: Option<bool>,
    pub timestamped: Option<bool>,
    pub hash_algorithm: &'static str,
    /// `authenticode` hashes the signed regions of the PE image (checksum field and certificate
    /// table excluded) via `CryptCATAdminCalcHashFromFileHandle2` — the same digest Authenticode
    /// itself signs, and what the tool database must be keyed on to ever match. `full_file` is the
    /// fallback when that call fails; the tool database MUST know which one it is comparing against,
    /// which is exactly why this field exists instead of assuming one.
    pub hash_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_status: Option<String>,
}

/// One observation, with its code and detail bound together.
///
/// `tier` is derived here and is deliberately limited to 2 and 3: a collector with no local tool
/// database **must not** emit tier 1, and this one ships none. Tier 1 is the server's call, because
/// the tool database updates centrally and any collector's copy is stale by construction.
#[derive(Debug, Clone)]
pub enum Observation {
    /// Tier 3 — context. Everything is running something; the process list is the join key the
    /// other signals resolve against, not a finding on its own.
    Process { subject: Subject, detail: DetailS1 },
    /// Tier 3, always — a collector with no local tool database cannot know "known-bad" from
    /// "known-good", so it never escalates its own hash match. The escalation to tier 1 happens
    /// server-side, against `subject.sha256`, which is why this signal exists at all.
    Signature { subject: Subject, detail: DetailS2 },
    /// Tier 2 when the mic holder shows no window; tier 3 otherwise.
    Microphone { subject: Subject, detail: DetailS3 },
    /// Tier 2 when actually capture-excluded; tier 3 for a non-default affinity that is not the
    /// exclusion flag.
    CaptureExcluded { subject: Subject, detail: DetailS5 },
    /// Tier 3 — never a finding, only context for what the candidate was doing.
    Foreground { subject: Subject, detail: DetailS6 },
}

impl Observation {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Process { .. } => "S1",
            Self::Signature { .. } => "S2",
            Self::Microphone { .. } => "S3",
            Self::CaptureExcluded { .. } => "S5",
            Self::Foreground { .. } => "S6",
        }
    }

    pub fn scope(&self) -> &'static str {
        match self {
            Self::Process { .. } | Self::Signature { .. } | Self::Microphone { .. } => "process",
            Self::CaptureExcluded { .. } | Self::Foreground { .. } => "window",
        }
    }

    pub fn tier(&self) -> u8 {
        match self {
            Self::Process { .. } | Self::Signature { .. } | Self::Foreground { .. } => 3,
            Self::Microphone { detail, .. } => {
                // Windows' own system-sounds session owns a capture session and has no window. It
                // is not a finding, and tiering it would put Windows itself in front of the
                // interviewer every session.
                if detail.is_system_sounds {
                    return 3;
                }
                // TODO(P1): this should key on `has_visible_window`, which is the real
                // discriminator — a tray-resident assistant owns only hidden windows and is
                // currently demoted to tier 3 here. Not flipped yet because an idle Teams client
                // also owns only hidden windows on the one machine measured so far, and a false
                // tier 2 against the meeting client is worse than the miss. Flip it once a live
                // call confirms Teams presents a visible window while in the call. Note the server
                // cannot correct this later: a consumer must not raise a tier above the one it
                // arrived with.
                if detail.holds_microphone && !detail.has_window {
                    2
                } else {
                    3
                }
            }
            Self::CaptureExcluded { detail, .. } => {
                if detail.capture_excluded {
                    2
                } else {
                    3
                }
            }
        }
    }

    /// Stable while the underlying thing is the same, different when it is not — so the panel
    /// renders one persistent row rather than a new row every second.
    pub fn observation_key(&self) -> Option<String> {
        match self {
            Self::Process { subject, .. } => Some(format!("S1:pid:{}", subject.pid)),
            Self::Signature { subject, .. } => Some(format!("S2:pid:{}", subject.pid)),
            Self::Microphone { subject, detail } => Some(match &detail.device {
                Some(d) => format!("S3:pid:{}:dev:{}", subject.pid, d.id),
                None => format!("S3:pid:{}", subject.pid),
            }),
            Self::CaptureExcluded { detail, .. } => detail
                .window
                .as_ref()
                .and_then(|w| w.id.clone())
                .map(|id| format!("S5:{id}")),
            Self::Foreground { .. } => Some("S6:foreground".to_string()),
        }
    }

    pub(crate) fn into_signal(self) -> Signal {
        let code = self.code();
        let scope = self.scope();
        let tier = self.tier();
        let observation_key = self.observation_key();

        let (subject, detail) = match self {
            Self::Process { subject, detail } => (subject, to_value(&detail)),
            Self::Signature { subject, detail } => (subject, to_value(&detail)),
            Self::Microphone { subject, detail } => (subject, to_value(&detail)),
            Self::CaptureExcluded { subject, detail } => (subject, to_value(&detail)),
            Self::Foreground { subject, detail } => (subject, to_value(&detail)),
        };

        Signal {
            code,
            tier,
            scope,
            subject: Some(subject),
            detail,
            observation_key,
            first_observed_ts: None,
        }
    }
}

fn to_value<T: Serialize>(t: &T) -> serde_json::Value {
    // Detail payloads are plain structs of scalars; serialisation cannot fail. An object is still
    // the only valid shape, so a bug here degrades to an empty object rather than a panic in a
    // probe running on someone else's laptop.
    serde_json::to_value(t).unwrap_or_else(|_| serde_json::Value::Object(Default::default()))
}
