//! S3 — which process holds an active microphone capture session.
//!
//! The only signal that catches audio-only assistants. They render no window and set no capture
//! flag, but they cannot listen to the candidate without opening a capture session, and that
//! session names its owning pid.
//!
//! # The rule
//!
//! **Enumerate sessions. Never open a capture stream.** Enumeration is a read of the session list
//! and is silent. Opening a stream trips the Windows microphone consent prompt, breaks P1's exit
//! criterion, and would mean a transparency product had itself started listening to the candidate.
//! `tests/deny_capture_apis.rs` fails the build if any capture entry point appears in this crate.
//!
//! # The path
//!
//! ```text
//! CoCreateInstance(MMDeviceEnumerator)
//!   -> IMMDeviceEnumerator::EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE)
//!   -> IMMDevice::Activate::<IAudioSessionManager2>()
//!   -> IAudioSessionManager2::GetSessionEnumerator()
//!   -> IAudioSessionControl2::{GetState, GetProcessId, IsSystemSoundsSession}
//! ```
//!
//! Every active capture endpoint is walked, not just the default one: a candidate routing audio
//! through a second or virtual device would otherwise be invisible.
//!
//! # The eRender pass
//!
//! A loopback-capturing tool — recording the *interviewer*, e.g. the Recall.ai desktop SDK Cluely
//! ships — opens its session on a **render** (playback) endpoint via `AUDCLNT_STREAMFLAGS_LOOPBACK`,
//! not a capture endpoint. Without also walking `eRender`, that process holds no session on anything
//! this probe looks at and is invisible — not degraded, not tier 3, simply absent.
//!
//! This does **not** turn into a mic-owner detector. `IAudioSessionControl2` exposes no property
//! that tells a loopback-capturing session apart from an ordinary one playing music: both are just
//! "this pid owns a session on a render endpoint, state active." So a render-endpoint row is emitted
//! as context only — [`DetailS3::render_session`] is the only constructor that can produce one, and
//! it is the only one that forces `holds_microphone: false`. What eRender buys is visibility, not
//! classification: the process that was invisible now appears in front of the interviewer, who can
//! read the process name and decide for themselves. That is the whole product philosophy — expose,
//! do not verdict — applied to the one blind spot enumeration alone cannot resolve.
//!
//! # Three traps, all of which the C# spike paid for
//!
//! 1. **Vtable ordering.** Handled by using generated bindings — see this crate's `Cargo.toml`.
//! 2. **`IsSystemSoundsSession` is not a boolean.** It returns `S_OK` (0) for true and `S_FALSE`
//!    (1) for false. Both are *success* HRESULTs, so the generated `Result<()>` wrapper reports
//!    `Ok` for both and cannot distinguish them — the bug HANDOFF §4 predicted, wearing a new hat.
//!    [`is_system_sounds`] therefore reads the raw HRESULT through the vtable.
//! 3. **COM lifetime.** Objects are released when their RAII wrappers drop. At 1 Hz over a
//!    60-minute session that is ~3,600 iterations, and a leak here looks fine for thirty seconds.

use std::collections::HashMap;

use cp_signals::{AudioDevice, DetailS3, DeviceKind, ImagePath, Observation, Subject};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use windows::core::Interface;
use windows::Win32::Devices::FunctionDiscovery::PKEY_Device_FriendlyName;
use windows::Win32::Media::Audio::{
    eCapture, eRender, AudioSessionStateActive, AudioSessionStateExpired,
    AudioSessionStateInactive, IAudioSessionControl2, IAudioSessionManager2, IMMDevice,
    IMMDeviceEnumerator, MMDeviceEnumerator, DEVICE_STATE_ACTIVE,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_ALL, COINIT_MULTITHREADED, STGM_READ,
};

use crate::affinity::WindowSweep;
use crate::process::ProcessInfo;

thread_local! {
    static COM_READY: bool = init_com();
}

/// COM must be initialised per thread. `RPC_E_CHANGED_MODE` means someone already initialised this
/// thread with a different apartment model — not a failure for our purposes, since we only ever
/// read from in-proc objects.
fn init_com() -> bool {
    unsafe {
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        hr.is_ok() || hr.0 == RPC_E_CHANGED_MODE
    }
}

const RPC_E_CHANGED_MODE: i32 = -2147417850; // 0x80010106

/// One process holding one session on one device — capture or render. See the module doc's "eRender
/// pass" section for why render is here at all and why it never implies mic possession.
#[derive(Debug, Clone)]
pub struct MicHolder {
    pub pid: u32,
    pub device_native_id: String,
    pub device_name: Option<String>,
    pub state: SessionState,
    pub is_system_sounds: bool,
    pub flow: Flow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Capture,
    Render,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Inactive,
    Expired,
    Unknown,
}

impl SessionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Expired => "expired",
            Self::Unknown => "unknown",
        }
    }
}

/// Enumerate session owners across every active capture endpoint, and — see the module doc — every
/// active render endpoint too.
///
/// Returns an error only when the *whole* probe could not run. A single device that fails is
/// skipped and counted — a partial answer is still an answer, but the caller must mark the sample
/// incomplete so it cannot read as a clean machine.
pub fn enumerate() -> Result<(Vec<MicHolder>, u32), String> {
    if !COM_READY.with(|r| *r) {
        return Err("CoInitializeEx failed".to_string());
    }

    let mut holders = Vec::new();
    let mut failed_devices = 0u32;

    unsafe {
        let enumerator: IMMDeviceEnumerator =
            CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)
                .map_err(|e| format!("CoCreateInstance(MMDeviceEnumerator): {}", hr(&e)))?;

        for (data_flow, flow, _flow_name) in
            [(eCapture, Flow::Capture, "eCapture"), (eRender, Flow::Render, "eRender")]
        {
            // A flow-level failure (not a single device — the whole endpoint collection) is counted
            // the same way a single failed device is, rather than aborting the other flow with `?`.
            // A render-endpoint outage must not cost the capture-endpoint results already gathered:
            // a partial answer is still an answer, same rule this function documents for devices.
            let Ok(devices) = enumerator.EnumAudioEndpoints(data_flow, DEVICE_STATE_ACTIVE) else {
                failed_devices += 1;
                continue;
            };
            let Ok(count) = devices.GetCount() else {
                failed_devices += 1;
                continue;
            };

            for i in 0..count {
                match devices.Item(i) {
                    Ok(device) => {
                        if scan_device(&device, flow, &mut holders).is_err() {
                            failed_devices += 1;
                        }
                    }
                    Err(_) => failed_devices += 1,
                }
            }
        }
    }

    Ok((holders, failed_devices))
}

unsafe fn scan_device(device: &IMMDevice, flow: Flow, out: &mut Vec<MicHolder>) -> Result<(), String> {
    let native_id = device_id(device)?;
    let name = friendly_name(device);

    let manager: IAudioSessionManager2 = device
        .Activate(CLSCTX_ALL, None)
        .map_err(|e| format!("Activate(IAudioSessionManager2): {}", hr(&e)))?;

    let sessions = manager
        .GetSessionEnumerator()
        .map_err(|e| format!("GetSessionEnumerator: {}", hr(&e)))?;

    let count = sessions.GetCount().map_err(|e| format!("GetCount: {}", hr(&e)))?;

    for s in 0..count {
        let Ok(control) = sessions.GetSession(s) else {
            continue;
        };
        let Ok(control2) = control.cast::<IAudioSessionControl2>() else {
            continue;
        };

        let state = match control2.GetState() {
            Ok(st) if st == AudioSessionStateActive => SessionState::Active,
            Ok(st) if st == AudioSessionStateInactive => SessionState::Inactive,
            Ok(st) if st == AudioSessionStateExpired => SessionState::Expired,
            Ok(_) => SessionState::Unknown,
            Err(_) => SessionState::Unknown,
        };

        // Expired sessions are dead; reporting them as mic holders would be a lie. Inactive ones
        // are kept deliberately: a session lingers inactive after a tool stops listening, and that
        // interval is itself worth showing.
        if state == SessionState::Expired {
            continue;
        }

        let Ok(pid) = control2.GetProcessId() else {
            continue;
        };

        out.push(MicHolder {
            pid,
            device_native_id: native_id.clone(),
            device_name: name.clone(),
            state,
            is_system_sounds: is_system_sounds(&control2),
            flow,
        });
    }

    Ok(())
}

/// Read `IsSystemSoundsSession` as the tri-state HRESULT it actually is.
///
/// `S_OK` (0) means yes, `S_FALSE` (1) means no. Both are success codes, so the generated
/// `Result<()>` wrapper returns `Ok` for both and throws the answer away. Reading the raw HRESULT
/// through the vtable is the only way to get it — and getting it wrong makes Windows' own system
/// sounds appear as findings, which is exactly the symptom HANDOFF §4 says to watch for.
unsafe fn is_system_sounds(control2: &IAudioSessionControl2) -> bool {
    let vtable = Interface::vtable(control2);
    let hr = (vtable.IsSystemSoundsSession)(control2.as_raw());
    hr.0 == 0 // S_OK only
}

unsafe fn device_id(device: &IMMDevice) -> Result<String, String> {
    let pwstr = device
        .GetId()
        .map_err(|e| format!("IMMDevice::GetId: {}", hr(&e)))?;
    if pwstr.is_null() {
        return Err("IMMDevice::GetId returned null".to_string());
    }
    let s = pwstr.to_string().unwrap_or_default();
    CoTaskMemFree(Some(pwstr.0 as *const _));
    Ok(s)
}

unsafe fn friendly_name(device: &IMMDevice) -> Option<String> {
    let store = device.OpenPropertyStore(STGM_READ).ok()?;
    let value = store.GetValue(&PKEY_Device_FriendlyName).ok()?;
    let s = value.to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Session-scoped device identifier.
///
/// **Never the raw endpoint id.** The MMDevice string embeds a per-machine GUID that is a stable
/// cross-session hardware fingerprint; shipping it would turn a proctoring signal into a tracking
/// one, and the schema rejects it outright. `HMAC-SHA256(native_id, key = session_id)` truncated to
/// 32 hex is stable *within* an interview — enough to correlate two sessions on one device, which
/// is what S7 needs — and useless outside it.
fn scoped_device_id(native_id: &str, session_id: &uuid::Uuid) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(session_id.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(native_id.as_bytes());
    let bytes = mac.finalize().into_bytes();
    bytes[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Classify the endpoint. Deliberately conservative: `unknown` rather than a guess, because
/// "virtual audio device" is a tier-3 finding and an inference dressed as an observation is exactly
/// what the coverage model exists to prevent. Real classification is S7 and lands with it.
fn device_kind(_native_id: &str) -> DeviceKind {
    DeviceKind::Unknown
}

/// Build the S3 observations.
///
/// `windows` is passed in rather than re-swept so that `has_window` comes from the same cycle as
/// the microphone reading. That cross-reference is the whole signal: a mic holder with **no
/// window** is the audio-assistant signature, while a meeting client holds the mic and has one.
pub fn probe(
    windows_sweep: &WindowSweep,
    processes: &[ProcessInfo],
    session_id: &uuid::Uuid,
) -> Result<(Vec<Observation>, u32), String> {
    let (holders, failed_devices) = enumerate()?;

    let by_pid: HashMap<u32, &ProcessInfo> = processes.iter().map(|p| (p.pid, p)).collect();
    let mut out = Vec::with_capacity(holders.len());

    for h in holders {
        let has_window = windows_sweep.pids_with_windows.contains(&h.pid);
        let has_visible_window = windows_sweep.pids_with_visible_windows.contains(&h.pid);

        let subject = by_pid
            .get(&h.pid)
            .map(|p| p.to_subject())
            .unwrap_or_else(|| {
                // A session whose process we could not resolve. `access_denied` rather than
                // `exited`: the session is live, so the process exists — we simply could not open
                // it, which is the non-elevated case and a coverage fact, not an absence.
                Subject::new(h.pid, None, ImagePath::AccessDenied)
            })
            .with_has_window(has_window);

        let device = Some(AudioDevice::session_scoped(
            scoped_device_id(&h.device_native_id, session_id),
            h.device_name.clone(),
            device_kind(&h.device_native_id),
        ));

        let detail = match h.flow {
            Flow::Capture => DetailS3 {
                // Possession, per the contract — this process owns a non-expired capture session.
                // Expired sessions never reach here, so every emitted row owns one by construction.
                //
                // Deliberately NOT `state == Active`. A push-to-talk or VAD-gated assistant is
                // inactive between utterances while still owning the stream and the endpoint;
                // deriving possession from activity would drop it to tier 3 mid-sentence and make
                // the panel row flicker at the poll rate. Activity lives in `session_state`.
                holds_microphone: true,
                has_window,
                has_visible_window,
                device,
                session_state: h.state.as_str(),
                is_system_sounds: h.is_system_sounds,
                pre_existing: None,
                endpoint_flow: "capture",
            },
            // See the module doc's "eRender pass" section: a render-endpoint session is context,
            // never a mic-possession claim, and this is the only constructor that can produce one.
            Flow::Render => DetailS3::render_session(
                has_window,
                has_visible_window,
                device,
                h.state.as_str(),
                h.is_system_sounds,
                None,
            ),
        };

        out.push(Observation::Microphone { subject, detail });
    }

    Ok((out, failed_devices))
}

/// Capability probe: can this collector enumerate capture and render sessions at all? Returns
/// `(capture_sessions, render_sessions)` separately so the coverage report can state each honestly
/// — a render count of zero should read as "nothing was playing", not as "the eRender pass didn't
/// run".
///
/// Runs the real path rather than asserting from the platform — "measured, not assumed" is only
/// true if something actually called the API and looked at the result.
pub fn probe_capability() -> Result<(u32, u32), String> {
    enumerate().map(|(holders, _)| {
        let capture = holders.iter().filter(|h| h.flow == Flow::Capture).count() as u32;
        let render = holders.iter().filter(|h| h.flow == Flow::Render).count() as u32;
        (capture, render)
    })
}

fn hr(e: &windows::core::Error) -> String {
    format!("0x{:08X}", e.code().0)
}
