//! The capability prober — "measured, not assumed".
//!
//! Every capability here is answered by **actually calling the API once and looking at the result**,
//! never by inferring from the platform or the build. That is why every entry below is constructed
//! with [`Capability::probed`] or [`Capability::degraded`], both of which stamp
//! `method: "probed"`; anything asserted from configuration would be `declared`, and the panel is
//! required to render that as unverified.
//!
//! This is the half of the contract that stops the other half from lying. An empty signal list from
//! a blind collector and an empty signal list from a clean machine are the same bytes. Only this
//! report tells them apart.

use cp_signals::coverage::{
    Capability, CapabilityKey, CapabilityReason, CapabilityState, CoverageReason, CoverageReport,
    Platform,
};
use uuid::Uuid;

use crate::{affinity, audio, platform as platform_probe, process, signature};

pub fn platform() -> Platform {
    let (os_version, os_build) = match platform_probe::version() {
        Some((version, build)) => (Some(version), Some(build)),
        None => (None, None),
    };
    Platform {
        os: "windows",
        os_version,
        os_build,
        arch: match std::env::consts::ARCH {
            "x86_64" => "x86_64",
            "aarch64" => "arm64",
            _ => "other",
        },
        locale: None,
    }
}

/// Probe every capability once. Called at handshake and again on any permission or device change.
pub fn probe_all() -> Vec<Capability> {
    let mut out = Vec::new();

    // --- S1 + process paths -------------------------------------------------------------------
    // One call answers two capabilities, and they are deliberately separate keys: enumerating
    // processes and being able to read their images are different powers, and the second is what
    // gates S2. Parsing `S2_signature` out of `S1_processes` by string prefix would work by luck.
    match process::snapshot() {
        Ok(procs) => {
            let total = procs.len() as u64;
            let unreadable = procs.iter().filter(|p| !p.path.is_readable()).count() as u64;

            out.push(
                Capability::probed(CapabilityKey::S1Processes, "CreateToolhelp32Snapshot")
                    .with_limit("processes_total", total),
            );

            if unreadable == 0 {
                out.push(Capability::probed(
                    CapabilityKey::ProcessPaths,
                    "QueryFullProcessImageNameW",
                ));
            } else {
                // Expected, not exceptional: running non-elevated, every session-0 service refuses.
                // Measured at 180 of 324 on a real machine. The panel needs permanent copy for this
                // rather than an exception state, which is what the numbers below are for.
                out.push(
                    Capability::degraded(
                        CapabilityKey::ProcessPaths,
                        CapabilityState::Partial,
                        CapabilityReason::AccessDenied,
                        "QueryFullProcessImageNameW",
                    )
                    .with_detail(
                        "Non-elevated: session-0 service images are unreadable. An image that \
                         cannot be read cannot be hashed, so S2 coverage is capped at the readable \
                         set and tier 1 cannot fire for the remainder.",
                    )
                    .with_limit("processes_total", total)
                    .with_limit("paths_unreadable", unreadable),
                );
            }
        }
        Err(e) => {
            out.push(
                Capability::degraded(
                    CapabilityKey::S1Processes,
                    CapabilityState::Denied,
                    CapabilityReason::ProbeFailed,
                    "CreateToolhelp32Snapshot",
                )
                .with_detail(e.clone()),
            );
            out.push(Capability::degraded(
                CapabilityKey::ProcessPaths,
                CapabilityState::Unknown,
                CapabilityReason::ProbeFailed,
                "QueryFullProcessImageNameW",
            ));
        }
    }

    // --- S2 ------------------------------------------------------------------------------------
    // Measured against the collector's own image, which is guaranteed readable, so this answers
    // "can the verification APIs be called at all" independent of any other process's path — that
    // ceiling is `process_paths`, reported above, not this one.
    match std::env::current_exe() {
        Ok(exe) => {
            let (sig, detail) = signature::cached(&exe.to_string_lossy());
            if detail.hash_source != "none" {
                out.push(
                    Capability::degraded(
                        CapabilityKey::S2Signature,
                        CapabilityState::Partial,
                        CapabilityReason::CollectorScope,
                        "WinVerifyTrust + CryptCATAdminCalcHashFromFileHandle2",
                    )
                    .with_detail(
                        "Hash and signer are only produced for images process_paths can read. A \
                         protected or cross-bitness process is capped there, not here. Revocation \
                         is never checked, to keep verification off the network.",
                    ),
                );
            } else {
                out.push(
                    Capability::degraded(
                        CapabilityKey::S2Signature,
                        CapabilityState::Denied,
                        CapabilityReason::ProbeFailed,
                        "WinVerifyTrust + CryptCATAdminCalcHashFromFileHandle2",
                    )
                    .with_detail(format!("Could not hash the collector's own image: {sig:?}")),
                );
            }
        }
        Err(e) => out.push(
            Capability::degraded(
                CapabilityKey::S2Signature,
                CapabilityState::Unknown,
                CapabilityReason::ProbeFailed,
                "current_exe",
            )
            .with_detail(e.to_string()),
        ),
    }

    // --- S3 ------------------------------------------------------------------------------------
    // Unsupported rather than denied: `denied` means the candidate could fix it by granting
    // something, and the panel is required to offer remediation for that. Nobody can grant their
    // way out of an unwritten probe.
    // Never `full`, and this is not pessimism. eRender closed the biggest gap — a loopback session
    // on a render endpoint (AUDCLNT_STREAMFLAGS_LOOPBACK), the Recall.ai desktop-SDK path Cluely
    // ships, now appears at all, as context (endpoint_flow: render, holds_microphone forced false —
    // WASAPI exposes no property that tells a loopback capture apart from ordinary playback). What
    // still does not appear:
    //
    //   * process-loopback activation (AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK);
    //   * exclusive-mode streams and kernel-streaming clients.
    //
    // Reporting `full` here would mean an interviewer reads "microphone ✓" beside an empty finding
    // list while a class of tool is structurally invisible. An unstated blind spot is a coverage
    // lie; a stated one is a product fact.
    match audio::probe_capability() {
        Ok((capture_sessions, render_sessions)) => out.push(
            Capability::degraded(
                CapabilityKey::S3MicOwner,
                CapabilityState::Partial,
                CapabilityReason::CollectorScope,
                "IAudioSessionManager2::GetSessionEnumerator",
            )
            .with_detail(
                "Capture and render endpoints are both enumerated. A render-endpoint session is \
                 shown as context only, never as a microphone finding — WASAPI has no property \
                 that distinguishes a loopback capture from ordinary playback. \
                 Process-loopback activation, exclusive-mode streams and kernel-streaming clients \
                 are not enumerated and will not appear at all.",
            )
            .with_limit("capture_sessions_visible", capture_sessions as u64)
            .with_limit("render_sessions_visible", render_sessions as u64),
        ),
        Err(e) => out.push(
            Capability::degraded(
                CapabilityKey::S3MicOwner,
                CapabilityState::Denied,
                CapabilityReason::ProbeFailed,
                "IAudioSessionManager2::GetSessionEnumerator",
            )
            .with_detail(e),
        ),
    }

    // --- S5 ------------------------------------------------------------------------------------
    match affinity::sweep() {
        Ok(sweep) => {
            let cap = Capability::probed(
                CapabilityKey::S5CaptureExcluded,
                "GetWindowDisplayAffinity",
            )
            .with_limit("windows_total", sweep.total as u64);

            if sweep.unreadable == 0 {
                out.push(cap);
            } else {
                // Some windows refuse the read. Not evidence of cleanliness — a coverage number.
                out.push(
                    Capability::degraded(
                        CapabilityKey::S5CaptureExcluded,
                        CapabilityState::Partial,
                        CapabilityReason::AccessDenied,
                        "GetWindowDisplayAffinity",
                    )
                    .with_detail("Display affinity unreadable for some top-level windows.")
                    .with_limit("windows_total", sweep.total as u64)
                    .with_limit("windows_unreadable", sweep.unreadable as u64),
                );
            }
        }
        Err(e) => out.push(
            Capability::degraded(
                CapabilityKey::S5CaptureExcluded,
                CapabilityState::Denied,
                CapabilityReason::ProbeFailed,
                "EnumWindows",
            )
            .with_detail(e),
        ),
    }

    // --- S6 ------------------------------------------------------------------------------------
    // Windows needs no permission for window titles. On macOS this is the capability most often
    // denied, which is exactly why it is a separate key rather than folded into S1.
    out.push(Capability::probed(
        CapabilityKey::S6WindowTitles,
        "GetWindowTextW",
    ));

    // --- scope ---------------------------------------------------------------------------------
    // A host agent *is* the host machine, so it cannot observe one from outside. Collector C
    // reports the mirror image, and that asymmetry is precisely why A and C pair.
    out.push(Capability::not_applicable(CapabilityKey::HostMachine));

    // Polling is the P1 shipping decision. ETW is available on Windows immediately, but a sample
    // cadence that can miss a short-lived process is a coverage fact, not an implementation detail.
    out.push(
        Capability::degraded(
            CapabilityKey::RealtimeEvents,
            CapabilityState::Partial,
            CapabilityReason::DegradedPolling,
            "polling",
        )
        .with_detail(
            "Polling only. A process that starts and exits between samples is not observed.",
        ),
    );

    out
}

pub fn report(session_id: Uuid, collector_instance_id: Uuid, seq: u64) -> CoverageReport {
    CoverageReport::new(
        session_id,
        collector_instance_id,
        seq,
        CoverageReason::Handshake,
        platform(),
        probe_all(),
    )
}
