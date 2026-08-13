//! Windows probes for Collector A.
//!
//! # The rule this crate exists to hold
//!
//! **Enumerate audio sessions. Never open a capture stream.**
//!
//! Enumeration does not trip the Windows microphone consent prompt; opening a stream does. P1's
//! exit criterion is a 60-minute session with no crash and no mic-permission prompt loop, and a
//! monitoring agent that itself asks for the microphone is also indefensible on its own terms.
//!
//! `deny_capture_apis.rs` is a test that fails the build if any capture entry point appears in this
//! crate's source. It is deliberately crude — a grep — because the failure it prevents is one that
//! only shows up in front of a candidate.
//!
//! # Non-elevated, always
//!
//! Requiring UAC costs install completions, and everything worth catching runs as the candidate's
//! own user anyway. The cost is measured and known: on a real machine, `OpenProcess` was refused
//! for **180 of 324** processes — every session-0 service. Those become
//! [`ImagePath::AccessDenied`], never a silent absence, and the count lands in the coverage
//! report's `limits` so the panel can state the ceiling rather than imply completeness.

#![cfg(windows)]

pub mod affinity;
pub mod audio;
pub mod capability;
pub mod foreground;
pub mod platform;
pub mod process;
pub mod signature;

use std::time::Instant;

use cp_signals::{Observation, ProbeErrorKind, SampleMeta, Signal};

/// One full scan. Returns the observations plus the per-sample honesty record.
///
/// The window sweep runs once and feeds both S5 and the pid→has-window set, which is what turns
/// "this process holds the microphone" into "this process holds the microphone **and shows no
/// UI**" — the audio-assistant signature.
pub fn scan(poll_interval_ms: u32, session_id: &uuid::Uuid) -> (Vec<Signal>, SampleMeta) {
    let started = Instant::now();
    let mut meta = SampleMeta::snapshot(0, poll_interval_ms);
    let mut observations: Vec<Observation> = Vec::new();

    let windows = match affinity::sweep() {
        Ok(w) => w,
        Err(e) => {
            // A failed window sweep is not an empty desktop. Mark the sample incomplete so it can
            // never be read as "clean".
            meta.record_error("S5", ProbeErrorKind::ApiFailure, e);
            affinity::WindowSweep::default()
        }
    };

    let processes = match process::snapshot() {
        Ok(p) => p,
        Err(e) => {
            meta.record_error("S1", ProbeErrorKind::ApiFailure, e);
            Vec::new()
        }
    };

    meta.count_unreadable(
        "process_paths",
        processes.iter().filter(|p| !p.path.is_readable()).count() as u32,
    );

    for proc in &processes {
        let (s1, s2) = process::observe(proc, &windows);
        observations.push(s1);
        if let Some(s2) = s2 {
            observations.push(s2);
        }
    }

    for excluded in &windows.non_default {
        observations.push(affinity::observe(excluded, &processes));
    }

    if let Some(fg) = foreground::probe(&processes) {
        observations.push(fg);
    }

    match audio::probe(&windows, &processes, session_id) {
        Ok((holders, failed_devices)) => {
            observations.extend(holders);
            if failed_devices > 0 {
                // Some capture endpoints refused enumeration. The sample is not clean — it is
                // partial, and a partial S3 must never read as "nothing is listening".
                meta.record_error(
                    "S3",
                    ProbeErrorKind::ApiFailure,
                    format!("{failed_devices} capture endpoint(s) could not be enumerated"),
                );
                meta.count_unreadable("audio_endpoints", failed_devices);
            }
        }
        Err(e) => meta.record_error("S3", ProbeErrorKind::ApiFailure, e),
    }

    meta.scan_duration_ms = Some(started.elapsed().as_millis() as u64);
    (observations.into_iter().map(Signal::from).collect(), meta)
}
