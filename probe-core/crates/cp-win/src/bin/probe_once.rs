//! Developer harness: one coverage report and one sample, as NDJSON on stdout.
//!
//! Replaces the C# spike as the thing to reach for when debugging a probe. Not shipped, not signed.
//!
//! ```text
//! cargo run -p cp-win --bin probe-once
//! cargo run -p cp-win --bin probe-once -- --pretty
//! ```
//!
//! Piping this into `schemas/conformance_test.py` is the cross-language check the contract asks
//! for: types written in Rust, validated against the same JSON Schema the Go pipeline will use.

use cp_signals::Envelope;
use uuid::Uuid;

fn main() {
    let pretty = std::env::args().any(|a| a == "--pretty");
    let session_id = Uuid::new_v4();
    let instance_id = Uuid::new_v4();

    let coverage = cp_win::capability::report(session_id, instance_id, 1);
    emit(&coverage, pretty);

    let (signals, meta) = cp_win::scan(1000, &session_id);
    let envelope = Envelope::sample(session_id, instance_id, 2, signals, meta);
    emit(&envelope, pretty);

    let e = envelope;
    let sig_count = e.signals.as_ref().map(Vec::len).unwrap_or(0);
    let m = e.sample_meta.as_ref().expect("sample carries meta");
    eprintln!(
        "\n{} signal(s) · scan {} ms · complete={} · {} probe error(s)",
        sig_count,
        m.scan_duration_ms.unwrap_or(0),
        m.complete,
        m.probe_errors.len()
    );
    for err in &m.probe_errors {
        eprintln!(
            "  probe error [{} {:?}]: {}",
            err.code,
            err.kind,
            err.message.as_deref().unwrap_or("(no message)")
        );
    }
    if !m.complete {
        eprintln!(
            "\nThis sample is INCOMPLETE. An empty or short signal list here does not mean a clean\n\
             machine - read it against the coverage report above."
        );
    }
}

fn emit<T: serde::Serialize>(v: &T, pretty: bool) {
    let s = if pretty {
        serde_json::to_string_pretty(v)
    } else {
        serde_json::to_string(v)
    };
    println!("{}", s.expect("contract types serialise"));
}
