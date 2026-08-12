//! The probe host process.
//!
//! Reads newline-delimited JSON commands on stdin, writes NDJSON responses on stdout, and keeps
//! diagnostics on stderr. This is the entire Rust↔Go boundary: **the probe emits envelope JSON and
//! the supervisor ships it.** Nothing else crosses.
//!
//! # Why a separate process rather than a linked library
//!
//! COM lives here. A fault in a COM call — a misbehaving audio driver, a device removed mid-call —
//! takes down *this* process, and the supervisor restarts it and records a coverage gap. Linked in,
//! the same fault would take down the agent, and the candidate's interview with it.
//!
//! Every command is wrapped in `catch_unwind` so a probe panic returns an error object rather than
//! unwinding across the process boundary.
//!
//! # Protocol
//!
//! ```text
//! ->  {"id":1,"op":"coverage","session_id":"...","instance_id":"...","seq":1}
//! <-  {"id":1,"ok":true,"message":{...coverage report...}}
//!
//! ->  {"id":2,"op":"scan","session_id":"...","instance_id":"...","seq":2,"poll_interval_ms":1000}
//! <-  {"id":2,"ok":true,"message":{...signal envelope...}}
//!
//! ->  {"id":3,"op":"ping"}
//! <-  {"id":3,"ok":true}
//! ```
//!
//! An unparseable line gets an error response rather than a silent drop, because a supervisor that
//! sees nothing back cannot distinguish a wedged probe from a quiet machine — the same failure this
//! whole product is built to avoid.

use std::io::{BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};

use cp_signals::Envelope;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct Command {
    #[serde(default)]
    id: u64,
    op: String,
    session_id: Option<Uuid>,
    instance_id: Option<Uuid>,
    seq: Option<u64>,
    poll_interval_ms: Option<u32>,
}

#[derive(Debug, Serialize)]
struct Response {
    id: u64,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Response {
    fn ok(id: u64, message: Option<serde_json::Value>) -> Self {
        Self {
            id,
            ok: true,
            message,
            error: None,
        }
    }
    fn err(id: u64, error: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            message: None,
            error: Some(error.into()),
        }
    }
}

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    eprintln!("probe-serve ready ({})", cp_signals::COLLECTOR_ID);

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Command>(line) {
            Ok(cmd) => dispatch(cmd),
            Err(e) => Response::err(0, format!("unparseable command: {e}")),
        };

        let encoded = serde_json::to_string(&response)
            .unwrap_or_else(|_| r#"{"id":0,"ok":false,"error":"response encode failed"}"#.into());

        if writeln!(stdout, "{encoded}").is_err() || stdout.flush().is_err() {
            break; // supervisor is gone
        }
    }
}

fn dispatch(cmd: Command) -> Response {
    let id = cmd.id;

    // A probe panic must not unwind across the process boundary. It becomes an error response, the
    // supervisor marks the sample incomplete, and the session continues honestly degraded rather
    // than dying mid-interview.
    let result = catch_unwind(AssertUnwindSafe(|| match cmd.op.as_str() {
        "ping" => Ok(None),

        "coverage" => {
            let (session_id, instance_id) = ids(&cmd)?;
            let report = cp_win::capability::report(session_id, instance_id, cmd.seq.unwrap_or(1));
            Ok(Some(serde_json::to_value(report).map_err(|e| e.to_string())?))
        }

        "scan" => {
            let (session_id, instance_id) = ids(&cmd)?;
            let (signals, meta) =
                cp_win::scan(cmd.poll_interval_ms.unwrap_or(1000), &session_id);
            let envelope = Envelope::sample(
                session_id,
                instance_id,
                cmd.seq.unwrap_or(1),
                signals,
                meta,
            );
            Ok(Some(serde_json::to_value(envelope).map_err(|e| e.to_string())?))
        }

        other => Err(format!("unknown op '{other}'")),
    }));

    match result {
        Ok(Ok(message)) => Response::ok(id, message),
        Ok(Err(e)) => Response::err(id, e),
        Err(_) => Response::err(id, "probe panicked"),
    }
}

fn ids(cmd: &Command) -> Result<(Uuid, Uuid), String> {
    match (cmd.session_id, cmd.instance_id) {
        (Some(s), Some(i)) => Ok((s, i)),
        _ => Err("session_id and instance_id are required".to_string()),
    }
}
