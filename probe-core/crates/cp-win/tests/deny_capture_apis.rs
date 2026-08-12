//! Build-breaking guard: this crate must never **open** an audio capture stream.
//!
//! Enumerating audio sessions does not trip the Windows microphone consent prompt. Opening a
//! capture stream does — and P1's exit criterion is a 60-minute session with no crash and no
//! mic-permission prompt loop. A monitoring agent that itself asks the candidate for the microphone
//! is also indefensible on its own terms.
//!
//! The check is a grep, deliberately. It is crude, it will occasionally need an exemption, and it
//! catches the one mistake whose cost is paid in front of a candidate rather than in CI.

use std::fs;
use std::path::Path;

/// Entry points that acquire a capture stream. Enumeration APIs are absent on purpose: those are
/// the ones this crate is *supposed* to call.
const FORBIDDEN: &[&str] = &[
    "IAudioClient",
    "IAudioCaptureClient",
    "ActivateAudioInterfaceAsync",
    "waveInOpen",
    "waveInStart",
    "MediaCapture",
    "AudioRecord",
    "CaptureDevice",
];

#[test]
fn no_capture_api_reaches_this_crate() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut findings = Vec::new();
    walk(&src, &mut findings);

    assert!(
        findings.is_empty(),
        "\n\nForbidden audio-capture API referenced in cp-win:\n{}\n\n\
         cp-win enumerates audio sessions; it never opens a capture stream. Opening one triggers \n\
         the Windows microphone consent prompt, which breaks P1's exit criterion and undermines \n\
         the product's own premise. If this is a false positive, narrow the pattern rather than \n\
         deleting the check.\n",
        findings.join("\n")
    );
}

fn walk(dir: &Path, findings: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, findings);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            for (n, line) in text.lines().enumerate() {
                // Doc comments describe what must NOT be called; they are the specification, not a
                // violation of it.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                for pat in FORBIDDEN {
                    if line.contains(pat) {
                        findings.push(format!(
                            "  {}:{}  {}",
                            path.display(),
                            n + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }
}
