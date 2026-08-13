//! S1 — the process list, and the pid → identity resolution the other signals join against.
//!
//! On its own S1 proves nothing. Its value is as the key: S2 hashes the paths it finds, S3 resolves
//! session owners against it, S5 attributes windows to it.
//!
//! Identity is `(pid, name)` here and `(pid, create_time)` in the supervisor's differ. Never the
//! name alone — a rename defeats name matching, and that weakness is the reason the behavioural
//! signals exist at all.

use cp_signals::{DetailS1, ImagePath, Observation, Subject};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

const ERROR_ACCESS_DENIED: u32 = 5;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: Option<String>,
    pub path: ImagePath,
}

impl ProcessInfo {
    pub fn to_subject(&self) -> Subject {
        let mut s = Subject::new(self.pid, self.name.clone(), self.path.clone());
        s.parent_pid = Some(self.parent_pid);
        s
    }
}

pub fn snapshot() -> Result<Vec<ProcessInfo>, String> {
    let snap: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Err(format!("CreateToolhelp32Snapshot failed: win32={}", unsafe {
            GetLastError()
        }));
    }

    let mut out = Vec::with_capacity(400);
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    unsafe {
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let name = wide_to_string(&entry.szExeFile);
                out.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    parent_pid: entry.th32ParentProcessID,
                    name: if name.is_empty() { None } else { Some(name) },
                    path: resolve_path(entry.th32ProcessID),
                });
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }

    Ok(out)
}

/// Resolve a pid's image path, distinguishing *why* it failed.
///
/// `access_denied` is a permanent capability limit — S2 can never hash that image. `exited` is a
/// one-cycle race. Collapsing both into `null` loses the distinction the whole S2 coverage story
/// turns on, which is why [`ImagePath`] has separate variants rather than an `Option<String>`.
fn resolve_path(pid: u32) -> ImagePath {
    if pid == 0 {
        return ImagePath::NotApplicable; // System Idle Process
    }

    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return match GetLastError() {
                ERROR_ACCESS_DENIED => ImagePath::AccessDenied,
                _ => ImagePath::Exited,
            };
        }

        let mut buf = [0u16; 32768];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);

        if ok == 0 {
            return ImagePath::Unknown;
        }
        ImagePath::Readable(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Builds the S1 observation and, when the image is readable, the S2 observation that shares its
/// `Subject` — so a consumer never sees the same pid report `signature_state: not_checked` on one
/// signal and `valid` on another in the same sample.
pub fn observe(
    p: &ProcessInfo,
    windows: &crate::affinity::WindowSweep,
) -> (Observation, Option<Observation>) {
    let window_count = windows.window_counts.get(&p.pid).copied().unwrap_or(0);
    let has_window = window_count > 0;

    let mut subject = p.to_subject().with_has_window(has_window);

    let s2 = if let ImagePath::Readable(path) = &p.path {
        let (sig, detail) = crate::signature::cached(path);
        subject = subject.with_signature(sig);
        Some(Observation::Signature { subject: subject.clone(), detail })
    } else {
        None
    };

    let s1 = Observation::Process {
        subject,
        detail: DetailS1 {
            present: true,
            has_window,
            window_count,
            // Refined once S8/session lookup lands. `unknown` is the honest answer meanwhile —
            // guessing "interactive" would be a claim the probe has not earned.
            session_kind: "unknown",
        },
    };

    (s1, s2)
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}
