//! S6 — the foreground window and its title.
//!
//! Titles only. Never contents, never keystrokes, never the clipboard (NG3).
//!
//! Polled here. The event-driven form is `SetWinEventHook(EVENT_SYSTEM_FOREGROUND)` with a message
//! pump on a dedicated thread, which belongs with the probe host rather than in a stateless scan —
//! and polling is the shipping decision for P1 regardless.

use cp_signals::{DetailS6, ImagePath, Observation, Subject, WindowRef};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowThreadProcessId, IsWindowVisible,
};

use crate::affinity::read_title;
use crate::process::ProcessInfo;

pub fn probe(processes: &[ProcessInfo]) -> Option<Observation> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.is_null() {
            // Nothing is focused — a locked workstation, or focus in transit. Absence of a
            // foreground window is not a finding and must not be reported as one.
            return None;
        }

        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);

        let subject = processes
            .iter()
            .find(|p| p.pid == pid)
            .map(ProcessInfo::to_subject)
            .unwrap_or_else(|| Subject::new(pid, None, ImagePath::Exited))
            .with_has_window(true);

        Some(Observation::Foreground {
            subject,
            detail: DetailS6 {
                is_foreground: true,
                window: Some(WindowRef::new(
                    hwnd as isize,
                    read_title(hwnd),
                    IsWindowVisible(hwnd) != 0,
                )),
            },
        })
    }
}
