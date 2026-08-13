//! S5 — per-window capture-exclusion state.
//!
//! A tool that hides itself from screen capture must set `WDA_EXCLUDEFROMCAPTURE`, and that flag is
//! readable cross-process with no elevation. Renaming the binary changes nothing, which is the
//! entire point: the flag *is* the feature those tools sell, so they cannot stop setting it.
//!
//! Measured on a real machine: `GetWindowDisplayAffinity` succeeded on every top-level window, zero
//! failures, and nothing on a normal desktop set a non-default affinity.

use std::ffi::c_void;

use cp_signals::{DetailS5, ImagePath, Observation, Subject, WindowRef};
use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowDisplayAffinity, GetWindowTextW, GetWindowThreadProcessId,
    IsWindowVisible,
};

use crate::process::ProcessInfo;

pub const WDA_NONE: u32 = 0x0000_0000;
pub const WDA_MONITOR: u32 = 0x0000_0001;
pub const WDA_EXCLUDEFROMCAPTURE: u32 = 0x0000_0011;

pub fn affinity_name(affinity: u32) -> String {
    match affinity {
        WDA_NONE => "WDA_NONE".to_string(),
        WDA_MONITOR => "WDA_MONITOR".to_string(),
        WDA_EXCLUDEFROMCAPTURE => "WDA_EXCLUDEFROMCAPTURE".to_string(),
        // Reported rather than folded into WDA_NONE: an unknown non-zero value is not evidence of
        // cleanliness, and silently normalising it would hide exactly the thing worth seeing.
        other => format!("WDA_UNKNOWN_0x{other:08x}"),
    }
}

#[derive(Debug, Clone)]
pub struct WindowObservation {
    pub hwnd: isize,
    pub pid: u32,
    pub affinity: u32,
    pub title: Option<String>,
    pub visible: bool,
}

/// One sweep, two products: the S5 findings, and the set of pids owning at least one top-level
/// window. The second is what makes a headless mic holder distinguishable from a meeting client.
#[derive(Debug, Default)]
pub struct WindowSweep {
    pub non_default: Vec<WindowObservation>,
    /// Owns at least one top-level window, **including hidden ones**. This is what the schema's
    /// `has_window` means, so it must not be narrowed.
    pub pids_with_windows: std::collections::HashSet<u32>,
    /// Owns at least one top-level window that is actually *visible*.
    ///
    /// `EnumWindows` returns hidden top-level windows, and tray applications own several — measured
    /// here, 235 of 268 windows were invisible and 47 of 60 window-owning pids owned only invisible
    /// ones. Without this, every Electron tray app looks windowed, and a tray-resident audio
    /// assistant is demoted out of tier 2 — the exact tool class S3 exists to catch.
    pub pids_with_visible_windows: std::collections::HashSet<u32>,
    pub window_counts: std::collections::HashMap<u32, u32>,
    /// Windows whose affinity could not be read. Dead handles race the enumeration constantly, so
    /// this is counted rather than listed — but it is **not** treated as "no finding". It is a
    /// coverage number.
    pub unreadable: u32,
    pub total: u32,
}

struct SweepState {
    sweep: WindowSweep,
}

pub fn sweep() -> Result<WindowSweep, String> {
    let mut state = SweepState {
        sweep: WindowSweep::default(),
    };

    let ok = unsafe {
        EnumWindows(
            Some(enum_proc),
            &mut state as *mut SweepState as isize as LPARAM,
        )
    };

    if ok == 0 {
        return Err(format!(
            "EnumWindows failed: win32={}",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        ));
    }

    Ok(state.sweep)
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> i32 {
    let state = &mut *(lparam as *mut c_void as *mut SweepState);
    let s = &mut state.sweep;
    s.total += 1;

    let visible = IsWindowVisible(hwnd) != 0;

    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, &mut pid);
    if pid != 0 {
        s.pids_with_windows.insert(pid);
        *s.window_counts.entry(pid).or_insert(0) += 1;
        if visible {
            s.pids_with_visible_windows.insert(pid);
        }
    }

    let mut affinity: u32 = 0;
    if GetWindowDisplayAffinity(hwnd, &mut affinity) == 0 {
        s.unreadable += 1;
        return 1; // keep enumerating
    }

    if affinity != WDA_NONE {
        s.non_default.push(WindowObservation {
            hwnd: hwnd as isize,
            pid,
            affinity,
            title: read_title(hwnd),
            visible,
        });
    }

    1
}

/// Window **titles**, never window contents (NG3).
pub(crate) unsafe fn read_title(hwnd: HWND) -> Option<String> {
    let mut buf = [0u16; 512];
    let len = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
    if len < 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

pub fn observe(w: &WindowObservation, processes: &[ProcessInfo]) -> Observation {
    let subject = processes
        .iter()
        .find(|p| p.pid == w.pid)
        .map(ProcessInfo::to_subject)
        .unwrap_or_else(|| {
            // The window outlived its process in our snapshot, or the process appeared between the
            // two sweeps. Exited is the honest state; it is not the same as access_denied.
            Subject::new(w.pid, None, ImagePath::Exited)
        });

    Observation::CaptureExcluded {
        subject,
        detail: DetailS5 {
            capture_excluded: w.affinity == WDA_EXCLUDEFROMCAPTURE,
            affinity_raw: Some(w.affinity),
            affinity_name: affinity_name(w.affinity),
            window: Some(WindowRef::new(w.hwnd, w.title.clone(), w.visible)),
        },
    }
}
