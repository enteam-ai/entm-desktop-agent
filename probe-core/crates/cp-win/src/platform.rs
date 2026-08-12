//! Platform version — `RtlGetVersion`, not `GetVersionExW`.
//!
//! `GetVersionExW` (and `GetVersionEx`) lies unless the process carries a manifest declaring
//! which Windows release it was "designed for" — without one it reports Windows 8 regardless of
//! the real OS, silently. `RtlGetVersion`, exported from `ntdll.dll`, is the actual kernel-level
//! answer and is not subject to that compatibility shim. Reporting a wrong build is worse than
//! reporting none: `S5_capture_excluded: unsupported` means one thing on Windows 10 1809 (before
//! `WDA_EXCLUDEFROMCAPTURE` existed) and something else entirely on Windows 11, and a coverage
//! report that got the version wrong would mislabel which case applies.
//!
//! Not part of the generated `windows` crate's COM surface (nothing here is COM), and deliberately
//! not routed through `windows-sys` either — this is the one Windows API in this crate hand-
//! declared directly against `ntdll.dll`'s documented ABI, the same "measured, not assumed"
//! standard this crate holds everywhere else, applied here because getting a raw NTSTATUS-return
//! FFI declaration wrong fails silently (a garbage version string), not with a compile error.

use std::mem::size_of;

#[repr(C)]
struct OsVersionInfoW {
    os_version_info_size: u32,
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    platform_id: u32,
    csd_version: [u16; 128],
}

#[link(name = "ntdll")]
extern "system" {
    // Returns an NTSTATUS; 0 is STATUS_SUCCESS. The caller must set `os_version_info_size` before
    // calling — RtlGetVersion validates it and fails otherwise, the same contract GetVersionExW
    // has, but without the manifest-gated lie GetVersionExW adds on top of it.
    fn RtlGetVersion(version_information: *mut OsVersionInfoW) -> i32;
}

/// `(major.minor, build)` — e.g. `("10.0", "26200")`. `None` only if the kernel call itself
/// fails, which has never been observed; failure here degrades the coverage report's
/// `platform.os_version`/`os_build` to `null` rather than reporting a guess.
pub fn version() -> Option<(String, String)> {
    let mut info = OsVersionInfoW {
        os_version_info_size: size_of::<OsVersionInfoW>() as u32,
        major_version: 0,
        minor_version: 0,
        build_number: 0,
        platform_id: 0,
        csd_version: [0; 128],
    };

    // SAFETY: `info` is a valid, correctly-sized, mutable `OsVersionInfoW` for the duration of the
    // call, matching RtlGetVersion's documented contract; the struct's layout matches the
    // documented `OSVERSIONINFOW` field order and widths exactly.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status != 0 {
        return None;
    }

    Some((
        format!("{}.{}", info.major_version, info.minor_version),
        info.build_number.to_string(),
    ))
}
