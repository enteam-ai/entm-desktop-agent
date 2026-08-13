//! S2 — Authenticode hash and code signer.
//!
//! Two independent Win32 calls, deliberately not one: `WinVerifyTrust` answers "is this signature
//! valid", and the catalog-admin hash functions answer "what is this file's Authenticode hash" —
//! the digest a central tool database keys on. A file can be unsigned and still need hashing (the
//! tool database matches on hash OR signer, not only signer), so neither call can stand in for the
//! other.
//!
//! # Revocation is deliberately off
//!
//! `WTD_REVOKE_NONE`. Revocation checking can hit the network per file, and the exit criterion for
//! P1 is 60 unattended minutes with no hang — a CRL fetch stalling on a captive portal is exactly
//! the kind of failure that criterion exists to catch. `revocation_checked` is reported honestly as
//! `false` rather than silently implying a check that did not happen.
//!
//! # Cost is bounded by a cache, not by scope
//!
//! Every process gets a hash attempt — narrowing to "just the mic holder" or "just the foreground
//! window" would make S2 blind to a known-bad tool sitting quietly in the background, which is
//! half of what a tool database is for. What bounds the cost instead is [`cached`]: verification
//! runs once per distinct image **path** and is reused for the rest of the collector's lifetime.
//! The first scan after launch pays for every process running at that moment; every scan after
//! pays only for what is new. Measured, not assumed — see the `probe-once` run in `progress.md`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;

use cp_signals::{DetailS2, Signature};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE, TRUST_E_NOSIGNATURE,
};
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows_sys::Win32::Security::WinTrust::{
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WinVerifyTrust,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};

fn cache() -> &'static Mutex<HashMap<String, (Signature, DetailS2)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Signature, DetailS2)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Verify `path` once and remember the result. See the module doc for why this is what bounds cost
/// rather than narrowing which processes get checked.
pub fn cached(path: &str) -> (Signature, DetailS2) {
    if let Some(hit) = cache().lock().unwrap().get(path) {
        return hit.clone();
    }
    let result = verify(path);
    cache().lock().unwrap().insert(path.to_string(), result.clone());
    result
}

fn wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct HashResult {
    sha256: String,
    hash_source: &'static str,
    /// Set when the file's hash matches an entry in a catalog already registered on this machine
    /// (`%windir%\System32\CatRoot`) — how most core OS binaries are signed, since embedding a
    /// signature in every system file was never how Windows Update distributes them. A plain
    /// `WinVerifyTrust` file check does **not** consult catalogs on its own; this is the second
    /// lookup that finds what it misses.
    catalog_path: Option<String>,
}

/// The Authenticode hash — the same digest the signature itself covers, and the tool database's
/// primary join key. Falls back to a full-file SHA-256 if the catalog-admin call fails; the wire
/// says which one it got via `hash_source` so a consumer never compares the wrong pair.
fn authenticode_hash(path_w: &[u16]) -> Option<HashResult> {
    unsafe {
        let h = CreateFileW(
            path_w.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return None;
        }

        let mut hcatadmin: isize = 0;
        let algo = wide_null("SHA256");
        let acquired =
            CryptCATAdminAcquireContext2(&mut hcatadmin, std::ptr::null(), algo.as_ptr(), std::ptr::null(), 0);

        let mut raw_hash: Option<Vec<u8>> = None;
        if acquired != 0 {
            let mut cb: u32 = 0;
            CryptCATAdminCalcHashFromFileHandle2(hcatadmin, h, &mut cb, std::ptr::null_mut(), 0);
            if cb > 0 {
                let mut buf = vec![0u8; cb as usize];
                let ok = CryptCATAdminCalcHashFromFileHandle2(hcatadmin, h, &mut cb, buf.as_mut_ptr(), 0);
                if ok != 0 {
                    buf.truncate(cb as usize);
                    raw_hash = Some(buf);
                }
            }
        }

        let catalog_path = match &raw_hash {
            Some(bytes) if acquired != 0 => {
                let hcatinfo = CryptCATAdminEnumCatalogFromHash(
                    hcatadmin,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    0,
                    std::ptr::null_mut(),
                );
                if hcatinfo != 0 {
                    let mut info: CATALOG_INFO = std::mem::zeroed();
                    info.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
                    let path = if CryptCATCatalogInfoFromContext(hcatinfo, &mut info, 0) != 0 {
                        let end = info.wszCatalogFile.iter().position(|&c| c == 0).unwrap_or(260);
                        Some(String::from_utf16_lossy(&info.wszCatalogFile[..end]))
                    } else {
                        None
                    };
                    CryptCATAdminReleaseCatalogContext(hcatadmin, hcatinfo, 0);
                    path
                } else {
                    None
                }
            }
            _ => None,
        };

        if acquired != 0 {
            CryptCATAdminReleaseContext(hcatadmin, 0);
        }

        let result = match raw_hash {
            Some(bytes) => Some(HashResult { sha256: hex(&bytes), hash_source: "authenticode", catalog_path }),
            // The catalog-admin path needs no elevation and no signature to already be present —
            // it failing at all is rare enough that a full read-and-hash fallback is worth the I/O.
            // No catalog lookup is possible from a plain byte hash, so this path is never a member.
            None => full_file_hash(h).map(|sha256| HashResult { sha256, hash_source: "full_file", catalog_path: None }),
        };

        CloseHandle(h);
        result
    }
}

fn full_file_hash(h: HANDLE) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, SetFilePointer, FILE_BEGIN};
    unsafe {
        if SetFilePointer(h, 0, std::ptr::null_mut(), FILE_BEGIN) == u32::MAX {
            return None;
        }
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let mut read: u32 = 0;
            if ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut read, std::ptr::null_mut()) == 0 {
                return None;
            }
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read as usize]);
        }
        Some(hex(&hasher.finalize()))
    }
}

/// Read the leaf signer's display name via `CertGetNameStringW`, the same string Explorer's
/// Digital Signatures tab shows. Empty rather than absent on failure — the caller decides what
/// "couldn't read the name" means for a signature that otherwise verified.
unsafe fn signer_display_name(cert: *const CERT_CONTEXT) -> Option<String> {
    let needed = CertGetNameStringW(
        cert,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        std::ptr::null(),
        std::ptr::null_mut(),
        0,
    );
    if needed <= 1 {
        return None;
    }
    let mut buf = vec![0u16; needed as usize];
    let written = CertGetNameStringW(
        cert,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        std::ptr::null(),
        buf.as_mut_ptr(),
        needed,
    );
    if written == 0 {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let name = String::from_utf16_lossy(&buf[..end]);
    if name.is_empty() { None } else { Some(name) }
}

struct TrustResult {
    /// Raw `WinVerifyTrust` HRESULT. 0 = trusted; see the module doc for how the rest is derived.
    status: i32,
    signer: Option<String>,
    chain_trusted: Option<bool>,
    timestamped: Option<bool>,
}

fn verify_trust(path_w: &[u16]) -> TrustResult {
    unsafe {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path_w.as_ptr(),
            hFile: std::ptr::null_mut(),
            pgKnownSubject: std::ptr::null_mut(),
        };

        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: std::ptr::null_mut(),
            pSIPClientData: std::ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file_info },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: std::ptr::null_mut(),
            pwszURLReference: std::ptr::null_mut(),
            dwProvFlags: 0,
            dwUIContext: 0,
            pSignatureSettings: std::ptr::null_mut(),
        };

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(-1isize as _, &mut action, &mut data as *mut _ as *mut _);

        let mut signer = None;
        let mut chain_trusted = None;
        let mut timestamped = None;

        if !data.hWVTStateData.is_null() {
            let prov_data = WTHelperProvDataFromStateData(data.hWVTStateData);
            if !prov_data.is_null() {
                let sgnr = WTHelperGetProvSignerFromChain(prov_data, 0, 0, 0);
                if !sgnr.is_null() {
                    timestamped = Some((*sgnr).csCounterSigners > 0);

                    // The leaf (index 0) is the actual signing certificate — that is whose subject
                    // name goes on the wire. `fTrustedRoot` is only meaningful on the chain's LAST
                    // element, the root CA; reading it off the leaf reports "is Microsoft itself a
                    // self-signed root", which is never true and would make every valid signature
                    // read as untrusted.
                    let leaf = WTHelperGetProvCertFromChain(sgnr, 0);
                    if !leaf.is_null() && !(*leaf).pCert.is_null() {
                        signer = signer_display_name((*leaf).pCert);
                    }

                    let chain_len = (*sgnr).csCertChain;
                    if chain_len > 0 {
                        let root = WTHelperGetProvCertFromChain(sgnr, chain_len - 1);
                        if !root.is_null() {
                            chain_trusted = Some((*root).fTrustedRoot != 0);
                        }
                    }
                }
            }

            // Release the verification state regardless of outcome — WTD_STATEACTION_VERIFY
            // allocates it, and every path through this function (valid, invalid, unsigned) must
            // close it or the handle leaks for the life of the probe process.
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(-1isize as _, &mut action, &mut data as *mut _ as *mut _);
        }

        TrustResult { status, signer, chain_trusted, timestamped }
    }
}

fn verify(path: &str) -> (Signature, DetailS2) {
    let path_w = wide_null(path);
    let hash = authenticode_hash(&path_w);
    let mut trust = verify_trust(&path_w);
    let mut via_catalog = false;

    let Some(hash) = hash else {
        return (
            Signature::Unavailable,
            DetailS2 {
                verified: None,
                chain_trusted: None,
                revocation_checked: None,
                timestamped: None,
                hash_algorithm: "sha256",
                hash_source: "none",
                platform_status: Some(format!("{:#010x}", trust.status as u32)),
            },
        );
    };
    let HashResult { sha256, hash_source, catalog_path } = hash;

    // A direct WinVerifyTrust file check does not walk catalogs on its own — most core OS binaries
    // are catalog-signed, not embedded-signed, and read as `TRUST_E_NOSIGNATURE` without this. If
    // the hash matched a catalog registered on this machine, verify *that* catalog file instead:
    // it is itself just a signed file, checked the same way `verify_trust` checks any other.
    if trust.status != 0 {
        if let Some(cat_path) = &catalog_path {
            let cat_trust = verify_trust(&wide_null(cat_path));
            if cat_trust.status == 0 {
                via_catalog = true;
                trust = cat_trust;
            }
        }
    }

    let detail = DetailS2 {
        verified: Some(trust.status == 0),
        chain_trusted: trust.chain_trusted,
        // See the module doc: revocation is intentionally never checked, to keep this off the
        // network on a 60-minute unattended run.
        revocation_checked: Some(false),
        timestamped: trust.timestamped,
        hash_algorithm: "sha256",
        hash_source,
        platform_status: Some(if via_catalog {
            format!("catalog:{:#010x}", trust.status as u32)
        } else {
            format!("{:#010x}", trust.status as u32)
        }),
    };

    let signature = if trust.status == 0 {
        Signature::Valid {
            // The type requires a signer string for `Valid`; WinVerifyTrust succeeding without a
            // readable subject name has not been observed but is not provably impossible, so this
            // is a documented degrade rather than an unwrap.
            signer: trust.signer.unwrap_or_else(|| "unknown".to_string()),
            sha256,
        }
    } else if trust.status == TRUST_E_NOSIGNATURE {
        Signature::Unsigned { sha256 }
    } else {
        Signature::Invalid { signer: trust.signer, sha256 }
    };

    (signature, detail)
}

