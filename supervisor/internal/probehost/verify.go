package probehost

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// SignatureInfo is what the verification actually measured â€” not asserted from configuration. See
// [verifyAuthenticode].
type SignatureInfo struct {
	Valid  bool
	Signer string
	Status string
}

// verifyAuthenticode checks a file's Authenticode signature via PowerShell's
// Get-AuthenticodeSignature â€” the same official check behind Windows Explorer's own Digital
// Signatures tab, and one that already correctly handles catalog-signed binaries.
//
// This shells out rather than hand-rolling WinTrust bindings in Go, on purpose. `cp-win` already
// has one hand-verified WinVerifyTrust implementation (Rust, generated bindings, measured against
// a real machine, two defects found and fixed along the way â€” see progress.md). A second,
// hand-written one in Go, using raw syscalls with manually-laid-out structs and no equivalent
// generated-binding safety net, is exactly the kind of code that can silently always report
// "valid" from a struct-offset bug â€” which is worse than having no check at all. Shelling out to
// Microsoft's own, already-correct implementation is the lower-risk choice here.
//
// The PSModulePath line is load-bearing, not tidying. Get-AuthenticodeSignature lives in the
// autoloaded module Microsoft.PowerShell.Security, and autoload searches PSModulePath in order. A
// machine with PowerShell 7 installed puts its module directory on that path, and those modules
// declare CompatiblePSEditions = 'Core', which Windows PowerShell 5.1 finds but refuses to load â€”
// failing with "the module could not be loaded", not with "command not found". Observed on
// windows-latest in CI and reproduced locally by planting a Core-only manifest ahead of the real
// one. Pinning the search path to this interpreter's own $PSHOME\Modules makes the resolution
// deterministic, and it is scoped to the child process, so nothing else on the machine is affected.
func verifyAuthenticode(path string) (SignatureInfo, error) {
	// Single-quoted PowerShell string: escape ' as '' rather than passing path via $args, which
	// behaves inconsistently across PowerShell -Command invocations depending on version.
	escaped := strings.ReplaceAll(path, "'", "''")
	script := fmt.Sprintf(`
$ErrorActionPreference = "Stop"
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$sig = Get-AuthenticodeSignature -LiteralPath '%s'
$signer = $null
if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
[PSCustomObject]@{ Status = $sig.Status.ToString(); Signer = $signer } | ConvertTo-Json -Compress
`, escaped)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		// PowerShell explains itself on stderr, and Output() has already captured it into
		// ExitError.Stderr. Wrapping only the ExitError throws that away and leaves "exit status 1",
		// which says nothing about whether the file was unreadable, the cmdlet was unavailable, or
		// the script itself was wrong. This check runs on a candidate's machine where nobody can
		// reproduce it interactively, so the one chance to learn why is to carry the reason with it.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return SignatureInfo{}, fmt.Errorf("Get-AuthenticodeSignature: %w: %s",
				err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return SignatureInfo{}, fmt.Errorf("Get-AuthenticodeSignature: %w", err)
	}

	var parsed struct {
		Status string
		Signer string
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return SignatureInfo{}, fmt.Errorf("parse signature check output %q: %w", out, err)
	}

	return SignatureInfo{
		Valid:  parsed.Status == "Valid",
		Signer: parsed.Signer,
		Status: parsed.Status,
	}, nil
}

// verifyBeforeSpawn is the gate Start calls before it ever spawns the probe.
//
// `expectedPublisher` is a substring match against the certificate subject (e.g. `O=Contoso Corp`),
// not an exact-string comparison â€” a subject contains CN/O/L/S/C fields in a fixed order, and
// matching on the organisation field alone survives a CN change (product rename) without a code
// change. Empty means unarmed: the probe is not yet signed (no EV certificate has been ordered â€”
// see progress.md's "non-engineering, already blocking" section), so this call MUST NOT block
// startup today, but it still runs and logs what it finds, so the gap is measured, not assumed.
func verifyBeforeSpawn(exePath, expectedPublisher string) error {
	info, err := verifyAuthenticode(exePath)
	if err != nil {
		if expectedPublisher == "" {
			// Unarmed: PowerShell being unavailable, or any other check failure, must not stop the
			// agent from running pre-signing. Once a publisher is configured this becomes fatal.
			return nil
		}
		return fmt.Errorf("could not verify probe signature: %w", err)
	}

	if expectedPublisher == "" {
		return nil
	}

	if !info.Valid {
		return fmt.Errorf("probe signature is not valid (status: %s) â€” refusing to spawn an unverified binary", info.Status)
	}
	if !strings.Contains(info.Signer, expectedPublisher) {
		return fmt.Errorf("probe signer %q does not match expected publisher %q", info.Signer, expectedPublisher)
	}
	return nil
}
