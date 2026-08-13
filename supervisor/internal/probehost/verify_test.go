package probehost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Run against real files, the same discipline as cp-win's S2 Authenticode work: a known-signed
// system binary and the (currently unsigned) probe binary this session actually builds.
func TestVerifyAuthenticodeAgainstAKnownSignedBinary(t *testing.T) {
	path := filepath.Join(os.Getenv("WINDIR"), "System32", "notepad.exe")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("notepad.exe not found at %s", path)
	}

	info, err := verifyAuthenticode(path)
	if err != nil {
		t.Fatalf("verifyAuthenticode: %v", err)
	}
	if !info.Valid {
		t.Errorf("expected notepad.exe to have a valid signature, got status %q", info.Status)
	}
	if info.Signer == "" {
		t.Error("expected a non-empty signer for a validly-signed system binary")
	}
	t.Logf("notepad.exe: status=%s signer=%s", info.Status, info.Signer)
}

// Regression test for the failure this check hit on windows-latest: Get-AuthenticodeSignature lives
// in the autoloaded module Microsoft.PowerShell.Security, and a machine with PowerShell 7 installed
// puts pwsh's module directory on PSModulePath. Those modules declare CompatiblePSEditions='Core',
// which Windows PowerShell 5.1 resolves first and then refuses to load — so the cmdlet is "found"
// and unusable, and the whole signature check fails.
//
// A candidate with PowerShell 7 installed is an ordinary case, not an exotic one, so this must keep
// working regardless of what is on the inherited PSModulePath.
func TestVerifyAuthenticodeSurvivesAPowerShell7ModulePath(t *testing.T) {
	target := filepath.Join(os.Getenv("WINDIR"), "System32", "notepad.exe")
	if _, err := os.Stat(target); err != nil {
		t.Skipf("notepad.exe not found at %s", target)
	}

	// A stand-in for pwsh's own copy of the module: same name, Core-only, ahead of the real one.
	fake := t.TempDir()
	modDir := filepath.Join(fake, "Microsoft.PowerShell.Security")
	if err := os.MkdirAll(modDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `@{
  ModuleVersion = '7.4.0'
  GUID = 'a94c8c7e-9810-47c0-b8af-65089c13a35a'
  CompatiblePSEditions = @('Core')
  PowerShellVersion = '7.0'
  RootModule = 'Microsoft.PowerShell.Security.dll'
  CmdletsToExport = @('Get-AuthenticodeSignature')
}`
	if err := os.WriteFile(filepath.Join(modDir, "Microsoft.PowerShell.Security.psd1"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PSModulePath", fake+string(os.PathListSeparator)+os.Getenv("PSModulePath"))

	info, err := verifyAuthenticode(target)
	if err != nil {
		t.Fatalf("the signature check must not depend on the inherited PSModulePath: %v", err)
	}
	if !info.Valid {
		t.Errorf("expected notepad.exe to verify even with a Core-only module shadowing the real one, got status %q", info.Status)
	}
}

func TestVerifyAuthenticodeAgainstTheUnsignedProbeBuild(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "probe-core", "target", "debug", "probe-serve.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("probe-serve.exe not built at %s", path)
	}

	info, err := verifyAuthenticode(path)
	if err != nil {
		t.Fatalf("verifyAuthenticode: %v", err)
	}
	// Dev builds are unsigned today — no EV certificate has been ordered yet. This is exactly what
	// verifyBeforeSpawn's unarmed mode exists for.
	if info.Valid {
		t.Errorf("expected the dev probe build to be unsigned, got status %q", info.Status)
	}
	t.Logf("probe-serve.exe: status=%s", info.Status)
}

func TestVerifyBeforeSpawnIsUnarmedWithNoExpectedPublisher(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "probe-core", "target", "debug", "probe-serve.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("probe-serve.exe not built at %s", path)
	}

	if err := verifyBeforeSpawn(path, ""); err != nil {
		t.Errorf("expected no error with an empty expected publisher (unarmed pre-signing), got: %v", err)
	}
}

func TestVerifyBeforeSpawnRefusesAMismatchedPublisher(t *testing.T) {
	path := filepath.Join(os.Getenv("WINDIR"), "System32", "notepad.exe")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("notepad.exe not found at %s", path)
	}

	// Asserting only "some error came back" is not enough, and this test proved it: on a machine
	// where verifyAuthenticode itself fails, verifyBeforeSpawn returns "could not verify probe
	// signature", which is an error, so the weaker assertion went green while the mechanism under
	// test was entirely broken. A refusal test has to name the refusal it expects, or it cannot
	// fail for its own subject.
	err := verifyBeforeSpawn(path, "O=Some Publisher That Is Not Microsoft")
	if err == nil {
		t.Fatal("expected an error when the signer does not match the expected publisher")
	}
	if !strings.Contains(err.Error(), "does not match expected publisher") {
		t.Fatalf("expected a publisher-mismatch refusal, got a different failure: %v", err)
	}
}

func TestVerifyBeforeSpawnAcceptsAMatchingPublisher(t *testing.T) {
	path := filepath.Join(os.Getenv("WINDIR"), "System32", "notepad.exe")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("notepad.exe not found at %s", path)
	}

	if err := verifyBeforeSpawn(path, "Microsoft"); err != nil {
		t.Errorf("expected a substring match against the real signer to pass, got: %v", err)
	}
}
