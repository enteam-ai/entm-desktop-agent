package probehost

import (
	"os"
	"path/filepath"
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

	if err := verifyBeforeSpawn(path, "O=Some Publisher That Is Not Microsoft"); err == nil {
		t.Error("expected an error when the signer does not match the expected publisher")
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
