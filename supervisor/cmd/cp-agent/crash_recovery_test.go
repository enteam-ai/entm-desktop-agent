package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/enteam-ai/entm-desktop-agent/supervisor/internal/probehost"
)

// probeServePath locates the real probe-serve.exe built from agent/probe-core. This test exercises
// restartProbe against the actual Rust binary, not a stub â€” the same reasoning that governs every
// other probe check this session: a crash-recovery path that has never seen a real crash is
// unverified, not working.
func probeServePath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("probe-serve is Windows-only")
	}
	abs, err := filepath.Abs(filepath.Join("..", "..", "..", "probe-core", "target", "debug", "probe-serve.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Skipf("probe-serve.exe not built at %s â€” run `cargo build -p cp-win --bins` first", abs)
	}
	return abs
}

// This is the scenario progress.md describes as untested: "a probe death currently ends the
// session instead of restarting." It launches the real probe, kills it out from under the
// supervisor exactly as a crash would, and confirms restartProbe brings back a working one.
func TestRestartProbeRecoversFromADeadProcess(t *testing.T) {
	probePath := probeServePath(t)

	host, err := probehost.Start(probePath, "", 0)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := host.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	const session = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	const instance = "9c5b94b1-35ad-49bb-b118-8e8fc24abf80"
	// A brand-new process has a cold S2 signature cache (~4s measured against every readable
	// process â€” see probehost's ScanWithTimeout doc), so this uses the generous warm-up timeout
	// rather than Scan()'s default, exactly as cmd/cp-agent's real startup path now does.
	if _, err := host.ScanWithTimeout(session, instance, 1, 1000, probeWarmupTimeout); err != nil {
		t.Fatalf("scan before kill: %v", err)
	}

	// Simulate the probe dying out from under the supervisor. Close() ends the process the same
	// way a real crash leaves it: gone, stdin/stdout severed â€” it is not standing in for a clean
	// shutdown here, it is the mechanism under test's own kill path, reused to cause the failure.
	host.Close()

	if _, err := host.Scan(session, instance, 2, 1000); err == nil {
		t.Fatal("expected Scan against a dead probe to fail â€” the precondition for restarting")
	}

	newHost, err := restartProbe(probePath, "", 0)
	if err != nil {
		t.Fatalf("restartProbe did not recover: %v", err)
	}
	defer newHost.Close()

	if _, err := newHost.ScanWithTimeout(session, instance, 1, 1000, probeWarmupTimeout); err != nil {
		t.Fatalf("scan after restart: %v", err)
	}
}

// restartProbe must give up rather than retry forever against a path that can never work â€” an
// unbounded retry loop would itself be a way to fail the 60-minute unattended exit criterion.
func TestRestartProbeGivesUpOnANonexistentBinary(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("probe-serve is Windows-only")
	}
	_, err := restartProbe(filepath.Join(t.TempDir(), "does-not-exist.exe"), "", 0)
	if err == nil {
		t.Fatal("expected restartProbe to fail against a nonexistent binary")
	}
}
