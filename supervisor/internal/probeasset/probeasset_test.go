package probeasset

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/enteam-ai/entm-desktop-agent/supervisor/internal/appdir"
)

// Extraction runs on the candidate's machine, once, immediately after they click Accept and
// immediately before the probe is spawned. There is no operator watching and no second chance, so
// these exercise a real filesystem rather than a stubbed one.

func TestExtractToWritesThePayload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), appdir.Name)
	want := []byte("pretend this is probe-serve.exe")

	path, err := extractTo(dir, want)
	if err != nil {
		t.Fatalf("extractTo: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("extracted bytes differ from the payload:\n got %q\nwant %q", got, want)
	}
}

// A second session must not rewrite a copy that is already correct. Rewriting an executable on
// every run is both pointless disk churn and the repeated-dropper behaviour AV heuristics score
// against, so "already correct" has to mean "left alone", not "written again with the same bytes".
func TestExtractToReusesAnIdenticalCopy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), appdir.Name)
	payload := []byte("pretend this is probe-serve.exe")

	first, err := extractTo(dir, payload)
	if err != nil {
		t.Fatalf("first extractTo: %v", err)
	}

	// Backdate it rather than sleeping: if the second call rewrites the file, the timestamp moves,
	// and this is deterministic where a sleep-and-compare is merely likely.
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(first, old, old); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	before, err := os.Stat(first)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	second, err := extractTo(dir, payload)
	if err != nil {
		t.Fatalf("second extractTo: %v", err)
	}
	if second != first {
		t.Fatalf("same payload resolved to a different path:\n first %s\nsecond %s", first, second)
	}

	after, err := os.Stat(second)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("an already-correct copy was rewritten: mtime moved from %s to %s",
			before.ModTime(), after.ModTime())
	}
}

// The extraction directory is writable by the candidate, who has an obvious motive to swap a probe
// that reports on them for one that reports nothing. The Authenticode check in probehost is the
// control that actually binds the binary to a publisher; this is the cheaper layer in front of it,
// and it has to actually fire.
func TestExtractToReplacesATamperedCopy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), appdir.Name)
	payload := []byte("pretend this is probe-serve.exe")

	path, err := extractTo(dir, payload)
	if err != nil {
		t.Fatalf("extractTo: %v", err)
	}

	tampered := []byte("a probe that reports nothing at all")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("plant the tampered copy: %v", err)
	}

	again, err := extractTo(dir, payload)
	if err != nil {
		t.Fatalf("extractTo after tampering: %v", err)
	}
	if again != path {
		t.Fatalf("tampering changed the resolved path: %s -> %s", path, again)
	}

	got, err := os.ReadFile(again)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if bytes.Equal(got, tampered) {
		t.Fatal("a tampered probe was left in place and would have been spawned")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("tampered copy was replaced with the wrong bytes: %q", got)
	}
}

// Two agent versions on one machine must not collide: an upgrade lands beside the old copy rather
// than racing to overwrite a file a previous session may still hold open.
func TestExtractToIsContentAddressed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), appdir.Name)

	v1, err := extractTo(dir, []byte("probe v1"))
	if err != nil {
		t.Fatalf("v1: %v", err)
	}
	v2, err := extractTo(dir, []byte("probe v2"))
	if err != nil {
		t.Fatalf("v2: %v", err)
	}

	if v1 == v2 {
		t.Fatalf("different payloads resolved to the same path: %s", v1)
	}
	if _, err := os.Stat(v1); err != nil {
		t.Fatalf("extracting v2 disturbed v1: %v", err)
	}
}

// Without -tags embedprobe there is no payload, and Extract must say so rather than return a path
// to nothing -- a dev build that silently produced an empty file would fail later, inside
// probehost, as a much more confusing error.
func TestExtractWithoutAnEmbeddedProbeReportsWhy(t *testing.T) {
	if Available() {
		t.Skip("this build embeds a probe; the no-embed path cannot be exercised here")
	}
	if _, err := Extract(); err == nil {
		t.Fatal("expected Extract to fail in a build with no embedded probe")
	}
}
