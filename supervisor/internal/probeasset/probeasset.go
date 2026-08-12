// Package probeasset carries the Rust probe binary inside the agent's own executable, so that the
// candidate downloads and runs exactly one file.
//
// One file is a product requirement, not a convenience. The agent is run once, by someone who did
// not choose to run it, minutes before a job interview. Every extra artifact is another step they
// can get wrong and another thing that looks like it is hiding something.
//
// # Why extract a second process instead of linking the probe in
//
// The probe runs as a separate process on purpose. A misbehaving audio driver, or a device removed
// mid-interview, kills the probe rather than the agent, and probehost restarts it inside the same
// session without disturbing the candidate's consent or the mirror window (internal/probehost's
// package doc has the reasoning, and cmd/cp-agent's crash-recovery test proves it against the real
// binary). Linking the Rust in as a library would make that same fault end the interview instead.
// So the goal here is one *file*, not one process, and the two are separable.
//
// # Where it lands, and why not %TEMP%
//
// Extraction writes to the agent's one application directory (see internal/appdir), which on
// Windows is under %LOCALAPPDATA%. Writing an executable into %TEMP% and running it
// is the shape of a malware dropper and is exactly what AV and EDR heuristics score against; a
// stable per-user application directory, written once and reused by content hash across sessions,
// is both quieter and honest about what it is. Nothing else is created: no registry keys, no
// service, no autostart, no Start-menu entry. The agent is still not "installed" in any sense that
// requires uninstalling.
//
// # Trusting the extracted copy
//
// The file is hash-checked against the embedded bytes on every run, so a leftover, corrupt, or
// deliberately swapped copy is rewritten rather than trusted. That matters because %LOCALAPPDATA%
// is writable by the candidate, who has an obvious motive to replace a probe that reports on them
// with one that reports nothing. It is defence in depth rather than the primary control:
// probehost still verifies the probe's Authenticode signature before spawning it, which is the
// check that actually binds the binary to a publisher.
//
// # Dev builds have no embedded probe
//
// Without the `embedprobe` build tag -- the default, and what `go build ./...` and `go test ./...`
// use -- there is no embedded probe and [Available] reports false. The agent then falls back to a
// probe-serve.exe sitting beside it, which is the layout a local cargo+go build already produces.
// Release builds copy the freshly-built probe into this directory and build with -tags embedprobe.
// A missing probe therefore breaks the release build loudly at compile time instead of shipping an
// agent that discovers at runtime, in front of a candidate, that it has nothing to run.
package probeasset

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/enteam-ai/entm-desktop-agent/supervisor/internal/appdir"
)

// Available reports whether this build carries an embedded probe.
func Available() bool { return len(embedded) > 0 }

// Extract writes the embedded probe to a per-user application directory and returns its path,
// reusing an already-correct copy from a previous session rather than rewriting it.
//
// The filename is content-addressed. An agent upgrade therefore lands beside the old copy instead
// of racing to overwrite a file some other process may still hold open, and two agent versions on
// one machine cannot be confused for each other.
func Extract() (string, error) {
	if len(embedded) == 0 {
		return "", errors.New("this build has no embedded probe (built without -tags embedprobe)")
	}

	dir, err := appdir.Ensure()
	if err != nil {
		return "", err
	}
	return extractTo(dir, embedded)
}

// extractTo is Extract with the directory and the payload passed in, so the behaviour that actually
// matters -- reuse, and replacement of a copy that no longer matches -- is testable against a real
// filesystem in any build, rather than only in one built with -tags embedprobe.
func extractTo(dir string, data []byte) (string, error) {
	sum := sha256.Sum256(data)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}

	path := filepath.Join(dir, "probe-serve-"+hex.EncodeToString(sum[:8])+".exe")
	if ok, err := matches(path, sum); err != nil {
		return "", err
	} else if ok {
		return path, nil
	}

	if err := writeAtomic(path, data); err != nil {
		return "", err
	}
	return path, nil
}

// matches reports whether path already holds exactly the embedded bytes. A file that is absent is
// not an error; a file that cannot be read is, because silently rewriting over something unreadable
// would hide a real problem with the directory.
func matches(path string, want [32]byte) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read the extracted probe at %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, fmt.Errorf("read the extracted probe at %s: %w", path, err)
	}
	var got [32]byte
	copy(got[:], h.Sum(nil))
	return got == want, nil
}

// writeAtomic writes to a temporary file in the same directory and renames it into place, so a
// crash or a full disk mid-write cannot leave a truncated executable behind for the next session to
// find, hash-check, and rewrite -- or worse, for probehost to try to spawn.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)

	f, err := os.CreateTemp(dir, ".probe-serve-*.tmp")
	if err != nil {
		return fmt.Errorf("stage the probe in %s: %w", dir, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once the rename below has succeeded

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write the probe to %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("flush the probe to %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}

	// Windows will not rename onto an existing file. Reaching here means the existing copy failed
	// its hash check, so replacing it is the intent; a failure to remove it almost always means
	// another process still holds it open, which is worth saying plainly.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("replace the existing probe at %s (is another agent still running?): %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("move the probe into place at %s: %w", path, err)
	}
	return nil
}
