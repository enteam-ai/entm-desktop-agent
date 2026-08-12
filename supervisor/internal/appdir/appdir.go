// Package appdir names the one directory this agent is allowed to create on the candidate's
// machine.
//
// It exists so that claim has a single authority. The README tells the candidate that nothing is
// installed and that exactly one folder gets written; two packages independently joining their own
// string onto os.UserCacheDir would let that promise drift silently the moment one of them changed.
// Anything the agent puts on disk, other than the session sink it was told to write, belongs here
// or is a bug.
package appdir

import (
	"fmt"
	"os"
	"path/filepath"
)

// Name is the folder created under the per-user application data directory.
const Name = "Enteam"

// Path reports where the directory would be, without creating it.
func Path() (string, error) {
	base, err := os.UserCacheDir() // %LOCALAPPDATA% on Windows
	if err != nil {
		return "", fmt.Errorf("locate the per-user application directory: %w", err)
	}
	return filepath.Join(base, Name), nil
}

// Ensure reports the directory, creating it if it does not exist.
//
// 0o700 rather than something more permissive: the extracted probe and the operational log are this
// user's business and nobody else's on a shared machine.
func Ensure() (string, error) {
	dir, err := Path()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	return dir, nil
}
