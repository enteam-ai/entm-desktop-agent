//go:build embedprobe

package probeasset

import _ "embed"

// probe-serve.exe is a build input, not source: the release build copies it here from
// probe-core/target/release before compiling. It is gitignored for that reason -- committing a
// binary into the repository that exists to prove what the source does would defeat the point.
//
//go:embed probe-serve.exe
var embedded []byte
