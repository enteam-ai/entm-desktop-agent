//go:build !embedprobe

package probeasset

// No embedded probe in a dev build. The agent falls back to a probe-serve.exe sitting next to it,
// which is what a local `cargo build` + `go build` already produces, and it keeps `go build ./...`
// and `go test ./...` working in a fresh checkout with no Rust toolchain present.
var embedded []byte
