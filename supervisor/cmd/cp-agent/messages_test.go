package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The supervisor hand-builds its lifecycle messages rather than sharing the Rust types, so nothing
// but a schema check can prove they are on-contract. This writes one of each to a file that
// schema_check.py validates against schemas/signal-envelope.v1.json — the same cross-language check
// the Rust side gets, for the same reason: two producers, one contract.
func TestLifecycleMessagesAreWellFormed(t *testing.T) {
	const session = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	const instance = "9c5b94b1-35ad-49bb-b118-8e8fc24abf80"

	msgs := []any{
		event(session, instance, 1, "consent_granted", false),
		event(session, instance, 2, "consent_declined", true),
		event(session, instance, 3, "candidate_quit", true),
		collectorError(session, instance, 4, "api_failure", true, os.ErrDeadlineExceeded),
		collectorError(session, instance, 5, "crash_recovered", true, os.ErrDeadlineExceeded),
		collectorError(session, instance, 6, "crash_recovered", false, os.ErrDeadlineExceeded),
		gapDeclared(session, instance, 7, 41, 45),
		coverageChanged(session, instance, 8, 9, []byte(`{"capabilities":{}}`)),
		sessionEnded(session, instance, 10),
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "events.ndjson")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range msgs {
		encoded, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}

		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("roundtrip: %v", err)
		}

		// The header is duplicated across both schema documents and is required in full. A missing
		// field here is a message the ingest gateway rejects at runtime, which is the expensive
		// place to find out.
		for _, key := range []string{
			"schema_version", "type", "collector_id",
			"collector_instance_id", "session_id", "seq", "ts",
		} {
			if _, ok := decoded[key]; !ok {
				t.Errorf("message missing required header field %q: %s", key, encoded)
			}
		}

		if decoded["type"] != "session_event" {
			t.Errorf("want type session_event, got %v", decoded["type"])
		}

		ev, ok := decoded["event"].(map[string]any)
		if !ok {
			t.Fatalf("event body missing: %s", encoded)
		}

		// A lifecycle event carries no tier, ever. Assigning a risk tier to "candidate declined
		// monitoring" is precisely the verdict this product refuses to render (NG4), and a schema
		// that merely omits the field would not stop someone adding it later.
		if _, present := ev["tier"]; present {
			t.Error("lifecycle event carries a tier; it must not")
		}

		if _, err := f.Write(append(encoded, '\n')); err != nil {
			t.Fatal(err)
		}
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Copy where schema_check.py can find it. Kept out of TempDir's cleanup deliberately.
	out := filepath.Join("testdata", "lifecycle-events.ndjson")
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s for schema validation", out)
}

func TestTimestampMatchesContractPattern(t *testing.T) {
	// UTC with a literal Z and millisecond precision. Offsets are rejected by the schema: evidence
	// timelines get compared across collectors in different timezones.
	ts := nowUTC()
	if len(ts) != len("2026-07-29T10:14:03.221Z") {
		t.Fatalf("timestamp %q is not the contract shape", ts)
	}
	if ts[len(ts)-1] != 'Z' {
		t.Errorf("timestamp %q must end in Z", ts)
	}
	if ts[10] != 'T' || ts[23] != 'Z' {
		t.Errorf("timestamp %q has the wrong layout", ts)
	}
}

func TestNewUUIDIsVersion4(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		u := newUUID()
		if len(u) != 36 {
			t.Fatalf("uuid %q wrong length", u)
		}
		if u[14] != '4' {
			t.Errorf("uuid %q is not version 4", u)
		}
		if c := u[19]; c != '8' && c != '9' && c != 'a' && c != 'b' {
			t.Errorf("uuid %q has wrong variant nibble %q", u, c)
		}
		if seen[u] {
			t.Fatalf("uuid collision on %q", u)
		}
		seen[u] = true
	}
}
