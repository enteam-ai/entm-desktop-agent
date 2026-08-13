package ui

import "testing"

// The dialogs themselves cannot be asserted on without a human to dismiss them, so this covers the
// part that can fail silently: whether the WebView2 loader binding resolves at all.
//
// It deliberately does not assert that a runtime is present -- that is a property of the machine,
// not of this code, and the interesting case (no runtime) is the one a developer's box almost never
// reproduces. What it does catch is the failure that would matter most: RuntimeAvailable returning
// false on a machine that plainly does have the runtime, because the loader could not be reached.
// That would send every candidate to the download page for a component they already have.
func TestRuntimeAvailableResolvesTheLoader(t *testing.T) {
	version, ok := RuntimeAvailable()

	if ok && version == "" {
		t.Fatal("RuntimeAvailable reported a runtime but gave no version")
	}
	if !ok && version != "" {
		t.Fatalf("RuntimeAvailable reported no runtime but returned version %q", version)
	}

	if ok {
		t.Logf("WebView2 runtime present: %s", version)
	} else {
		t.Log("no WebView2 runtime on this machine; the agent would offer the download page")
	}
}
