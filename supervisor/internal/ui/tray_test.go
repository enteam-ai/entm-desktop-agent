package ui

import (
	"testing"
	"time"
)

// A real tray icon, created and torn down against the actual Win32 APIs — RegisterClassExW,
// CreateWindowExW, Shell_NotifyIconW(NIM_ADD), then Stop's full shutdown handshake
// (Shell_NotifyIconW(NIM_DELETE), a thread-posted msgQuit, DestroyWindow, the real WM_DESTROY it
// generates, PostQuitMessage, GetMessage returning WM_QUIT).
//
// This is specifically a regression test for a real bug found and fixed while writing Stop: a
// message posted via PostThreadMessageW carries hwnd == 0, so DispatchMessageW never routes it
// through a WndProc — sending WM_DESTROY directly that way would have made Stop hang forever,
// waiting on <-t.stopped, because the WndProc's PostQuitMessage would never run. Stop is run in
// its own goroutine here specifically so a regression that reintroduces that hang fails this test
// (it times out) instead of hanging `go test` itself indefinitely.
func TestStartTrayCreatesAndStopsCleanly(t *testing.T) {
	var showCalls, stopCalls int
	tray, err := StartTray("cp-agent tray test", func() { showCalls++ }, func() { stopCalls++ })
	if err != nil {
		t.Fatalf("StartTray: %v", err)
	}
	if tray == nil {
		t.Fatal("expected a non-nil Tray")
	}

	done := make(chan struct{})
	go func() {
		tray.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return within 5s — the PostThreadMessageW/WM_DESTROY shutdown handshake is hung")
	}
}

// Stop must be safe to call on a nil *Tray (StartTray failed, or was never called) and safe to
// call more than once — main.go's own `defer tray.Stop()` relies on both.
func TestTrayStopIsNilSafeAndIdempotent(t *testing.T) {
	var nilTray *Tray
	nilTray.Stop() // must not panic

	tray, err := StartTray("cp-agent tray idempotency test", nil, nil)
	if err != nil {
		t.Fatalf("StartTray: %v", err)
	}

	done := make(chan struct{})
	go func() {
		tray.Stop()
		tray.Stop() // second call must not hang or panic
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a second Stop() call hung")
	}
}
