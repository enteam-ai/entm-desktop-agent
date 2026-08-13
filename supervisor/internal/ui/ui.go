// Package ui owns the one window the candidate sees, in its two states: the consent gate and the
// live mirror.
//
// These are not decoration. They are two of the three non-negotiables in the product spec — the
// candidate sees the same feed, and quit is always one click — and they are what separates a
// consent-based transparency tool from covert monitoring under GDPR Art. 6(1)(a) and BIPA.
//
// WebView2 is used rather than native Win32 because the runtime ships with Windows 11 and the same
// markup renders unchanged if macOS is ever picked up again. No cgo: the binding is pure Go.
//
// One window, not two. An earlier version created a second, independent WebView2 window for the
// mirror after fully destroying the consent window. WebView2 defaults its user-data folder to
// %AppData%\<exe name>\EBWebView — keyed by executable, not by window — so the second environment
// was created against the same profile directory the first was still tearing down against. Observed
// on a real run: the mirror window opened blank and closed itself, with no click from the
// candidate. Reusing a single window/environment across both views (SetHtml swaps the page in
// place) avoids the whole class of bug rather than trying to win the teardown race.
package ui

import (
	_ "embed"
	"runtime"
	"sync"

	webview "github.com/jchv/go-webview2"
)

//go:embed assets/consent.html
var consentHTML string

//go:embed assets/mirror.html
var mirrorHTML string

// Decision is the candidate's answer to the consent gate.
type Decision int

const (
	// Declined covers both an explicit decline and closing the window. Silence is not consent.
	Declined Decision = iota
	Granted
)

// App is the one native window used for both the consent gate and, once granted, the live mirror.
type App struct {
	w webview.WebView
}

// NewApp creates the window. Returns nil if no WebView2 runtime is present — the caller must not
// proceed to monitor without it; there is no non-GUI fallback for consent.
func NewApp() *App {
	runtime.LockOSThread()

	w := webview.NewWithOptions(webview.WebViewOptions{
		Debug: false,
		WindowOptions: webview.WindowOptions{
			Title:  "Interview monitoring — your consent",
			Width:  760,
			Height: 640,
		},
	})
	if w == nil {
		return nil
	}
	return &App{w: w}
}

// AskConsent shows the consent gate and blocks until the candidate answers or closes the window.
//
// Nothing else in the agent may run before this returns Granted. Declining — including closing the
// window — is a supported outcome, not an error: the interview proceeds and the panel simply says
// monitoring was declined.
func (a *App) AskConsent() Decision {
	decision := Declined // default: closing the window is a decline
	var once sync.Once

	a.w.Bind("accept", func() {
		once.Do(func() {
			decision = Granted
			a.w.Terminate()
		})
	})
	a.w.Bind("decline", func() {
		once.Do(func() {
			a.w.Terminate()
		})
	})

	a.w.SetHtml(consentHTML)
	a.w.Run()

	return decision
}

// ShowMirror switches the same window from the consent gate to the live mirror. onStop is called
// when the candidate clicks "Stop monitoring" inside the page — closing the window itself (the
// native X) does not route through this binding; see the package doc on App.Run for how that path
// is still caught.
func (a *App) ShowMirror(onStop func()) {
	a.w.Bind("stopMonitoring", func() {
		onStop()
		a.w.Terminate()
	})
	a.w.SetTitle("What your interviewer sees")
	a.w.SetHtml(mirrorHTML)
}

// ShowCoverage renders the coverage row. Called at handshake and on any change.
func (a *App) ShowCoverage(report []byte) {
	a.eval("renderCoverage", report)
}

// ShowSample renders one reading. Safe to call from a background goroutine.
func (a *App) ShowSample(envelope []byte) {
	a.eval("renderSample", envelope)
}

func (a *App) eval(fn string, payload []byte) {
	if a == nil || a.w == nil || len(payload) == 0 {
		return
	}
	js := fn + "(" + string(payload) + ")"
	a.w.Dispatch(func() { a.w.Eval(js) })
}

// Run blocks on the UI message loop until the window closes, by any means: "Stop monitoring",
// declining consent, or the native close button. The caller distinguishes candidate- from
// collector-initiated endings itself (see cmd/cp-agent); Run makes no claim about which happened,
// only that the window is gone. Call Destroy once, after the last Run returns — Run may be called
// more than once on the same App (consent, then mirror), so it does not tear the window down
// itself.
func (a *App) Run() {
	if a == nil || a.w == nil {
		return
	}
	a.w.Run()
}

// BringToFront restores and focuses the window — the tray icon's "Show" action and double-click
// both route here, since a candidate who minimized or lost track of the mirror window needs a way
// back to it that doesn't require Task Manager.
func (a *App) BringToFront() {
	if a == nil || a.w == nil {
		return
	}
	showMainWindow(a.w.Window())
}

// Close ends the current UI message loop from a background goroutine — used when the collector
// itself decides the session is over (e.g. the probe could not be restarted) and something has to
// make Run return.
func (a *App) Close() {
	if a != nil && a.w != nil {
		a.w.Terminate()
	}
}

// Destroy releases the native window. Call exactly once, after the final Run has returned.
func (a *App) Destroy() {
	if a != nil && a.w != nil {
		a.w.Destroy()
	}
}
