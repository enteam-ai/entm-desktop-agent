// Failures the candidate has to actually see.
//
// Every fatal path in this agent used to end at log.Fatal. That is fine when a developer runs it
// from a terminal and reads stderr. It is close to useless for the person this software is actually
// aimed at: someone who double-clicked an executable from their Downloads folder, minutes before a
// job interview, and gets a console window that flashes and disappears -- or, once the release build
// links with -H windowsgui, no window at all. From where they are sitting the program simply did
// nothing, which is both the least helpful and the most suspicious way for it to fail.
//
// A native message box needs no runtime, no window class, and no message loop, so it still works in
// exactly the situation the WebView2 window does not -- which is the situation that matters most
// here. Declared against user32/shell32 directly, reusing the lazy DLL handles tray.go already
// opens, for the same reason tray.go hand-declares its own surface.
package ui

import (
	"runtime"
	"unsafe"

	"github.com/jchv/go-webview2/webviewloader"
	"golang.org/x/sys/windows"
)

var (
	procMessageBoxW   = user32.NewProc("MessageBoxW")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

const (
	mbOK          = 0x00000000
	mbYesNo       = 0x00000004
	mbIconError   = 0x00000010
	mbIconWarning = 0x00000030
	// Without these the dialog can open behind whatever the candidate is looking at, which for a
	// process that has no other window is indistinguishable from it never having opened.
	mbSetForeground = 0x00010000
	mbTopMost       = 0x00040000

	idYes        = 6
	swShowNormal = 1
)

// webView2DownloadURL is Microsoft's own page rather than a direct installer link: sending someone
// a link that downloads an executable is the exact pattern this product spends the rest of its
// effort not resembling, and the page carries Microsoft's branding, which is the reassurance the
// candidate needs at that moment.
const webView2DownloadURL = "https://developer.microsoft.com/microsoft-edge/webview2/"

// RuntimeAvailable reports the installed WebView2 runtime version, and whether there is one at all.
//
// Checked up front rather than inferred from NewApp returning nil. NewApp can fail for more than
// one reason, and "the runtime is missing" is the only one with an action the candidate can take,
// so it deserves to be distinguished before the attempt rather than guessed at afterwards.
func RuntimeAvailable() (string, bool) {
	version, err := webviewloader.GetInstalledVersion()
	if err != nil || version == "" {
		return "", false
	}
	return version, true
}

// ReportFatal tells the candidate, in a window they cannot miss, that monitoring could not start.
//
// It deliberately does not explain what to do: the callers that can offer a real action say so
// themselves (see OfferRuntimeInstall). Inventing advice for a failure the candidate cannot fix
// wastes their time in the minutes before an interview.
func ReportFatal(message string) {
	messageBox("Interview monitoring could not start", message, mbOK|mbIconError)
}

// OfferRuntimeInstall explains the one fatal condition the candidate can actually resolve, and
// opens Microsoft's download page if they want it. Reports whether they accepted.
//
// The per-user note is load-bearing, not filler. The WebView2 Evergreen Runtime installs without
// administrator rights, which is the difference between a one-minute fix and a dead end for a
// candidate on a locked-down corporate laptop -- exactly the population most likely to be missing
// it in the first place.
func OfferRuntimeInstall() bool {
	const message = "This app needs a Microsoft component called the WebView2 Runtime, " +
		"which isn't installed on this PC.\n\n" +
		"It's a free download from Microsoft and takes about a minute. " +
		"You do not need administrator rights.\n\n" +
		"Open the download page now?"

	if messageBox("Interview monitoring could not start", message, mbYesNo|mbIconWarning) != idYes {
		return false
	}
	openURL(webView2DownloadURL)
	return true
}

func messageBox(title, text string, flags uintptr) int {
	textPtr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return 0
	}
	titlePtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return 0
	}

	ret, _, _ := procMessageBoxW.Call(
		0, // no owner window: by the time this is called there may not be one
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		flags|mbSetForeground|mbTopMost,
	)
	runtime.KeepAlive(textPtr)
	runtime.KeepAlive(titlePtr)
	return int(ret)
}

// openURL hands the link to whatever the candidate's default browser is. Failure is ignored on
// purpose: the dialog has already named the component, so a candidate whose machine has no
// registered browser handler can still search for it, and there is nothing useful to say about a
// ShellExecute error at that point.
func openURL(url string) {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return
	}
	target, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return
	}
	procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(target)),
		0,
		0,
		swShowNormal,
	)
	runtime.KeepAlive(verb)
	runtime.KeepAlive(target)
}
