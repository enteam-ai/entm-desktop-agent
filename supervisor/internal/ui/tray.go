// System tray icon — a visible presence for the running agent outside the mirror window, so the
// candidate can find and re-open (or stop) it after minimizing or closing the window to the
// background, and so "is this thing still running" has an answer that doesn't require Task
// Manager.
//
// Runs on its OWN, separately OS-thread-locked goroutine with its own Win32 message loop —
// deliberately not sharing App's thread/loop. Shell_NotifyIconW's callback messages are delivered
// to whatever window owns the icon, and Windows has no requirement that that window share a
// thread with any other window in the process; giving the tray icon its own thread means it
// cannot be starved by (or itself starve) the WebView2 message pump App.Run already owns, and
// either one can be created, run, and torn down independently of the other's lifecycle.
//
// Hand-rolled directly against user32.dll/shell32.dll rather than a third-party systray package:
// every mainstream Go systray library (including the most widely used one) is built to OWN the
// process's message loop via its own blocking Run(onReady, onExit) call, which cannot coexist
// with go-webview2's App.Run also blocking on GetMessage for its own window on a shared thread.
// Two independent single-purpose message loops on two independent locked threads sidesteps that
// conflict entirely, and the Win32 surface this needs (RegisterClassExW, CreateWindowExW,
// Shell_NotifyIconW, a two-item popup menu) is small enough that hand-declaring it — the same
// "measured, not assumed" standard the Rust probes hold themselves to — is less risk than fighting
// a library's ownership assumptions.
package ui

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32  = windows.NewLazySystemDLL("user32.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")

	procRegisterClassExW   = user32.NewProc("RegisterClassExW")
	procUnregisterClassW   = user32.NewProc("UnregisterClassW")
	procCreateWindowExW    = user32.NewProc("CreateWindowExW")
	procDefWindowProcW     = user32.NewProc("DefWindowProcW")
	procDestroyWindow      = user32.NewProc("DestroyWindow")
	procGetMessageW        = user32.NewProc("GetMessageW")
	procTranslateMessage   = user32.NewProc("TranslateMessage")
	procDispatchMessageW   = user32.NewProc("DispatchMessageW")
	procPostQuitMessage    = user32.NewProc("PostQuitMessage")
	procPostThreadMessageW = user32.NewProc("PostThreadMessageW")
	procLoadIconW          = user32.NewProc("LoadIconW")
	procCreatePopupMenu    = user32.NewProc("CreatePopupMenu")
	procAppendMenuW        = user32.NewProc("AppendMenuW")
	procDestroyMenu        = user32.NewProc("DestroyMenu")
	procTrackPopupMenu     = user32.NewProc("TrackPopupMenuEx")
	procSetForegroundWin   = user32.NewProc("SetForegroundWindow")
	procShowWindow         = user32.NewProc("ShowWindow")
	procGetCursorPos       = user32.NewProc("GetCursorPos")

	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")

	// trayInstanceCounter gives each Tray its own window class name. A fixed, shared name would
	// make a second StartTray call within the same process fail RegisterClassExW outright
	// ("class already exists") — production only ever calls StartTray once per process, but
	// nothing about the type should silently assume that from the outside, and this is what makes
	// two Trays in one process (this package's own tests, for one) actually independent instead
	// of colliding.
	trayInstanceCounter atomic.Uint64
)

const (
	wsExToolWindow = 0x00000080
	wsPopup        = 0x80000000
	cwUseDefault   = -2147483648 // 0x80000000 as int32, exported as an untyped constant for CreateWindowExW's x/y/w/h params

	wmDestroy       = 0x0002
	wmApp           = 0x8000
	wmRButtonUp     = 0x0205
	wmLButtonDblClk = 0x0203
	wmCommand       = 0x0111

	nimAdd     = 0x00000000
	nimDelete  = 0x00000002
	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004

	idiApplication = 32512 // stock icon resource id — a placeholder, same staging as the Teams manifest's placeholder icons

	trayCallbackMsg = wmApp + 1
	// msgQuit is Stop's shutdown signal, posted via PostThreadMessageW — see Stop's doc comment
	// for why this must be a custom message rather than WM_DESTROY itself.
	msgQuit    = wmApp + 2
	menuIDShow = 1
	menuIDStop = 2

	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100

	swRestore = 9
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type msg struct {
	hwnd    windows.Handle
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

type point struct{ x, y int32 }

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             windows.Handle
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            windows.Handle
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uTimeoutOrVer    uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     windows.Handle
}

// Tray is one running tray icon. Nil-safe on every method — matches App's own style — so a
// caller that skipped Start (or hit an error creating it) can still call Stop unconditionally at
// shutdown.
type Tray struct {
	mu        sync.Mutex
	hwnd      windows.Handle
	threadID  uint32
	className *uint16
	stopped   chan struct{}
}

// StartTray creates and shows the tray icon, and returns once it is either fully up or has failed
// — every step (RegisterClassExW, CreateWindowExW, and Shell_NotifyIconW's own NIM_ADD) has its
// real Win32 return code checked, and the first failure is what StartTray returns; it does not
// assume success from having reached the end without a panic.
//
// onShow is invoked when the candidate left-double-clicks the icon or picks "Show" from its
// context menu; onStop when they pick "Stop monitoring" — the same action the mirror window's own
// button already triggers, wired through the same onStop callback App.ShowMirror was given.
func StartTray(title string, onShow func(), onStop func()) (*Tray, error) {
	ready := make(chan error, 1)
	t := &Tray{stopped: make(chan struct{})}

	go func() {
		// LockOSThread: this goroutine's OS thread becomes the tray's dedicated UI thread for its
		// entire life. Never unlocked — the thread exits (and is discarded) when this goroutine
		// returns, at Stop.
		runtime.LockOSThread()

		hwnd, err := t.createWindow(title, onShow, onStop)
		if err != nil {
			ready <- err
			return
		}
		t.mu.Lock()
		t.hwnd = hwnd
		t.mu.Unlock()

		if err := t.addIcon(hwnd, title); err != nil {
			ready <- err
			return
		}
		ready <- nil

		t.messageLoop(hwnd)
		close(t.stopped)
	}()

	if err := <-ready; err != nil {
		return nil, err
	}
	return t, nil
}

// Stop removes the icon and ends its message loop. Safe to call on a nil *Tray or more than once.
//
// The shutdown signal is a CUSTOM thread message (msgQuit), not WM_DESTROY directly: messages
// delivered via PostThreadMessageW carry hwnd == 0 (they are not associated with any window), so
// DispatchMessageW never routes them through a WndProc — only the message loop itself, reading
// msg.message directly, ever sees them. The loop responds by calling DestroyWindow on the tray's
// own thread (required — only the thread that created a window may destroy it), which is what
// actually generates a real WM_DESTROY dispatched to the WndProc below, which calls
// PostQuitMessage, which is what ends GetMessage's loop. Skipping the custom message and posting
// WM_DESTROY directly here would silently hang Stop forever, since it would never reach WndProc.
func (t *Tray) Stop() {
	if t == nil {
		return
	}
	t.mu.Lock()
	hwnd := t.hwnd
	threadID := t.threadID
	t.mu.Unlock()
	if hwnd == 0 {
		return
	}

	nid := notifyIconDataW{cbSize: uint32(unsafe.Sizeof(notifyIconDataW{})), hWnd: hwnd}
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))

	if threadID != 0 {
		procPostThreadMessageW.Call(uintptr(threadID), msgQuit, 0, 0)
	}
	<-t.stopped
}

func (t *Tray) createWindow(title string, onShow func(), onStop func()) (windows.Handle, error) {
	instance := trayInstanceCounter.Add(1)
	className, err := windows.UTF16PtrFromString(fmt.Sprintf("EnteamTrayWndClass-%d", instance))
	if err != nil {
		return 0, err
	}
	t.mu.Lock()
	t.className = className
	t.mu.Unlock()

	wndProc := windows.NewCallback(func(hwnd windows.Handle, message uint32, wParam, lParam uintptr) uintptr {
		switch message {
		case trayCallbackMsg:
			switch lParam {
			case wmRButtonUp:
				t.showContextMenu(hwnd)
			case wmLButtonDblClk:
				if onShow != nil {
					onShow()
				}
			}
			return 0
		case wmCommand:
			switch wParam {
			case menuIDShow:
				if onShow != nil {
					onShow()
				}
			case menuIDStop:
				if onStop != nil {
					onStop()
				}
			}
			return 0
		case wmDestroy:
			procPostQuitMessage.Call(0)
			return 0
		}
		ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(message), wParam, lParam)
		return ret
	})

	wc := wndClassExW{
		lpfnWndProc:   wndProc,
		lpszClassName: className,
	}
	wc.cbSize = uint32(unsafe.Sizeof(wc))
	r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if r == 0 {
		return 0, fmt.Errorf("tray: RegisterClassExW: %w", err)
	}

	titlePtr, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return 0, err
	}

	hwnd, _, err := procCreateWindowExW.Call(
		wsExToolWindow,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(titlePtr)),
		wsPopup,
		0, 0, 0, 0,
		0, 0, 0, 0,
	)
	if hwnd == 0 {
		return 0, fmt.Errorf("tray: CreateWindowExW: %w", err)
	}

	t.mu.Lock()
	t.threadID = windows.GetCurrentThreadId()
	t.mu.Unlock()

	return windows.Handle(hwnd), nil
}

func (t *Tray) addIcon(hwnd windows.Handle, tooltip string) error {
	hIcon, _, _ := procLoadIconW.Call(0, idiApplication)
	if hIcon == 0 {
		return fmt.Errorf("tray: LoadIconW: no stock icon available")
	}

	nid := notifyIconDataW{
		cbSize:           uint32(unsafe.Sizeof(notifyIconDataW{})),
		hWnd:             hwnd,
		uID:              1,
		uFlags:           nifMessage | nifIcon | nifTip,
		uCallbackMessage: trayCallbackMsg,
		hIcon:            windows.Handle(hIcon),
	}
	copy(nid.szTip[:], windows.StringToUTF16(truncateForTip(tooltip)))

	ok, _, err := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
	if ok == 0 {
		return fmt.Errorf("tray: Shell_NotifyIconW(NIM_ADD): %w", err)
	}
	return nil
}

func (t *Tray) showContextMenu(hwnd windows.Handle) {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	showLabel, _ := windows.UTF16PtrFromString("What your interviewer sees")
	stopLabel, _ := windows.UTF16PtrFromString("Stop monitoring")
	procAppendMenuW.Call(hMenu, 0, menuIDShow, uintptr(unsafe.Pointer(showLabel)))
	procAppendMenuW.Call(hMenu, 0, menuIDStop, uintptr(unsafe.Pointer(stopLabel)))

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	// SetForegroundWindow before tracking the menu: the documented workaround for a popup menu
	// that otherwise fails to dismiss itself when the user clicks away, because a tray-owned
	// window is never the foreground window by default.
	procSetForegroundWin.Call(uintptr(hwnd))
	procTrackPopupMenu.Call(hMenu, tpmRightButton|tpmReturnCmd, uintptr(pt.x), uintptr(pt.y), 0, uintptr(hwnd), 0)
}

func (t *Tray) messageLoop(hwnd windows.Handle) {
	for {
		var m msg
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 { // 0 = WM_QUIT, -1 = error; both end the loop
			return
		}
		if m.message == msgQuit {
			// Thread-posted (hwnd == 0 on the message itself); DestroyWindow must run on this
			// same thread, and doing so is what generates the real WM_DESTROY the WndProc below
			// turns into PostQuitMessage — see Stop's doc comment for the full chain.
			procDestroyWindow.Call(uintptr(hwnd))
			// No window uses this class anymore, so it's safe to free the registration here — a
			// class name is process-global namespace, and leaving it registered would make a
			// second StartTray in this same process pick a fresh instance-numbered name (fine)
			// but leak the old registration for the life of the process (not fine over many
			// start/stop cycles, even though production only ever starts one).
			t.mu.Lock()
			className := t.className
			t.mu.Unlock()
			if className != nil {
				procUnregisterClassW.Call(uintptr(unsafe.Pointer(className)), 0)
			}
			continue
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// showMainWindow brings hwnd (App's own webview.Window()) to the foreground — App.BringToFront
// is the exported entry point every caller outside this file actually uses.
func showMainWindow(hwnd unsafe.Pointer) {
	if hwnd == nil {
		return
	}
	h := windows.Handle(uintptr(hwnd))
	procShowWindow.Call(uintptr(h), swRestore)
	procSetForegroundWin.Call(uintptr(h))
}

func truncateForTip(s string) string {
	// szTip is WCHAR[128] including the NUL terminator; leave room for it.
	const max = 127
	r := []rune(s)
	if len(r) > max {
		return string(r[:max])
	}
	return s
}
