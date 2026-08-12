// Package winguard holds the two Windows-specific lifecycle guarantees the agent needs and Go's
// standard library has no notion of: that only one copy of the agent runs on a machine at a time,
// and that a probe subprocess cannot outlive the agent that spawned it.
package winguard

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutexW = modkernel32.NewProc("CreateMutexW")
)

// AcquireSingleInstance tries to become the only running copy of the agent under `name`, a
// well-known, product-specific name shared by every launch. If another instance already holds it,
// `held` is false and the caller must not proceed — two collectors sampling the same machine under
// two sessions is a coverage-integrity problem this product has no honest way to represent.
//
// `CreateMutexW` returns a valid handle to the EXISTING object when one already exists — the
// distinguishing signal lives in the low-level error code (`ERROR_ALREADY_EXISTS`), not in whether
// the call "failed". golang.org/x/sys/windows's own `CreateMutex` wrapper discards that code on the
// success path (it only sets `err` when the handle itself is invalid), so this calls the raw
// syscall directly to read it — `LazyProc.Call`'s error return is always the last-error value from
// that exact call, which is what makes reading it here race-free.
func AcquireSingleInstance(name string) (held bool, release func(), err error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false, nil, fmt.Errorf("encode mutex name: %w", err)
	}

	r0, _, e1 := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(namePtr)))
	handle := windows.Handle(r0)
	if handle == 0 {
		return false, nil, fmt.Errorf("CreateMutexW: %w", e1)
	}

	if e1 == windows.ERROR_ALREADY_EXISTS {
		_ = windows.CloseHandle(handle)
		return false, nil, nil
	}

	return true, func() { _ = windows.CloseHandle(handle) }, nil
}

// NewProcessJob creates a Windows Job Object that kills every process still assigned to it the
// instant its last handle closes — including when THIS process is killed abruptly (Task Manager
// "End task", a crash, a forced TerminateProcess), since Windows closes a dying process's handles
// automatically. The returned handle must stay open for the agent's entire lifetime: closing it
// early kills whatever it still holds, and never closing it at all is exactly the point — the OS
// does that for us on exit.
func NewProcessJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject: %w", err)
	}

	return job, nil
}

// AssignPID ties the process identified by pid to job. The probe is spawned via os/exec, which
// exposes a PID but not a Windows handle directly, so this opens one purely for the assignment call
// — the job tracks the process internally afterward independent of this handle staying open.
func AssignPID(job windows.Handle, pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		return fmt.Errorf("AssignProcessToJobObject(%d): %w", pid, err)
	}
	return nil
}
