package winguard

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A second CreateMutexW call for the same name always reports ERROR_ALREADY_EXISTS, regardless of
// which process (or, as here, which call) created it first — this is a real property of the named
// kernel object, not a simulation of it, so exercising it twice in one process is a genuine test.
func TestAcquireSingleInstanceRefusesASecondHolder(t *testing.T) {
	name := fmt.Sprintf(`Local\entm-teams-winguard-test-%d-%d`, os.Getpid(), time.Now().UnixNano())

	held1, release1, err := AcquireSingleInstance(name)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if !held1 {
		t.Fatal("expected the first acquire to succeed")
	}
	defer release1()

	held2, release2, err := AcquireSingleInstance(name)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if held2 {
		t.Fatal("expected the second acquire to be refused while the first is still held")
	}
	if release2 != nil {
		t.Error("expected a nil release func when the instance was not acquired")
	}

	release1()

	held3, release3, err := AcquireSingleInstance(name)
	if err != nil {
		t.Fatalf("third acquire: %v", err)
	}
	if !held3 {
		t.Fatal("expected acquire to succeed again once the first holder released it")
	}
	if release3 != nil {
		release3()
	}
}

// This is the actual scenario the job object exists for: the agent (this process, standing in for
// cp-agent.exe) dies without cleanly stopping the probe first. Windows closes a dying process's
// handles automatically, so closing the job handle here is exactly what happens on an abrupt kill —
// not a simulation of it, the real mechanism, exercised directly against a real child process.
func TestJobObjectKillsAssignedProcessWhenItsHandleCloses(t *testing.T) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper process: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }() // safety net if the mechanism under test fails

	job, err := NewProcessJob()
	if err != nil {
		t.Fatalf("NewProcessJob: %v", err)
	}

	if err := AssignPID(job, cmd.Process.Pid); err != nil {
		t.Fatalf("AssignPID: %v", err)
	}

	if err := windows.CloseHandle(job); err != nil {
		t.Fatalf("CloseHandle(job): %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
		// The 30s sleep did not run to completion — the job's kill-on-close limit ended it.
	case <-time.After(5 * time.Second):
		t.Fatal("process was not killed within 5s of the job handle closing")
	}
}
