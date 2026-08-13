// Package probehost owns the entire Rustâ†”Go boundary.
//
// The probe emits envelope JSON and the supervisor ships it. That is the whole contract, and it
// lives here and nowhere else â€” no other package in the agent knows that a probe is a separate
// process, speaks NDJSON, or is written in Rust.
//
// The probe runs out-of-process on purpose. COM lives in there, and a fault in a COM call â€” a
// misbehaving audio driver, a device removed mid-interview â€” kills the probe rather than the agent.
// The supervisor notices, restarts it, and records the gap as reduced coverage. Linked in-process,
// the same fault would end the candidate's interview.
package probehost

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/enteam-ai/entm-desktop-agent/supervisor/internal/winguard"
)

// Timeout for a single command. A probe that has not answered in this long is treated as wedged;
// the caller degrades coverage rather than waiting, because a stalled probe and an idle machine
// look identical from here.
const CommandTimeout = 5 * time.Second

type Host struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader

	mu     sync.Mutex
	nextID uint64
	closed bool
}

type command struct {
	ID             uint64 `json:"id"`
	Op             string `json:"op"`
	SessionID      string `json:"session_id,omitempty"`
	InstanceID     string `json:"instance_id,omitempty"`
	Seq            uint64 `json:"seq,omitempty"`
	PollIntervalMs int    `json:"poll_interval_ms,omitempty"`
}

type response struct {
	ID      uint64          `json:"id"`
	OK      bool            `json:"ok"`
	Message json.RawMessage `json:"message"`
	Error   string          `json:"error"`
}

// Start launches the probe process, after verifying its Authenticode signature.
//
// `expectedPublisher` is matched against the certificate subject and empty until an EV certificate
// exists (see `verifyBeforeSpawn`) â€” the agent is the one component a candidate can most easily
// tamper with, and spawning an unverified binary from a path we do not fully control is the
// obvious attack, but that gate cannot go live before there is a real signature to check.
//
// `job` ties the probe's lifetime to the agent's: if it is a valid handle from
// `winguard.NewProcessJob`, the probe is assigned to it, so an abrupt kill of the agent (Task
// Manager "End task", a crash) cannot leave the probe running invisibly after the candidate's
// mirror window is gone. Pass the zero Handle to skip this â€” tests spawning probes with no agent
// lifetime to tie them to have no job to assign into.
func Start(exePath, expectedPublisher string, job windows.Handle) (*Host, error) {
	if err := verifyBeforeSpawn(exePath, expectedPublisher); err != nil {
		return nil, fmt.Errorf("probe signature check: %w", err)
	}

	cmd := exec.Command(exePath)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("probe stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("probe stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start probe %q: %w", exePath, err)
	}

	if job != 0 {
		// Best-effort: the probe is already running and functional either way. Losing this safety
		// net means an abrupt agent kill could leave it orphaned â€” worse hygiene, but no worse
		// than every version of this collector before the job object existed.
		_ = winguard.AssignPID(job, cmd.Process.Pid)
	}

	// A full snapshot on a busy machine runs to a few hundred kilobytes, so this reader must grow
	// rather than cap. bufio.Reader.ReadString appends without limit; bufio.Scanner would silently
	// truncate at its token size, and a truncated envelope is worse than a missing one â€” it looks
	// like valid data.
	return &Host{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdout, 64*1024),
	}, nil
}

// Ping checks the probe is alive and answering.
func (h *Host) Ping() error {
	_, err := h.call(command{Op: "ping"})
	return err
}

// Coverage asks what the collector can and cannot see, measured rather than assumed.
func (h *Host) Coverage(sessionID, instanceID string, seq uint64) (json.RawMessage, error) {
	return h.call(command{
		Op:         "coverage",
		SessionID:  sessionID,
		InstanceID: instanceID,
		Seq:        seq,
	})
}

// Scan takes one full sample, under the default CommandTimeout.
//
// This is only correct once the probe's per-path signature cache is warm â€” see
// [Host.ScanWithTimeout] and its caller in cmd/cp-agent for why the very first scan after any
// (re)start needs a longer allowance and must not use this method.
func (h *Host) Scan(sessionID, instanceID string, seq uint64, pollIntervalMs int) (json.RawMessage, error) {
	return h.callWithTimeout(command{
		Op:             "scan",
		SessionID:      sessionID,
		InstanceID:     instanceID,
		Seq:            seq,
		PollIntervalMs: pollIntervalMs,
	}, CommandTimeout)
}

// ScanWithTimeout is [Host.Scan] with an explicit timeout, for the one caller that cannot use
// CommandTimeout: the first scan after a (re)start, whose S2 signature cache is empty. Measured on
// a real machine: ~4s cold against every readable process, ~30ms once the cache is warm â€” cold is
// close enough to the 5s default that a slower or loaded machine will exceed it, so it must never
// share a timeout with the steady-state 1Hz scans that follow it.
func (h *Host) ScanWithTimeout(sessionID, instanceID string, seq uint64, pollIntervalMs int, timeout time.Duration) (json.RawMessage, error) {
	return h.callWithTimeout(command{
		Op:             "scan",
		SessionID:      sessionID,
		InstanceID:     instanceID,
		Seq:            seq,
		PollIntervalMs: pollIntervalMs,
	}, timeout)
}

func (h *Host) call(c command) (json.RawMessage, error) {
	return h.callWithTimeout(c, CommandTimeout)
}

func (h *Host) callWithTimeout(c command, timeout time.Duration) (json.RawMessage, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil, errors.New("probe host is closed")
	}

	h.nextID++
	c.ID = h.nextID

	encoded, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encode command: %w", err)
	}
	if _, err := h.stdin.Write(append(encoded, '\n')); err != nil {
		return nil, fmt.Errorf("write command: %w", err)
	}

	type result struct {
		raw json.RawMessage
		err error
	}
	done := make(chan result, 1)

	go func() {
		line, err := h.stdout.ReadString('\n')
		if err != nil {
			done <- result{err: fmt.Errorf("read response: %w", err)}
			return
		}
		var r response
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			done <- result{err: fmt.Errorf("decode response: %w", err)}
			return
		}
		if r.ID != c.ID {
			// Strictly request/response at one command in flight, so this means the stream has
			// desynchronised. Failing loudly beats pairing a reply with the wrong request.
			done <- result{err: fmt.Errorf("response id %d does not match request %d", r.ID, c.ID)}
			return
		}
		if !r.OK {
			done <- result{err: fmt.Errorf("probe error: %s", r.Error)}
			return
		}
		done <- result{raw: r.Message}
	}()

	select {
	case res := <-done:
		return res.raw, res.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("probe did not answer %q within %s", c.Op, timeout)
	}
}

func (h *Host) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	_ = h.stdin.Close()
	_ = h.cmd.Process.Kill()
	_ = h.cmd.Wait()
}
