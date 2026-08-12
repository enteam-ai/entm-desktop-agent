// Command cp-agent is Collector A â€” the agent that runs on the candidate's own machine.
//
// The order of operations here is the product, not an implementation detail:
//
//  1. Ask for consent. Nothing else runs until the candidate answers.
//  2. If declined, say so on the wire and exit. That is a supported outcome, not an error.
//  3. Only then start the probe, report coverage, and begin sampling.
//  4. Show the candidate the identical feed, live, for as long as it runs.
//  5. Let them stop it in one click, and tell the interviewer that they did.
//
// Everything below is in service of those five lines.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/enteam-ai/entm-desktop-agent/supervisor/internal/appdir"
	"github.com/enteam-ai/entm-desktop-agent/supervisor/internal/probeasset"
	"github.com/enteam-ai/entm-desktop-agent/supervisor/internal/probehost"
	"github.com/enteam-ai/entm-desktop-agent/supervisor/internal/sink"
	"github.com/enteam-ai/entm-desktop-agent/supervisor/internal/ui"
	"github.com/enteam-ai/entm-desktop-agent/supervisor/internal/winguard"
)

const (
	schemaVersion = "1.0"
	collectorID   = "host-agent/0.1.0"

	// Local\ scopes it to this login session rather than the whole machine (Global\), matching who
	// consent and the mirror window are actually for. Two sessions for two different candidates
	// logged into the same machine are a real, if rare, scenario and must not collide.
	singleInstanceMutexName = `Local\entm-teams-collector-a`
)

func main() {
	var (
		probePath  = flag.String("probe", "", "path to probe-serve executable; empty resolves it automatically (see resolveProbePath)")
		outPath    = flag.String("out", "session.jsonl", "local NDJSON sink (P1; replaced by the WSS uplink in P2)")
		intervalMs = flag.Int("interval-ms", 1000, "sampling interval")
		sessionID  = flag.String("session", "", "session id (P2: comes from the join token)")
		// Empty until the EV certificate is ordered and the probe is actually signed â€” see
		// progress.md. The check still runs and logs unarmed; it refuses to spawn only once this is
		// set to something like "O=<the certificate's registered organisation>".
		expectedPublisher = flag.String("expected-publisher", "", "required Authenticode signer substring for the probe binary; empty means unarmed (pre-signing)")
	)
	flag.Parse()

	log.SetFlags(log.Ltime)
	if closeLog := startLogging(); closeLog != nil {
		defer closeLog()
	}

	// A second launch must not open a second consent screen or start a second sampling loop â€”
	// nothing downstream is built to reconcile two collectors reporting on the same machine under
	// two sessions, and that is a coverage-integrity question this product has no honest way to
	// answer, not merely an inconvenience.
	held, releaseInstance, err := winguard.AcquireSingleInstance(singleInstanceMutexName)
	if err != nil {
		fatal("single-instance check: %v", err)
	}
	if !held {
		log.Print("another instance of this agent is already running on this machine â€” exiting")
		return
	}
	defer releaseInstance()

	if *sessionID == "" {
		*sessionID = newUUID()
	}
	instanceID := newUUID()

	out, err := sink.Open(*outPath)
	if err != nil {
		fatal("sink: %v", err)
	}
	defer out.Close()

	// seq is shared by every message type â€” samples, coverage reports and lifecycle events â€” so
	// their relative order is provable. It is monotonic within this instance, not within the
	// session: two collectors can share a session_id. `collector_instance_id` means one continuous
	// run of this Go process specifically â€” a probe (Rust subprocess) restart does NOT mint a new
	// instance or reset seq, because the candidate's consent and the mirror window never restarted;
	// see the ticker goroutine below for how that gap is declared instead. A new instance is for
	// when THIS process restarts, which nothing does today â€” the job object below ties the probe's
	// life to this one, not the other way around, and there is still no wrapper that would relaunch
	// the agent itself after a crash.
	var seq atomic.Uint64

	// ---- 1. consent, before anything else --------------------------------------------------
	// WebView2 is a hard requirement, not a preference. The mirror window is one of the product's
	// three non-negotiables -- the candidate sees the identical feed -- so an agent that cannot show
	// what it is sending must not send anything. Refusing here is the correct decision; the point of
	// checking before NewApp is that "the runtime is missing" is the ONE fatal condition the
	// candidate can actually resolve themselves, and it earns a specific message rather than the
	// generic one every other window failure gets.
	if version, ok := ui.RuntimeAvailable(); ok {
		log.Printf("WebView2 runtime %s", version)
	} else {
		log.Print("no WebView2 runtime installed; cannot show the consent screen or the mirror window")
		ui.OfferRuntimeInstall()
		os.Exit(1)
	}

	app := ui.NewApp()
	if app == nil {
		fatal("could not open a window; refusing to monitor without a consent screen")
	}
	defer app.Destroy()

	// The window itself is not destroyed here even on decline â€” see the deferred app.Destroy
	// below. It is the same window ShowMirror would otherwise switch into the live mirror; on
	// decline there is no mirror phase, so the deferred Destroy at the end of main is what
	// finally closes it.
	if app.AskConsent() != ui.Granted {
		log.Print("consent declined â€” exiting without collecting anything")
		_ = out.WriteValue(event(*sessionID, instanceID, seq.Add(1), "consent_declined", true))
		return
	}
	_ = out.WriteValue(event(*sessionID, instanceID, seq.Add(1), "consent_granted", false))
	log.Print("consent granted")

	// ---- 2. probe ---------------------------------------------------------------------------
	// The job object is best-effort: a probe still runs and functions without it, just without the
	// guarantee that an abrupt kill of THIS process (Task Manager, a crash) takes the probe with
	// it. Never held to be fatal, since it protects against an edge case, not the main path.
	job, jobErr := winguard.NewProcessJob()
	if jobErr != nil {
		log.Printf("job object: %v â€” an abrupt agent kill would not take the probe with it", jobErr)
		job = 0
	}

	// Resolved here, after consent, and deliberately not earlier: in a release build this writes
	// the embedded probe to disk, and putting a file on the candidate's machine before they have
	// answered would contradict the consent screen's own promise that nothing happens until they do.
	probeExe, err := resolveProbePath(*probePath)
	if err != nil {
		fatal("probe: %v", err)
	}

	host, err := probehost.Start(probeExe, *expectedPublisher, job)
	if err != nil {
		fatal("probe: %v", err)
	}
	hh := &hostHolder{host: host}
	defer hh.closeCurrent()

	if err := host.Ping(); err != nil {
		fatal("probe not answering: %v", err)
	}

	// ---- 3. coverage, before the first sample ------------------------------------------------
	// It must arrive first. A sample that reaches a consumer before the coverage report can be
	// read as complete when it is not, and "nothing flagged" is meaningless without it.
	coverage, err := host.Coverage(*sessionID, instanceID, seq.Add(1))
	if err != nil {
		fatal("coverage: %v", err)
	}
	if err := out.WriteRaw(coverage); err != nil {
		fatal("sink: %v", err)
	}

	// ---- 4. mirror + sampling ----------------------------------------------------------------
	stopped := make(chan struct{})
	var closeOnce sync.Once
	var collectorEnded atomic.Bool

	// closeSession is the one path that ends the session, whether the candidate clicked Stop or
	// the collector gave up on a dead probe. sync.Once means whichever reason fires first wins â€”
	// the two can race (a restart-give-up and a click landing in the same instant) and only one
	// terminal event may ever be written.
	closeSession := func(collectorInitiated bool) {
		closeOnce.Do(func() {
			collectorEnded.Store(collectorInitiated)
			close(stopped)
		})
	}

	app.ShowMirror(func() {
		log.Print("candidate stopped monitoring")
		closeSession(false)
	})
	mirror := app

	// The tray icon is a convenience, not a non-negotiable â€” a candidate who minimizes or loses
	// track of the mirror window still needs a way back to it (or to Stop) without Task Manager,
	// but a tray failure (a locked-down environment without a notification area, for instance)
	// must never stop monitoring from proceeding. Never fatal; only logged.
	tray, trayErr := ui.StartTray("Enteam â€” monitoring active", mirror.BringToFront, func() {
		log.Print("candidate stopped monitoring from the tray icon")
		closeSession(false)
	})
	if trayErr != nil {
		log.Printf("tray icon: %v â€” monitoring continues without one", trayErr)
	} else {
		log.Print("tray icon started")
	}
	defer tray.Stop()

	mirror.ShowCoverage(coverage)

	// tickerDone is closed when the sampling goroutine has actually returned â€” not merely when
	// `stopped` is closed. The two are not the same moment: a scan already in flight (in
	// particular the cold warm-up scan, ~4s on a real machine) holds probehost's internal mutex
	// for its full duration and does not notice `stopped` until it next reaches the select below.
	// hh.closeCurrent(), deferred in main, takes that same mutex â€” calling it before the goroutine
	// has actually unwound raced the two, and on a real run produced an out-of-order seq (the
	// warm-up scan's envelope, allocated before candidate_quit, written to disk after it) and a
	// spurious "probe host is closed â€” restarting the probe" during what should have been a clean
	// shutdown. Waiting for tickerDone below closes that gap.
	tickerDone := make(chan struct{})

	go func() {
		defer close(tickerDone)

		ticker := time.NewTicker(time.Duration(*intervalMs) * time.Millisecond)
		defer ticker.Stop()

		var lastSampleSeq uint64

		// Warm the S2 signature cache before joining the 1Hz cadence. Measured on a real machine:
		// ~4s cold against every readable process, ~30ms once warm â€” close enough to the 5s
		// default CommandTimeout that a slower or loaded machine would read the very first scan as
		// a wedged probe and restart it needlessly. Runs here, in the background goroutine, rather
		// than before mirror.Run() starts pumping the window, so the mirror does not sit unpainted
		// for the several seconds this takes. Skipped outright if the session already ended before
		// this goroutine got scheduled (a very fast decline-to-quit is a real, if unlikely, case).
		select {
		case <-stopped:
			return
		default:
		}
		if n, err := warmUpScan(hh.get(), out, mirror, *sessionID, instanceID, &seq, *intervalMs); err != nil {
			log.Printf("initial scan failed: %v â€” sampling will attempt recovery on the next tick", err)
		} else {
			lastSampleSeq = n
		}

		for {
			select {
			case <-stopped:
				return
			case <-ticker.C:
				n := seq.Add(1)
				current := hh.get()
				envelope, err := current.Scan(*sessionID, instanceID, n, *intervalMs)
				if err != nil {
					// probe-serve wraps every command in catch_unwind and reports probe failures as
					// degraded content, never as a protocol-level error â€” so a Scan() error here
					// means the probe process itself is gone or wedged, not a transient hiccup
					// inside one signal. Restarting is the correct response, not a retry-in-place.
					log.Printf("scan %d failed: %v â€” restarting the probe", n, err)
					current.Close()

					newHost, restartErr := restartProbe(probeExe, *expectedPublisher, job)
					if restartErr != nil {
						log.Printf("probe would not restart: %v â€” ending the session", restartErr)
						_ = out.WriteValue(collectorError(*sessionID, instanceID, seq.Add(1), "crash_recovered", false, restartErr))
						_ = out.WriteValue(sessionEnded(*sessionID, instanceID, seq.Add(1)))
						closeSession(true)
						return
					}
					hh.swap(newHost)

					// The gap is declared under the SAME collector_instance_id and the SAME seq
					// stream â€” only the internal Rust process bounced; the candidate's consent, the
					// mirror window and the interview did not restart. See probehost's package doc.
					_ = out.WriteValue(collectorError(*sessionID, instanceID, seq.Add(1), "crash_recovered", true, err))
					_ = out.WriteValue(gapDeclared(*sessionID, instanceID, seq.Add(1), lastSampleSeq, n))

					covSeq := seq.Add(1)
					newCoverage, covErr := newHost.Coverage(*sessionID, instanceID, covSeq)
					if covErr != nil {
						log.Printf("post-restart coverage failed: %v", covErr)
					} else if err := out.WriteRaw(newCoverage); err != nil {
						log.Printf("sink: %v", err)
					} else {
						mirror.ShowCoverage(newCoverage)
						_ = out.WriteValue(coverageChanged(*sessionID, instanceID, seq.Add(1), covSeq, newCoverage))
					}

					// The new process's S2 cache is empty too â€” same reasoning as the startup
					// warm-up. Without this, the very next regular tick would cold-scan under the
					// short timeout and could restart-loop on a slow machine.
					if wn, err := warmUpScan(newHost, out, mirror, *sessionID, instanceID, &seq, *intervalMs); err != nil {
						log.Printf("post-restart warm-up scan failed: %v", err)
					} else {
						lastSampleSeq = wn
					}
					continue
				}
				if err := out.WriteRaw(envelope); err != nil {
					log.Printf("sink: %v", err)
				}
				mirror.ShowSample(envelope)
				lastSampleSeq = n
			}
		}
	}()

	// Closing the window is the same as clicking Stop. Both end the session cleanly and say so.
	go func() {
		<-stopped
		mirror.Close()
	}()

	mirror.Run()

	// Run returns whenever the window closes, by any means. "Stop monitoring" routes through the
	// stopMonitoring binding and already called closeSession above; the native close button does
	// not touch that binding at all â€” WM_CLOSE goes straight to WM_DESTROY to Terminate inside the
	// webview library, bypassing our JS bridge entirely. This is the catch-all for that path: if
	// nothing has closed `stopped` yet, the window going away is what ends the session.
	closeSession(false)

	// The sampling goroutine reacts to `stopped` asynchronously â€” it can be mid-scan, holding
	// probehost's mutex, when the window closes. Waiting here for it to actually exit is what
	// makes the deferred hh.closeCurrent() below safe to run without racing that scan.
	<-tickerDone

	// ---- 5. terminal event -------------------------------------------------------------------
	// Ending cleanly and telling the interviewer it ended is correct behaviour. "Stopped at minute
	// 14" is information, not a failure. But if the collector ended the session itself (the probe
	// could not be restarted), `sessionEnded` was already written above â€” writing candidate_quit
	// too would falsely attribute the collector's own decision to the candidate.
	if !collectorEnded.Load() {
		_ = out.WriteValue(event(*sessionID, instanceID, seq.Add(1), "candidate_quit", true))
	}
	log.Printf("session ended â€” %d messages written to %s", seq.Load(), *outPath)
}

// hostHolder lets the ticker goroutine swap in a freshly-restarted probe while the deferred
// cleanup in main still reaches whichever process is current, not whichever one existed at
// startup.
type hostHolder struct {
	mu   sync.Mutex
	host *probehost.Host
}

func (hh *hostHolder) get() *probehost.Host {
	hh.mu.Lock()
	defer hh.mu.Unlock()
	return hh.host
}

func (hh *hostHolder) swap(h *probehost.Host) {
	hh.mu.Lock()
	defer hh.mu.Unlock()
	hh.host = h
}

func (hh *hostHolder) closeCurrent() {
	hh.mu.Lock()
	defer hh.mu.Unlock()
	if hh.host != nil {
		hh.host.Close()
	}
}

// restartProbe relaunches a dead or wedged probe. Three attempts, short backoff â€” probe-serve's
// single-threaded command loop means one wedged call blocks every command after it forever, so a
// scan failure always means "this process is done," never "try again in place."
func restartProbe(probePath, expectedPublisher string, job windows.Handle) (*probehost.Host, error) {
	delays := []time.Duration{0, 250 * time.Millisecond, 750 * time.Millisecond}
	var lastErr error
	for _, d := range delays {
		if d > 0 {
			time.Sleep(d)
		}
		h, err := probehost.Start(probePath, expectedPublisher, job)
		if err != nil {
			lastErr = err
			continue
		}
		if err := h.Ping(); err != nil {
			h.Close()
			lastErr = err
			continue
		}
		return h, nil
	}
	return nil, fmt.Errorf("%d attempts, last error: %w", len(delays), lastErr)
}

// probeWarmupTimeout must comfortably exceed the measured cold-cache cost (~4s on a real machine,
// hashing every readable process for the first time) with real margin for a slower or busier one.
const probeWarmupTimeout = 30 * time.Second

// warmUpScan takes one scan against a cold S2 cache and, on success, writes and displays it like
// any other sample. Returns the seq it used so the caller can seed lastSampleSeq for the next gap
// declaration.
func warmUpScan(host *probehost.Host, out *sink.Sink, mirror *ui.App, sessionID, instanceID string, seqCounter *atomic.Uint64, intervalMs int) (uint64, error) {
	n := seqCounter.Add(1)
	envelope, err := host.ScanWithTimeout(sessionID, instanceID, n, intervalMs, probeWarmupTimeout)
	if err != nil {
		return n, err
	}
	if err := out.WriteRaw(envelope); err != nil {
		log.Printf("sink: %v", err)
	}
	mirror.ShowSample(envelope)
	return n, nil
}

// ---- message helpers -------------------------------------------------------------------------

type envelopeHeader struct {
	SchemaVersion       string `json:"schema_version"`
	Type                string `json:"type"`
	CollectorID         string `json:"collector_id"`
	CollectorInstanceID string `json:"collector_instance_id"`
	SessionID           string `json:"session_id"`
	Seq                 uint64 `json:"seq"`
	Ts                  string `json:"ts"`
}

type sessionEventMsg struct {
	envelopeHeader
	Event sessionEventBody `json:"event"`
}

type sessionEventBody struct {
	Code        string           `json:"code"`
	Initiator   string           `json:"initiator"`
	Terminal    bool             `json:"terminal"`
	OccurredAt  string           `json:"occurred_at"`
	Message     string           `json:"message,omitempty"`
	Consent     *consentBody     `json:"consent,omitempty"`
	Error       *errorBody       `json:"error,omitempty"`
	Gap         *gapBody         `json:"gap,omitempty"`
	CoverageRef *coverageRefBody `json:"coverage_ref,omitempty"`
}

// gapBody is present on sample_gap_declared â€” the collector's own account of samples it knows it
// dropped, rather than leaving the server to infer the size of a gap from seq alone.
type gapBody struct {
	FromSeq         uint64 `json:"from_seq"`
	ToSeq           uint64 `json:"to_seq"`
	DroppedEstimate uint64 `json:"dropped_estimate"`
	Cause           string `json:"cause"`
}

// coverageRefBody is present on coverage_changed, pointing at the coverage_report message that
// carries the new state rather than duplicating it inline.
type coverageRefBody struct {
	Seq                uint64 `json:"seq"`
	CapabilitiesDigest string `json:"capabilities_digest,omitempty"`
}

// consentBody is the GDPR Art. 6(1)(a) artefact: a timestamped record of what was shown and what
// was accepted.
type consentBody struct {
	NoticeVersion string   `json:"notice_version"`
	NoticeLocale  string   `json:"notice_locale"`
	ScopeAck      []string `json:"scope_ack"`
	DecisionTs    string   `json:"decision_ts"`
}

type errorBody struct {
	Kind          string   `json:"kind"`
	Retryable     bool     `json:"retryable"`
	AffectedCodes []string `json:"affected_codes,omitempty"`
}

// noticeVersion identifies the exact consent text the candidate was shown, so the record proves
// what was consented TO rather than merely that a button was clicked.
//
// **Bump this whenever assets/consent.html changes.** A stored consent naming a version whose text
// nobody can reproduce is not a consent record.
const noticeVersion = "2026-08-03.1"

// consentScope lists the capability keys the notice actually describes, in the order it describes
// them. Consent is per-capability on purpose: if the collector later gains a signal, an old
// acceptance must not silently cover it â€” the notice changes, the version bumps, and the candidate
// is asked again.
//
// These four correspond one-to-one with the bullets under "What it reads" in assets/consent.html.
// S2_signature is deliberately absent: the notice does not mention hashing binaries, so no consent
// for it exists. If S2 ships, the notice must say so first.
var consentScope = []string{
	"S1_processes",
	"S3_mic_owner",
	"S6_window_titles",
	"S5_capture_excluded",
}

func header(sessionID, instanceID string, seq uint64, msgType string) envelopeHeader {
	return envelopeHeader{
		SchemaVersion:       schemaVersion,
		Type:                msgType,
		CollectorID:         collectorID,
		CollectorInstanceID: instanceID,
		SessionID:           sessionID,
		Seq:                 seq,
		Ts:                  nowUTC(),
	}
}

// event builds a lifecycle message. Note there is no tier field: giving "candidate declined
// monitoring" a risk tier would be rendering the verdict this product refuses to render.
func event(sessionID, instanceID string, seq uint64, code string, terminal bool) sessionEventMsg {
	body := sessionEventBody{
		Code:       code,
		Initiator:  "candidate",
		Terminal:   terminal,
		OccurredAt: nowUTC(),
	}

	switch code {
	case "consent_granted", "consent_declined", "consent_withdrawn":
		body.Consent = &consentBody{
			NoticeVersion: noticeVersion,
			NoticeLocale:  "en",
			ScopeAck:      consentScope,
			DecisionTs:    body.OccurredAt,
		}
	}

	return sessionEventMsg{
		envelopeHeader: header(sessionID, instanceID, seq, "session_event"),
		Event:          body,
	}
}

// collectorError builds a collector_error event. `kind` and `retryable` distinguish a scan that
// lost one cycle but recovered (`crash_recovered`, retryable) from one that could not be recovered
// at all (`crash_recovered`, not retryable â€” the session ends right after).
func collectorError(sessionID, instanceID string, seq uint64, kind string, retryable bool, cause error) sessionEventMsg {
	return sessionEventMsg{
		envelopeHeader: header(sessionID, instanceID, seq, "session_event"),
		Event: sessionEventBody{
			Code:       "collector_error",
			Initiator:  "collector",
			Terminal:   false,
			OccurredAt: nowUTC(),
			// Diagnostic only, and deliberately not candidate data: NG3 applies to error strings
			// as much as to signals.
			Message: cause.Error(),
			Error: &errorBody{
				Kind:      kind,
				Retryable: retryable,
				// A failed scan loses every signal in that cycle, not one of them. Naming the lot
				// is what lets the pipeline degrade the right coverage keys rather than guessing.
				AffectedCodes: []string{"S1", "S2", "S3", "S5", "S6"},
			},
		},
	}
}

// gapDeclared marks a probe-restart gap under the SAME collector_instance_id and seq stream â€” the
// Rust process bounced, not the Go supervisor, so nothing about the session's identity changed.
func gapDeclared(sessionID, instanceID string, seq, fromSeq, toSeq uint64) sessionEventMsg {
	return sessionEventMsg{
		envelopeHeader: header(sessionID, instanceID, seq, "session_event"),
		Event: sessionEventBody{
			Code:       "sample_gap_declared",
			Initiator:  "collector",
			Terminal:   false,
			OccurredAt: nowUTC(),
			Gap: &gapBody{
				FromSeq:         fromSeq,
				ToSeq:           toSeq,
				DroppedEstimate: 1,
				Cause:           "collector_restart",
			},
		},
	}
}

// coverageChanged points at the fresh coverage_report a restarted probe produced. The digest is a
// cheap correlation aid for a consumer deciding whether capabilities actually changed â€” not part
// of the evidence chain, which hashes the coverage report itself.
func coverageChanged(sessionID, instanceID string, seq, coverageSeq uint64, coverageBytes []byte) sessionEventMsg {
	digest := sha256.Sum256(coverageBytes)
	return sessionEventMsg{
		envelopeHeader: header(sessionID, instanceID, seq, "session_event"),
		Event: sessionEventBody{
			Code:       "coverage_changed",
			Initiator:  "collector",
			Terminal:   false,
			OccurredAt: nowUTC(),
			CoverageRef: &coverageRefBody{
				Seq:                coverageSeq,
				CapabilitiesDigest: hex.EncodeToString(digest[:]),
			},
		},
	}
}

// sessionEnded is the collector's own terminal event for when a dead probe could not be
// restarted. Distinct from candidate_quit â€” initiator is "collector" â€” so the record never
// attributes the collector's decision to the candidate.
func sessionEnded(sessionID, instanceID string, seq uint64) sessionEventMsg {
	return sessionEventMsg{
		envelopeHeader: header(sessionID, instanceID, seq, "session_event"),
		Event: sessionEventBody{
			Code:       "session_ended",
			Initiator:  "collector",
			Terminal:   true,
			OccurredAt: nowUTC(),
			Message:    "probe could not be restarted after repeated attempts; monitoring ended",
		},
	}
}

func nowUTC() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// fatal ends the session with a reason the candidate can actually read.
//
// A straight replacement for log.Fatalf, including the part where deferred cleanup does not run --
// log.Fatalf calls os.Exit too, so nothing that was previously released still is. What changes is
// that the message reaches a person: the release build has no console, and even the dev build only
// shows one for as long as the process lives, which for a startup failure is a flash.
func fatal(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	ui.ReportFatal(msg)
	os.Exit(1)
}

// startLogging tees the log to a file, and returns a closer, or nil if no file could be opened.
//
// Needed because the release build links with -H windowsgui and therefore has no console at all:
// without this, every log line -- including the ones explaining why a session ended early -- would
// go nowhere, and diagnosing a candidate's failed run would be guesswork. Writing to os.Stderr as
// well is harmless in that build (the handle is simply invalid) and keeps dev runs unchanged.
//
// Operational only. This records what the agent DID -- consent answered, probe restarted, session
// ended -- and never what it observed. No process name, window title, or signal of any kind is
// written here; those go to the sink and to the mirror window, which is the feed the candidate was
// shown and agreed to. That distinction is why opening this before the consent gate does not
// contradict the notice's promise that nothing is recorded until they answer.
func startLogging() func() {
	dir, err := appdir.Ensure()
	if err != nil {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	return func() { f.Close() }
}

// resolveProbePath decides which probe-serve binary this run will spawn.
//
// Three cases, in order. An explicit -probe wins, because a developer pointing at a specific build
// means it. Otherwise a release build extracts the probe it carries (see internal/probeasset) --
// the candidate downloaded one file and there is nothing beside it to find. Otherwise this is a dev
// build, and the probe is expected next to the agent, which is what a local cargo+go build produces.
func resolveProbePath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if probeasset.Available() {
		return probeasset.Extract()
	}
	return siblingProbePath(), nil
}

func siblingProbePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "probe-serve.exe"
	}
	return filepath.Join(filepath.Dir(exe), "probe-serve.exe")
}

// newUUID generates a v4 UUID without pulling in a dependency for the one place P1 needs it.
//
// P2 replaces this entirely: the session id is server-issued and arrives inside the single-use
// join token. A collector never mints its own session id in production â€” an id the server did not
// issue cannot be tied to an interview.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Fatalf("uuid: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
