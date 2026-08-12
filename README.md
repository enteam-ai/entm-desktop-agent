# Interview transparency agent

The desktop agent a candidate runs during an Enteam interview. It reports what is running on the
machine, shows the candidate the identical feed the interviewer sees, and stops on one click.

**This source is public on purpose.** You are being asked to run monitoring software on your own
computer, minutes before a job interview, by a company you do not work for. "Trust us" is not a
reasonable thing to ask in that position. Everything the agent can observe, and everything it can
send, is in this repository and can be checked without taking anyone's word for it.

---

## What it does

1. Asks for consent. Nothing else runs until you answer.
2. If you decline, it records that and exits, having collected nothing.
3. Only then does it start the probe and begin sampling, once per second.
4. Shows you the identical feed, live, for as long as it runs.
5. Lets you stop it in one click, and tells the interviewer that you did.

Those five steps are the order of operations in
[`supervisor/cmd/cp-agent/main.go`](supervisor/cmd/cp-agent/main.go), not a description written
afterwards.

## What it reads

| | Signal | What it actually looks at |
|---|---|---|
| S1 | Running processes | Process names, ids, and executable paths |
| S2 | Code signature | SHA-256 of the executable, and who signed it |
| S3 | Microphone owner | Which process holds an audio session, and on which device |
| S5 | Capture-excluded windows | Which windows are flagged to hide themselves from screen sharing |
| S6 | Foreground window | Which window is in front, and its title |

## What it never reads

Not what you type. Not what is inside your windows. Not your screen, camera, or audio. Not your
files, your clipboard, or your browsing history.

The strongest of these is enforced by the build rather than by a promise:
[`deny_capture_apis.rs`](probe-core/crates/cp-win/tests/deny_capture_apis.rs) fails compilation if
any audio-capture entry point appears anywhere in the probe. The agent *enumerates* audio sessions
— it can see that some process holds the microphone — and it has no code path that can open one.
That is also why running it never triggers a Windows microphone-permission prompt.

## What leaves your machine

The window titles are the sensitive part, and pretending otherwise would be dishonest: a title can
say more than the application name does. That is why it is named explicitly on the consent screen
before you agree, and why it appears in your mirror window while the session runs.

Everything sent is on screen in that window. There is no second channel, no summary computed
somewhere you cannot see, and no field in the message format that the mirror does not render.

## What it does not decide

The agent reports; it does not judge. This is structural, not a policy:

- **It contains no list of tools.** There is no list of "cheating apps," no product names, no
  process-name matching. Searching this repository for the name of any specific tool turns up
  comments explaining why a signal exists — never a comparison. Detection is structural: a window
  flagged to hide from screen capture is reported as exactly that, whatever program set the flag.
- **It cannot report the highest severity.** Signals carry a tier, and
  [`Observation::tier()`](probe-core/crates/cp-signals/src/detail.rs) can only ever return 2 or 3.
  Tier 1 — "this is a known tool" — requires a database this agent does not have and is not
  shipped with. That judgment happens on the server, against the hash, and it is not made here.
- **The tier it does assign is structural.** "Holds the microphone and shows no window" is tier 2.
  It describes a shape, not an identity, and it knows nothing about what the program is.

## What it puts on your machine

Nothing is installed. No registry keys, no service, no autostart entry, nothing in Add/Remove
Programs. Two files are written under `%LOCALAPPDATA%\Enteam\`:

- `probe-serve-<hash>.exe` — the probe, unpacked from inside the agent on first run. See below.
- `agent.log` — an operational log of what the agent did: consent answered, probe restarted,
  session ended. It contains no process names, no window titles, and no signals.

Delete the folder whenever you like. The next run recreates what it needs.

## Two things a careful reader will notice

Both are deliberate, and better explained here than discovered.

**It unpacks and runs a second executable.** You download one file; inside it is a second program,
the probe, which gets written to `%LOCALAPPDATA%` and launched. Writing an executable and running
it is also what malware does, so it is worth saying why: the probe runs as a separate process so
that a misbehaving audio driver kills the probe rather than your interview — the agent restarts it
and carries on. The alternative, linking it in, would turn a driver fault into a lost session. The
unpacked copy is hash-checked against the copy inside the agent on every run, so a tampered one is
replaced rather than trusted, and its code signature is verified before it is ever launched.

**It launches PowerShell, once.** To perform that signature check, using Windows' own
`Get-AuthenticodeSignature` — the same check behind the Digital Signatures tab in file properties.
It runs against one file, the probe, and it reads nothing else. The reasoning is in
[`verify.go`](supervisor/internal/probehost/verify.go): a hand-written signature verifier is the
kind of code that can silently always answer "valid," which is worse than having no check at all.

## How it is built

Two languages, one file.

```
probe-core/    Rust    the probes; the only code that touches a Windows API
supervisor/    Go      consent, the mirror window, the tray icon, the sampling loop
```

The release build compiles the probe first and embeds it into the agent
([`internal/probeasset`](supervisor/internal/probeasset)), so what you download is a single
`cp-agent.exe` with nothing beside it to install or misplace.

### Build it yourself

Requires the Rust and Go toolchains, and Windows.

```powershell
cd probe-core
cargo build --release -p cp-win --bins

copy target\release\probe-serve.exe ..\supervisor\internal\probeasset\

cd ..\supervisor
go build -tags embedprobe -ldflags="-H windowsgui" -o ..\dist\cp-agent.exe .\cmd\cp-agent
```

Released builds are produced by
[the workflow in this repository](.github/workflows/build-windows.yml), on GitHub's runners, from
the commit the release points at.

## Requirements and limits

- **Windows only.** macOS is not supported. A candidate on a Mac cannot run this at all, and the
  interviewer is shown that there was no collector — not that the machine was clean.
- **Needs the Microsoft WebView2 Runtime**, which ships with Windows 11 and is present on most
  Windows 10 machines. Without it the agent refuses to start rather than monitoring without showing
  you the mirror window, and it will point you at the free Microsoft download, which installs
  without administrator rights.
- **Runs as you.** It does not ask for administrator rights and does not need them.

## What is not in this repository

The server that receives these reports, and the database of known tools it matches them against,
are not open. The agent is the part that runs on your machine, so it is the part where the question
"what is this actually doing to me" deserves an answer you can verify yourself.

## Status

Pre-release, and under active development. Not yet code-signed — until it is, Windows SmartScreen
will warn about it on download.
