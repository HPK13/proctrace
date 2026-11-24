# proctrace

A lightweight endpoint agent that watches processes, checks who started them, and flags the suspicious ones, with a plain-language reason and a MITRE ATT&CK tag for every alert.

It runs in one of two modes from the same binary:

- **Standalone:** writes events to a local JSONL file you can read, `jq`, or tail with Filebeat, Fluent Bit or the Wazuh agent.
- **Forward:** spools events locally and ships them over HTTPS (optionally mutual TLS) to a central collector.

> **Status: early development (v0.2).** Process collection currently polls the OS process table, which can miss processes that exit within the scan interval. Real-time ETW collection is the next milestone; see the [roadmap](#roadmap).

## What it checks

For every process it records the PID, name, image path, command line, start time, SHA-256 of the executable and, on Windows, the executable's **OriginalFileName** (from its version resource). Then:

- **Validates the parent.** A process's parent PID is only a number. If the real parent has exited, the OS can give that PID to an unrelated process, so proctrace only accepts a parent that *started before* the child. The result is recorded as `verified`, `parent_exited`, `pid_reused` or `no_parent`, and parent-based rules only fire on verified parents.
- **Resists simple evasion before matching:**
  - Rules that name a program also match its OriginalFileName, so `powershell.exe` copied to `update.exe` is still recognised.
  - Command lines are normalised: Unicode dashes, `^` carets, PowerShell backticks, quotes and `"I"+"EX"` concatenation are stripped.
  - PowerShell `-EncodedCommand` payloads (and every prefix PowerShell accepts, like `-enco`) are decoded, and rules run on the hidden script too.
- **Runs detection rules**, built into the binary (`rules/default.json`):

| Rule | Detects | ATT&CK |
|---|---|---|
| PT-W001 | Office app spawning PowerShell, cmd, mshta, rundll32, … | T1204.002, T1059 |
| PT-W002 / W003 | `svchost.exe` not started by `services.exe`; `lsass.exe` not started by `wininit.exe` | T1036.005 |
| PT-W004 | Core Windows binaries running outside `System32` | T1036.005 |
| PT-W005 / W006 | Lookalike names (`scvhost.exe`, `lsass .exe`) and non-ASCII homoglyphs | T1036 |
| PT-W007 | Encoded, obfuscated or download-cradle PowerShell | T1059.001, T1027 |
| PT-W008–W011 | LOLBin abuse: rundll32 `javascript:`, regsvr32 Squiblydoo, certutil download/decode, mshta | T1218, T1105 |
| PT-W012 / L001 | Web server spawning a shell (web shell) | T1505.003 |
| PT-W013 / L002 | Binaries running from temp or other user-writable folders (low confidence; Defender excepted) | T1204 |
| PT-W014 | Renamed system utility (OriginalFileName ≠ running name) | T1036.003 |

Each matching rule adds a detection. The event's `risk_score` (0–100) is the top rule score plus 5 for each extra detection.

## Quick start

Requires Go 1.24 or newer; the `toolchain` line in `go.mod` makes Go fetch the current patched release (1.27.4) automatically. No third-party dependencies.

```sh
git clone https://github.com/HPK13/proctrace
cd proctrace
go build -o proctrace.exe ./cmd/proctrace

proctrace.exe -once -alerts                  # one-off scan, print only flagged processes
```

A one-off scan run without admin rights works from anywhere, but can't read the paths or command lines of other users' and system processes. To run it elevated, install it first (next section).

Cross-compile for Windows from any OS:

```sh
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o proctrace.exe ./cmd/proctrace
```

## Installing safely

proctrace **refuses to run with admin rights** if a non-admin user can modify its executable, its folder, its config, a custom rules file or its data folder. Otherwise malware running as a normal user could swap the binary or edit the config and have it run with admin rights. Install it in an admin-only folder, from an **admin** PowerShell:

```powershell
New-Item -ItemType Directory "C:\Program Files\proctrace" -Force
Copy-Item .\proctrace.exe "C:\Program Files\proctrace\"           # copy, don't move
Copy-Item .\configs\local.example.json "C:\Program Files\proctrace\config.json"
icacls "C:\Program Files\proctrace" /reset /T                       # inherit Program Files permissions
icacls "C:\Program Files\proctrace" /setowner Administrators /T

& "C:\Program Files\proctrace\proctrace.exe" -config "C:\Program Files\proctrace\config.json"
```

Events are written to `C:\Program Files\proctrace\data\`. If the check fails, proctrace lists each file and who can write to it. `-allow-unsafe-paths` overrides the check for testing only.

## Privacy

Command lines often contain passwords and tokens. proctrace masks them **after** detection (rules still see the full text) and **before** anything is written or sent:

```
net use \\srv\share P@ssw0rd! /user:admin   →  net use \\srv\share [REDACTED] /user:admin
curl -H "Authorization: Bearer eyJ..."      →  curl -H "Authorization: Bearer [REDACTED]"
mysql -u root -pSecret123                   →  mysql -u root -p[REDACTED]
```

Covered: `password=`/`token=`/`api_key=`-style values, `--password`/`--token` flags, URL credentials, Bearer/Basic headers, `net use`/`net user`, `sqlcmd -P`, `mysql -p`, `psexec -p`, `schtasks /p`, `ConvertTo-SecureString`, and AWS, GitHub, Slack, Google, JWT and PEM private-key formats. Redaction is pattern-based and best-effort, so protect the event files anyway. Set `privacy.drop_command_lines` to record no command lines at all.

## Example alert

```json
{
  "@timestamp": "2026-11-24T05:26:27Z",
  "event": { "kind": "alert", "category": ["process"], "type": ["start"], "risk_score": 80 },
  "process": {
    "pid": 7412, "name": "update.exe",
    "executable": "C:\\Users\\bob\\Downloads\\update.exe",
    "command_line": "update.exe -nop -c Get-Process",
    "pe": { "original_file_name": "PowerShell.EXE.MUI" },
    "hash": { "sha256": "…" },
    "parent": { "pid": 6120, "name": "WINWORD.EXE" }
  },
  "proctrace": {
    "parent_status": "verified",
    "detections": [
      { "rule_id": "PT-W001", "title": "Office application spawned a shell or script host",
        "severity": "high", "score": 75, "attack": ["T1204.002", "T1059"],
        "reason": "process update.exe (originally powershell.exe); parent WINWORD.EXE" },
      { "rule_id": "PT-W014", "title": "Renamed Windows system utility",
        "severity": "high", "score": 75, "attack": ["T1036.003"],
        "reason": "renamed copy of powershell.exe running as update.exe" }
    ]
  }
}
```

Field names follow the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) (`process.*`, `process.pe.*`, `event.*`, `host.*`), so the events can go into Elastic, OpenSearch, Wazuh or Sentinel without a custom parser.

## Configuration

See `configs/local.example.json` and `configs/forward.example.json`.

| Key | Meaning |
|---|---|
| `mode` | `local` or `forward` |
| `scan_interval` | Polling interval, e.g. `"2s"` |
| `rules_path` | Custom rule file (relative to the config file). Omit to use the built-in rules |
| `data_dir` | Folder for all output files (relative to the executable). Default `data` |
| `only_alerts` | Output only processes that matched a rule |
| `stdout` | Also print events to stdout |
| `hash.enabled`, `hash.max_file_mb` | Hash executables; skip files larger than this |
| `privacy.redact_command_lines` | Mask secrets in command lines (default `true`) |
| `privacy.drop_command_lines` | Don't record command lines at all |
| `privacy.max_command_line` | Truncate command lines to this many bytes (default 4096) |
| `local.path`, `local.max_size_mb` | Event file name inside `data_dir`, rotated to `.1` at the size limit |
| `forward.url` | HTTPS endpoint that accepts NDJSON (`application/x-ndjson`); `https://` is required |
| `forward.ca_file` | CA used to verify the collector |
| `forward.cert_file` / `key_file` | Client certificate for mutual TLS |
| `forward.token_env` | Name of an environment variable holding a bearer token |
| `forward.spool_path`, `flush_interval`, `max_batch_mb` | Spool file name inside `data_dir`, and batching |

Output file settings must be plain file names. Folders, `..`, drive letters and `file:stream` names are rejected, so a config value can't make the agent write anywhere else.

In forward mode, every event is written to the spool file before anything is sent, and a batch is deleted only after the collector returns a 2xx response. Events therefore survive network outages and restarts. Any HTTP input that accepts NDJSON works as the collector: Vector, Fluent Bit, Logstash, or your own service.

## Writing rules

Start from the built-in set:

```sh
proctrace -dump-rules > my-rules.json
proctrace -rules my-rules.json -once -alerts
```

A rule matches when **all** of its `match` conditions hold. Within a list, **any** entry is enough. Comparisons are case-insensitive. If the optional `except` block (same conditions) also matches, the rule doesn't fire.

```json
{
  "id": "PT-X001",
  "title": "Excel spawned certutil",
  "severity": "high",
  "score": 70,
  "attack": ["T1105"],
  "match": {
    "parent_name": ["excel.exe"],
    "name": ["certutil.exe"],
    "command_line_regex": ["urlcache"]
  },
  "except": {
    "path_prefix": ["c:\\program files\\trusted vendor\\"]
  }
}
```

| Condition | Matches when |
|---|---|
| `name` / `name_not` | Process name (or, for `name`, its OriginalFileName) is / isn't in the list |
| `renamed_from` | OriginalFileName is in the list but the process runs under another name |
| `parent_name` / `parent_name_not` | Verified parent is / isn't in the list |
| `path_prefix` / `path_prefix_not` / `path_contains` | Executable path starts with / doesn't start with / contains a value |
| `command_line_regex` | Regex matches the normalised command line or decoded PowerShell payload |
| `name_lookalike` | Name is 1–2 edits away from a listed name |
| `name_non_ascii` | Name contains non-ASCII characters |
| `parent_status` | Lineage result is in the list (`verified`, `pid_reused`, …) |

Add test cases for new rules in `internal/detect/engine_test.go`.

## Layout

```
cmd/proctrace/        entry point and pipeline wiring
internal/collector/   process sources (snapshot now, ETW next)
internal/lineage/     parent resolution and PID-reuse checks
internal/enrich/      hashing and PE OriginalFileName
internal/detect/      rule engine, command-line normalisation, PowerShell decoding
internal/redact/      secret masking for command lines
internal/harden/      refuses elevated runs from user-writable files
internal/winapi/      loads Windows DLLs from System32 only
internal/output/      stdout, JSONL file and HTTPS forwarder
internal/config/      configuration
rules/                built-in detection rules (embedded in the binary)
docs/                 architecture notes
```

## Roadmap

- [x] Process snapshot collector (Windows Toolhelp32 + NtQueryInformationProcess, Linux /proc)
- [x] Parent validation (creation-time check, PID reuse)
- [x] SHA-256 hashing with cache
- [x] JSON rule engine with risk scoring and ATT&CK tags
- [x] Local JSONL output with rotation
- [x] HTTPS/mTLS forwarder with crash-safe spool
- [x] Evasion resistance: OriginalFileName, command-line normalisation, PowerShell decoding, rule exceptions
- [x] Agent hardening: secret redaction, confined output paths, unsafe-install check, embedded rules, System32-only DLL loading
- [ ] **ETW collector** (`Microsoft-Windows-Kernel-Process`) for real-time process starts without gaps
- [ ] PPID-spoofing and command-line-spoofing detection (compare with ETW creation data)
- [ ] Detect image tampering: executable missing or changed since the process started
- [ ] Authenticode signature checks (signed / unsigned / signer name), usable in `except`
- [ ] Run as a Windows service (install / uninstall commands)
- [ ] Sigma rule import (process_creation subset)
- [ ] Per-host baselining: alert on first-seen parent→child pairs
- [ ] Central-side enrichment: VirusTotal / MalwareBazaar hash lookups

## Security

proctrace runs with high privileges, so it is designed to be **read-only**: it opens no listening ports, never executes other programs, and never runs commands received from the network. CI runs [govulncheck](https://go.dev/doc/security/vuln/) on every push and weekly. See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[Apache License 2.0](LICENSE)