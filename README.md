# proctrace

A lightweight endpoint agent that watches processes, checks who started them, and flags the suspicious ones, with a plain-language reason and a MITRE ATT&CK tag for every alert.

It runs in one of two modes from the same binary:

- **Standalone:** writes events to a local JSONL file you can read, `jq`, or tail with Filebeat, Fluent Bit or the Wazuh agent.
- **Forward:** spools events locally and ships them over HTTPS (optionally mutual TLS) to a central collector.

> **Status: early development (v0.1).** Process collection currently polls the OS process table, which can miss processes that exit within the scan interval. Real-time ETW collection is the next milestone; see the [roadmap](#roadmap).

## What it checks

For every process it records the PID, name, image path, command line, start time and SHA-256 of the executable, and then:

- **Validates the parent.** A process's parent PID is only a number. If the real parent has exited, the OS can give that PID to an unrelated process, so proctrace only accepts a parent that *started before* the child. The result is recorded as `verified`, `parent_exited`, `pid_reused` or `no_parent`, and parent-based rules only fire on verified parents.
- **Runs detection rules** (`rules/default.json`), including:

| Rule | Detects | ATT&CK |
|---|---|---|
| PT-W001 | Office app spawning PowerShell, cmd, mshta, rundll32, … | T1204.002, T1059 |
| PT-W002 / W003 | `svchost.exe` not started by `services.exe`; `lsass.exe` not started by `wininit.exe` | T1036.005 |
| PT-W004 | Core Windows binaries running outside `System32` | T1036.005 |
| PT-W005 / W006 | Lookalike names (`scvhost.exe`, `lsass .exe`) and non-ASCII homoglyphs | T1036 |
| PT-W007 | Encoded or download-cradle PowerShell | T1059.001, T1027 |
| PT-W008–W011 | LOLBin abuse: rundll32 `javascript:`, regsvr32 Squiblydoo, certutil download/decode, mshta | T1218, T1105 |
| PT-W012 / L001 | Web server spawning a shell (web shell) | T1505.003 |
| PT-W013 / L002 | Binaries running from temp or other user-writable folders (low confidence) | T1204 |

Each matching rule adds a detection. The event's `risk_score` (0–100) is the top rule score plus 5 for each extra detection.

## Quick start

Requires Go 1.24+. No third-party dependencies.

```sh
git clone https://github.com/HPK13/proctrace
cd proctrace
go build -o proctrace ./cmd/proctrace        # proctrace.exe on Windows

./proctrace -once -alerts                    # one-off scan, print only flagged processes
./proctrace                                  # run continuously with default settings
./proctrace -config configs/local.example.json
```

Run it from an elevated prompt on Windows. Without admin rights it can't read the image path or command line of other users' and system processes.

Cross-compile for Windows from any OS:

```sh
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o proctrace.exe ./cmd/proctrace
```

### Example alert

```json
{
  "@timestamp": "2026-11-21T05:26:27Z",
  "event": { "kind": "alert", "category": ["process"], "type": ["start"], "risk_score": 75 },
  "process": {
    "pid": 7412, "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -nop -c Get-Process",
    "hash": { "sha256": "…" },
    "parent": { "pid": 6120, "name": "WINWORD.EXE" }
  },
  "proctrace": {
    "parent_status": "verified",
    "detections": [
      { "rule_id": "PT-W001", "title": "Office application spawned a shell or script host",
        "severity": "high", "score": 75, "attack": ["T1204.002", "T1059"],
        "reason": "process powershell.exe; parent WINWORD.EXE" }
    ]
  }
}
```

Field names follow the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) (`process.*`, `event.*`, `host.*`), so the events can go into Elastic, OpenSearch, Wazuh or Sentinel without a custom parser.

## Configuration

See `configs/local.example.json` and `configs/forward.example.json`.

| Key | Meaning |
|---|---|
| `mode` | `local` or `forward` |
| `scan_interval` | Polling interval, e.g. `"2s"` |
| `rules_path` | Rule file to load |
| `only_alerts` | Output only processes that matched a rule |
| `stdout` | Also print events to stdout |
| `hash.max_file_mb` | Skip hashing files larger than this |
| `local.path`, `local.max_size_mb` | JSONL output file, rotated to `.1` at the size limit |
| `forward.url` | HTTPS endpoint that accepts NDJSON (`application/x-ndjson`) |
| `forward.ca_file` | CA used to verify the collector |
| `forward.cert_file` / `key_file` | Client certificate for mutual TLS |
| `forward.token_env` | Name of an environment variable holding a bearer token |
| `forward.spool_path`, `flush_interval`, `max_batch_mb` | Local spool and batching |

In forward mode, every event is written to the spool file before anything is sent, and a batch is deleted only after the collector returns a 2xx response. Events therefore survive network outages and restarts. Any HTTP input that accepts NDJSON works as the collector: Vector, Fluent Bit, Logstash, or your own service.

## Writing rules

A rule matches when **all** of its conditions hold. Within a list, **any** entry is enough. Comparisons are case-insensitive.

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
  }
}
```

Available conditions: `name`, `name_not`, `parent_name`, `parent_name_not`, `path_prefix_not`, `path_contains`, `command_line_regex`, `name_lookalike`, `name_non_ascii`, `parent_status`. Add test cases for new rules in `internal/detect/engine_test.go`.

## Layout

```
cmd/proctrace/        entry point and pipeline wiring
internal/collector/   process sources (snapshot now, ETW next)
internal/lineage/     parent resolution and PID-reuse checks
internal/enrich/      hashing (signature checks planned)
internal/detect/      rule engine
internal/output/      stdout, JSONL file and HTTPS forwarder
internal/config/      configuration
rules/                detection rules
docs/                 architecture notes
```

## Roadmap

- [x] Process snapshot collector (Windows Toolhelp32 + NtQueryInformationProcess, Linux /proc)
- [x] Parent validation (creation-time check, PID reuse)
- [x] SHA-256 hashing with cache
- [x] JSON rule engine with risk scoring and ATT&CK tags
- [x] Local JSONL output with rotation
- [x] HTTPS/mTLS forwarder with crash-safe spool
- [ ] **ETW collector** (`Microsoft-Windows-Kernel-Process`) for real-time process starts without gaps
- [ ] PPID-spoofing detection (compare the claimed parent with the creating process from ETW)
- [ ] Authenticode signature checks (signed / unsigned / signer name)
- [ ] Run as a Windows service (install / uninstall commands)
- [ ] Sigma rule import (process_creation subset)
- [ ] Per-process network connections
- [ ] Central-side enrichment: VirusTotal / MalwareBazaar hash lookups
- [ ] Memory inspection: RWX regions, process hollowing indicators

## Security

proctrace runs with high privileges, so it is designed to be **read-only**: it never executes commands received from the network. See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[Apache License 2.0](LICENSE)
