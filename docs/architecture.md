# Architecture

```
            ┌──────────────────────── proctrace agent ────────────────────────┐
            │                                                                  │
 OS ──────► │ collector ──► lineage ──► enrich ──► detect ──► redact ──► sinks │
            │ (snapshot,    (parent     (SHA-256,  (JSON       (secrets   ├ stdout│
            │  ETW next)    validation)  PE name,   rules)      masked)   ├ JSONL │
            │                            signer*)                         └ fwd ──────► HTTPS / mTLS
            └──────────────────────────────────────────────────────────────────┘    collector
                                                                     (spool file)
* planned
```

Collection, lineage, enrichment and detection are identical in both modes. The `mode` setting only chooses the output sink, so detection logic is written and tested once.

## Collector

`collector.Collector` is the extension point. `Snapshot` polls the process table every `scan_interval` and emits processes it has not seen before, keyed on PID + start time so a reused PID counts as a new process. The previous snapshot is kept, so a parent that exited between scans can still be named.

Windows: `CreateToolhelp32Snapshot` gives PID, PPID and name. Each process is then opened with `PROCESS_QUERY_LIMITED_INFORMATION` (the least access that works) for `GetProcessTimes`, `QueryFullProcessImageNameW` and `NtQueryInformationProcess(ProcessCommandLineInformation)`.

Known gap: anything that starts and exits within one interval is missed. The planned ETW collector removes this gap. It subscribes to the `Microsoft-Windows-Kernel-Process` provider, receives every start event with the command line and the *actual* creating process ID, and so also makes PPID-spoofing detection possible.

## Lineage

The OS-reported PPID is not trusted on its own. A candidate parent is accepted only if it started before the child; otherwise the PID was reused. Rules that test the parent (`parent_name`, `parent_name_not`) never fire unless the parent is `verified`, which keeps PID-reuse mix-ups from becoming false alerts.

## Enrichment

Each executable is read once (cached by path, size and modification time) for its SHA-256 and, on Windows, its PE `OriginalFileName` from the version resource. The original name is set by the publisher at build time, so it survives renaming the file.

## Detection

Rules are data (`rules/default.json`), embedded in the binary with `go:embed` and compiled once at start-up. A custom rule file can replace them; the agent logs the rule source and its SHA-256 at start-up, so a swapped rule file is visible.

Before matching, each process is prepared once: `name` conditions also match the OriginalFileName, and command lines are normalised (Unicode dashes, carets, backticks, quotes and string concatenation removed). PowerShell `-EncodedCommand` payloads are decoded so regexes see the hidden script. An `except` block on a rule suppresses it for known-good cases instead of disabling it. All conditions in a rule must hold, and any entry in a list condition is enough. Each detection carries a reason string built from the conditions that matched, so an analyst can see *why* without reading the rule. Risk score = highest rule score + 5 per additional detection, capped at 100.

## Redaction

After detection and before output, command lines go through `internal/redact`, which masks passwords, tokens and keys (generic `key=value` and flag patterns, tool-specific arguments such as `net use` and `sqlcmd -P`, and known token formats). Rules therefore see the full command line, while nothing secret is stored or forwarded.

## Output

- `Writer`: JSONL to stdout.
- `File`: JSONL file with size-based rotation (`.1`).
- `Forwarder`: appends to a spool file. On each flush the spool is renamed to `.inflight` and POSTed as NDJSON. Bytes are dropped from `.inflight` only after a 2xx response. Writes never block on the network, and a crash or outage loses nothing that reached the spool.

## Self-protection

- **Unsafe-install check:** when running elevated, the agent checks the owner and access list of its executable and folder, config, custom rules, certificates and data folder. If any non-admin principal can write to them, it refuses to start.
- **Confined output:** output file settings must be bare file names inside `data_dir`, which resolves relative to the executable, never the current directory.
- **DLL loading:** Windows DLLs are loaded by absolute System32 path (`internal/winapi`), so a DLL planted next to the exe is never loaded.

## Design constraints

- **Standard library only** (for now): small attack surface and supply chain, and a single static binary.
- **Read-only agent:** no remote command execution. An agent running as SYSTEM that accepts commands is a ready-made backdoor if the server is compromised.
- **Least privilege:** processes are opened with limited query rights only.
- **ECS field names**, so events need no custom parser downstream.