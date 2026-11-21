# Architecture

```
            ┌──────────────────────── proctrace agent ────────────────────────┐
            │                                                                  │
 OS ──────► │ collector ──► lineage ──► enrich ──► detect ──► output sinks     │
            │ (snapshot,    (parent     (SHA-256,  (JSON      ├─ stdout        │
            │  ETW next)    validation)  signer*)   rules)    ├─ local JSONL   │
            │                                                 └─ forwarder ──────► HTTPS / mTLS
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

## Detection

Rules are data (`rules/default.json`), compiled once at start-up. All conditions in a rule must hold, and any entry in a list condition is enough. Each detection carries a reason string built from the conditions that matched, so an analyst can see *why* without reading the rule. Risk score = highest rule score + 5 per additional detection, capped at 100.

## Output

- `Writer`: JSONL to stdout.
- `File`: JSONL file with size-based rotation (`.1`).
- `Forwarder`: appends to a spool file. On each flush the spool is renamed to `.inflight` and POSTed as NDJSON. Bytes are dropped from `.inflight` only after a 2xx response. Writes never block on the network, and a crash or outage loses nothing that reached the spool.

## Design constraints

- **Standard library only** (for now): small attack surface and supply chain, and a single static binary.
- **Read-only agent:** no remote command execution. An agent running as SYSTEM that accepts commands is a ready-made backdoor if the server is compromised.
- **Least privilege:** processes are opened with limited query rights only.
- **ECS field names**, so events need no custom parser downstream.
