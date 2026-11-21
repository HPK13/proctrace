# Security policy

proctrace runs with elevated privileges on endpoints, so security issues in it matter.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's
[private vulnerability reporting](https://github.com/HPK13/proctrace/security/advisories/new)
with:

- the affected version or commit
- steps to reproduce, or a proof of concept
- the impact you observed

You should get an acknowledgement within 7 days.

## Scope

In scope: the agent binary, rule engine, forwarder (TLS handling, spool files) and default configuration.
Detection gaps (a technique the default rules don't catch) are welcome as normal issues or pull requests.
