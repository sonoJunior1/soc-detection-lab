# Rule 03 — Discovery: /etc/passwd read via command

**Tactic:** Discovery (TA0007)
**Technique:** T1087.001 — Account Discovery: Local Account
**Platform:** Linux · **Severity:** Low · **Risk score:** 21

## What it detects

An adversary reading `/etc/passwd` on a Linux host to enumerate local user accounts, using any common text utility (`cat`, `less`, `more`, `head`, `tail`, `grep`, `awk`, `strings`).

## Query

```kql
data_stream.dataset : "endpoint.events.process" and
event.type : "start" and
process.name : ("cat" or "less" or "more" or "head" or "tail" or "grep" or "awk" or "strings") and
process.args : "/etc/passwd"
```

## What it anchors on

The **target file** (`process.args : "/etc/passwd"`) plus a set of **reader binaries**. Anchoring on the file being read, not one tool, means an attacker who switches `cat` → `grep` → `strings` is still caught — the file is the durable signal.

This is the Linux counterpart to rule 04 (Windows account enumeration) — a direct example of lesson 1 in [docs/05-detection-engineering.md](../docs/05-detection-engineering.md): the same objective looks completely different per OS.

## False-positive tuning

Admins and scripts read `/etc/passwd` legitimately, so this can be noisy. Narrow by user context or correlate with other Discovery activity. Covering the file read rather than one tool is the right trade-off — better a slightly noisy rule than a missed technique.

## Validation

Validated against a Caldera Linux account-discovery ability — alert fired, confirmed against the operation log.