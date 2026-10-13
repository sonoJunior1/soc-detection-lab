# Rule 04 — Local account enumeration via Win32_UserAccount

**Tactic:** Discovery (TA0007)
**Technique:** T1087.001 — Account Discovery: Local Account
**Platform:** Windows · **Severity:** Low · **Risk score:** 21

## What it detects

An adversary querying the `Win32_UserAccount` WMI class via PowerShell to enumerate user accounts — building a target list for privilege escalation or lateral movement.

## Query

```kql
event.type : "start" and
process.name : "powershell.exe" and
process.command_line : (*ExecutionPolicy*Bypass* and *Win32_UserAccount*)
```

## What it anchors on

`*Win32_UserAccount*` (the WMI class that returns account objects) plus `*ExecutionPolicy*Bypass*`. The class name is the durable anchor — the technique can't be done this way without naming it. The bypass flag separates scripted recon from an admin poking at WMI interactively.

> Sub-technique note: filtered with `LocalAccount=True` it's specifically T1087.001; without that filter it also returns domain accounts (T1087.002). Tag it in Kibana to match your actual query.

## False-positive tuning

Inventory and identity tooling can query `Win32_UserAccount`. Exclude known agents by parent process or image path rather than loosening the class match.

## Validation

Validated against a Caldera account-discovery ability — alert fired, confirmed against the operation log.