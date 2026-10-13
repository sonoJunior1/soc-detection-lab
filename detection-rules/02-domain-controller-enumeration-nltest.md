# Rule 02 — Discovery: Domain Controller enumeration via nltest

**Tactic:** Discovery (TA0007)
**Technique:** T1018 — Remote System Discovery
**Platform:** Windows · **Severity:** Low · **Risk score:** 21

## What it detects

An adversary running `nltest` with `dsgetdc` to locate domain controllers — mapping Active Directory to find remote systems for lateral movement.

## Query

```kql
event.type : "start" and
process.name : "powershell.exe" and
process.command_line : (*ExecutionPolicy*Bypass* and *nltest* and *dsgetdc*)
```

## What it anchors on

Three strings together: `*nltest*` (the DC-enumeration utility), `*dsgetdc*` (the operation that locates a DC), and `*ExecutionPolicy*Bypass*` (the scripted-attacker marker). `nltest /dsgetdc` is a signature move for DC discovery — an attacker can't do it this way without both the tool and the operation.

## False-positive tuning

Domain-join and AD-health scripts occasionally call `nltest`. The `dsgetdc` + bypass combination keeps it tight. Low/21 because a single DC lookup is weak on its own — meaningful as part of a Discovery cluster. Exclude known management scripts by parent process.

## Validation

Validated against a Caldera remote-system-discovery ability — alert fired, confirmed against the operation log.