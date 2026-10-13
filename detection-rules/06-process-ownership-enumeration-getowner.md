# Rule 06 — Process ownership enumeration via GetOwner

**Tactic:** Discovery (TA0007)
**Technique:** T1033 — System Owner/User Discovery
**Platform:** Windows · **Severity:** Low · **Risk score:** 21

## What it detects

An adversary using PowerShell + WMI (`Win32_Process` → `GetOwner`) to find which user account owns running processes — identifying active/privileged users without running `whoami`.

## Query

```kql
event.type : "start" and
process.name : "powershell.exe" and
process.command_line : (*ExecutionPolicy*Bypass* and *win32_process* and *getowner*)
```

## What it anchors on

Three command-line strings together: `*win32_process*` (the WMI class), `*getowner*` (the method mapping a process to its owner), and `*ExecutionPolicy*Bypass*`. Requiring all three is what keeps it specific — any one alone is noisy; the three in one command line is deliberate owner enumeration. Relies on command-line visibility (lesson 2).

## False-positive tuning

Admin/monitoring scripts occasionally query `Win32_Process`, but rarely with `getowner` + bypass together. Exclude known-good scripts by parent process or signing status rather than loosening the match.

## Validation

Validated against a Caldera WMI-based user/owner discovery ability — alert fired, confirmed against the operation log.