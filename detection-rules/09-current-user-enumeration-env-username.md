# Rule 09 — Current user enumeration via $env:username

**Tactic:** Discovery (TA0007)
**Technique:** T1033 — System Owner/User Discovery
**Platform:** Windows · **Severity:** Low · **Risk score:** 21

## What it detects

An adversary reading the `$env:username` environment variable in PowerShell to identify the current user — a quieter alternative to `whoami` that calls no external binary.

## Query

```kql
event.type : "start" and
process.name : "powershell.exe" and
process.command_line : (*ExecutionPolicy*Bypass* and *$env* and *username*)
```

## What it anchors on

`*$env*` + `*username*` together, plus the bypass marker. This rule is a direct example of lesson 2 in [docs/05-detection-engineering.md](../docs/05-detection-engineering.md): `$env:username` is a built-in variable access, so typed *interactively* it spawns no process and leaves no process-creation event. This rule catches it only when passed **as a command-line argument** (e.g. `powershell.exe -Command "$env:username"`), where it appears in `process.command_line`.

That's a deliberate, honest limitation: the interactive case needs PowerShell script-block / module logging, not process telemetry.

## False-positive tuning

Legit scripts read `$env:username` constantly, so `$env` + `username` alone would be noisy — the bypass requirement is what narrows it. Expect to tune this one hardest in production; consider pairing with other Discovery activity rather than alerting alone.

## Validation

Validated against a Caldera user-discovery ability that passes `$env:username` on the command line — alert fired, confirmed against the operation log.