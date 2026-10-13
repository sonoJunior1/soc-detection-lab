# Rule 10 — Defense Evasion: PowerShell history cleared

**Tactic:** Defense Evasion (TA0005)
**Technique:** T1070.003 — Indicator Removal: Clear Command History
**Platform:** Windows · **Severity:** Low · **Risk score:** 21

## What it detects

An adversary running `Clear-History` to wipe the PowerShell session's command history — an anti-forensic step to hide what commands they ran.

## Query

```kql
event.type : "start" and
process.name : "powershell.exe" and
process.command_line : (*ExecutionPolicy*Bypass* and *Clear-History*)
```

## What it anchors on

`*Clear-History*` (the cmdlet that clears session history) plus `*ExecutionPolicy*Bypass*`. Unlike the Discovery rules, this catches the attacker **cleaning up** — indicator-removal activity is strong signal because legit users almost never script `Clear-History` with a bypass. It also flags that *something happened before it worth hiding*.

## False-positive tuning

`Clear-History` run interactively by a developer is normal and won't match (no bypass wrapper). For broader coverage, also watch for `Remove-Item` against the PSReadLine `ConsoleHost_history.txt` file — attackers sometimes delete that instead.

## Validation

Validated against a Caldera indicator-removal ability — alert fired, confirmed against the operation log.