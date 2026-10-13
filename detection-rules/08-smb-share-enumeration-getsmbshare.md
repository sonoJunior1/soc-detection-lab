# Rule 08 — SMB share enumeration via Get-SmbShare

**Tactic:** Discovery (TA0007)
**Technique:** T1135 — Network Share Discovery
**Platform:** Windows · **Severity:** Low · **Risk score:** 21

## What it detects

An adversary running `Get-SmbShare` in PowerShell to enumerate the SMB/network shares on a host — finding file shares to target for data collection or lateral movement.

## Query

```kql
event.type : "start" and
process.name : "powershell.exe" and
process.command_line : (*ExecutionPolicy*Bypass* and *Get-SmbShare*)
```

## What it anchors on

`*Get-SmbShare*` (the cmdlet that lists SMB shares) plus `*ExecutionPolicy*Bypass*`. The cmdlet is the durable anchor — enumerating shares this way requires it. The bypass flag ties it to the scripted-attacker pattern rather than an admin listing shares interactively.

## False-positive tuning

Admins and backup/file-management scripts run `Get-SmbShare`. The bypass requirement narrows it. Low/21 on its own — stronger when it appears alongside other Discovery activity. Exclude known management scripts by parent process.

## Validation

Caldera Discovery operation, ability "View admin shares" (T1135) — alert fired, matched the operation log.