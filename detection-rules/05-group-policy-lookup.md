# Rule 05 — Group Policy Lookup

**Tactic:** Discovery (TA0007)
**Technique:** T1615 — Group Policy Discovery
**Platform:** Windows · **Severity:** Medium · **Risk score:** 47

## What it detects

An adversary running `gpresult /R` to dump the Resultant Set of Policy (RSoP) for the current user and computer — revealing Group Policy and security settings used to plan privilege escalation or evasion.

## Query

```kql
event.type : "start" and
process.name : "powershell.exe" and
process.command_line : (*ExecutionPolicy*Bypass* and *gpresult /R*)
```

## What it anchors on

`*gpresult /R*` (the native Group Policy enumeration command; `/R` prints the RSoP summary) plus `*ExecutionPolicy*Bypass*`. `gpresult` is the native tool for this technique, so the command string is a durable anchor — you can't enumerate Group Policy this way without it.

## False-positive tuning

Admins run `gpresult` for troubleshooting, but rarely wrapped in an ExecutionPolicy bypass. Rated Medium/47 — higher than the plain Discovery rules because Group Policy recon is a stronger signal of targeted intent. Exclude legit management scripts by parent process.

## Validation

Validated against a Caldera Group Policy discovery ability — alert fired, confirmed against the operation log.