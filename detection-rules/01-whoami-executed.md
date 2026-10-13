# Rule 01 — Discovery: whoami executed

**Tactic:** Discovery (TA0007)
**Technique:** T1033 — System Owner/User Discovery
**Platform:** Windows · **Severity:** Low · **Risk score:** 21

## What it detects

An adversary running `whoami` to find out which user context they're operating in — a common first step after initial access.

## Query

```kql
process.name : "whoami.exe"
```

## What it anchors on

`process.name : "whoami.exe"` — the Windows binary name. On Linux the same technique is `whoami` (no `.exe`), which is why this is Windows-specific. A rule matching `"whoami"` would miss every Windows execution ([docs/05-detection-engineering.md](../docs/05-detection-engineering.md), lesson 1).

## False-positive tuning

`whoami` runs legitimately. On its own it's weak signal — strongest when correlated with other Discovery activity in a short window. Rated Low/21 for that reason.

## Validation

Caldera Discovery operation, ability "Identify active user" — alert fired, matched the operation log.