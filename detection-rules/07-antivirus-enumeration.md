# Rule 07 — AntiVirus Enumeration

**Tactic:** Discovery (TA0007)
**Technique:** T1518.001 — Software Discovery: Security Software Discovery
**Platform:** Windows · **Severity:** Medium · **Risk score:** 47

## What it detects

An adversary querying the Windows Security Center / `AntiVirusProduct` WMI class (via `Get-WmiObject` or `Get-CimInstance`) to enumerate installed antivirus and security products — reconnaissance before trying to disable or evade them.

## Query

```kql
event.type : "start" and
process.name : "powershell.exe" and
process.command_line : (*AntiVirusProduct* or *SecurityCenter*) and
process.command_line : (*Get-WmiObject* or *Get-CimInstance*)
```

## What it anchors on

Both conditions must hold: a security-related WMI class (`*AntiVirusProduct*` / `*SecurityCenter*`) **and** a query cmdlet (`*Get-WmiObject*` / `*Get-CimInstance*`). Pairing the class with the cmdlet makes it specific. Covering both legacy (`Get-WmiObject`) and modern (`Get-CimInstance`) means an attacker who switched to CIM to look cleaner is still caught.

## False-positive tuning

Endpoint-management/inventory tools sometimes query `AntiVirusProduct`. Rated Medium/47 — enumerating defenses is a stronger signal of attacker intent than generic Discovery. Exclude known agents by parent process or image path.

## Validation

Validated against a Caldera security-software-discovery ability — alert fired, confirmed against the operation log.