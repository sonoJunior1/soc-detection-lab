# 05 — Detection engineering

This is the part that matters most. Collecting logs is easy; **writing detections that actually catch an adversary — and knowing why they work — is the skill.** Here's what I learned writing and tuning 11 rules against real Caldera attacks.

## How I approached a rule

For each technique I wanted to catch, I asked:

1. **What durable signal does this behavior leave?** Not the exact command string (easy to change), but the underlying behavior.
2. **Anchor on the most specific reliable field first**, then generalize only enough to survive small variations — specific → general, not the reverse.
3. **Test it against Caldera**, then **tune for false positives** by looking at what legit activity also matches.

## The three lessons that changed how I write rules

### 1. The same technique looks different per OS
`whoami` on Linux is `whoami`; on Windows it's `whoami.exe`. A rule that matches `process.name : "whoami"` silently misses every Windows execution. **A detection is only as good as its coverage of how the technique actually appears on each platform you defend.**

### 2. Not every command creates a process event
Shell built-ins don't spawn a child process, so they generate **no process-creation event**:
- `hostname` in PowerShell
- `$env:username`
- history/environment lookups

If your rule only watches process creation, these slip past entirely. You need **command-line / script-block visibility** to catch them, not just process telemetry. This is why "I have EDR" ≠ "I have coverage."

### 3. The strongest signal is often the parent, not the command
`net.exe` running is normal. `net.exe` spawned by a Word document or an unexpected parent is not. **The anomalous parent process is frequently a stronger, harder-to-evade signal than the command itself** — an attacker can rename a binary, but the execution chain that launched it is much harder to disguise.

## The rules

The 11 rules I wrote live in [`../detection-rules/`](../detection-rules/), one file each, with:
- the KQL / ES|QL query
- the MITRE ATT&CK tactic + technique
- a one-line description of the behavior
- a note on what signal it anchors on and any false-positive tuning

## Measuring coverage

Writing rules isn't the end — you have to prove they work. I ran a Caldera Discovery operation and confirmed **4/4 techniques detected**, matching Caldera's operation log to the Kibana alerts down to the event counts. See the [validation table in the README](../README.md#the-validation-the-important-part).

That closes the loop: **collect telemetry → emulate the adversary → detect → measure coverage.**
