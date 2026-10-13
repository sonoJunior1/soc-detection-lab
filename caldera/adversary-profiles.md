# Caldera adversary profiles

The attack chains I ran to validate detections.

## Discovery profile (validated run)

Run against the Windows victim. Four abilities, all Discovery tactic:

| Ability | MITRE technique | What it does | Detected |
|---------|-----------------|--------------|----------|
| Identify active user | T1033 | `whoami` — current user context | ✅ |
| Identify local users | T1087.001 | enumerate local accounts | ✅ |
| Find user processes | T1057 | list running processes | ✅ |
| View admin shares | T1135 | enumerate network/admin shares | ✅ |

**Result: 4 / 4 detected.** Each detection was confirmed by matching the Caldera operation log to the corresponding Kibana alert, down to the event counts.

## How to reproduce

1. Deploy the Sandcat agent to the victim (see [`../docs/04-caldera.md`](../docs/04-caldera.md)).
2. Select the Discovery adversary profile.
3. Run the operation.
4. In Kibana, open the alerts and confirm one fired per ability.

