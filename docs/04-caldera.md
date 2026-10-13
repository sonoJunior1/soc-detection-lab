# 04 — MITRE Caldera

[MITRE Caldera](https://caldera.mitre.org/) is the adversary emulation platform. It deploys an agent to a victim, runs real ATT&CK techniques, and logs exactly what it did — which is perfect for testing whether your detections fire.

## Version

- Caldera **5.3.0**

## Concepts (quick glossary)

- **Agent** — the implant that runs on the victim (I used the **Sandcat** agent).
- **Ability** — a single technique Caldera can execute (e.g. "Identify active user").
- **Adversary profile** — an ordered set of abilities = an attack chain.
- **Operation** — one run of an adversary profile against agents.

## Setup

1. Run Caldera on the VPS (Docker or directly).
2. Deploy the Sandcat agent to the Windows victim over the Tailscale mesh.
3. Pick or build an adversary profile — I used a **Discovery** profile (see [`../caldera/adversary-profiles.md`](../caldera/adversary-profiles.md)).
4. Run the operation and watch the operation log.
5. Cross-check: for each ability Caldera ran, confirm an alert fired in Kibana.

## Gotchas I hit

- **Caldera regenerates its config and can write an empty `red:` password.**
  Caldera kept overwriting `conf/local.yml` and generating an empty password for the `red` user. Fix: let Caldera generate a complete config once (so all the required `app.contact.*` keys exist), then edit the passwords into that file with a small script (I used PyYAML to set them reliably rather than fragile regex), and mount it **read-only** (`:ro`) so Caldera can't regenerate over it.

- **A hand-written config missing `app.contact.*` keys crashes the agent tunnel** with:
  ```
  AttributeError: 'NoneType' object has no attribute 'split'
  ```
  That's the symptom of an incomplete config — don't hand-write it from scratch, edit a generated one.

