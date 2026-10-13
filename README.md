# SOC Detection Lab

A full Security Operations Center detection pipeline, built from scratch on a cloud VPS — then tested with MITRE's own attack tool.

This repo is both a build guide (so you can make your own) and a detection-engineering portfolio: the detection rules here are ones I wrote and validated myself, not copied from a tutorial.

---

## What this is

I built a complete SOC pipeline to practice **detection engineering** with real data instead of theory:

- **Elastic Stack** (Elasticsearch, Kibana, Fleet) — TLS everywhere, no public ports
- **Windows + Linux endpoints** connected over a **private mesh network** with role-based access
- **Elastic Defend (EDR)** collecting process, network, and file telemetry
- **12M+ events ingested** — real data to hunt through with KQL and ES|QL
- **10 detection rules I wrote myself**, mapped to MITRE ATT&CK
- **MITRE Caldera** for adversary emulation

Then I ran a Caldera attack against a Windows victim and watched the detections fire in real time.

**Result: every technique Caldera executed was detected.** I verified it by matching Caldera's operation log against my alerts, down to the event counts.

---

## The validation (the important part)

> I attacked my own SOC and measured coverage — this is what makes it detection engineering, not just log collection.

I ran a **Caldera Discovery operation** against a Windows victim. It executed 4 abilities:

| Caldera ability        | MITRE technique | Detected? |
|------------------------|-----------------|-----------|
| Identify active user   | T1033           | ✅        |
| Identify local users   | T1087.001       | ✅        |
| Find user processes    | T1057           | ✅        |
| View admin shares      | T1135           | ✅        |

**4 / 4 techniques detected.** See [`caldera/adversary-profiles.md`](caldera/adversary-profiles.md) and the cropped screenshots in [`screenshots/`](screenshots/).

---

## Architecture

```
[ Windows endpoint ]  [ Linux endpoint ]
         \                  /
          \                /     (Elastic Agent + Elastic Defend EDR)
           \              /
        [ Tailscale private mesh ]   ← role-based access (tags), no public ports
                   |
        [ Hetzner VPS ]
           Elasticsearch + Kibana + Fleet   (Docker, TLS)
                   |
        [ MITRE Caldera ]  ← launches attacks to test detections
```

Full walkthrough in [`docs/01-architecture.md`](docs/01-architecture.md).

---

## Repo map

| Path | What's in it |
|------|--------------|
| [`docs/`](docs/) | Step-by-step build guide |
| [`detection-rules/`](detection-rules/) | The 11 rules I wrote, with MITRE mapping |
| [`docker/`](docker/) | Docker Compose + env template (scrubbed) |
| [`caldera/`](caldera/) | Adversary emulation setup and profiles |
| [`screenshots/`](screenshots/) | Kibana alerts, Caldera op log, Fleet (cropped) |

---

## Build it yourself

1. [Architecture overview](docs/01-architecture.md)
2. [Elastic Stack setup](docs/02-elastic-setup.md)
3. [Tailscale private mesh](docs/03-tailscale.md)
4. [MITRE Caldera](docs/04-caldera.md)
5. [Detection engineering](docs/05-detection-engineering.md)

---

## Credits / built with

- **[Elastic](https://www.elastic.co/)** — Elasticsearch, Kibana, Fleet, Elastic Defend
- **[MITRE](https://www.mitre.org/)** — [ATT&CK](https://attack.mitre.org/) and [Caldera](https://caldera.mitre.org/)
- **[Tailscale](https://tailscale.com/)** — private mesh networking
- **[Hetzner](https://www.hetzner.com/)** — cloud VPS

---

## About

Built by Souleymane Sono while studying detection engineering. I'm early in the field — this lab taught me the full loop: **collect telemetry → emulate the adversary → detect → measure coverage.** That's threat-informed defense in miniature.

Feedback and questions welcome — open an issue.
