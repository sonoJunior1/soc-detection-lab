# 01 — Architecture

## The idea

A SOC has three jobs: **collect** telemetry from endpoints, **detect** malicious behavior in that telemetry, and **validate** that the detections actually work. This lab does all three, end to end, on infrastructure you fully control.

## Components

| Layer | Tool | Role |
|-------|------|------|
| Backend / storage | **Elasticsearch** | Stores all event telemetry |
| Analyst UI | **Kibana** | Hunting (KQL / ES\|QL), building rules, viewing alerts |
| Agent management | **Fleet** | Enrolls and manages endpoint agents from one place |
| Endpoint sensor | **Elastic Agent + Elastic Defend** | EDR — collects process, network, file events |
| Networking | **Tailscale** | Private mesh so endpoints reach the stack with no public ports |
| Adversary | **MITRE Caldera** | Runs real attack techniques to test detections |
| Host | **Hetzner VPS** | Runs the stack in Docker |

## How traffic flows

```
Windows endpoint ──┐
                   ├─ Elastic Agent (EDR) ──► Tailscale mesh ──► Fleet / Elasticsearch (VPS)
Linux endpoint  ───┘

Analyst ──► Tailscale ──► Kibana (VPS)   [hunt, write rules, review alerts]

Caldera (VPS) ──► Tailscale ──► Windows victim   [launch attack → generates telemetry → rules fire]
```

## Design choices worth calling out

- **No public ports.** The stack is only reachable over the Tailscale mesh. Nothing in this lab is exposed to the open internet.
- **TLS everywhere**, using a private CA — same as you'd expect in a real deployment.
- **Role-based access with Tailscale tags.** Endpoints are tagged (e.g. `tag:soclab`, `tag:target`) and ACL grants control who can reach what — so a victim machine can't reach the SOC backend, only the other way around.
- **Hardened host.** SSH key-only, host firewall (UFW) + cloud firewall, no unnecessary services.

