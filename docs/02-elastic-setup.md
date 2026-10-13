# 02 — Elastic Stack setup

The Elastic Stack (Elasticsearch, Kibana, Fleet Server) runs in Docker on the VPS. Everything uses TLS with a private CA and is reachable only over the Tailscale mesh.

## Prerequisites

- A VPS (I used Hetzner) with Docker and Docker Compose installed
- Tailscale installed on the VPS (see [03-tailscale.md](03-tailscale.md))
- Enough RAM — Elasticsearch is memory-hungry; give it room

## Version

- Elastic Stack **9.5.4** (Elasticsearch, Kibana, Fleet, Elastic Agent, Elastic Defend)

## Steps

1. **Bring up Elasticsearch + Kibana** with the Docker Compose file in [`../docker/docker-compose.yml`](../docker/docker-compose.yml).
   - Copy `.env.example` to `.env` and set your own passwords. **Never commit `.env`.**
2. **Generate the certificates** (private CA + per-node certs) and mount them into the containers.
3. **Enroll Fleet Server**, then add the integrations you want (System, Elastic Defend).
4. **Set the Fleet output correctly.** This is the one that bit me — see the gotcha below.

## Gotchas I hit (so you don't)

- **Fleet output must point to the internal address the containers can actually reach.**
  My agent policy was using the default output (the Tailscale IP), which the Docker containers can't loop back to. Result: Fleet Server showed **Unhealthy / context deadline exceeded**. Fix: set the policy output to the internal Elasticsearch address (`https://es01:9200`) instead of the external one.

- **Service tokens don't get revoked from the Kibana GUI.**
  The Kibana UI revokes *enrollment* tokens, not *service* tokens. If a service token leaks, you have to revoke it via the Elasticsearch API. Clicking through the Fleet wizard multiple times also silently creates multiple service tokens — check for extras and revoke the ones you aren't using.

- **KQL needs `field : "value"`, not bare words.**
  Searching `whoami` in Discover returns nothing. You need `process.name : "whoami.exe"`. Bare words don't match the way you'd expect.

## Verify it's working

In Kibana → Discover or Dev Tools, run an ES|QL count:

```esql
FROM logs-* | STATS count = COUNT(*)
```

If events are flowing, you'll see the count climb. (Mine reached 12,461,786.)


