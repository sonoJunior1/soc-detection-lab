# 03 — Tailscale private mesh

Tailscale connects the VPS, the endpoints, and the analyst machine on one private network — with **no public ports** on any of them. Access between machines is controlled with tags and ACL grants.

## Why a mesh instead of opening ports

If you expose Elasticsearch/Kibana to the public internet, you're now running a target. The mesh means the SOC backend has zero public attack surface — you can only reach it if you're on the tailnet.

## Tagging model (role-based access)

| Tag | Applied to | Can reach |
|-----|------------|-----------|
| `tag:soclab` | VPS (Elastic + Caldera) | — |
| `tag:target` | Victim endpoints | Should NOT reach the SOC backend |

The point: a victim machine is **untrusted**. ACL grants let the SOC reach the target (to run Caldera, collect telemetry), but not the other way around. That models a real environment where a compromised endpoint shouldn't be able to pivot into your security stack.

## Steps

1. Install Tailscale on the VPS, endpoints, and your analyst machine.
2. Define tags in the Tailscale admin console and assign them to machines.
3. Write ACL grants so only the intended direction of access is allowed.
4. Confirm the endpoints reach the VPS over its `100.x` tailnet address, and that a `tag:target` machine cannot reach the SOC backend.

## Gotcha I hit

- **Don't tag your own analyst/attacker machine as `tag:target`.**
  I accidentally tagged my Kali laptop `tag:target`, which cut off its own SSH access (it was now "untrusted" per the ACL). Fix:
  ```bash
  sudo tailscale up --reset --force-reauth
  ```
  then re-tag it correctly in the admin console.


