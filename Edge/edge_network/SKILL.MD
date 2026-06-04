---
id: edge_network
name: Edge Network Diagnostics
version: 1.0
role: follow_up
description: Diagnose DNS / proxy / certificate / connectivity problems affecting Microsoft Edge.
runtime:
  python: scripts/edge_network.py
needs_admin: false
triggers_for: [page_load_failure, cert_error, proxy_issue, dns_issue, sync_error]
---

## When to use
After `edge_diagnostics` classifies any network-flavored problem, or directly
when the user reports `ERR_*` page-load errors, certificate warnings, proxy
errors, or sync failures.

## Inputs

| Field | Required | Description |
|---|---|---|
| `extra.targets` | no | List of hostnames to probe. Defaults to Edge-critical endpoints. |
| `extra.skip_internet` | no | If `true`, skip outbound probes (useful for restricted environments). |

Default targets (Edge-critical):
- `edge.microsoft.com`
- `config.edge.skype.com`
- `clients2.google.com` (for some Edge components)
- `login.microsoftonline.com` (sync / sign-in)
- `www.microsoft.com`

## What it checks

1. **System proxy** — `netsh winhttp show proxy` and `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`.
2. **Edge proxy policy** — `ProxyMode`, `ProxyServer`, `ProxyPacUrl` from `Software\Policies\Microsoft\Edge`.
3. **DNS resolution** — `Resolve-DnsName` per target.
4. **TCP/443 reachability** — Python socket connect with 3s timeout.
5. **TLS handshake** — `ssl.create_default_context().wrap_socket()`, captures certificate subject/issuer/notAfter.

## Output

`raw.system_proxy`, `raw.edge_proxy_policy`, `raw.targets[]` with per-target
`dns`, `tcp`, `tls`, `error` fields.

`root_cause` set when:
- A configured proxy is unreachable
- DNS fails for all probed hosts
- TLS chain validation fails on Edge-critical hosts

## Invocation

```powershell
python edge_network\scripts\edge_network.py '{"extra":{"targets":["edge.microsoft.com","internal.corp.local"]}}'
```

## Notes
- No traffic decryption. We perform a normal TLS handshake using the system
  trust store.
- Set `extra.skip_internet=true` to run only the local-config checks.

## Report sections (envelope v2.1)

This skill emits the standard envelope plus three structured advisory fields seeded from `_shared/playbook.json` via `_shared.playbook.merge_into_result(...)`:

- `solutions[]` — concrete fixes for key problems (`problem_ref / title / severity / steps / references`).
- `next_steps[]` — suggested follow-up actions, optionally pointing at the next skill to run.
- `additional_logs_needed[]` — extra data sources required to deepen analysis.

Legacy `recommendations: string[]` is auto-derived from the three structured fields when not set (prefixes `[fix:...]` / `[next:...]` / `[logs:...]`).

## Log/source dependency

- ``_shared/sources/netlog`` (``NetlogFilter``: ``source_type / phase / contains``). Live ping / proxy / DNS checks remain local to this skill.

Each shared reader exposes the same surface (`discover / iter_entries / summarise / apply_filter / around_window / query`); this skill calls `query(...)` rather than parsing files inline.
