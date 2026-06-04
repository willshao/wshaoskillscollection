# Skill: `edge_netlog`

Analyse Chromium **net-export** captures (`edge://net-export`) and surface the
root cause for page-load / cert / proxy / DNS failures.

## Why it exists

The `netlog` log kind has been listed as a recommended follow-up in
`playbook.json` (for `page_load_failure`, `cert_error`, `proxy_issue`) since
v1, but no skill actually consumed it. This skill closes that gap.

## Input

Standard contract envelope. The skill is interested in two things:

| Field | Notes |
|---|---|
| `extra.netlog_paths` | List of net-export JSON file paths to analyse. |
| `extra.folder`       | Folder to scan (recursively) for `*.json` net-export files. |
| `time_range`         | Optional; currently advisory. Net-export `time` is a per-session millisecond offset so absolute correlation requires `constants.timeTickOffset` (out of scope). |

If neither is provided, the skill returns `ok=true` with a warning finding and
populates `additional_logs_needed` with `log_kind=netlog`.

## What it reports

For every file:

* total event count, top source types (`URL_REQUEST`, `HOST_RESOLVER_IMPL`,
  `SOCKET`, ...), phase distribution
* URL requests whose `params` contain `net_error` strings (`ERR_*` codes)
* DNS resolution failures
* TLS handshake failures (`ERR_CERT_*`)
* Proxy fallback events
* Slowest URL requests (top N, by begin→end span in the same source_id)

These are translated into the standard `findings` / `solutions` /
`next_steps` / `additional_logs_needed` blocks.

## CLI

```
python edge_netlog/scripts/edge_netlog.py '{"extra":{"netlog_paths":["C:\\dumps\\edge-net.json"]}}'
python edge_netlog/scripts/edge_netlog.py '{"extra":{"folder":"C:\\dumps"}}'
```
