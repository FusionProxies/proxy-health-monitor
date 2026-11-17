# REST API

The API is read-only, with one exception (`POST .../check`, below). Responses are JSON with `Cache-Control: no-store`. Credentials never appear in any response: proxy URLs are shown as `http://us***:***@host:port` and query values of target URLs are masked.

## Authentication

Without `server.auth_token`, the API answers on loopback only. With a token, every endpoint except `/api/health` needs either:

```
Authorization: Bearer <token>
```

or HTTP Basic authentication with any username and the token as the password (this is what the browser login uses). After 10 failed attempts within a minute, an address gets `429` for a minute.

```bash
curl -H "Authorization: Bearer $PROXY_MONITOR_TOKEN" http://127.0.0.1:8090/api/proxies
```

## Endpoints

| Method and path | Returns |
|---|---|
| `GET /api/health` | `{"status":"ok"}`. Public, for load balancers and container health checks. With valid credentials it also returns the version, uptime and proxy count |
| `GET /api/proxies` | Every configured proxy: state, protocol, masked URL, target, labels, last check, last error, and 24-hour statistics with an hourly availability sparkline |
| `GET /api/proxies/{name}` | One proxy: availability and latency for 1h, 24h, 7d and 30d, median time per phase, the latest 30 checks, recent errors (7 days), incidents, effective thresholds |
| `GET /api/proxies/{name}/checks?window=24h&failed=1&limit=500` | Raw checks, newest first. `window`: `1h`, `6h`, `24h`, `7d`, `30d`. `failed=1` returns failures only. `limit` up to 5000 |
| `GET /api/proxies/{name}/series?window=24h` | Time buckets (checks, successes, uptime, p50, p95) for charts. Bucket width: 1m for 1h, 5m for 6h, 15m for 24h, 2h for 7d, 6h for 30d. Buckets without checks are included with `checks: 0` |
| `GET /api/metrics` | Summary: proxies per state, checks and uptime over 24 hours, open incidents |
| `GET /api/incidents?status=open&proxy=name&window=7d&limit=200` | Incidents, newest first, with duration |
| `GET /api/alerts?limit=100` | Alert history: sent, suppressed (with the reason) and failed |
| `GET /api/settings` | The effective configuration without secrets: intervals, thresholds, retention, targets, alert channel names |
| `GET /metrics` | Prometheus text format, see [metrics.md](metrics.md) |
| `POST /api/proxies/{name}/check` | Queue an immediate check. See below |

### Check now

`POST /api/proxies/{name}/check` is the only endpoint that changes anything, and it only moves the next check of one proxy forward. It requires:

- `server.auth_token` to be configured (otherwise it answers `403`), and valid credentials;
- the header `X-Proxy-Monitor-Request: 1`, and an `Origin` header (if present) matching the host, so another website cannot trigger it from a logged-in browser;
- at least 10 seconds since the last check of that proxy (1 second for proxies on localhost). Otherwise `409`.

```bash
curl -X POST -H "Authorization: Bearer $PROXY_MONITOR_TOKEN" -H "X-Proxy-Monitor-Request: 1" \
  http://127.0.0.1:8090/api/proxies/office-http/check
```

## Example: `GET /api/proxies`

```json
{
  "proxies": [
    {
      "name": "vendor-socks5",
      "protocol": "SOCKS5 (remote DNS)",
      "scheme": "socks5h",
      "url": "socks5h://ve***:***@proxy.vendor.example:1080",
      "target": "own-health",
      "target_url": "https://health.example.com/healthz",
      "check": "http",
      "labels": {"provider": "vendor"},
      "interval": "2m",
      "timeout": "10s",
      "state": "healthy",
      "last_check": "2026-11-17T10:42:00Z",
      "last_ok": "2026-11-17T10:42:00Z",
      "last_failure": "2026-11-17T09:10:00Z",
      "consecutive_failures": 0,
      "last_total_ms": 412.5,
      "last_24h": {"checks": 720, "successes": 716, "failures": 4, "uptime": 99.44, "avg_ms": 430.2, "min_ms": 301.0, "p50_ms": 418.0, "p95_ms": 612.4, "max_ms": 1840.1, "ttfb_p50_ms": 120.3, "errors": {"timeout": 4}},
      "spark_24h": [100, 100, 98.3, 100]
    }
  ],
  "demo": false
}
```

The numbers above illustrate the format only.

## Error classes

| Class | Meaning |
|---|---|
| `dns_failure` | The proxy host (or, with `socks5://`, the target) did not resolve |
| `connection_refused` | Nothing listens on the proxy port |
| `connection_failed` | TCP failed, or the proxy closed the connection |
| `timeout` | A phase did not finish in time; the message names the phase |
| `auth_failed` | HTTP 407, SOCKS5 authentication rejected, or credentials required but not configured |
| `protocol_error` | The proxy does not speak the expected protocol (for example an HTTP proxy checked as SOCKS5) |
| `proxy_rejected` | The proxy refused the request by policy (HTTP 403 to CONNECT, SOCKS5 reply 0x02) |
| `upstream_unreachable` | The proxy could not reach the target (HTTP 502/503/504 to CONNECT, SOCKS5 replies 0x03 to 0x06) |
| `proxy_error` | Other proxy-side failure |
| `tls_error` | TLS with an `https://` proxy or with the target failed (including certificate checks) |
| `unexpected_status` | The target answered with a status not in `expect_status` |
| `body_mismatch` | The body did not contain `expect_body` |
