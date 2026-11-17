# Metrics and definitions

## What one check measures

```
 start
   |-- DNS ------------ resolve the proxy host (and, for socks5://, the target)
   |-- connect -------- TCP connect to the proxy
   |-- proxy handshake  TLS to an https:// proxy, then CONNECT or the SOCKS5 negotiation
   |-- TLS ------------ TLS with the target, through the tunnel (https:// targets)
   |-- request -------- send one request
   |-- TTFB ----------- until the first byte of the response
   `-- total ---------- until the body (up to max_body_bytes) is read
```

- **Connection latency** = DNS + connect + proxy handshake: the time until a usable tunnel existed.
- **Time to first byte** (TTFB) starts when the request has been written. It is measured above TLS, so TLS session tickets do not count as the response.
- **Response time** is the total.
- **Bytes** count everything that crossed the socket to the proxy in both directions, which is what a metered plan bills.

In forward mode (absolute-form request to a plain HTTP proxy) there is no handshake: the proxy reads the request and connects to the target in the same step, so that time appears in TTFB.

## Statistics

- **Uptime** for a period is successful checks divided by all checks in the period. A period without checks has no uptime, and the dashboard shows "no data" instead of 0% or 100%.
- **Latency statistics** (average, median, p95, minimum, maximum) use the total time of successful checks only.
- **Percentiles** use linear interpolation between the two nearest ranks (the method of numpy's default and Excel's PERCENTILE.INC). The median of 100 ms, 200 ms, 300 ms and 400 ms is 250 ms.
- **Downtime** in reports is the summed duration of down incidents within the period.

## States

| State | Meaning |
|---|---|
| unknown | No check has run yet |
| healthy | The last check passed and no latency or availability incident is open |
| degraded | Not down, but the last check failed, or a latency or availability incident is open |
| down | `failure_threshold` consecutive failures, until `recovery_threshold` consecutive successes |

## Prometheus

`GET /metrics` (bearer token if `server.auth_token` is set). Counters start at zero when the monitor starts; use `rate()` and `increase()`.

| Metric | Type | Labels |
|---|---|---|
| `proxy_monitor_up` | gauge | `proxy`, `protocol`, `target`: 1 if the last check passed |
| `proxy_monitor_state` | gauge | `proxy`, `state`: 1 for the current state, 0 for the others |
| `proxy_monitor_consecutive_failures` | gauge | `proxy` |
| `proxy_monitor_open_incidents` | gauge | `proxy` |
| `proxy_monitor_checks_total` | counter | `proxy`, `result` (`success`, `failure`) |
| `proxy_monitor_check_errors_total` | counter | `proxy`, `class` (see [api.md](api.md#error-classes)) |
| `proxy_monitor_last_check_timestamp_seconds` | gauge | `proxy` |
| `proxy_monitor_last_success_timestamp_seconds` | gauge | `proxy` |
| `proxy_monitor_phase_seconds` | gauge | `proxy`, `phase` (`dns`, `connect`, `proxy_handshake`, `tls`, `ttfb`, `total`): the last successful check |
| `proxy_monitor_check_duration_seconds` | histogram | `proxy`: total time of successful checks. Buckets 0.05 to 30 seconds |
| `proxy_monitor_check_bytes_total` | counter | `proxy`, `direction` (`in`, `out`) |
| `proxy_monitor_build_info` | gauge | `version` |
| `proxy_monitor_start_time_seconds` | gauge | |

Ready-made scrape configuration and alert rules: [examples/prometheus](../examples/prometheus).
