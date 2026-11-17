# Configuration reference

proxy-monitor reads one YAML file (`-config`, or the `PROXY_MONITOR_CONFIG` environment variable, default `proxy-monitor.yaml`). `proxy-monitor init` writes an annotated starting point and `proxy-monitor validate` checks a file without contacting anything.

Unknown keys are errors, so a typo such as `intervall` is reported instead of ignored. Every problem in a file is listed at once.

## Secrets and environment variables

Write `${NAME}` anywhere and the value of the environment variable `NAME` is used. A missing variable is an error that names the variable. `$$` is a literal dollar sign. Values from the environment are never parsed as YAML, so a password such as `null` or `~` stays a password.

Every credential the configuration knows (proxy usernames and passwords, the API token, webhook URLs and secrets, SMTP passwords, bot tokens, sensitive target headers) is registered with the redactor at startup and masked in every log line, API response, alert and report.

## Durations

`500ms`, `30s`, `5m`, `2h`, `1h30m`, and days: `7d`, `30d`.

## `storage`

| Key | Default | Meaning |
|---|---|---|
| `path` | `proxy-monitor.db` | SQLite file. Relative paths are relative to the configuration file |
| `retention` | `30d` | How long raw check results are kept (minimum `1h`) |
| `incident_retention` | `180d` | How long closed incidents and the alert history are kept. Open incidents are never deleted |

Retention runs one minute after start and then every hour, deleting in batches so monitoring continues meanwhile.

## `server`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Serve the dashboard, API and `/metrics` |
| `listen` | `127.0.0.1:8090` | Address to listen on |
| `auth_token` | none | Required for the API, dashboard and metrics when set. At least 16 characters |
| `allowed_hosts` | `[]` | Extra `Host` header names accepted (the public name behind a reverse proxy) |
| `allow_remote_without_auth` | `false` | Listen on a non-loopback address without a token. Only for a port that Docker publishes on `127.0.0.1`, or behind a reverse proxy that authenticates |

A non-loopback `listen` without `auth_token` is refused unless `allow_remote_without_auth` is set. See [security.md](security.md).

## `monitor`

| Key | Default | Meaning |
|---|---|---|
| `interval` | `60s` | Default interval per proxy |
| `timeout` | `10s` | Default timeout per check (maximum `2m`, must be shorter than the interval) |
| `jitter` | `0.1` | Each interval varies by up to this fraction (0 to 0.5), so checks do not line up |
| `concurrency` | `4` | Checks running at the same time, all proxies together (1 to 64) |
| `min_interval` | `10s` | Lowest interval allowed for remote proxies. It can be raised, not lowered below 10s. Proxies on `127.0.0.1`, `::1` or `localhost` may go down to 1s |

Every request carries `User-Agent: proxy-health-monitor/<version> (+https://github.com/FusionProxies/proxy-health-monitor)` unless a target sets its own in `headers`.

After a restart, the first checks are spread over the first interval (at most 30 seconds) so they do not fire at once.

## `thresholds`

Global defaults. A proxy can override any of them under its own `thresholds:`.

| Key | Default | Meaning |
|---|---|---|
| `failure_threshold` | `3` | Consecutive failed checks before a proxy is **down** |
| `recovery_threshold` | `2` | Consecutive successful checks before a down proxy is **recovered** |
| `latency` | `3s` | The proxy is **slow** when the median total time of the last `latency_samples` successful checks is above this |
| `latency_samples` | `5` | See above |
| `availability` | `95` | Percentage of successful checks in `availability_window` below which availability is **low** |
| `availability_window` | `1h` | Window for the rule above (1m to 7d) |
| `availability_min_checks` | `10` | The availability rule needs at least this many checks in the window |

## `targets`

A target is the endpoint each check requests through a proxy. Use an endpoint you control: `proxy-monitor target` runs a tiny one that answers `ok`.

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Referenced by proxies |
| `url` | required | `http://` or `https://`. No credentials in the URL; use `headers` |
| `check` | `http` | `http`: one request and the full response. `tunnel`: stop after the tunnel (and the TLS handshake for `https://`), sending no request |
| `method` | `GET` | `GET` or `HEAD` |
| `expect_status` | `[200]` | Accepted status codes |
| `expect_body` | none | Text the body must contain |
| `headers` | none | Extra request headers. Values of headers named like auth, token, key, secret or cookie are treated as secrets |
| `max_body_bytes` | `65536` | At most this much of the body is read (0 to 1 MiB) |
| `ca_file` | none | PEM file with the CA that signed the target certificate |
| `insecure_skip_verify` | `false` | Skip certificate checks for this target (avoid) |
| `max_concurrent` | `2` | Checks against this target at the same time, all proxies together (1 to 16) |
| `min_spacing` | `500ms` | Minimum time between two checks against this target |

If there is exactly one target, proxies may omit `target`.

## `proxies`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | 1 to 64 letters, digits, `.`, `_`, `-`. History is stored by name |
| `url` | required | `http://`, `https://` (TLS to the proxy), `socks5://` (target resolved locally) or `socks5h://` (target resolved by the proxy), with host and port |
| `username`, `password` | from the URL | Override the URL credentials. Easier for passwords with special characters |
| `mode` | automatic | `http(s)://` proxies only. `forward` sends an absolute-form request (plain `http://` targets); `connect` opens a CONNECT tunnel. Default: `connect` for `https://` targets and tunnel checks, otherwise `forward` |
| `target` | the only target | Name of a target |
| `interval`, `timeout` | from `monitor` | Per-proxy schedule |
| `labels` | none | `key: value` pairs shown in the dashboard and API. Keys match `[a-zA-Z_][a-zA-Z0-9_]*` |
| `thresholds` | none | Overrides, same keys as the global `thresholds` |
| `ca_file`, `insecure_skip_verify` | none | TLS settings for an `https://` proxy |
| `disabled` | `false` | Keep the proxy in the file (and its history) without checking it |

SOCKS5 is checked with TCP CONNECT only. SOCKS4, UDP ASSOCIATE and BIND are not used. When credentials are configured, only username/password authentication is offered to a SOCKS5 proxy, so a proxy that also trusts your IP address cannot hide a broken password.

A proxy removed from the file loses its current state at the next start; its open incidents are closed with a note, and its history stays until retention removes it.

## `alerts`

See [alerts.md](alerts.md).
