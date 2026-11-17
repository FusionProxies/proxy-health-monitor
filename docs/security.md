# Security and responsible use

## Scope: your own infrastructure

proxy-health-monitor is for monitoring proxies you operate or are explicitly authorized to monitor, through target endpoints you control.

- It contacts nothing that is not in the configuration file: each check goes through one configured proxy to one configured target.
- Intervals have a floor of 10 seconds for remote proxies (1 second only for proxies on the same machine). Per-target limits (`max_concurrent`, `min_spacing`) and the global `concurrency` cap the load on every endpoint.
- It has no proxy lists, no discovery, no scanning, no rotation of identities, and no feature that hides or changes who sends a request. Each request carries a `User-Agent` that names the project.
- SOCKS5 is used for TCP CONNECT only.

If you monitor a commercial proxy service, check that its terms allow automated health checks and count the traffic: on metered plans checks are billed traffic.

## Credentials

- Put secrets in environment variables and reference them as `${NAME}`. Keep the configuration file readable only by the user that runs the monitor (`proxy-monitor init` creates it with mode 0600).
- Every known credential is masked in logs, API responses, the dashboard, alerts, reports and `/metrics`. Credentials that appear inside URLs are masked by pattern even if they were never configured. Usernames are shown as their first two characters plus `***`.
- The database stores timings, status codes, failure classes and masked error messages. It stores no credentials, no response bodies and no headers.

## Dashboard and API exposure

| Layer | What it does |
|---|---|
| Loopback by default | `listen: 127.0.0.1:8090`. Nothing is reachable from the network unless you change it |
| Token required off loopback | A non-loopback `listen` without `auth_token` is refused at startup (unless `allow_remote_without_auth` is set explicitly) |
| Token comparison | Constant time; at least 16 characters; 10 failed attempts per minute per address, then `429` |
| Host check | On a loopback listener only `localhost`, `127.0.0.1`, `::1` and `allowed_hosts` are accepted, which blocks DNS rebinding attacks from web pages |
| Read-only API | One write endpoint exists (check now). It needs a token, a custom header and a same-origin request, and respects the interval floor |
| Browser hardening | Strict Content-Security-Policy (no inline scripts or styles, no third-party requests), `X-Frame-Options: DENY`, `nosniff`, `no-referrer` |
| Configuration is read-only | The dashboard shows settings but cannot change them |

### Exposing the dashboard

Prefer, in this order:

1. Keep it on `127.0.0.1` and reach it through an SSH tunnel: `ssh -L 8090:127.0.0.1:8090 server`.
2. A reverse proxy with TLS on the same host ([examples/nginx](../examples/nginx/proxy-monitor.conf)), with `auth_token` set and the public name in `allowed_hosts`.
3. Docker with the port published on `127.0.0.1` ([docker-compose.yml](../docker-compose.yml)).

The server speaks plain HTTP. Do not send the token over an untrusted network without TLS in front.

## Reporting a vulnerability

Please report security problems privately, as described in the [organization security policy](https://github.com/FusionProxies/.github/blob/main/SECURITY.md), not in a public issue.
