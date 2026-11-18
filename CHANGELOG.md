# Changelog

## v0.2.0 (2026-11-18)

- `proxy-monitor doctor <proxy-url>`: checks one proxy without a configuration file and explains the failure in plain language with concrete fixes. It also lints the URL (missing scheme, `host:port:user:pass` exports, unencoded `@`, `/`, `?`, `#` or `%` in passwords, SOCKS4) and the `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` variables. Text or `-json`; exit code 0, 1 or 2.
- Check results name the step that failed: `failed_phase` (`dns`, `connect`, `proxy_handshake`, `target_tls`, `response`) in `check -json` and `doctor -json` (not stored in the database yet).

## v0.1.0 (2026-11-17)

First release.

- Health checks for HTTP forward proxies, HTTP CONNECT (also over TLS to the proxy) and SOCKS5 TCP CONNECT with username/password authentication, local or remote DNS.
- Per-phase timing (DNS, connect, proxy handshake, TLS, time to first byte, total), bytes per check, and 12 failure classes.
- SQLite history with retention; states, incidents (down, latency, availability) that survive restarts.
- Alerts to the console, signed webhooks, email, Telegram and Discord, with deduplication, cooldown and a rate limit.
- Dashboard (overview, proxy detail, incidents, settings), read-only REST API, Prometheus metrics.
- CLI: `init`, `validate`, `check`, `start`, `status`, `report`, `target`, `demo`, `healthcheck`.
- Safety: loopback by default, token required elsewhere, Host check, credential masking everywhere, interval floor, global and per-target limits.
