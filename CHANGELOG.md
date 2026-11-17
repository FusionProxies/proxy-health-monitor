# Changelog

## v0.1.0 (2026-11-17)

First release.

- Health checks for HTTP forward proxies, HTTP CONNECT (also over TLS to the proxy) and SOCKS5 TCP CONNECT with username/password authentication, local or remote DNS.
- Per-phase timing (DNS, connect, proxy handshake, TLS, time to first byte, total), bytes per check, and 12 failure classes.
- SQLite history with retention; states, incidents (down, latency, availability) that survive restarts.
- Alerts to the console, signed webhooks, email, Telegram and Discord, with deduplication, cooldown and a rate limit.
- Dashboard (overview, proxy detail, incidents, settings), read-only REST API, Prometheus metrics.
- CLI: `init`, `validate`, `check`, `start`, `status`, `report`, `target`, `demo`, `healthcheck`.
- Safety: loopback by default, token required elsewhere, Host check, credential masking everywhere, interval floor, global and per-target limits.
