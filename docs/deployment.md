# Deployment

proxy-monitor is one static binary with an embedded dashboard and a pure-Go SQLite driver (no cgo). It needs no other service. A small VPS is plenty: memory use depends mostly on the number of proxies and the chart windows people open.

## Binary

Download the file for your platform from [Releases](https://github.com/FusionProxies/proxy-health-monitor/releases), verify it against `checksums.txt`, and run:

```bash
chmod +x proxy-monitor_linux_amd64
./proxy-monitor_linux_amd64 init
./proxy-monitor_linux_amd64 start
```

Or build from source with Go 1.24 or newer:

```bash
go install github.com/FusionProxies/proxy-health-monitor/cmd/proxy-monitor@latest
```

## systemd

A hardened unit file with setup steps is in [examples/systemd/proxy-monitor.service](../examples/systemd/proxy-monitor.service). Stopping the service lets in-flight checks finish (up to 5 seconds) and delivers queued alerts (up to 10 seconds).

## Docker

```bash
mkdir -p config
cp examples/docker/proxy-monitor.yaml config/proxy-monitor.yaml   # edit: your proxies and target
cat > .env <<'ENV'
PROXY_MONITOR_TOKEN=change-me-to-a-long-random-string
PROXY_USER=...
PROXY_PASS=...
ENV
docker compose up -d
```

- The image is distroless and runs as a non-root user. Data lives in the `proxy-monitor-data` volume at `/data`.
- Inside the container the server listens on `0.0.0.0:8090`, so the token is required. Compose publishes the port on the host's `127.0.0.1` only.
- The image has a health check (`proxy-monitor healthcheck`) against `/api/health`.

Without Compose:

```bash
docker build -t proxy-health-monitor .
docker run -d --name proxy-monitor --env-file .env \
  -v "$PWD/config:/config:ro" -v proxy-monitor-data:/data \
  -p 127.0.0.1:8090:8090 proxy-health-monitor
```

## Reverse proxy

Keep proxy-monitor on `127.0.0.1:8090` and terminate TLS in front of it. Add the public name to `server.allowed_hosts`, otherwise the Host check answers `421`. nginx example: [examples/nginx/proxy-monitor.conf](../examples/nginx/proxy-monitor.conf). With Caddy:

```
monitor.example.com {
    reverse_proxy 127.0.0.1:8090
}
```

## Prometheus and Grafana

Scrape `/metrics` with the token as a bearer token: [examples/prometheus](../examples/prometheus). The alert rules there show down, success-rate, p95 latency and staleness alerts built from the exported metrics.

## In CI

`proxy-monitor check` runs every proxy once and exits with `1` if any check fails, which makes it usable as a pipeline step or a cron job:

```bash
proxy-monitor check -config proxy-monitor.yaml -json > proxy-check.json
```

Only point CI checks at proxies and targets you are allowed to test.

## Backups

The database is a single SQLite file in WAL mode. To back it up while the monitor runs, use `sqlite3 proxy-monitor.db ".backup backup.db"`, or stop the monitor and copy the file.
