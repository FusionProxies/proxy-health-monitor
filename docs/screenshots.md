# How the screenshots are made

Screenshots of the dashboard are taken from the real dashboard running in demo mode, never from mock-ups:

```bash
proxy-monitor demo
```

Demo mode starts seven local test proxies on `127.0.0.1` with different behaviours (a healthy forward proxy, CONNECT and SOCKS5 proxies with authentication, a slow SOCKS5 proxy, a CONNECT proxy that fails about one request in five, a proxy with a scripted outage of 2 minutes in every 9, and one with a rotated password) and runs the normal monitor against them every 5 seconds. Every number on the screenshots comes from those real checks. The dashboard shows a "DEMO DATA" banner on every page in this mode; keep it visible in every screenshot.

To reproduce them:

1. Run `proxy-monitor demo` and wait about 20 minutes so the charts have history and at least two outages and recoveries happened.
2. Open http://127.0.0.1:8090 at a window width of 1440 pixels.
3. Capture: the Overview, the detail page of `flaky-connect` (1h window), the Incidents page, and the Settings page.
4. Save them as PNG in `assets/screenshots/`: `overview.png`, `proxy-detail.png`, `incidents.png`, `settings.png`.
