# How it relates to other tools

## proxy-checker (same organization)

[proxy-checker](https://github.com/FusionProxies/proxy-checker) is a one-shot CLI: give it a list, it checks every proxy in parallel and prints which work, their latency and the exit IP, country and network. It is the right tool for sorting a list.

proxy-health-monitor is for proxies you keep using: it checks the same proxies on a schedule, stores the history, opens and closes incidents, sends alerts, and serves a dashboard, a REST API and Prometheus metrics. It does not look up exit IP or geolocation, and it only talks to targets you configure.

| | proxy-checker | proxy-health-monitor |
|---|---|---|
| Runs | once | continuously (or once with `check`) |
| Input | a list of proxies | a reviewed configuration file |
| Target | third-party IP services (configurable) | your own health endpoint |
| History, incidents, alerts | no | yes |
| Phase timing (DNS, connect, handshake, TLS, TTFB) | total only | every phase |
| Failure classes | error text | 12 stable classes |
| SOCKS4 | yes | no (SOCKS5 TCP CONNECT only) |
| Exit IP and country | yes | no |

## General uptime monitors

Uptime monitors such as Uptime Kuma and Gatus, and the Prometheus blackbox exporter, can send an HTTP check through a proxy. There the proxy is a transport setting of a website check.

proxy-health-monitor makes the proxy itself the monitored object:

- the proxy handshake is timed and diagnosed on its own (HTTP 407 versus a SOCKS5 reply code versus silence on the port);
- several proxies share one controlled target, with per-target limits so the target is never flooded;
- incidents, availability and latency rules are per proxy, and credentials in proxy URLs are masked everywhere.

They work well together: export `/metrics` to the Prometheus you already run and keep your website monitors where they are.
