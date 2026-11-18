# proxy-monitor doctor

`proxy-monitor doctor` checks **one proxy** without a configuration file and tells you, in plain language, which step failed, why that usually happens and what to try. Use it when a proxy "does not work" and the error from your browser, curl or scraper says little (`407 Proxy Authentication Required`, `ERR_TUNNEL_CONNECTION_FAILED`, `curl: (56) CONNECT tunnel failed`, `Connection reset by peer`).

```
proxy-monitor doctor [flags] [proxy-url]
```

It makes one connection through the proxy to one target. It never prints passwords: usernames are shortened and passwords replaced with `***` in text and JSON.

## What it checks

1. **The proxy URL as you typed it**, before anything is sent:
   - no scheme (`1.2.3.4:8080`), which most tools read as `http://`;
   - the `host:port:user:pass` export format that providers hand out, which is not a URL (doctor rewrites it and checks the rewritten form);
   - `@`, `/`, `?`, `#` or a lone `%` inside a username or password, which cut the URL in the wrong place (doctor shows the percent-encoded form);
   - `https://` (TLS to the proxy itself, rarely what you want) and `socks5://` versus `socks5h://` (who resolves the site's name);
   - SOCKS4, which this tool does not check;
   - a port that usually belongs to the other protocol (1080 for SOCKS, 3128 or 8080 for HTTP).
2. **The proxy environment variables** that curl, Python, Go, Node and most CLIs read:
   - `HTTP_PROXY` and `http_proxy` set to different values (tools disagree on which wins; curl ignores uppercase `HTTP_PROXY`);
   - `HTTPS_PROXY=https://...`, usually a mistake for `http://`;
   - only `HTTP_PROXY` set, so `https://` requests go direct;
   - `NO_PROXY` covering the target;
   - credentials in the environment (masked in the output).
3. **One check through the proxy**, timed step by step: resolve the proxy host, TCP connect, proxy handshake (HTTP CONNECT, SOCKS5, or TLS to an `https://` proxy), TLS with the target through the tunnel, request and response.
4. **The explanation** for the failure class (the same 12 classes `proxy-monitor check` uses), adjusted to the protocol and the step that failed.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-target` | `https://example.com/` | URL requested through the proxy. Use one you are allowed to test, ideally your own (`proxy-monitor target` runs a small endpoint) |
| `-mode` | `connect` for `https://` targets, `forward` for `http://` | HTTP proxies only: `connect` (tunnel) or `forward` (absolute-form request) |
| `-timeout` | `15s` | limit for the whole check, at most `2m` |
| `-json` | off | print the report as JSON |
| `-no-env` | off | skip the environment variable checks |

The proxy URL can come from the argument, or, without one, from `HTTPS_PROXY`, `HTTP_PROXY` or `ALL_PROXY` (in that order, uppercase first). Put the password in `PROXY_PASSWORD` to keep it out of your shell history:

```bash
PROXY_PASSWORD='p@ss:word' proxy-monitor doctor http://customer-1@proxy.example.com:8080
```

Exit codes: `0` the proxy works, `1` the check failed, `2` the URL or the flags are unusable (nothing was sent).

## Examples

Real output. A port where nothing listens:

```
$ proxy-monitor doctor -no-env http://127.0.0.1:9
proxy-monitor doctor
  proxy   http://127.0.0.1:9  (HTTP CONNECT, from argument)
  target  https://example.com/

Proxy URL
  ok    parsed as HTTP CONNECT

Connection
  ok    resolve the proxy host 127.0.0.1         0ms
  FAIL  TCP connect to 127.0.0.1:9               1ms
  -     proxy handshake (HTTP CONNECT)
  -     TLS with example.com through the tunnel
  -     request and response

Result: connection_refused: the proxy refused the connection (nothing is listening on that port)

Nothing accepts connections on that port
  The proxy host answered, but no service listens on 9.

What to try:
  1. check the port: providers often use different ports for HTTP and SOCKS5, and for rotating and sticky sessions
  2. check that the proxy or the plan is active
  3. a local firewall or antivirus can also refuse outgoing connections
```

A provider export line with a wrong password, against a real proxy gateway (ours, with made-up credentials):

```
$ proxy-monitor doctor -no-env "resi.fusionproxy.net:12286:doctor-demo:wr@ng-pass"
proxy-monitor doctor
  proxy   http://do***:***@resi.fusionproxy.net:12286  (HTTP CONNECT, from argument)
  target  https://example.com/

Proxy URL
  FAIL  host:port:user:pass is a provider export format, not a proxy URL
        fix: write it as a URL, scheme first and the login before the @: http://do***:***@resi.fusionproxy.net:12286 (doctor checks that form; special characters in the password get percent-encoded)

Connection
  ok    resolve the proxy host resi.fusionproxy.net  82ms
  ok    TCP connect to resi.fusionproxy.net:12286    33ms
  FAIL  proxy handshake (HTTP CONNECT)               32ms
  -     TLS with example.com through the tunnel
  -     request and response

Result: auth_failed: the proxy rejected the username or password (HTTP 407)

The proxy rejected the login
  The proxy answered HTTP 407 Proxy Authentication Required.

What to try:
  1. copy the username and password again from your provider's dashboard
  2. percent-encode special characters in the password (@ as %40, : as %3A, # as %23)
  3. check that the account still has traffic or an active plan: many providers answer 407 when it runs out
  4. if you use username parameters (country, session), check their syntax in your provider's docs
```

## JSON

`-json` prints one object:

| Field | Meaning |
|---|---|
| `proxy` | the proxy URL, username shortened, no password |
| `proxy_from` | `argument` or the environment variable it came from |
| `protocol` | for example `HTTP CONNECT`, `SOCKS5 (remote DNS)` |
| `target` | the target URL (query values masked) |
| `url_findings`, `env_findings` | arrays of `{level, message, fix}`; `level` is `ok`, `info`, `warn` or `fail` |
| `checked` | whether a connection was attempted |
| `ok` | whether the check passed |
| `phases` | `[{key, name, status, duration}]`; `key` is `dns`, `connect`, `proxy_handshake`, `target_tls` or `response`; `status` `info` means not reached; `duration` is in nanoseconds |
| `result` | the raw check result, as in `proxy-monitor check -json`, including `error_class` and `failed_phase` |
| `advice` | `{title, why, fixes}` for a failed check |

## Limits

- One request, one target. A proxy that works for `example.com` can still be blocked by the site you care about; run doctor with `-target` set to a page of that site you are allowed to load.
- It does not test anonymity, exit country or speed over time. For that, run `proxy-monitor start` with a configuration, or see [proxy-checker](https://github.com/FusionProxies/proxy-checker) for bulk lists.
- SOCKS4 and UDP are not checked.
