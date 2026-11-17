# Alerts

## Events

| Event | Fires when | Severity |
|---|---|---|
| `down` | `failure_threshold` consecutive checks failed | critical |
| `still_down` | the proxy is still down after `repeat_interval` (only if set) | warning |
| `recovered` | a down proxy passed `recovery_threshold` consecutive checks | info |
| `latency` | the median of the last `latency_samples` successful checks is above `latency` | warning |
| `latency_resolved` | that median is back at or below the threshold | info |
| `availability` | fewer than `availability` percent of checks succeeded in `availability_window` (with at least `availability_min_checks` checks) | warning |
| `availability_resolved` | the success rate is back at or above the threshold | info |

`down`, `latency` and `availability` each open an incident; the matching resolution closes it. Latency and availability alerts do not open while a proxy is down, and an availability alert does not open within one window after a down incident ended, because that outage was already reported.

## Flood control

1. **Deduplication.** One notification per incident and event.
2. **Cooldown** (`alerts.cooldown`, default `10m`). After an alert of one kind (down, latency or availability) is sent for a proxy, a new incident of the same kind for that proxy within the cooldown is recorded but not sent, and neither is its resolution. A proxy that flaps every minute produces one down/recovered pair per cooldown. The cooldown survives restarts.
3. **Rate limit** (`alerts.max_per_minute`, default `20`). Above it, alerts are counted and one summary message is sent when the minute is over, naming the affected proxies.

Every decision, sent or suppressed with the reason, is kept in the alert history (`/api/alerts`, the Incidents page).

## Channels

All channels are optional and can be combined. Each one takes an `events:` list to receive only some events; without it, a channel receives all of them.

```yaml
alerts:
  cooldown: 10m
  max_per_minute: 20
  repeat_interval: 1h        # reminders while down; 0 (default) turns them off, minimum 5m
  console: true              # log lines (default true)

  webhooks:
    - name: ops
      url: https://hooks.example.com/proxy-monitor
      secret: ${WEBHOOK_SECRET}
      headers:
        X-Team: infra
      events: [down, recovered, availability]

  email:
    host: smtp.example.com
    port: 587                # 587 with STARTTLS (default), or 465 with tls: tls
    tls: starttls            # starttls | tls | none (none only for a relay on localhost)
    username: ${SMTP_USER}
    password: ${SMTP_PASS}
    from: proxy-monitor@example.com
    to: [ops@example.com]

  telegram:
    bot_token: ${TELEGRAM_BOT_TOKEN}
    chat_id: ${TELEGRAM_CHAT_ID}

  discord:
    - name: alerts-channel
      webhook_url: ${DISCORD_WEBHOOK_URL}
      events: [down, recovered]
```

Delivery runs in the background with up to three attempts per channel (timeout 15 seconds each). On shutdown, queued alerts get up to 10 seconds to go out.

## Webhook payload

```json
{
  "event": "down",
  "severity": "critical",
  "proxy": "vendor-socks5",
  "protocol": "SOCKS5 (remote DNS)",
  "proxy_url": "socks5h://ve***:***@proxy.vendor.example:1080",
  "labels": {"provider": "vendor"},
  "time": "2026-11-17T10:42:00Z",
  "incident_id": 12,
  "title": "[DOWN] vendor-socks5",
  "message": "3 consecutive failed checks; last error: no answer within 10s during the SOCKS5 handshake",
  "error_class": "timeout",
  "error": "no answer within 10s during the SOCKS5 handshake",
  "consecutive_failures": 3,
  "source": "proxy-health-monitor"
}
```

Resolution events add `duration_seconds`; latency events add `latency_ms`; availability events add `availability` (percent).

### Verifying the signature

With `secret` set, each request carries:

```
X-Proxy-Monitor-Timestamp: 1763376120
X-Proxy-Monitor-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<raw body>">
```

Compute the HMAC over the raw body bytes, compare in constant time, and reject old timestamps. A complete Python example is in [examples/webhook-receiver/verify.py](../examples/webhook-receiver/verify.py).

## Telegram and Discord notes

- Telegram: create a bot with @BotFather, add it to the chat, and use the chat id (group ids start with `-100`). The token is masked in logs even when an HTTP error quotes the API URL.
- Discord: messages are sent with `allowed_mentions` empty, so an alert cannot ping `@everyone`.
