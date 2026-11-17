"""Verify a proxy-monitor webhook signature (Python 3, standard library only).

The monitor sends:
    X-Proxy-Monitor-Timestamp: <unix seconds>
    X-Proxy-Monitor-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<raw body>">
"""
import hashlib
import hmac
import time


def verify(secret: str, timestamp: str, signature: str, body: bytes, max_age: int = 300) -> bool:
    if not timestamp.isdigit() or abs(time.time() - int(timestamp)) > max_age:
        return False  # too old: possibly a replay
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return hmac.compare_digest("sha256=" + mac.hexdigest(), signature)


if __name__ == "__main__":
    body = b'{"event":"down"}'
    ts = str(int(time.time()))
    sig = "sha256=" + hmac.new(b"s3cret", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    print("valid:", verify("s3cret", ts, sig, body))
    print("tampered:", verify("s3cret", ts, sig, body + b" "))
