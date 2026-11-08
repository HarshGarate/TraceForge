"""Host / Origin / token / size / header enforcement, tested at the ASGI layer (no web framework needed)."""
import asyncio

from traceforge.security import SecurityConfig, SecurityMiddleware

H = {"host": "127.0.0.1:8000"}


async def _app(scope, receive, send):
    body = b""
    while True:
        m = await receive()
        body += m.get("body", b"")
        if not m.get("more_body"):
            break
    await send({"type": "http.response.start", "status": 200, "headers": [(b"x-content-type-options", b"old")]})
    await send({"type": "http.response.body", "body": f"ok {len(body)}".encode()})


def call(mw, method="GET", path="/", headers=None, query=b"", body=b"", chunks=None):
    async def go():
        parts = list(chunks or [body])
        out = []

        async def receive():
            if parts:
                b = parts.pop(0)
                return {"type": "http.request", "body": b, "more_body": bool(parts)}
            return {"type": "http.disconnect"}

        async def send(m):
            out.append(m)

        scope = {"type": "http", "method": method, "path": path, "query_string": query, "scheme": "http", "client": ("127.0.0.1", 1),
                 "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]}
        await mw(scope, receive, send)
        return out[0]["status"], {k.decode(): v.decode() for k, v in out[0]["headers"]}, b"".join(m.get("body", b"") for m in out[1:])
    return asyncio.run(go())


def mw(**kw):
    events = []
    cfg = SecurityConfig(token=kw.pop("token", "T0KEN"), reusable_token=kw.pop("reusable", False), on_event=lambda n, d: events.append(n), **kw)
    m = SecurityMiddleware(_app, cfg)
    m.events = events
    return m


def test_foreign_host_header_is_refused_dns_rebinding():
    m = mw()
    assert call(m, headers={"host": "evil.example.com"})[0] == 400
    assert call(m, headers={"host": "127.0.0.1:8000"}, path="/healthz")[0] == 200
    assert call(m, headers={"host": "localhost:8000"}, path="/healthz")[0] == 200
    assert call(m, headers={"host": "[::1]:8000"}, path="/healthz")[0] == 200
    assert call(m, headers={"host": "192.168.1.9:8000"}, path="/healthz")[0] == 200      # IP literals cannot be rebinding names
    assert call(mw(allow_ip_hosts=False), headers={"host": "192.168.1.9"}, path="/healthz")[0] == 400
    assert call(SecurityMiddleware(_app, SecurityConfig(allowed_hosts={"soc.example.org"}, token=None)), headers={"host": "soc.example.org"})[0] == 200


def test_cross_origin_requests_are_refused():
    m = mw()
    assert call(m, "POST", "/api/clear", {**H, "origin": "http://evil.example.com"})[0] == 403
    assert call(m, "POST", "/api/clear", {**H, "origin": "null"})[0] == 403
    assert call(m, "POST", "/api/clear", {**H, "origin": "http://127.0.0.1:9999"})[0] == 403         # other port = other origin
    assert call(m, "POST", "/api/clear", {**H, "sec-fetch-site": "cross-site"})[0] == 403
    assert call(m, "GET", "/api/meta", {**H, "origin": "http://evil.example.com"})[0] == 403


def test_token_is_required_exchanged_once_and_cookie_is_locked_down():
    m = mw()
    assert call(m, headers=H)[0] == 401 and call(m, path="/api/meta", headers=H)[0] == 401
    assert b"Access token required" in call(m, headers=H)[2] and b"error" in call(m, path="/api/meta", headers=H)[2]
    assert call(m, headers=H, query=b"token=wrong")[0] == 401
    status, h, _ = call(m, headers=H, query=b"token=T0KEN")
    assert status == 303 and h["location"] == "/"
    cookie = h["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie and "T0KEN" not in cookie
    sid = cookie.split(";")[0]
    assert call(m, path="/api/meta", headers={**H, "cookie": sid})[0] == 200
    assert call(m, path="/api/meta", headers={**H, "cookie": "tf_session=forged"})[0] == 401
    assert call(m, headers={**H}, query=b"token=T0KEN")[0] == 401                  # single-use link cannot be replayed without the cookie
    assert call(m, headers={**H, "x-traceforge-token": "T0KEN"}, path="/api/meta")[0] == 401   # header only for reusable tokens
    assert m.events.count("session_opened") == 1 and "access_denied" in m.events


def test_reusable_token_allows_header_and_repeated_links():
    m = mw(reusable=True)
    assert call(m, path="/api/meta", headers={**H, "x-traceforge-token": "T0KEN"})[0] == 200
    assert call(m, headers=H, query=b"token=T0KEN")[0] == 303 and call(m, headers=H, query=b"token=T0KEN")[0] == 303


def test_no_token_mode_still_checks_host_and_origin():
    m = mw(token=None)
    assert call(m, path="/api/meta", headers=H)[0] == 200
    assert call(m, "POST", "/api/clear", {**H, "origin": "http://evil.example.com"})[0] == 403


def test_denied_events_are_rate_limited():
    m = mw()
    for _ in range(20):
        call(m, path="/api/meta", headers=H)
    assert m.events.count("access_denied") == 1


def test_request_size_cap_for_declared_and_streamed_bodies():
    m = mw(token=None, max_request_bytes=1000)
    assert call(m, "POST", "/u", {**H, "content-length": "5000"}, body=b"x")[0] == 413
    assert call(m, "POST", "/u", H, chunks=[b"x" * 600, b"x" * 600])[0] == 413
    assert call(m, "POST", "/u", H, body=b"x" * 900)[0:3:2] == (200, b"ok 900")


def test_security_headers_replace_weaker_ones_and_forbid_framing():
    status, h, _ = call(mw(token=None), "POST", "/api/x", H, body=b"1")
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY" and h["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in h["content-security-policy"] and "default-src 'self'" in h["content-security-policy"]
    assert h["cross-origin-opener-policy"] == "same-origin" and h["cross-origin-resource-policy"] == "same-origin"
    assert h["cache-control"] == "no-store" and "geolocation=()" in h["permissions-policy"]


def test_websockets_are_refused():
    sent = []

    async def go():
        async def send(m):
            sent.append(m)
        await SecurityMiddleware(_app, SecurityConfig(token=None))({"type": "websocket", "headers": []}, None, send)
    asyncio.run(go())
    assert sent[0]["type"] == "websocket.close"


def test_config_from_environment():
    c = SecurityConfig.from_env({"TRACEFORGE_TOKEN": "fixed", "TRACEFORGE_ALLOWED_HOSTS": "soc.example.org, Box.local"})
    assert c.token == "fixed" and c.reusable_token and {"soc.example.org", "box.local", "localhost"} <= c.allowed_hosts
    assert SecurityConfig.from_env({"TRACEFORGE_TOKEN": "off"}).token is None
    assert not SecurityConfig.from_env({"TRACEFORGE_TOKEN": "x", "TRACEFORGE_TOKEN_REUSABLE": "0"}).reusable_token
    assert SecurityConfig.from_env({}).token is None       # nothing set: local use needs no token (Host/Origin checks still apply)
