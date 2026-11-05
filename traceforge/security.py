"""Access control and request hardening for the local web console (pure ASGI, no framework dependency).

What it enforces on every request, in this order:
  1. Host header must be an allowed name (blocks DNS-rebinding: an attacker's domain pointed at 127.0.0.1).
  2. A browser Origin header, when present, must be this site itself (blocks cross-site requests such as a
     malicious page POSTing "clear all evidence" to http://127.0.0.1:8000).
  3. An optional access token (always on for Docker / network use; opt-in on localhost): the launch link carries ``?token=...``; it is exchanged once for an HttpOnly,
     SameSite=Strict session cookie. Without a valid cookie (or token header) the API answers 401.
  4. A cap on request body size.
  5. Security headers on every response (CSP with frame-ancestors none, no-sniff, no-referrer, COOP/CORP ...).

``/healthz`` is exempt from the token (it reveals nothing) so container health checks work.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import secrets
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from .hardening import MAX_REQUEST_BYTES

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
COOKIE = "tf_session"
SESSION_SECONDS = 8 * 3600
MAX_SESSIONS = 50
CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'")
SECURITY_HEADERS = [
    ("x-content-type-options", "nosniff"), ("referrer-policy", "no-referrer"), ("content-security-policy", CSP),
    ("x-frame-options", "DENY"), ("cross-origin-opener-policy", "same-origin"), ("cross-origin-resource-policy", "same-origin"),
    ("permissions-policy", "camera=(), microphone=(), geolocation=()"),
]


def _truthy(v: str | None, default: bool) -> bool:
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class SecurityConfig:
    allowed_hosts: set[str] = field(default_factory=lambda: set(LOCAL_HOSTS))
    token: str | None = None                      # None = no token required (tests, trusted setups)
    reusable_token: bool = True                   # False = the launch link works once, then only the session cookie
    allow_ip_hosts: bool = True                   # IP-literal Host headers cannot be DNS-rebinding names
    max_request_bytes: int = MAX_REQUEST_BYTES
    on_event: Callable[[str, dict], None] | None = None

    @classmethod
    def for_tests(cls, *hosts: str) -> "SecurityConfig":
        return cls(allowed_hosts=set(LOCAL_HOSTS) | set(hosts or ("testserver",)), token=None)

    @classmethod
    def from_env(cls, env=None) -> "SecurityConfig":
        """TRACEFORGE_TOKEN (a value, or 'off'), TRACEFORGE_TOKEN_REUSABLE, TRACEFORGE_ALLOWED_HOSTS (comma list).
        With nothing set no token is required (local use); Host and Origin checks always apply."""
        env = os.environ if env is None else env
        raw = env.get("TRACEFORGE_TOKEN")
        if raw is None or raw.strip().lower() in ("off", "none", "disabled", ""):
            token, reusable = None, True
        else:
            token, reusable = raw.strip(), _truthy(env.get("TRACEFORGE_TOKEN_REUSABLE"), True)
        hosts = set(LOCAL_HOSTS) | {h.strip().lower() for h in env.get("TRACEFORGE_ALLOWED_HOSTS", "").split(",") if h.strip()}
        return cls(allowed_hosts=hosts, token=token, reusable_token=reusable)


def _hostname(host_header: str) -> str:
    h = host_header.strip().lower()
    if h.startswith("["):                                  # [::1]:8000
        return h[1:].split("]", 1)[0]
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def _is_ip(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


class SecurityMiddleware:
    def __init__(self, app, config: SecurityConfig | None = None):
        self.app = app
        self.cfg = config or SecurityConfig.from_env()
        self._sessions: dict[str, float] = {}
        self._launch_used = False
        self._last_denied = 0.0

    # ------------------------------------------------------------------ helpers
    def _emit(self, name: str, **detail) -> None:
        if self.cfg.on_event:
            try:
                self.cfg.on_event(name, detail)
            except Exception:  # noqa: BLE001 - auditing must never break a request
                pass

    async def _respond(self, send, status: int, body: bytes, ctype: str, headers: list[tuple[str, str]] | None = None, api: bool = False):
        hdrs = [("content-type", ctype), ("content-length", str(len(body))), ("cache-control", "no-store")] + (headers or []) + SECURITY_HEADERS
        await send({"type": "http.response.start", "status": status, "headers": [(k.encode(), v.encode()) for k, v in hdrs]})
        await send({"type": "http.response.body", "body": body})

    async def _json(self, send, status: int, message: str):
        await self._respond(send, status, json.dumps({"error": message}).encode(), "application/json")

    def _host_ok(self, host: str) -> bool:
        name = _hostname(host)
        return bool(name) and (name in self.cfg.allowed_hosts or (self.cfg.allow_ip_hosts and _is_ip(name)))

    def _session_ok(self, cookie_header: str) -> bool:
        if not cookie_header:
            return False
        try:
            jar = SimpleCookie(cookie_header)
        except Exception:  # noqa: BLE001
            return False
        morsel = jar.get(COOKIE)
        if not morsel:
            return False
        import time
        now = time.time()
        for sid, exp in list(self._sessions.items()):
            if exp < now:
                del self._sessions[sid]
        return any(hmac.compare_digest(morsel.value, sid) for sid in self._sessions)

    def _new_session(self) -> str:
        import time
        if len(self._sessions) >= MAX_SESSIONS:
            self._sessions.pop(next(iter(self._sessions)))
        sid = secrets.token_urlsafe(32)
        self._sessions[sid] = time.time() + SESSION_SECONDS
        return sid

    # ------------------------------------------------------------------ ASGI
    async def __call__(self, scope, receive, send):
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        h = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        path, method = scope["path"], scope["method"]
        api = path.startswith("/api")

        if not self._host_ok(h.get("host", "")):
            await self._respond(send, 400, b"Invalid Host header.", "text/plain; charset=utf-8")
            return
        if path == "/healthz":
            await self._respond(send, 200, b'{"status":"ok"}', "application/json")
            return
        origin = h.get("origin")
        if origin is not None:
            if origin == "null" or urlsplit(origin).netloc.lower() != h.get("host", "").lower():
                await self._json(send, 403, "Cross-origin request refused.")
                return
        elif h.get("sec-fetch-site") == "cross-site" and method not in ("GET", "HEAD"):
            await self._json(send, 403, "Cross-site request refused.")
            return

        if self.cfg.token:
            query = parse_qs(scope.get("query_string", b"").decode("latin-1"))
            presented = (query.get("token") or [""])[0]
            if method == "GET" and path == "/" and presented:
                if hmac.compare_digest(presented, self.cfg.token) and (self.cfg.reusable_token or not self._launch_used):
                    self._launch_used = True
                    sid = self._new_session()
                    secure = "; Secure" if scope.get("scheme") == "https" else ""
                    cookie = f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}{secure}"
                    self._emit("session_opened", client=(scope.get("client") or ["?"])[0])
                    await self._respond(send, 303, b"", "text/plain", [("location", "/"), ("set-cookie", cookie)])
                    return
            header_tok = h.get("x-traceforge-token", "")
            header_ok = bool(header_tok) and self.cfg.reusable_token and hmac.compare_digest(header_tok, self.cfg.token)
            if not (header_ok or self._session_ok(h.get("cookie", ""))):
                import time
                if time.time() - self._last_denied > 60:          # at most one audit entry per minute, so probing cannot flood the log
                    self._last_denied = time.time()
                    self._emit("access_denied", path=path[:80])
                if api:
                    await self._json(send, 401, "Access token required. Open the link printed in the terminal where TraceForge was started.")
                else:
                    await self._respond(send, 401, _LOCKED_PAGE.encode(), "text/html; charset=utf-8")
                return

        # body size cap (Content-Length first, then a running count for chunked bodies)
        limit = self.cfg.max_request_bytes
        try:
            declared = int(h.get("content-length", "0") or 0)
        except ValueError:
            declared = 0
        if declared > limit:
            await self._json(send, 413, f"The upload is larger than {limit // 2**20} MB.")
            return
        seen = 0

        async def limited_receive():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > limit:
                    raise _TooLarge()
            return msg

        started = False

        async def secured_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                names = {k for k, _ in SECURITY_HEADERS} | {"cache-control"}
                kept = [(k, v) for k, v in message.get("headers", []) if k.decode("latin-1").lower() not in names]
                kept += [(k.encode(), v.encode()) for k, v in SECURITY_HEADERS]
                kept.append((b"cache-control", b"no-store" if api else b"no-cache"))
                message = {**message, "headers": kept}
            await send(message)

        try:
            await self.app(scope, limited_receive, secured_send)
        except _TooLarge:
            if not started:
                await self._json(send, 413, f"The upload is larger than {limit // 2**20} MB.")


class _TooLarge(Exception):
    pass


_LOCKED_PAGE = """<!doctype html><html lang="en"><meta charset="utf-8"><title>TraceForge - access token required</title>
<body style="font-family:system-ui,sans-serif;background:#161826;color:#e7e9f5;display:grid;place-items:center;height:100vh;margin:0">
<div style="max-width:520px;padding:28px;border:1px solid #3a3f5c;border-radius:12px;background:#1f2233">
<h2 style="margin-top:0">Access token required</h2>
<p>This TraceForge console is protected. Open the link printed in the terminal where you started it
(it looks like <code>http://127.0.0.1:8000/?token=...</code>).</p>
<p style="color:#9aa0be;font-size:14px">The link works once per start-up, so close other copies of this page and restart TraceForge if it
has already been used.</p></div></body></html>"""
