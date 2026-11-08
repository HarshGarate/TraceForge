"""Start the web console:  traceforge serve   (or  python run.py)."""
from __future__ import annotations

import argparse
import ipaddress
import os
import secrets
import sys
import threading
import webbrowser

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
# Wildcard addresses are only recognised here (to decide whether the console is exposed); nothing is bound to them.
WILDCARD_HOSTS = {"0.0.0.0", "::"}   # nosec B104


def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost only)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    ap.add_argument("--db", help="SQLite file for case state (default: ./traceforge_data/traceforge.db); evidence is kept beside it")
    ap.add_argument("--allow-host", action="append", default=[], metavar="NAME",
                    help="extra Host header name to accept (repeatable), e.g. soc-box.example.org; IP addresses are always accepted")
    ap.add_argument("--token", help="require this fixed access token (also read from TRACEFORGE_TOKEN)")
    ap.add_argument("--require-token", action="store_true", help="require a random access token even on localhost (the link is printed and opened for you)")
    ap.add_argument("--reusable-token", action="store_true", help="with --require-token: let the launch link be opened more than once")


def configure_environment(args: argparse.Namespace) -> tuple[str | None, bool]:
    """Set the environment read by the app factory; returns (token or None, reusable)."""
    os.environ.setdefault("TRACEFORGE_DB", args.db or os.path.join("traceforge_data", "traceforge.db"))
    if args.db:
        os.environ["TRACEFORGE_DB"] = args.db
    exposed = args.host not in LOOPBACK                     # 0.0.0.0, :: or a LAN address: reachable by other machines
    if args.token or os.environ.get("TRACEFORGE_TOKEN"):
        token, reusable = args.token or os.environ["TRACEFORGE_TOKEN"], True
        if token.strip().lower() in ("off", "none", ""):
            token = None
    elif args.require_token or exposed:
        token, reusable = secrets.token_urlsafe(24), bool(args.reusable_token) and not exposed or exposed
    else:
        token, reusable = None, True                        # plain local use: no prompt, Host/Origin checks still apply
    os.environ["TRACEFORGE_TOKEN"] = token or "off"
    os.environ["TRACEFORGE_TOKEN_REUSABLE"] = "1" if reusable else "0"
    hosts = list(args.allow_host)
    if args.host not in LOOPBACK | WILDCARD_HOSTS:
        hosts.append(args.host)
    if hosts:
        os.environ["TRACEFORGE_ALLOWED_HOSTS"] = ",".join(hosts)
    return token, reusable


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="traceforge serve", description="TraceForge incident console")
    add_arguments(ap)
    args = ap.parse_args(argv)
    try:
        wildcard = ipaddress.ip_address(args.host).is_unspecified
    except ValueError:
        wildcard = False
    token, reusable = configure_environment(args)
    if (wildcard or args.host not in LOOPBACK) and token is None:
        print("\n  WARNING: the console is reachable from the network with the access token switched off.\n", file=sys.stderr)

    import uvicorn

    shown = "127.0.0.1" if wildcard or args.host == "localhost" else args.host
    base = f"http://{shown}:{args.port}"
    link = f"{base}/?token={token}" if token else base
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(link)).start()
    print(f"\n  TraceForge is running.  Open:  {link}")
    if token:
        print("  " + ("This link can be reused." if reusable else "This link works once; it is exchanged for a session cookie in your browser."))
    print("  Press Ctrl+C to stop.\n")
    uvicorn.run("traceforge.server:create_app", factory=True, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
