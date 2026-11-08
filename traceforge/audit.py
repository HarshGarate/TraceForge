"""Tamper-evident audit log of analyst actions.

Every entry stores the SHA-256 of the previous entry, so changing, deleting or re-ordering any earlier entry
breaks the chain and `verify()` reports the first entry that no longer matches. The table also refuses UPDATE and
DELETE through SQLite triggers, which stops accidental edits; an attacker with write access to the database file can
remove the triggers, which is exactly what the hash chain is there to reveal.

Limits (stated plainly in THREAT_MODEL.md): a chain cannot detect that the *newest* entries were cut off unless the
head hash was recorded elsewhere (reports and case files include it), and the actor name is whatever the analyst
typed into the investigation details: it is not an authenticated identity.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64
MAX_DETAIL_CHARS = 2000

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '{}',
  prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def entry_hash(seq: int, ts: str, actor: str, action: str, target: str, detail: str, prev_hash: str) -> str:
    payload = json.dumps([seq, ts, actor, action, target, detail, prev_hash], separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _clip(value, limit: int = 300):
    if isinstance(value, str):
        return value if len(value) <= limit else value[: limit - 3] + "..."
    if isinstance(value, dict):
        return {str(k): _clip(v, limit) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clip(v, limit) for v in list(value)[:50]]
    return value


def _cell(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


class AuditLog:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._lock = threading.Lock()
        conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ writing
    def append(self, actor: str, action: str, target: str = "", detail: dict | None = None) -> dict:
        detail_json = json.dumps(_clip(detail or {}), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len(detail_json) > MAX_DETAIL_CHARS:
            detail_json = json.dumps({"truncated": True}, separators=(",", ":"))
        with self._lock, self.conn:
            row = self.conn.execute("SELECT seq, entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
            ts = _now()
            actor, action, target = str(actor)[:120] or "unknown", str(action)[:60], str(target)[:300]
            h = entry_hash(seq, ts, actor, action, target, detail_json, prev)
            self.conn.execute("INSERT INTO audit(seq, ts, actor, action, target, detail, prev_hash, entry_hash) VALUES(?,?,?,?,?,?,?,?)",
                              (seq, ts, actor, action, target, detail_json, prev, h))
        return {"seq": seq, "ts": ts, "actor": actor, "action": action, "target": target, "detail": json.loads(detail_json), "entry_hash": h}

    # ------------------------------------------------------------------ reading
    @staticmethod
    def _row(r) -> dict:
        return {"seq": r[0], "ts": r[1], "actor": r[2], "action": r[3], "target": r[4], "detail": json.loads(r[5] or "{}"),
                "prev_hash": r[6], "entry_hash": r[7]}

    def entries(self, limit: int = 200, newest_first: bool = True, action: str = "") -> list[dict]:
        q, args = "SELECT seq, ts, actor, action, target, detail, prev_hash, entry_hash FROM audit", []
        if action:
            q, args = q + " WHERE action = ?", [action]
        q += " ORDER BY seq " + ("DESC" if newest_first else "ASC") + " LIMIT ?"
        return [self._row(r) for r in self.conn.execute(q, (*args, max(1, min(limit, 100_000))))]

    def head(self) -> dict:
        row = self.conn.execute("SELECT COUNT(*), MAX(seq) FROM audit").fetchone()
        last = self.conn.execute("SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return {"entries": row[0], "last_seq": row[1] or 0, "head_hash": last[0] if last else GENESIS}

    def verify(self) -> dict:
        """Walk the whole chain. ok=False names the first entry whose link or content does not match."""
        expected_seq, prev, count = 1, GENESIS, 0
        for r in self.conn.execute("SELECT seq, ts, actor, action, target, detail, prev_hash, entry_hash FROM audit ORDER BY seq"):
            count += 1
            seq, ts, actor, action, target, detail, prev_hash, h = r
            if seq != expected_seq:
                return {"ok": False, "entries": count, "first_bad_seq": expected_seq, "problem": f"entry {expected_seq} is missing (found {seq} instead).", **self.head()}
            if prev_hash != prev:
                return {"ok": False, "entries": count, "first_bad_seq": seq, "problem": f"entry {seq} does not link to the entry before it.", **self.head()}
            if entry_hash(seq, ts, actor, action, target, detail, prev_hash) != h:
                return {"ok": False, "entries": count, "first_bad_seq": seq, "problem": f"entry {seq} was modified after it was written.", **self.head()}
            expected_seq, prev = seq + 1, h
        return {"ok": True, "entries": count, "first_bad_seq": None, "problem": "", **self.head()}

    def export_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["seq", "timestamp_utc", "actor", "action", "target", "detail", "prev_hash", "entry_hash"])
        for e in self.entries(limit=100_000, newest_first=False):
            w.writerow([e["seq"], e["ts"], _cell(e["actor"]), e["action"], _cell(e["target"]),
                        _cell(json.dumps(e["detail"], sort_keys=True)), e["prev_hash"], e["entry_hash"]])
        return buf.getvalue()
