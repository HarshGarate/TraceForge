"""SQLite persistence for IOCs, analyst notes and verdicts.

The console stores its work in traceforge_data/traceforge.db (override with --db or TRACEFORGE_DB);
tests and the CLI use an in-memory database.
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone

import pandas as pd

from .audit import AuditLog

VERDICTS = ["Unreviewed", "Investigating", "Needs escalation", "True positive", "False positive", "Benign true positive"]
IOC_TYPES = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "username"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ioc_type TEXT NOT NULL, value TEXT NOT NULL,
  source TEXT, note TEXT, added_utc TEXT NOT NULL, UNIQUE(ioc_type, value));
CREATE TABLE IF NOT EXISTS notes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, author TEXT, note TEXT NOT NULL, created_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS verdicts(
  incident_id TEXT PRIMARY KEY, verdict TEXT NOT NULL, confidence_override INTEGER, updated_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checks(
  incident_id TEXT NOT NULL, step TEXT NOT NULL, PRIMARY KEY(incident_id, step));
CREATE TABLE IF NOT EXISTS evidence(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL UNIQUE, name TEXT NOT NULL, size INTEGER NOT NULL, added_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sigma_rules(
  id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL UNIQUE, rule_id TEXT NOT NULL, title TEXT NOT NULL,
  level TEXT NOT NULL, yaml TEXT NOT NULL, added_utc TEXT NOT NULL);
"""
CASE_FORMAT, CASE_VERSION = "traceforge-case", 2
MAX_IMPORT_ITEMS = 100_000


def classify_ioc(value: str) -> str:
    v = value.strip()
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", v):
        return "ipv4"
    if re.fullmatch(r"[0-9a-fA-F:]{3,}", v) and v.count(":") >= 2:
        return "ipv6"
    for n, t in ((64, "sha256"), (40, "sha1"), (32, "md5")):
        if re.fullmatch(rf"[a-fA-F0-9]{{{n}}}", v):
            return t
    if re.match(r"https?://", v, re.I):
        return "url"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", v, re.I):
        return "email"
    if re.fullmatch(r"([a-z0-9\-]+\.)+[a-z]{2,}", v, re.I):
        return "domain"
    return "username"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class Store:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.audit = AuditLog(self.conn)

    # IOCs
    def add_ioc(self, value: str, ioc_type: str | None = None, source: str = "analyst", note: str = "") -> bool:
        value = value.strip()
        if not value:
            return False
        ioc_type = ioc_type or classify_ioc(value)
        if ioc_type in ("domain", "username", "email", "md5", "sha1", "sha256", "ipv4", "ipv6", "url"):
            value = value.lower() if ioc_type != "url" else value
        try:
            with self.conn:
                self.conn.execute("INSERT INTO iocs(ioc_type,value,source,note,added_utc) VALUES(?,?,?,?,?)",
                                  (ioc_type, value, source, note, _now()))
            return True
        except sqlite3.IntegrityError:
            return False

    def delete_ioc(self, ioc_id: int) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM iocs WHERE id=?", (ioc_id,))

    def iocs(self) -> pd.DataFrame:
        return pd.read_sql_query("SELECT id, ioc_type, value, source, note, added_utc FROM iocs ORDER BY id", self.conn)

    # Notes & verdicts
    def add_note(self, incident_id: str, note: str, author: str = "analyst") -> None:
        if note.strip():
            with self.conn:
                self.conn.execute("INSERT INTO notes(incident_id,author,note,created_utc) VALUES(?,?,?,?)",
                                  (incident_id, author, note.strip(), _now()))

    def notes(self, incident_id: str | None = None) -> pd.DataFrame:
        q, args = "SELECT id, incident_id, author, note, created_utc FROM notes", ()
        if incident_id:
            q, args = q + " WHERE incident_id=?", (incident_id,)
        return pd.read_sql_query(q + " ORDER BY id", self.conn, params=args)

    def set_verdict(self, incident_id: str, verdict: str, confidence_override: int | None = None) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO verdicts(incident_id,verdict,confidence_override,updated_utc) VALUES(?,?,?,?) "
                "ON CONFLICT(incident_id) DO UPDATE SET verdict=excluded.verdict, "
                "confidence_override=excluded.confidence_override, updated_utc=excluded.updated_utc",
                (incident_id, verdict, confidence_override, _now()))

    def verdict(self, incident_id: str) -> dict:
        row = self.conn.execute("SELECT verdict, confidence_override FROM verdicts WHERE incident_id=?", (incident_id,)).fetchone()
        return dict(row) if row else {"verdict": "Unreviewed", "confidence_override": None}

    # Small key/value settings (investigation details survive a restart)
    def get_kv(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_kv(self, key: str, value: str) -> None:
        with self.conn:
            self.conn.execute("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def clear_iocs(self) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM iocs")

    # Remediation checklist
    def set_check(self, incident_id: str, step: str, done: bool) -> None:
        with self.conn:
            if done:
                self.conn.execute("INSERT OR IGNORE INTO checks(incident_id, step) VALUES(?,?)", (incident_id, step))
            else:
                self.conn.execute("DELETE FROM checks WHERE incident_id=? AND step=?", (incident_id, step))

    def checks(self, incident_id: str) -> set[str]:
        return {r["step"] for r in self.conn.execute("SELECT step FROM checks WHERE incident_id=?", (incident_id,))}

    def clear_work(self) -> None:
        """Forget per-incident work (notes, verdicts, checklists). IOCs are kept: they describe the adversary, not one dataset."""
        with self.conn:
            for t in ("notes", "verdicts", "checks"):
                self.conn.execute(f"DELETE FROM {t}")   # nosec B608

    # Evidence manifest (the files themselves live in the evidence vault)
    def evidence_sync(self, files: list[tuple[str, str, int]]) -> None:
        """Make the manifest equal to `files` = [(sha256, name, size)] in order."""
        with self.conn:
            known = {r["sha256"]: r["name"] for r in self.conn.execute("SELECT sha256, name FROM evidence")}
            wanted = {sha for sha, _, _ in files}
            for sha in set(known) - wanted:
                self.conn.execute("DELETE FROM evidence WHERE sha256=?", (sha,))
            for sha, name, size in files:
                if sha not in known:
                    self.conn.execute("INSERT INTO evidence(sha256,name,size,added_utc) VALUES(?,?,?,?)", (sha, name, size, _now()))

    def evidence_manifest(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT sha256, name, size, added_utc FROM evidence ORDER BY seq")]

    # Imported Sigma rules
    def sigma_add(self, sha256: str, rule_id: str, title: str, level: str, yaml_text: str) -> bool:
        try:
            with self.conn:
                self.conn.execute("INSERT INTO sigma_rules(sha256,rule_id,title,level,yaml,added_utc) VALUES(?,?,?,?,?,?)",
                                  (sha256, rule_id, title, level, yaml_text, _now()))
            return True
        except sqlite3.IntegrityError:
            return False

    def sigma_rows(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT id, sha256, rule_id, title, level, yaml, added_utc FROM sigma_rules ORDER BY id")]

    def sigma_delete(self, row_id: int) -> bool:
        with self.conn:
            return self.conn.execute("DELETE FROM sigma_rules WHERE id=?", (row_id,)).rowcount > 0

    # Case export / import (the way to persist work on ephemeral hosting)
    def export_case(self, case: dict | None = None) -> str:
        data = {
            "format": CASE_FORMAT, "version": CASE_VERSION, "exported_utc": _now(), "case": case or {},
            "iocs": self.iocs().to_dict("records"), "notes": self.notes().to_dict("records"),
            "verdicts": [dict(r) for r in self.conn.execute("SELECT * FROM verdicts")],
            "checks": [dict(r) for r in self.conn.execute("SELECT * FROM checks")],
            "sigma_rules": [{"sha256": r["sha256"], "rule_id": r["rule_id"], "title": r["title"], "level": r["level"], "yaml": r["yaml"]} for r in self.sigma_rows()],
            "evidence_manifest": self.evidence_manifest(),
            "audit": {"head": self.audit.head(), "entries": self.audit.entries(limit=5000, newest_first=False)},
        }
        return json.dumps(data, indent=2, default=str)

    def import_case(self, text: str) -> dict:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("the case file must contain a JSON object")
        if data.get("format", CASE_FORMAT) != CASE_FORMAT:
            raise ValueError("this is not a TraceForge case file")
        for key in ("iocs", "notes", "verdicts", "checks", "sigma_rules"):
            if not isinstance(data.get(key, []), list) or len(data.get(key, [])) > MAX_IMPORT_ITEMS:
                raise ValueError(f"'{key}' must be a list of at most {MAX_IMPORT_ITEMS} items")
        added = sum(self.add_ioc(i["value"], i.get("ioc_type"), i.get("source", "import"), i.get("note", "")) for i in data.get("iocs", []))
        for n in data.get("notes", []):
            self.add_note(n["incident_id"], n["note"], n.get("author", "import"))
        for v in data.get("verdicts", []):
            self.set_verdict(v["incident_id"], v["verdict"], v.get("confidence_override"))
        for c in data.get("checks", []):
            self.set_check(c["incident_id"], c["step"], True)
        sigma_added = sum(self.sigma_add(r["sha256"], r.get("rule_id", ""), r.get("title", ""), r.get("level", "medium"), r["yaml"])
                          for r in data.get("sigma_rules", []))
        return {"iocs_added": added, "notes": len(data.get("notes", [])), "verdicts": len(data.get("verdicts", [])),
                "sigma_rules": sigma_added, "case": data.get("case") or {}, "evidence_manifest": data.get("evidence_manifest", []),
                "source_audit_head": (data.get("audit") or {}).get("head", {})}
