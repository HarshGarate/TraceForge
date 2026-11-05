"""Workspace: the single place that owns case state and turns engine output into UI-ready data.

The web server (server.py) is a thin HTTP layer over this class, so everything here is also unit-testable
without HTTP. One Workspace == one analyst working one case (local tool, not a multi-tenant service).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from . import __version__
from .config import (PARAMS, RULES, SEVERITY_COLORS, SEVERITY_ORDER, TACTIC_ORDER, TECHNIQUE_NAMES,
                     merged_config, sanitize_config)
from . import sigma as sigma_mod
from .casecrypt import CaseCryptoError, decrypt_case, encrypt_case, is_encrypted_case
from .correlate import build_incidents
from .detect import run_detections
from .evidence import EvidenceVault, IntegrityError
from .exporters import navigator_layer, stix_bundle
from .hardening import MAX_UPLOAD_BYTES, UploadRejected, expand_upload
from .ingest import build_dataset, is_internal, normalize_file
from .redact import Redactor, policy_for
from .report import ReportContext, _label, build_json, build_markdown, build_pdf, csv_safe, executive_points
from .store import IOC_TYPES, VERDICTS, Store

SAMPLE_DIR = Path(__file__).resolve().parent / "sample_data"
SEVS = ["critical", "high", "medium", "low", "info"]
TLP = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]
CONTEXT_MARGIN = pd.Timedelta(minutes=10)
MAX_INCIDENT_EVENTS = 1500

# Analyst-facing "state" for each stored verdict (what the UI shows on incident cards).
STATE_LABEL = {
    "Unreviewed": "NEW", "Investigating": "INVESTIGATING", "True positive": "CONFIRMED",
    "Needs escalation": "ESCALATED", "False positive": "FALSE POSITIVE", "Benign true positive": "BENIGN",
}
STATE_ORDER = ["Unreviewed", "Investigating", "Needs escalation", "True positive", "False positive", "Benign true positive"]


DEFAULT_CASE = {"name": "Untitled investigation", "analyst": "Analyst", "organization": "", "tlp": "TLP:AMBER"}


class UserError(ValueError):
    """Raised for problems the analyst can fix (bad upload, unknown id); surfaced as HTTP 4xx."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _iso(ts) -> str | None:
    if ts is None or pd.isna(ts):
        return None
    return pd.Timestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(v):
    if v is None or v is pd.NA:
        return None
    if isinstance(v, float) and np.isnan(v):
        return None
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (np.floating,)):
        return None if np.isnan(v) else float(v)
    return v


def _techs(ids) -> list[dict]:
    out, seen = [], set()
    for t in ids:
        for part in re.split(r"[ /]+", str(t)):
            if re.fullmatch(r"T\d{4}(\.\d{3})?", part) and part not in seen:
                seen.add(part)
                out.append({"id": part, "name": TECHNIQUE_NAMES.get(part, "")})
    return out


def _nice_bucket(span_s: float, target: int = 48) -> int:
    for step in (10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400):
        if span_s / step <= target:
            return step
    return 86400


class Workspace:
    def __init__(self, db_path: str | None = None):
        db_path = db_path or os.environ.get("TRACEFORGE_DB") or ":memory:"
        if db_path != ":memory:":
            Path(db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self.store = Store(str(Path(db_path).expanduser()) if db_path != ":memory:" else db_path)
        persistent = db_path != ":memory:"
        self.vault = EvidenceVault(Path(db_path).expanduser().parent / "evidence" if persistent else None)
        self.lock = threading.RLock()
        self.case = dict(DEFAULT_CASE)
        try:
            self.case.update({k: v for k, v in json.loads(self.store.get_kv("case") or "{}").items() if k in DEFAULT_CASE})
        except (ValueError, TypeError):
            pass
        self.config = merged_config()
        self.files: list[tuple[str, bytes]] = []
        self._sample_hashes: set[str] = {_sha(p.read_bytes()) for p in SAMPLE_DIR.glob("*") if p.suffix in (".csv", ".json")} if SAMPLE_DIR.exists() else set()
        self._files_info: list[dict] = []
        self._broken: list[dict] = []          # manifest entries whose stored copy failed verification
        self.integrity: dict = {"checked_utc": None, "ok": True, "files": 0, "problems": []}
        self._sigma: dict[int, sigma_mod.SigmaRule] = {}
        self._empty()
        self._load_sigma()
        restored = self._restore_evidence()
        self._log("app_started", detail={"version": __version__, "evidence_restored": restored, "persistent": persistent})

    # ------------------------------------------------------------------ audit / persistence helpers
    def _log(self, action: str, target: str = "", detail: dict | None = None) -> None:
        self.store.audit.append(self.case.get("analyst", "analyst"), action, target, detail or {})

    def log_event(self, action: str, detail: dict | None = None) -> None:
        """Entry point for the HTTP layer (for example a new browser session)."""
        self._log(action, detail=detail)

    def _sync_evidence(self) -> None:
        """Make the vault and manifest mirror self.files (plus unresolved broken entries)."""
        entries = [(_sha(raw), name, len(raw)) for name, raw in self.files] + [(b["sha256"], b["name"], b["size"]) for b in self._broken]
        for name, raw in self.files:
            self.vault.put(_sha(raw), raw)
        self.store.evidence_sync(entries)
        keep = {e[0] for e in entries}
        for sha in self.vault.stored_hashes() - keep:
            self.vault.delete(sha)

    def _restore_evidence(self) -> int:
        if not self.vault.enabled:
            return 0
        manifest = self.store.evidence_manifest()
        files, problems = [], []
        for m in manifest:
            try:
                files.append((m["name"], self.vault.read(m["sha256"])))
            except IntegrityError as exc:
                problems.append({"name": m["name"], "sha256": m["sha256"], "size": m["size"], "problem": str(exc)})
        self._broken = problems
        if files:
            try:
                self.events, self.quality = build_dataset(files)
                self.files = files
                self._refresh_files_info()
                self.rebuild(keep_events=True)
            except Exception as exc:  # noqa: BLE001 - a stored file that no longer parses must not stop the app
                self.files = []
                self._empty()
                problems.append({"name": "stored evidence", "sha256": "", "size": 0, "problem": f"could not be re-analysed: {type(exc).__name__}"})
        self.integrity = {"checked_utc": _now_iso(), "ok": not problems, "files": len(manifest), "problems": problems}
        if problems:
            self._log("integrity_failure", detail={"problems": [{"name": p["name"], "problem": p["problem"]} for p in problems]})
        return len(files)

    def verify_integrity(self) -> dict:
        """Re-hash every stored evidence file and compare with the SHA-256 recorded at import."""
        with self.lock:
            problems = list(self._broken)
            for name, raw in self.files:
                sha = _sha(raw)
                bad = self.vault.check(sha, len(raw))
                if bad:
                    problems.append({"name": name, "sha256": sha, "size": len(raw), "problem": bad})
            self.integrity = {"checked_utc": _now_iso(), "ok": not problems, "files": len(self.files) + len(self._broken), "problems": problems}
            self._log("integrity_verified", detail={"ok": not problems, "files": self.integrity["files"], "failed": len(problems)})
            return self.integrity

    def audit_status(self) -> dict:
        return self.store.audit.verify()

    # ------------------------------------------------------------------ state
    def _empty(self) -> None:
        self.events = pd.DataFrame(columns=["event_id", "timestamp", "source"])
        self.quality: list = []
        self.findings = pd.DataFrame()
        self.incidents: list = []
        self.diagnostics: list = []
        self.ev_sev: dict[str, str] = {}
        self.ev_findings: dict[str, list[str]] = {}
        self.ev_index = pd.DataFrame()
        self._files_info = []

    @property
    def has_data(self) -> bool:
        return len(self.events) > 0

    @property
    def sample_loaded(self) -> bool:
        return any(hashlib.sha256(r).hexdigest() in self._sample_hashes for _, r in self.files)

    @staticmethod
    def _unique_name(name: str, taken: set[str]) -> str:
        if name not in taken:
            return name
        stem, dot, ext = name.rpartition(".")
        stem, ext = (stem, dot + ext) if dot else (name, "")
        n = 2
        while f"{stem} ({n}){ext}" in taken:
            n += 1
        return f"{stem} ({n}){ext}"

    def load_files(self, files: list[tuple[str, bytes]], replace: bool = False) -> dict:
        """Add files to the investigation. Each file is checked on its own: good ones are kept, bad ones are
        reported with a reason, exact duplicates are skipped. ZIP and gzip files are expanded safely first.
        Only when nothing at all is usable does it raise."""
        with self.lock:
            merged = [] if replace else list(self.files)
            known = {_sha(r) for _, r in merged}
            taken = {n for n, _ in merged}
            added, duplicates, rejected, expansions = [], [], [], []
            incoming: list[tuple[str, bytes]] = []
            for name, raw in files:
                if len(raw) > MAX_UPLOAD_BYTES:
                    rejected.append({"name": name, "error": f"larger than {MAX_UPLOAD_BYTES // 2**20} MB."})
                    continue
                if not raw.strip():
                    rejected.append({"name": name, "error": "the file is empty."})
                    continue
                try:
                    members, info = expand_upload(name, raw)
                except UploadRejected as exc:
                    rejected.append({"name": name, "error": str(exc)})
                    continue
                if info:
                    expansions.append({**info, "sha256": _sha(raw)})
                incoming.extend(members)
            for name, raw in incoming:
                if len(raw) > MAX_UPLOAD_BYTES:
                    rejected.append({"name": name, "error": f"larger than {MAX_UPLOAD_BYTES // 2**20} MB."})
                    continue
                if not raw.strip():
                    rejected.append({"name": name, "error": "the file is empty."})
                    continue
                h = _sha(raw)
                if h in known:
                    duplicates.append(name)
                    continue
                try:
                    df, _q = normalize_file(raw, name)
                except Exception as exc:  # parser errors are analyst-facing
                    msg = str(exc)
                    msg = msg.split(": ", 1)[1] if msg.startswith(f"{name}: ") else msg
                    rejected.append({"name": name, "error": msg if isinstance(exc, ValueError) else f"could not be read as CSV, JSON, XML or a text log ({type(exc).__name__})."})
                    continue
                if df.empty:
                    rejected.append({"name": name, "error": "none of its rows has a readable timestamp."})
                    continue
                unique = self._unique_name(name, taken)
                taken.add(unique)
                known.add(h)
                merged.append((unique, raw))
                added.append(unique)
            for r in rejected:
                self._log("evidence_rejected", r["name"], {"reason": r["error"]})
            if not added:
                if rejected:
                    raise UserError(" ".join(r["error"] if r["error"].startswith(r["name"]) else f"{r['name']}: {r['error']}" for r in rejected))
                return {"files_added": 0, "added": [], "duplicates": duplicates, "rejected": [], "events": len(self.events)}
            events, quality = build_dataset(merged)
            if replace:
                if self.files:
                    self._log("evidence_cleared", detail={"files": len(self.files), "reason": "replaced by a new import"})
                self.store.clear_work()
                self._broken = []
            repaired = {_sha(r) for n, r in merged if n in added} & {b["sha256"] for b in self._broken}
            self._broken = [b for b in self._broken if b["sha256"] not in repaired]
            self.files, self.events, self.quality = merged, events, quality
            for ex in expansions:
                self._log("archive_expanded", ex["archive"], {"archive_sha256": ex["sha256"], "kind": ex["kind"], "members": ex["members"]})
            self._sync_evidence()
            for n, r in merged:
                if n in added:
                    self._log("evidence_added", n, {"sha256": _sha(r), "bytes": len(r)})
            self._refresh_files_info()
            self.rebuild(keep_events=True)
            return {"files_added": len(added), "added": added, "duplicates": duplicates, "rejected": rejected, "events": len(events)}

    def load_sample(self) -> dict:
        files = [(p.name, p.read_bytes()) for p in sorted(SAMPLE_DIR.glob("*")) if p.suffix in (".csv", ".json")]
        return self.load_files(files, replace=True)

    def remove_file(self, sha256: str) -> dict:
        with self.lock:
            gone = [(n, r) for n, r in self.files if _sha(r) == sha256]
            broken = [x for x in self._broken if x["sha256"] == sha256]
            if not gone and not broken:
                raise UserError("That file is not part of this investigation.")
            keep = [(n, r) for n, r in self.files if _sha(r) != sha256]
            self._broken = [x for x in self._broken if x["sha256"] != sha256]
            self.files = keep
            self._log("evidence_removed", (gone or broken)[0][0] if gone else broken[0]["name"], {"sha256": sha256})
            self._sync_evidence()
            if not keep:
                self._empty()
                return self.meta()
            self.events, self.quality = build_dataset(keep)
            self._refresh_files_info()
            self.rebuild(keep_events=True)
            return self.meta()

    def clear(self) -> None:
        with self.lock:
            self._log("evidence_cleared", detail={"files": len(self.files)})
            self.files, self._broken = [], []
            self.store.clear_work()
            self._sync_evidence()
            self._empty()

    def new_investigation(self, data: dict, clear_iocs: bool = True) -> None:
        """Start from a blank page: evidence, notes, states and checklists are cleared (IOCs optionally kept)."""
        with self.lock:
            self._log("investigation_started", detail={"name": str(data.get("name", ""))[:120], "iocs_cleared": clear_iocs, "files_discarded": len(self.files)})
            self.files, self._broken = [], []
            self.store.clear_work()
            if clear_iocs:
                self.store.clear_iocs()
            self._sync_evidence()
            self._empty()
            self.case = dict(DEFAULT_CASE)
            self.set_case(data, log=False)

    def set_case(self, data: dict, log: bool = True) -> None:
        with self.lock:
            before = dict(self.case)
            for k in ("name", "analyst", "organization"):
                if k in data:
                    self.case[k] = str(data[k]).strip()[:120] or (DEFAULT_CASE[k] if k != "organization" else "")
            if data.get("tlp") in TLP:
                self.case["tlp"] = data["tlp"]
            self.store.set_kv("case", json.dumps(self.case))
            changed = {k: [before[k], self.case[k]] for k in self.case if before.get(k) != self.case[k]}
            if log and changed:
                self._log("case_updated", detail={"changed": changed})

    def set_config(self, overrides: dict | None) -> None:
        with self.lock:
            old = self.config
            self.config = sanitize_config(overrides) if overrides is not None else merged_config()
            changed = sorted(k for k in self.config if self.config[k] != old.get(k))
            if overrides is None:
                self._log("settings_reset")
            elif changed:
                self._log("settings_changed", detail={"changed": changed})
            if self.has_data:
                self.rebuild(keep_events=True)

    def _refresh_files_info(self) -> None:
        """Per-file facts shown on the Evidence page (computed once per change, not per request)."""
        span = self.events.groupby("source")["timestamp"].agg(["min", "max"]) if self.has_data else None
        sizes = {n: len(r) for n, r in self.files}
        hashes = {n: hashlib.sha256(r).hexdigest() for n, r in self.files}
        info = []
        for q in self.quality:
            lo, hi = (span.loc[q.filename, "min"], span.loc[q.filename, "max"]) if span is not None and q.filename in span.index else (None, None)
            info.append({"name": q.filename, "sha256": q.sha256, "size": sizes.get(q.filename, 0), "rows_read": q.rows_read, "events": q.rows_kept,
                         "bad_timestamp": q.bad_timestamp, "invalid_ips": q.invalid_ips, "truncated": q.truncated,
                         "start": _iso(lo), "end": _iso(hi), "mapped": q.mapped_fields, "unmapped": [str(c) for c in q.unmapped_columns][:12],
                         "sample": hashes.get(q.filename) in self._sample_hashes})
        self._files_info = info

    def rebuild(self, keep_events: bool = False) -> None:
        """(Re)run detection + correlation and refresh every derived index."""
        with self.lock:
            if not keep_events and self.files:
                self.events, self.quality = build_dataset(self.files)
            self.diagnostics = []
            iocs = self.store.iocs()[["ioc_type", "value", "note"]]
            self.findings = run_detections(self.events, self.config, iocs, diagnostics=self.diagnostics, sigma_rules=list(self._sigma.values()))
            self.incidents = build_incidents(self.findings, self.events, self.config)
            self.ev_sev, self.ev_findings = {}, {}
            for _, f in self.findings.iterrows():
                for eid in f["event_ids"]:
                    self.ev_findings.setdefault(eid, []).append(f["finding_id"])
                    if SEVERITY_ORDER[f["severity"]] > SEVERITY_ORDER.get(self.ev_sev.get(eid, "info"), -1):
                        self.ev_sev[eid] = f["severity"]
            self.ev_index = self.events.set_index("event_id", drop=False).rename_axis(None)

    # ------------------------------------------------------------------ helpers
    def _inc(self, incident_id: str):
        for i in self.incidents:
            if i.incident_id == incident_id:
                return i
        raise UserError(f"Unknown incident {incident_id}.")

    def _finding_row(self, finding_id: str):
        hit = self.findings[self.findings["finding_id"] == finding_id] if len(self.findings) else self.findings
        if hit.empty:
            raise UserError(f"Unknown finding {finding_id}.")
        return hit.iloc[0]

    def _state(self, inc) -> dict:
        v = self.store.verdict(inc.key)
        eff = v["confidence_override"] if v["confidence_override"] is not None else inc.confidence
        return {"verdict": v["verdict"], "state": STATE_LABEL.get(v["verdict"], v["verdict"].upper()),
                "confidence": int(eff), "confidence_label": _label(int(eff)), "overridden": v["confidence_override"] is not None}

    @staticmethod
    def _label(r) -> str:
        if r["command"]:
            return r["command"]
        if r["url"]:
            return (f"{int(r['status_code'])} " if pd.notna(r["status_code"]) else "") + r["url"]
        if r["message"]:
            return r["message"]
        dst = f" → {r['dst_ip']}" + (f":{int(r['dst_port'])}" if pd.notna(r["dst_port"]) else "") if pd.notna(r["dst_ip"]) else ""
        sent = f" ({int(r['bytes_out']):,} B out)" if pd.notna(r["bytes_out"]) else ""
        return f"{r['event_type']} {r['src_ip'] if pd.notna(r['src_ip']) else ''}{dst}{sent}".strip()

    def _event_dict(self, r, with_raw: bool = False) -> dict:
        eid = r["event_id"]
        fids = self.ev_findings.get(eid, [])
        d = {
            "id": eid, "ts": _iso(r["timestamp"]), "type": r["event_type"], "sev": self.ev_sev.get(eid, "info"),
            "alerted": bool(fids), "findings": fids, "label": self._label(r)[:400],
            "src_ip": _clean(r["src_ip"]), "dst_ip": _clean(r["dst_ip"]), "dst_port": _clean(r["dst_port"]),
            "user": _clean(r["user"]), "host": r["host"] or None, "source": r["source"], "status": _clean(r["status_code"]),
            "url": r["url"] or None, "command": r["command"] or None, "message": r["message"] or None, "bytes_out": _clean(r["bytes_out"]),
        }
        if with_raw:
            try:
                d["raw"] = json.loads(r["raw"])
            except (TypeError, ValueError):
                d["raw"] = {"raw": str(r["raw"])}
            d["finding_details"] = []
            for fid in fids:
                f = self._finding_row(fid)
                d["finding_details"].append({
                    "id": fid, "rule_id": f["rule_id"], "rule_name": f["rule_name"], "severity": f["severity"], "tactic": f["tactic"],
                    "techniques": _techs([f["technique"]]), "summary": f["summary"], "description": RULES[f["rule_id"]]["description"]})
        return d

    # ------------------------------------------------------------------ incidents
    def incident_cards(self) -> dict:
        cards = []
        counts = {v: 0 for v in VERDICTS}
        for inc in self.incidents:
            st = self._state(inc)
            counts[st["verdict"]] = counts.get(st["verdict"], 0) + 1
            ctx_n = len(self._context_ids(inc))
            tactics = [t for t in inc.tactics if t != "Threat Intel Match"]
            cards.append({
                "id": inc.incident_id, "key": inc.key, "title": inc.title, "severity": inc.severity, **st,
                "start": _iso(inc.start), "end": _iso(inc.end), "tactics": tactics[:4], "tactic_total": len(tactics),
                "alerted_events": len(inc.event_ids), "total_events": len(inc.event_ids) + ctx_n, "findings": len(inc.finding_ids),
                "ips": inc.entities["ip"][:3], "users": inc.entities["user"][:3], "hosts": inc.entities["host"][:3],
            })
        return {"incidents": cards, "counts": counts, "total": len(cards), "states": STATE_ORDER, "state_labels": STATE_LABEL}

    def _context_ids(self, inc) -> list[str]:
        """Events that touch the incident's entities near its time window but did not trigger a finding."""
        ev = self.events
        lo, hi = inc.start - CONTEXT_MARGIN, inc.end + CONTEXT_MARGIN
        win = ev[(ev["timestamp"] >= lo) & (ev["timestamp"] <= hi) & ~ev["event_id"].isin(set(inc.event_ids))]
        if win.empty:
            return []
        e = inc.entities
        m = win["src_ip"].isin(e["ip"]) | win["dst_ip"].isin(e["ip"]) | win["user"].isin(e["user"]) | win["host"].isin(e["host"])
        return win.loc[m, "event_id"].tolist()

    def incident_detail(self, incident_id: str) -> dict:
        inc = self._inc(incident_id)
        st = self._state(inc)
        done = self.store.checks(inc.key)
        notes = self.store.notes(inc.key)
        known = set(self.store.iocs()["value"].str.lower()) if len(self.store.iocs()) else set()
        fr = self.findings[self.findings["finding_id"].isin(inc.finding_ids)].sort_values("start")
        return {
            "id": inc.incident_id, "key": inc.key, "title": inc.title, "severity": inc.severity, **st,
            "start": _iso(inc.start), "end": _iso(inc.end), "entities": inc.entities, "sources": inc.sources,
            "tactics": [t for t in inc.tactics if t != "Threat Intel Match"], "techniques": _techs(inc.techniques),
            "summary": inc.summary, "confidence_factors": [{"factor": f, "points": p} for f, p in inc.confidence_factors],
            "base_confidence": inc.confidence,
            "remediation": [{"step": s, "done": s in done} for s in inc.remediation],
            "ioc_candidates": [{**c, "recorded": c["value"].lower() in known} for c in inc.ioc_candidates],
            "notes": [{"author": n["author"], "note": n["note"], "at": n["created_utc"]} for _, n in notes.iterrows()],
            "findings": [{"id": f["finding_id"], "rule_name": f["rule_name"], "severity": f["severity"], "tactic": f["tactic"],
                          "techniques": _techs([f["technique"]]), "start": _iso(f["start"]), "count": int(f["count"]), "summary": f["summary"]}
                         for _, f in fr.iterrows()],
            "alerted_events": len(inc.event_ids), "total_events": len(inc.event_ids) + len(self._context_ids(inc)),
        }

    def incident_events(self, incident_id: str, sev: str = "all", q: str = "", scope: str = "all",
                        t0: str | None = None, t1: str | None = None) -> dict:
        inc = self._inc(incident_id)
        ids = list(inc.event_ids)
        if scope != "alerted":
            ids += self._context_ids(inc)
        ev = self.ev_index.loc[ids].sort_values(["timestamp", "event_id"])
        # histogram uses everything in scope (before the severity / text / bucket filters) so the chart stays stable
        span = max(1.0, (ev["timestamp"].max() - ev["timestamp"].min()).total_seconds()) if len(ev) else 1.0
        step = _nice_bucket(span)
        sevs = ev["event_id"].map(lambda e: self.ev_sev.get(e, "info"))
        epoch = pd.Timestamp("1970-01-01", tz="UTC")
        bucket = (((ev["timestamp"] - epoch).dt.total_seconds() // step) * step).astype(int)
        hist: dict[int, dict] = {}
        for b, s in zip(bucket, sevs):
            hist.setdefault(int(b), {k: 0 for k in SEVS})[s] += 1
        hist_out = [{"t": int(b), "counts": c} for b, c in sorted(hist.items())]
        view = ev
        if sev != "all":
            view = view[sevs.loc[view.index] == sev]
        if t0 and t1:
            lo, hi = pd.Timestamp(t0), pd.Timestamp(t1)
            view = view[(view["timestamp"] >= lo) & (view["timestamp"] < hi)]
        if q.strip():
            needle = q.strip().lower()
            blob = view[["src_ip", "dst_ip", "user", "host", "url", "command", "message", "event_type"]].fillna("").astype(str).agg(" ".join, axis=1).str.lower()
            view = view[blob.str.contains(needle, regex=False)]
        total = len(view)
        view = view.head(MAX_INCIDENT_EVENTS)
        return {"events": [self._event_dict(r) for _, r in view.iterrows()], "total": total, "truncated": total > MAX_INCIDENT_EVENTS,
                "histogram": {"step": step, "buckets": hist_out}}

    def event_detail(self, event_id: str) -> dict:
        if event_id not in self.ev_index.index:
            raise UserError(f"Unknown event {event_id}.")
        return self._event_dict(self.ev_index.loc[event_id], with_raw=True)

    def set_state(self, incident_id: str, verdict: str, override: int | None) -> dict:
        inc = self._inc(incident_id)
        if verdict not in VERDICTS:
            raise UserError(f"Unknown state '{verdict}'.")
        if override is not None:
            override = max(0, min(100, int(override)))
        before = self.store.verdict(inc.key)
        self.store.set_verdict(inc.key, verdict, override)
        self._log("verdict_set", incident_id, {"key": inc.key, "verdict": verdict, "previous": before["verdict"], "confidence_override": override,
                                                "previous_override": before["confidence_override"]})
        return self._state(inc)

    def add_note(self, incident_id: str, text: str) -> None:
        inc = self._inc(incident_id)
        if not text.strip():
            raise UserError("Note is empty.")
        self.store.add_note(inc.key, text[:5000], self.case["analyst"])
        self._log("note_added", incident_id, {"key": inc.key, "chars": len(text[:5000]), "sha256": _sha(text[:5000].encode("utf-8"))})

    def set_check(self, incident_id: str, step: str, done: bool) -> None:
        inc = self._inc(incident_id)
        if step not in inc.remediation:
            raise UserError("Unknown remediation step.")
        self.store.set_check(inc.key, step, done)
        self._log("checklist_changed", incident_id, {"step": step, "done": done})

    def add_candidate_iocs(self, incident_id: str, values: list[str]) -> int:
        inc = self._inc(incident_id)
        by_val = {c["value"]: c for c in inc.ioc_candidates}
        n = 0
        for v in values:
            c = by_val.get(v)
            if c and self.store.add_ioc(c["value"], c["ioc_type"], inc.incident_id, c["note"]):
                n += 1
                self._log("ioc_added", incident_id, {"type": c["ioc_type"], "value": c["value"], "source": "incident candidate"})
        if n:
            self.rebuild(keep_events=True)
        return n

    # ------------------------------------------------------------------ findings / events / timeline
    def findings_list(self) -> list[dict]:
        out = []
        for _, f in self.findings.iterrows():
            inc = next((i.incident_id for i in self.incidents if f["finding_id"] in i.finding_ids), None)
            out.append({"id": f["finding_id"], "rule_id": f["rule_id"], "rule_name": f["rule_name"], "severity": f["severity"], "tactic": f["tactic"],
                        "techniques": _techs([f["technique"]]), "start": _iso(f["start"]), "end": _iso(f["end"]), "count": int(f["count"]),
                        "summary": f["summary"], "src_ip": f["src_ip"] or None, "user": f["user"] or None, "host": f["host"] or None, "incident": inc})
        return out

    def finding_detail(self, finding_id: str) -> dict:
        f = self._finding_row(finding_id)
        meta = RULES[f["rule_id"]]
        ev = self.ev_index.loc[f["event_ids"]].sort_values("timestamp").head(300)
        return {"id": finding_id, "rule_name": f["rule_name"], "severity": f["severity"], "tactic": f["tactic"], "techniques": _techs([f["technique"]]),
                "description": meta["description"], "remediation": meta["remediation"], "summary": f["summary"], "start": _iso(f["start"]), "end": _iso(f["end"]),
                "count": int(f["count"]), "events": [self._event_dict(r) for _, r in ev.iterrows()],
                "incident": next((i.incident_id for i in self.incidents if finding_id in i.finding_ids), None)}

    def events_page(self, page: int, size: int, q: str, types: list[str], source: str, flagged: bool) -> dict:
        ev = self.events
        if types:
            ev = ev[ev["event_type"].isin(types)]
        if source:
            ev = ev[ev["source"] == source]
        if flagged:
            ev = ev[ev["event_id"].isin(self.ev_findings.keys())]
        if q.strip():
            blob = ev[["src_ip", "dst_ip", "user", "host", "url", "command", "message", "event_type", "event_id"]].fillna("").astype(str).agg(" ".join, axis=1).str.lower()
            ev = ev[blob.str.contains(q.strip().lower(), regex=False)]
        size = max(10, min(500, size))
        total = len(ev)
        page = max(1, min(page, max(1, -(-total // size))))
        part = ev.iloc[(page - 1) * size: page * size]
        return {"total": total, "page": page, "size": size, "events": [self._event_dict(r) for _, r in part.iterrows()]}

    def timeline(self, lane: str, q: str, types: list[str], flagged: bool) -> dict:
        lanes = {"src_ip": "Source IP", "user": "User", "host": "Host", "source": "Log source", "event_type": "Event type"}
        if lane not in lanes:
            lane = "src_ip"
        ev = self.events
        if types:
            ev = ev[ev["event_type"].isin(types)]
        if flagged:
            ev = ev[ev["event_id"].isin(self.ev_findings.keys())]
        if q.strip():
            blob = ev[["src_ip", "dst_ip", "user", "host", "url", "command", "message"]].fillna("").astype(str).agg(" ".join, axis=1).str.lower()
            ev = ev[blob.str.contains(q.strip().lower(), regex=False)]
        total = len(ev)
        flagged_ids = set(self.ev_findings)
        keep = ev[ev["event_id"].isin(flagged_ids)]
        rest = ev[~ev["event_id"].isin(flagged_ids)]
        budget = max(0, 4000 - len(keep))
        if len(rest) > budget:
            rest = rest.sample(budget, random_state=1)
        ev = pd.concat([keep, rest]).sort_values("timestamp")
        col = ev[lane].replace("", pd.NA).fillna("unknown").astype(str)
        is_fl = ev["event_id"].isin(flagged_ids)
        fl_ct, all_ct = col[is_fl].value_counts(), col.value_counts()
        # lanes with flagged events first, then by volume; keep the chart readable with at most 24 lanes
        keep_lanes = sorted(all_ct.index, key=lambda x: (x == "unknown", -int(fl_ct.get(x, 0)), -int(all_ct[x]), x))[:24]
        col = col.where(col.isin(keep_lanes), "(other)")
        fl_ct, all_ct = col[is_fl].value_counts(), col.value_counts()
        order = sorted(set(col), key=lambda x: (x in ("unknown", "(other)"), -int(fl_ct.get(x, 0)), -int(all_ct[x]), x))
        pts = [{"id": e, "t": int(t.timestamp() * 1000), "lane": order.index(c), "type": ty, "sev": self.ev_sev.get(e, "info")}
               for e, t, c, ty in zip(ev["event_id"], ev["timestamp"], col, ev["event_type"])]
        return {"lane_label": lanes[lane], "lanes": order, "points": pts, "total": total, "sampled": total > len(pts),
                "incidents": [{"id": i.incident_id, "severity": i.severity, "start": int(i.start.timestamp() * 1000), "end": int(i.end.timestamp() * 1000)} for i in self.incidents],
                "findings": [{"id": f["finding_id"], "t": int(f["start"].timestamp() * 1000), "severity": f["severity"], "summary": f["summary"]} for _, f in self.findings.iterrows()]}

    # ------------------------------------------------------------------ dashboard / meta
    def meta(self) -> dict:
        ev = self.events
        span = (ev["timestamp"].max() - ev["timestamp"].min()) if self.has_data else pd.Timedelta(0)
        return {
            "version": __version__, "case": self.case, "has_data": self.has_data, "sample": self.sample_loaded,
            "events": len(ev), "sources": int(ev["source"].nunique()) if self.has_data else 0, "findings": len(self.findings),
            "incidents": len(self.incidents), "iocs": len(self.store.iocs()),
            "span_hours": round(span.total_seconds() / 3600, 1), "start": _iso(ev["timestamp"].min()) if self.has_data else None,
            "end": _iso(ev["timestamp"].max()) if self.has_data else None, "tlp_options": TLP, "diagnostics": self.diagnostics,
            "severity_colors": SEVERITY_COLORS, "verdicts": VERDICTS, "state_labels": STATE_LABEL,
            "files": self._files_info, "integrity": {**self.integrity, "stored": self.vault.enabled}, "audit": self.store.audit.head(),
            "sigma_rules": len(self._sigma), "persistent": self.vault.enabled,
        }

    def dashboard(self) -> dict:
        ev, f = self.events, self.findings
        d = self.meta()
        if not self.has_data:
            return d
        span = max(1.0, (ev["timestamp"].max() - ev["timestamp"].min()).total_seconds())
        step = _nice_bucket(span, 60)
        epoch = pd.Timestamp("1970-01-01", tz="UTC")
        bucket = (((ev["timestamp"] - epoch).dt.total_seconds() // step) * step).astype(int)
        sev = ev["event_id"].map(lambda e: self.ev_sev.get(e, "info"))
        hist: dict[int, dict] = {}
        for b, s in zip(bucket, sev):
            hist.setdefault(int(b), {k: 0 for k in SEVS})[s] += 1
        by_tactic: dict = {}
        if len(f):
            for (t, s), n in f.groupby(["tactic", "severity"]).size().items():
                by_tactic.setdefault(t, {})[s] = int(n)
        top_ips = ev.dropna(subset=["src_ip"]).groupby("src_ip").agg(events=("event_id", "size")).sort_values("events", ascending=False).head(8)
        flagged = {ip: 0 for ip in top_ips.index}
        for _, row in f.iterrows():
            for e in row["entities"]:
                if e.startswith("ip:") and e[3:] in flagged:
                    flagged[e[3:]] += 1
        rules = []
        for rid, meta in RULES.items():
            n = int((f["rule_id"] == rid).sum()) if len(f) else 0
            rules.append({"id": rid, "name": meta["name"], "tactic": meta["tactic"], "enabled": self.config.get(rid, {}).get("enabled", True),
                          "findings": n, "severity": meta["severity"]})
        d.update({
            "histogram": {"step": step, "buckets": [{"t": b, "counts": c} for b, c in sorted(hist.items())]},
            "by_tactic": by_tactic, "tactic_order": [t for t in TACTIC_ORDER if t in by_tactic],
            "top_ips": [{"ip": ip, "events": int(r["events"]), "findings": flagged[ip], "internal": is_internal(ip)} for ip, r in top_ips.iterrows()],
            "event_types": {k: int(v) for k, v in ev["event_type"].value_counts().items()},
            "incident_counts": {s: sum(1 for i in self.incidents if i.severity == s) for s in SEVS[:4]},
            "finding_counts": {s: int((f["severity"] == s).sum()) if len(f) else 0 for s in SEVS[:4]},
            "rules": rules, "quality": [self._quality(q) for q in self.quality],
            "top_incidents": self.incident_cards()["incidents"][:5],
        })
        return d

    @staticmethod
    def _quality(q) -> dict:
        return {"filename": q.filename, "sha256": q.sha256, "rows_read": q.rows_read, "rows_kept": q.rows_kept, "bad_timestamp": q.bad_timestamp,
                "invalid_ips": q.invalid_ips, "mapped": q.mapped_fields, "unmapped": [str(c) for c in q.unmapped_columns], "truncated": q.truncated}

    # ------------------------------------------------------------------ settings
    def settings(self) -> dict:
        cfg = self.config
        rules = []
        for rid, meta in RULES.items():
            rules.append({"id": rid, "name": meta["name"], "tactic": meta["tactic"], "technique": meta["technique"], "severity": meta["severity"],
                          "description": meta["description"], "enabled": cfg.get(rid, {}).get("enabled", True),
                          "params": [{"key": k, "label": lab, "kind": kind, "min": lo, "max": hi, "value": cfg[rid][k]} for k, lab, kind, lo, hi in PARAMS.get(rid, [])]})
        return {"rules": rules, "correlation_gap": cfg["correlation"]["max_gap_minutes"], "privileged_users": cfg["privileged_users"]}

    # ------------------------------------------------------------------ IOCs
    def iocs_list(self) -> dict:
        cur = self.store.iocs()
        hits: dict[str, int] = {}
        if len(self.findings):
            for _, f in self.findings[self.findings["rule_id"] == "ioc_match"].iterrows():
                m = re.search(r"IOC \S+ '(.+?)' appears", f["summary"])
                if m:
                    hits[m.group(1)] = int(f["count"])
        rows = [{"id": int(r["id"]), "type": r["ioc_type"], "value": r["value"], "source": r["source"], "note": r["note"] or "", "added": r["added_utc"],
                 "matches": hits.get(str(r["value"]).lower(), 0)} for _, r in cur.iterrows()]
        return {"iocs": rows, "types": IOC_TYPES}

    def add_iocs(self, values: list[str], ioc_type: str | None, note: str, source: str = "analyst") -> dict:
        added = dup = 0
        for v in values:
            v = v.strip()
            if not v:
                continue
            if self.store.add_ioc(v[:500], ioc_type if ioc_type in IOC_TYPES else None, source, note[:300]):
                added += 1
                self._log("ioc_added", detail={"value": v[:200], "source": source})
            else:
                dup += 1
        if added:
            self.rebuild(keep_events=True)
        return {"added": added, "duplicates": dup}

    def delete_ioc(self, ioc_id: int) -> None:
        cur = self.store.iocs()
        row = cur[cur["id"] == ioc_id]
        self.store.delete_ioc(ioc_id)
        if len(row):
            self._log("ioc_deleted", detail={"type": str(row.iloc[0]["ioc_type"]), "value": str(row.iloc[0]["value"])[:200]})
        self.rebuild(keep_events=True)

    # ------------------------------------------------------------------ Sigma rules
    def _load_sigma(self) -> None:
        self._sigma = {}
        for row in self.store.sigma_rows():
            rules, _skipped = sigma_mod.parse_rules(row["yaml"], row["title"])
            if rules:
                self._sigma[row["id"]] = rules[0]

    def sigma_list(self) -> dict:
        rows = []
        for row in self.store.sigma_rows():
            rule = self._sigma.get(row["id"])
            rows.append({"id": row["id"], "rule_id": row["rule_id"], "title": row["title"], "level": row["level"], "added": row["added_utc"],
                         "tactic": rule.tactic if rule else "", "techniques": rule.techniques if rule else [],
                         "matches": int((self.findings["rule_name"] == f"Sigma: {row['title']}").sum()) if len(self.findings) else 0})
        return {"rules": rows, "limit": sigma_mod.MAX_RULES}

    def sigma_import(self, files: list[tuple[str, bytes]]) -> dict:
        with self.lock:
            added, skipped = [], []
            for name, raw in files:
                rules, sk = sigma_mod.parse_rules(raw, name)
                skipped += sk
                for r in rules:
                    if len(self.store.sigma_rows()) >= sigma_mod.MAX_RULES:
                        skipped.append({"name": name, "reason": f"the limit of {sigma_mod.MAX_RULES} imported rules was reached."})
                        break
                    if self.store.sigma_add(r.sha256, r.rule_id, r.title, r.level, r.yaml_text):
                        added.append(r.title)
                        self._log("sigma_imported", r.title, {"rule_id": r.rule_id, "level": r.level, "file": name})
                    else:
                        skipped.append({"name": name, "reason": f"'{r.title}' is already imported."})
            if added:
                self._load_sigma()
                self.rebuild(keep_events=True)
            elif not skipped:
                raise UserError("No Sigma rules were found in the upload.")
            return {"added": added, "skipped": skipped}

    def sigma_delete(self, row_id: int) -> None:
        with self.lock:
            title = next((r["title"] for r in self.store.sigma_rows() if r["id"] == row_id), None)
            if title is None or not self.store.sigma_delete(row_id):
                raise UserError("Unknown Sigma rule.")
            self._log("sigma_removed", title)
            self._load_sigma()
            self.rebuild(keep_events=True)

    # ------------------------------------------------------------------ reports
    def _redactor(self, mode: str = "auto") -> Redactor:
        return Redactor.for_case(policy_for(self.case["tlp"], mode), self.events, self.incidents, self.store.iocs())

    def report_context(self, redact: str = "auto", verify: bool = True) -> ReportContext:
        verdicts = {i.incident_id: self.store.verdict(i.key) for i in self.incidents}
        notes = self.store.notes()
        if len(notes):
            ids = {i.key: i.incident_id for i in self.incidents}
            notes = notes[notes["incident_id"].isin(ids)].assign(incident_id=lambda d: d["incident_id"].map(ids))
        chain = self.store.audit.verify()
        ctx = ReportContext(case_name=self.case["name"], analyst=self.case["analyst"], organization=self.case["organization"], tlp=self.case["tlp"],
                            events=self.events, findings=self.findings, incidents=self.incidents, iocs=self.store.iocs(), notes=notes,
                            verdicts=verdicts, quality=self.quality, integrity=(self.verify_integrity() if verify else self.integrity) if self.has_data else None,
                            audit={"entries": chain["entries"], "head_hash": chain["head_hash"], "chain_ok": chain["ok"]},
                            rules_enabled=[r for r in RULES if self.config.get(r, {}).get("enabled", True)], sigma_titles=[r.title for r in self._sigma.values()])
        return self._redactor(redact).apply(ctx)

    def report_preview(self) -> dict:
        ctx = self.report_context("off", verify=False)
        unrev = [i.incident_id for i in self.incidents if self.store.verdict(i.key)["verdict"] == "Unreviewed"]
        pol = policy_for(self.case["tlp"], "auto")
        return {"points": executive_points(ctx) if self.has_data else [], "unreviewed": unrev, "tlp": self.case["tlp"],
                "redaction_auto": self._redactor("auto").describe() if pol.active else ""}

    def _export_log(self, kind: str, redact: str, data: bytes | str) -> None:
        raw = data if isinstance(data, bytes) else data.encode("utf-8")
        self._log("export", kind, {"tlp": self.case["tlp"], "redaction": policy_for(self.case["tlp"], redact).active, "mode": redact, "sha256": _sha(raw), "bytes": len(raw)})

    def pdf(self, redact: str = "auto") -> bytes:
        data = build_pdf(self.report_context(redact))
        self._export_log("report.pdf", redact, data)
        return data

    def markdown(self, redact: str = "auto") -> str:
        data = build_markdown(self.report_context(redact))
        self._export_log("report.md", redact, data)
        return data

    def json_report(self, redact: str = "auto") -> str:
        data = build_json(self.report_context(redact))
        self._export_log("report.json", redact, data)
        return data

    def _events_for_export(self, ids, redact: str) -> pd.DataFrame:
        df = self.events if ids is None else self.events[self.events["event_id"].isin(ids)]
        df = df.drop(columns=["raw"])
        return self._redactor(redact).frame(df, bulk=True)

    def evidence_csv(self, redact: str = "auto") -> str:
        data = csv_safe(self._events_for_export({x for i in self.incidents for x in i.event_ids}, redact)).to_csv(index=False)
        self._export_log("evidence.csv", redact, data)
        return data

    def events_csv(self, redact: str = "auto") -> str:
        data = csv_safe(self._events_for_export(None, redact)).to_csv(index=False)
        self._export_log("events.csv", redact, data)
        return data

    def _shareable_iocs(self, redact: str) -> pd.DataFrame:
        iocs, pol = self.store.iocs(), policy_for(self.case["tlp"], redact)
        if pol.users:
            iocs = iocs[iocs["ioc_type"] != "username"]
        if pol.internal_ips and len(iocs):
            iocs = iocs[~iocs.apply(lambda r: r["ioc_type"] in ("ipv4", "ipv6") and is_internal(r["value"]), axis=1)]
        return iocs

    def iocs_csv(self, redact: str = "auto") -> str:
        data = csv_safe(self._shareable_iocs(redact)).to_csv(index=False)
        self._export_log("iocs.csv", redact, data)
        return data

    def iocs_stix(self, redact: str = "auto") -> str:
        data = stix_bundle(self._shareable_iocs(redact), self.case["tlp"], self.case["name"])
        self._export_log("iocs.stix.json", redact, data)
        return data

    def attack_layer(self) -> str:
        data = navigator_layer(self.findings, self.case["name"])
        self._export_log("attack-layer.json", "off", data)
        return data

    def audit_csv(self) -> str:
        data = self.store.audit.export_csv()
        self._export_log("audit.csv", "off", data)
        return data

    # ------------------------------------------------------------------ case file (save / restore)
    def export_case(self, passphrase: str | None = None) -> str:
        text = self.store.export_case(self.case)
        if passphrase is not None:
            try:
                text = encrypt_case(text.encode("utf-8"), passphrase)
            except CaseCryptoError as exc:
                raise UserError(str(exc)) from exc
        self._log("case_exported", detail={"encrypted": passphrase is not None, "sha256": _sha(text.encode("utf-8"))})
        return text

    def import_case(self, raw: bytes, passphrase: str = "") -> dict:
        encrypted = is_encrypted_case(raw)
        if encrypted:
            if not passphrase:
                raise UserError("This case file is encrypted. Enter its passphrase.")
            try:
                raw = decrypt_case(raw, passphrase)
            except CaseCryptoError as exc:
                raise UserError(str(exc)) from exc
        try:
            res = self.store.import_case(raw.decode("utf-8"))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise UserError(f"Not a valid TraceForge case file: {exc}") from exc
        with self.lock:
            if res["case"]:
                self.set_case(res["case"], log=False)
            self._load_sigma()
            self.rebuild(keep_events=True)
            have = {_sha(r) for _, r in self.files}
            expected = res.pop("evidence_manifest")
            missing = [m.get("name", "?") for m in expected if m.get("sha256") not in have]
            res["evidence_check"] = {"expected": len(expected), "missing": missing}
            self._log("case_imported", detail={"encrypted": encrypted, "iocs_added": res["iocs_added"], "notes": res["notes"], "verdicts": res["verdicts"],
                                                "sigma_rules": res["sigma_rules"], "source_audit_head": res.pop("source_audit_head"), "evidence_missing": len(missing)})
        res.pop("case", None)
        res["encrypted"] = encrypted
        return res

    # ------------------------------------------------------------------ about
    def about(self) -> dict:
        return {"version": __version__, "privacy": "No data leaves this computer: TraceForge makes no outbound network requests and has no telemetry.",
                "persistent": self.vault.enabled, "rules": len(RULES), "sigma_rules": len(self._sigma)}
