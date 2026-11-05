"""Correlate findings into incidents and score them transparently."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

import pandas as pd

from .config import RULES, SEVERITY_ORDER, TACTIC_ORDER, merged_config
from .ingest import is_internal

_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


@dataclass
class Incident:
    incident_id: str
    title: str
    start: pd.Timestamp
    end: pd.Timestamp
    severity: str
    confidence: int
    confidence_label: str
    confidence_factors: list
    entities: dict
    finding_ids: list
    event_ids: list
    tactics: list
    techniques: list
    rule_ids: list
    sources: list
    narrative: list
    remediation: list
    ioc_candidates: list = field(default_factory=list)
    summary: str = ""
    key: str = ""  # stable identity (survives renumbering) used to attach notes/verdicts/checklists


def _find(parent, x):
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x


def link_findings(findings: pd.DataFrame, max_gap_minutes: float) -> list[list[int]]:
    """Union findings that share an entity and are within max_gap_minutes of each other."""
    n = len(findings)
    parent = list(range(n))
    by_entity: dict[str, list[int]] = {}
    for i, ents in enumerate(findings["entities"]):
        for e in ents:
            by_entity.setdefault(e, []).append(i)
    gap = pd.Timedelta(minutes=max_gap_minutes)
    for idxs in by_entity.values():
        idxs = sorted(idxs, key=lambda i: findings.iloc[i]["start"])
        reach_end = findings.iloc[idxs[0]]["end"]
        prev = idxs[0]
        for i in idxs[1:]:
            row = findings.iloc[i]
            if row["start"] - reach_end <= gap:
                parent[_find(parent, i)] = _find(parent, prev)
            prev = i if row["end"] >= reach_end else prev
            reach_end = max(reach_end, row["end"])
    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(_find(parent, i), []).append(i)
    return list(groups.values())


def score_confidence(group: pd.DataFrame, sources: list) -> tuple[int, str, list]:
    """Transparent heuristic: every point added or removed is listed so analysts can challenge it."""
    factors = [("Baseline for any rule-based finding", 20)]
    rules = set(group["rule_id"])
    tactics = (set(group["tactic"]) & set(TACTIC_ORDER)) - {"Threat Intel Match"}
    pts = min(30, 10 * len(rules))
    factors.append((f"{len(rules)} independent detection rule(s) fired", pts))
    if len(sources) >= 2:
        factors.append((f"Corroborated by {len(sources)} different log sources", 15))
    if len(tactics) >= 2:
        factors.append((f"Activity spans {len(tactics)} ATT&CK tactics (kill-chain progression)", 15))
    if rules & {"success_after_failures", "sensitive_activity", "large_outbound"}:
        factors.append(("Evidence of success/impact (login after failures, persistence or data transfer)", 10))
    if "ioc_match" in rules:
        factors.append(("Matches an analyst-recorded IOC", 10))
    if len(group) == 1 and group.iloc[0]["severity"] in ("low", "info"):
        factors.append(("Single low-severity finding", -10))
    score = max(5, min(95, sum(p for _, p in factors)))
    label = "High" if score >= 70 else "Medium" if score >= 40 else "Low"
    return score, label, factors


def _extract_ioc_candidates(group: pd.DataFrame, events: pd.DataFrame, event_ids: list) -> list[dict]:
    ev = events[events["event_id"].isin(event_ids)]
    cands: dict[tuple, str] = {}
    suspicious_ips = set()
    for ents in group["entities"]:
        suspicious_ips |= {e[3:] for e in ents if e.startswith("ip:")}
    for ip in sorted(suspicious_ips):
        if not is_internal(ip):
            cands[("ipv4" if ":" not in ip else "ipv6", ip)] = "External IP seen in correlated findings"
    for v in ev.loc[ev["event_type"].isin(["account_created"]), "user"].dropna().unique():
        cands[("username", str(v))] = "Account involved in persistence activity"
    for _, f in group[group["rule_id"] == "success_after_failures"].iterrows():
        if f["user"]:
            cands[("username", f["user"])] = "Account with successful login after failures"
    for text in (ev["command"] + " " + ev["message"]).tolist():
        for h in _HASH_RE.findall(text):
            kind = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h))
            if kind:
                cands[(kind, h.lower())] = "Hash found in event text"
    return [{"ioc_type": t, "value": v, "note": n} for (t, v), n in cands.items()]


def _narrative(group: pd.DataFrame) -> list[str]:
    lines = []
    for _, f in group.sort_values("start").iterrows():
        lines.append(f"{f['start']:%Y-%m-%d %H:%M:%S} UTC | {f['tactic']} | {f['rule_name']} | {f['summary']} [{f['finding_id']}]")
    return lines


def _title(group: pd.DataFrame, tactics: list) -> str:
    ips = sorted({e[3:] for ents in group["entities"] for e in ents if e.startswith("ip:") and not is_internal(e[3:])})
    users = sorted({e[5:] for ents in group["entities"] for e in ents if e.startswith("user:")})
    who = ", ".join(ips[:2] + users[:2]) or "unattributed activity"
    kind = "Multi-stage activity" if len(tactics) >= 3 else (f"{tactics[0]} activity" if tactics else "Suspicious activity")
    return f"{kind} involving {who}"


def _summary(g: pd.DataFrame, tactics: list, sources: list) -> list[str]:
    """[headline, progression line, one bullet per key finding..., closing caveat] - rendered as the incident Summary tab."""
    g = g.sort_values("start")
    span = g["end"].max() - g["start"].min()
    mins = int(span.total_seconds() // 60)
    dur = f"{mins // 60}h {mins % 60:02d}m" if mins >= 60 else f"{mins}m"
    lines = [f"{len(g)} detection finding(s) from {len(sources)} log source(s) were correlated between "
             f"{g['start'].min():%Y-%m-%d %H:%M} and {g['end'].max():%H:%M} UTC ({dur}).",
             "Observed kill-chain progression: " + (" → ".join(tactics) if tactics else "single stage") + "."]
    ranked = g.sort_values(["severity", "start"], key=lambda c: c.map(SEVERITY_ORDER) * -1 if c.name == "severity" else c)
    for _, f in ranked.head(8).sort_values("start").iterrows():
        lines.append(f"{f['start']:%H:%M:%S} · {f['summary']}")
    if len(g) > 8:
        lines.append(f"…and {len(g) - 8} lower-priority finding(s) listed under 'Findings in this incident'.")
    lines.append("Rule-based reconstruction from the imported evidence only; validate the highlighted events before taking action.")
    return lines


def _stable_key(g: pd.DataFrame) -> str:
    """Identity of an incident = its earliest detection finding (rule + time + entities), so analyst work survives
    threshold changes. IOC matches are ignored: recording an indicator must never orphan notes or verdicts."""
    base = g[g["rule_id"] != "ioc_match"]
    first = (base if len(base) else g).sort_values(["start", "rule_id"]).iloc[0]
    raw = f"{first['rule_id']}|{first['start'].isoformat()}|{','.join(first['entities'])}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def build_incidents(findings: pd.DataFrame, events: pd.DataFrame, config: dict | None = None) -> list[Incident]:
    cfg = merged_config(config)
    if findings.empty:
        return []
    groups = link_findings(findings, cfg["correlation"]["max_gap_minutes"])
    incidents = []
    for idxs in groups:
        g = findings.iloc[idxs].sort_values("start")
        event_ids = sorted({e for ids in g["event_ids"] for e in ids})
        ev = events[events["event_id"].isin(event_ids)]
        sources = sorted(ev["source"].unique())
        tactics = [t for t in TACTIC_ORDER if t in set(g["tactic"])]
        sev = max(g["severity"], key=lambda s: SEVERITY_ORDER[s])
        if len([t for t in tactics if t != "Threat Intel Match"]) >= 3 and SEVERITY_ORDER[sev] >= SEVERITY_ORDER["high"]:
            sev = "critical"
        score, label, factors = score_confidence(g, sources)
        ents: dict[str, list] = {"ip": [], "user": [], "host": []}
        for ents_list in g["entities"]:
            for e in ents_list:
                kind, val = e.split(":", 1)
                if val not in ents[kind]:
                    ents[kind].append(val)
        rem, seen = [], set()
        for rid in sorted(set(g["rule_id"]), key=lambda r: TACTIC_ORDER.index(RULES[r]["tactic"]), reverse=True):
            for step in RULES[rid]["remediation"]:
                if step not in seen:
                    seen.add(step)
                    rem.append(step)
        incidents.append(Incident(
            incident_id="", title=_title(g, tactics), start=g["start"].min(), end=g["end"].max(),
            severity=sev, confidence=score, confidence_label=label, confidence_factors=factors,
            entities=ents, finding_ids=g["finding_id"].tolist(), event_ids=event_ids, tactics=tactics,
            techniques=sorted({t for t in g["technique"] if t != "n/a"}), rule_ids=sorted(set(g["rule_id"])),
            sources=sources, narrative=_narrative(g), remediation=rem,
            ioc_candidates=_extract_ioc_candidates(g, events, event_ids),
            summary=_summary(g, tactics, sources), key=_stable_key(g)))
    incidents.sort(key=lambda i: (-SEVERITY_ORDER[i.severity], -i.confidence, i.start))
    for n, inc in enumerate(incidents, 1):
        inc.incident_id = f"INC-{n:03d}"
    return incidents
