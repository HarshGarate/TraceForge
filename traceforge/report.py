"""Incident report generation: PDF (reportlab), Markdown and JSON."""
from __future__ import annotations

import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from xml.sax.saxutils import escape

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_LEFT  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.pdfgen import canvas as rl_canvas  # noqa: E402
from reportlab.platypus import (Image, PageBreak, Paragraph, SimpleDocTemplate,  # noqa: E402
                                Spacer, Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents  # noqa: E402

from . import __version__  # noqa: E402
from .config import RULES, SEVERITY_COLORS, SEVERITY_ORDER, TACTIC_ORDER, TECHNIQUE_NAMES  # noqa: E402
from .ingest import is_internal  # noqa: E402

NAVY, SLATE, LIGHT = colors.HexColor("#0f172a"), colors.HexColor("#475569"), colors.HexColor("#f1f5f9")
ACCENT = colors.HexColor("#0ea5e9")


@dataclass
class ReportContext:
    case_name: str = "Untitled case"
    analyst: str = "Analyst"
    organization: str = ""
    tlp: str = "TLP:AMBER"
    events: pd.DataFrame = field(default_factory=pd.DataFrame)
    findings: pd.DataFrame = field(default_factory=pd.DataFrame)
    incidents: list = field(default_factory=list)
    iocs: pd.DataFrame = field(default_factory=pd.DataFrame)
    notes: pd.DataFrame = field(default_factory=pd.DataFrame)
    verdicts: dict = field(default_factory=dict)  # incident_id -> {"verdict", "confidence_override"}
    quality: list = field(default_factory=list)
    redaction: str = ""                      # description of any redaction applied (empty = none)
    integrity: dict | None = None            # result of the last evidence re-verification
    audit: dict | None = None                # {"entries", "head_hash", "chain_ok"}
    rules_enabled: list | None = None        # rule ids enabled for this run (None = all)
    sigma_titles: list = field(default_factory=list)
    generated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def integrity_lines(ctx: "ReportContext") -> list[str]:
    """Plain-text statements about evidence integrity and the audit log, shared by every report format."""
    out = []
    if ctx.integrity:
        i = ctx.integrity
        out.append(f"Evidence re-verified {i.get('checked_utc', '')} UTC: " + ("all stored files match their SHA-256." if i.get("ok") else
                   f"{len(i.get('problems', []))} file(s) failed verification - treat the affected evidence as unreliable."))
    if ctx.audit:
        a = ctx.audit
        out.append(f"Audit log: {a.get('entries', 0)} entries, hash chain " + ("intact" if a.get("chain_ok") else "BROKEN") + f", head {a.get('head_hash', '')}.")
    if ctx.redaction:
        out.append(ctx.redaction)
    return out


def csv_safe(df: pd.DataFrame) -> pd.DataFrame:
    """Neutralise spreadsheet formula injection (=, +, -, @) in exported CSV text cells."""
    out = df.copy()
    for col in out.columns:
        if out[col].dtype == object or str(out[col].dtype).startswith("str"):
            out[col] = [("'" + v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v for v in out[col]]
    return out


_PUNCT = {"\u2192": ">", "\u2190": "<", "\u2014": "-", "\u2013": "-", "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u2022": "-"}


def _ascii_punct(s: str) -> str:
    """The built-in PDF fonts cannot draw arrows or typographic quotes; map them to plain equivalents instead of '?'."""
    return s.translate(str.maketrans(_PUNCT))


def _t(x, limit: int | None = None) -> str:
    try:
        missing = x is None or (not isinstance(x, (list, dict, tuple, set)) and bool(pd.isna(x)))
    except (TypeError, ValueError):
        missing = False
    s = "" if missing else _ascii_punct(str(x))
    if limit and len(s) > limit:
        s = s[: limit - 3] + "..."
    return escape(s.encode("latin-1", "replace").decode("latin-1"))


def _eff(inc, ctx):
    v = ctx.verdicts.get(inc.incident_id, {})
    ov = v.get("confidence_override")
    return (ov if ov is not None else inc.confidence), v.get("verdict", "Unreviewed"), ov is not None


def _label(score: int) -> str:
    return "High" if score >= 70 else "Medium" if score >= 40 else "Low"


def _styles():
    ss = getSampleStyleSheet()
    base = ParagraphStyle("body", parent=ss["BodyText"], fontName="Helvetica", fontSize=9, leading=12.5, textColor=colors.HexColor("#1e293b"), alignment=TA_LEFT)
    return {
        "body": base,
        "small": ParagraphStyle("small", parent=base, fontSize=7.5, leading=10, textColor=SLATE),
        "cell": ParagraphStyle("cell", parent=base, fontSize=7.5, leading=9.5),
        "cellb": ParagraphStyle("cellb", parent=base, fontSize=7.5, leading=9.5, fontName="Helvetica-Bold"),
        "hdr": ParagraphStyle("hdr", parent=base, fontSize=7.5, leading=9.5, fontName="Helvetica-Bold", textColor=colors.white),
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=NAVY, spaceBefore=6, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=ACCENT, spaceBefore=8, spaceAfter=3, keepWithNext=1),
        "bullet": ParagraphStyle("bullet", parent=base, leftIndent=10, bulletIndent=0, spaceAfter=2),
    }


def _table(data, widths, header=True, extra=None):
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
             ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                  ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT])]
    t.setStyle(TableStyle(style + (extra or [])))
    return t


def _sev_chip(sev: str, st) -> Paragraph:
    return Paragraph(f'<font color="{SEVERITY_COLORS[sev]}"><b>{sev.upper()}</b></font>', st["cell"])


def _timeline_chart(ctx: ReportContext) -> io.BytesIO | None:
    f = ctx.findings
    if f.empty:
        return None
    fig, ax = plt.subplots(figsize=(7.4, 2.9), dpi=170)
    rows = [t for t in TACTIC_ORDER if t in set(f["tactic"])]
    for _, r in f.iterrows():
        if r["tactic"] not in rows:
            continue
        y = rows.index(r["tactic"])
        ax.scatter(r["start"], y, s=40 + 14 * min(r["count"], 30), color=SEVERITY_COLORS[r["severity"]], alpha=0.85, edgecolor="white", linewidth=0.6, zorder=3)
    ax.set_yticks(range(len(rows)), ["IOC match" if r == "Threat Intel Match" else r for r in rows], fontsize=7)
    ax.invert_yaxis()
    ax.grid(axis="x", color="#e2e8f0", zorder=0)
    ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%m-%d %H:%M"))
    ax.tick_params(axis="x", labelsize=6.5, rotation=20)
    ax.set_title("Findings over time by ATT&CK tactic (marker size = evidence events)", fontsize=8, loc="left")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    handles = [plt.Line2D([], [], marker="o", ls="", color=SEVERITY_COLORS[s], label=s) for s in ("low", "medium", "high", "critical")]
    ax.legend(handles=handles, fontsize=6.5, frameon=False, loc="upper left", bbox_to_anchor=(1.0, 1.0))
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    buf.seek(0)
    return buf


# ============================================================================== document structure helpers
TLP_COLORS = {"TLP:CLEAR": "#FFFFFF", "TLP:GREEN": "#33FF00", "TLP:AMBER": "#FFC000", "TLP:AMBER+STRICT": "#FFC000", "TLP:RED": "#FF2B2B"}
TLP_HANDLING = {
    "TLP:CLEAR": "Disclosure is not limited. May be distributed without restriction, subject to standard copyright rules.",
    "TLP:GREEN": "Limited disclosure. Recipients may share within their community or organisation, but not publicly.",
    "TLP:AMBER": "Limited disclosure. Recipients may share only within their organisation and with clients who need to know.",
    "TLP:AMBER+STRICT": "Limited disclosure. Recipients may share only within their own organisation, not with clients.",
    "TLP:RED": "Not for disclosure. Restricted to the named recipients only.",
}
TACTIC_LABEL = {"Threat Intel Match": "IOC match"}
PHASES = ("Immediate containment", "Investigation and scoping", "Recovery and hardening")
_PHASE_BY_VERB = {
    "block": 0, "isolate": 0, "disable": 0, "revoke": 0, "rate-limit": 0, "force": 0, "treat": 0, "suspend": 0, "quarantine": 0,
    "scope": 1, "identify": 1, "collect": 1, "hunt": 1, "verify": 1, "review": 1, "confirm": 1, "preserve": 1, "search": 1, "check": 1, "determine": 1, "contact": 1,
    "restore": 2, "enable": 2, "enforce": 2, "patch": 2, "reset": 2, "restrict": 2, "switch": 2, "rotate": 2, "harden": 2, "deploy": 2, "limit": 2,
}
SEVERITY_DEFINITIONS = [
    ("Critical", "Activity consistent with an active, multi-stage compromise. Raised automatically when an incident spans three or more ATT&CK tactics and contains at least one High finding. Respond immediately."),
    ("High", "Likely malicious activity that should be investigated promptly."),
    ("Medium", "Suspicious activity that needs validation; may be benign."),
    ("Low / Info", "Weak signal or context. Usually benign on its own."),
]


def _cell(x) -> str:
    """Escaped text for a table cell; empty or missing values show as a dash instead of <NA>."""
    return _t(x) or "-"


def _tactic_label(t: str) -> str:
    return TACTIC_LABEL.get(t, t)


def _when(start, end, fmt_time: str = "%H:%M") -> str:
    """Window text that never drops the date of the end time."""
    if start.date() == end.date():
        return f"{start:%Y-%m-%d} {start:{fmt_time}} to {end:{fmt_time}} UTC"
    return f"{start:%Y-%m-%d} {start:{fmt_time}} to {end:%Y-%m-%d} {end:{fmt_time}} UTC"


def report_id(ctx: "ReportContext") -> str:
    digest = hashlib.sha256(("|".join(sorted(q.sha256 for q in ctx.quality)) + "|" + ctx.case_name).encode("utf-8")).hexdigest()[:8].upper()
    return f"TF-{ctx.generated:%Y%m%d}-{digest}"


def report_status(ctx: "ReportContext") -> tuple[str, list[str]]:
    """FINAL only when every incident has an analyst verdict and the integrity checks are clean."""
    reasons = []
    unrev = [i.incident_id for i in ctx.incidents if ctx.verdicts.get(i.incident_id, {}).get("verdict", "Unreviewed") == "Unreviewed"]
    if unrev:
        reasons.append(f"{len(unrev)} of {len(ctx.incidents)} incident(s) have no analyst verdict ({', '.join(unrev[:6])}{'...' if len(unrev) > 6 else ''}).")
    if ctx.integrity and not ctx.integrity.get("ok", True):
        reasons.append("The evidence integrity check failed for one or more files.")
    if ctx.audit and not ctx.audit.get("chain_ok", True):
        reasons.append("The audit log hash chain is broken.")
    return ("DRAFT" if reasons else "FINAL"), reasons


def _phase(step: str) -> int:
    verb = step.split(" ", 1)[0].strip(".,:;").lower()
    return _PHASE_BY_VERB.get(verb, 1)


def _phased(steps: list[str]) -> list[tuple[str, list[str]]]:
    out: list[list[str]] = [[], [], []]
    for s in steps:
        out[_phase(s)].append(s)
    return [(PHASES[i], v) for i, v in enumerate(out) if v]


def _summary_lines(inc) -> list[str]:
    """Overview and kill-chain progression only; the per-event narrative is already in the timeline table."""
    lines = inc.summary if isinstance(inc.summary, list) else [str(inc.summary or "")]
    keep = [lines[0]] if lines and lines[0] else []
    if len(lines) > 1 and lines[1].startswith("Observed kill-chain"):
        keep.append(lines[1])
    return [x.replace("Threat Intel Match", "IOC match") for x in keep]


def _narr_rows(inc) -> list[tuple[str, str, str, str]]:
    rows = []
    for line in inc.narrative:
        ts, tactic, _, summary_ref = [p.strip() for p in line.split("|", 3)]
        summary, ref = summary_ref.rsplit(" [", 1)
        rows.append((ts, _tactic_label(tactic), summary, ref.rstrip("]")))
    return rows


def _detail(e) -> str:
    def s(k):
        v = e[k]
        return "" if v is None or (not isinstance(v, str) and pd.isna(v)) else str(v)
    if s("command"):
        return "cmd: " + s("command")
    if s("url"):
        return s("url") + (f" [{int(e['status_code'])}]" if pd.notna(e["status_code"]) else "")
    if s("message"):
        return s("message")
    if s("dst_ip") or pd.notna(e["dst_port"]):
        port = f":{int(e['dst_port'])}" if pd.notna(e["dst_port"]) else ""
        return f"to {s('dst_ip')}{port}"
    return ""


def _finding_incident_map(ctx: "ReportContext") -> dict[str, str]:
    return {fid: i.incident_id for i in ctx.incidents for fid in i.finding_ids}


def key_observations(ctx: "ReportContext") -> list[dict]:
    """One factual line per ATT&CK tactic observed: the most severe finding's own summary plus how many more there are."""
    f = ctx.findings
    if f.empty:
        return []
    order = [t for t in TACTIC_ORDER if t != "Threat Intel Match" and t in set(f["tactic"])] + sorted(set(f["tactic"]) - set(TACTIC_ORDER))
    out = []
    for tactic in order:
        g = f[f["tactic"] == tactic].copy()
        g["rank"] = g["severity"].map(SEVERITY_ORDER)
        top = g.sort_values(["rank", "start"], ascending=[False, True]).iloc[0]
        more = len(g) - 1
        out.append({"tactic": tactic, "severity": top["severity"], "text": top["summary"] + (f" (+{more} more {tactic.lower()} finding{'s' if more > 1 else ''})" if more else ""),
                    "refs": ", ".join(g["finding_id"].head(4)) + ("..." if len(g) > 4 else "")})
    return out


def affected_assets(ctx: "ReportContext") -> list[dict]:
    """Accounts, hosts and addresses that appear in incident entities, with how many incident events involve each."""
    if not ctx.incidents or ctx.events.empty:
        return []
    ev = ctx.events[ctx.events["event_id"].isin({e for i in ctx.incidents for e in i.event_ids})]
    ips = pd.concat([ev["src_ip"], ev["dst_ip"]]).dropna().astype(str)
    counts = {"user": ev["user"].dropna().astype(str).value_counts(), "host": ev.loc[ev["host"] != "", "host"].astype(str).value_counts(), "ip": ips.value_counts()}
    rows = []
    for kind in ("user", "host", "ip"):
        mentioned: dict[str, list[str]] = {}
        for i in ctx.incidents:
            for v in i.entities.get(kind, []):
                mentioned.setdefault(v, []).append(i.incident_id)
        for v, incs in mentioned.items():
            label = {"user": "Account", "host": "Host"}.get(kind) or ("Internal IP" if is_internal(v) else "External IP")
            rows.append({"type": label, "value": v, "incidents": ", ".join(incs), "events": int(counts[kind].get(v, 0))})
    order = {"Account": 0, "Host": 1, "Internal IP": 2, "External IP": 3}
    rows.sort(key=lambda r: (order[r["type"]], -r["events"], r["value"]))
    return rows


def _techniques(ctx: "ReportContext") -> list[dict]:
    seen: dict[str, dict] = {}
    for _, f in ctx.findings.iterrows():
        for t in re.findall(r"T\d{4}(?:\.\d{3})?", str(f["technique"])):
            d = seen.setdefault(t, {"id": t, "name": TECHNIQUE_NAMES.get(t, ""), "tactics": set(), "findings": 0})
            d["findings"] += 1
            d["tactics"].add(_tactic_label(f["tactic"]))
    return [dict(v, tactics=", ".join(sorted(v["tactics"]))) for _, v in sorted(seen.items())]


def _methodology(ctx: "ReportContext") -> list[str]:
    fired = sorted({RULES[r]["name"] for r in ctx.findings["rule_id"].unique() if r in RULES and r != "sigma_match"}) if len(ctx.findings) else []
    enabled = ctx.rules_enabled if ctx.rules_enabled is not None else [r for r in RULES if r != "sigma_match"]
    builtin = len([r for r in RULES if r != "sigma_match"])
    text = [
        "Pipeline: import (CSV, JSON/NDJSON, text logs, Windows Event XML and Sysmon, Zeek, AWS CloudTrail, ZIP/gzip bundles) > normalise timestamps to UTC, IP addresses, usernames and event types > rule-based detection > correlation of findings that share an IP, account or host within a configurable time gap > transparent scoring.",
        "TraceForge analyses only the files supplied. It is not a live SIEM and does not claim to detect attacks that are absent from the evidence or that no enabled rule covers.",
        "Timestamps without a timezone are interpreted as UTC. Rows without a parseable timestamp are dropped and counted, never guessed. No GeoIP or threat-intelligence feeds are queried; IOC matching uses only indicators recorded by the analyst.",
        "Severity and confidence are heuristics. A finding can be a false positive (for example a user on a mobile hotspot); the analyst verdict recorded in this report takes precedence.",
        f"Built-in rules enabled: {len([r for r in enabled if r != 'sigma_match'])} of {builtin}. Rules that produced findings in this run: {', '.join(fired) if fired else 'none'}.",
    ]
    if ctx.sigma_titles:
        text.append(f"Imported Sigma rules ({len(ctx.sigma_titles)}): " + "; ".join(ctx.sigma_titles[:15]) + (" ..." if len(ctx.sigma_titles) > 15 else "") + ".")
    return text


def executive_points(ctx: ReportContext) -> list[str]:
    ev, inc = ctx.events, ctx.incidents
    pts = []
    if len(ev):
        pts.append(f"{len(ev):,} events from {ev['source'].nunique()} source(s) were analysed, covering {_when(ev['timestamp'].min(), ev['timestamp'].max())}.")
    if inc:
        counts = {s: sum(1 for i in inc if i.severity == s) for s in ("critical", "high", "medium", "low")}
        pts.append(f"{len(ctx.findings)} rule finding(s) were correlated into {len(inc)} incident(s): " + ", ".join(f"{n} {s}" for s, n in counts.items() if n) + ".")
        top = inc[0]
        score, verdict, ov = _eff(top, ctx)
        real = [_tactic_label(t) for t in top.tactics if t != "Threat Intel Match"]
        pts.append(f"Highest priority: {top.incident_id} - {top.title}. Window {_when(top.start, top.end)}; ATT&CK tactics observed: {', '.join(real) or 'none'}; "
                   f"confidence {_label(score)} ({score}/100{', analyst override' if ov else ''}); analyst verdict: {verdict}.")
    else:
        pts.append("No rule findings were produced from the imported evidence; this does not prove the absence of malicious activity.")
    pts.append(f"{len(ctx.iocs)} indicator(s) of compromise are recorded for this case.")
    return pts


# ============================================================================== PDF
class _NumberedCanvas(rl_canvas.Canvas):
    """Two-pass canvas so every page can say 'Page X of Y'."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._saved: list[dict] = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self.setFont("Helvetica", 7)
            self.setFillColor(SLATE)
            self.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {self._pageNumber} of {total}")
            super().showPage()
        super().save()


class _Doc(SimpleDocTemplate):
    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name in ("h1", "inc"):
            self.notify("TOCEntry", (0 if flowable.style.name == "h1" else 1, escape(flowable.getPlainText()), self.page))


def _tlp_badge(canvas, x: float, y: float, label: str, align: str = "left") -> None:
    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 8)
    w = canvas.stringWidth(label, "Helvetica-Bold", 8) + 10
    x0 = x - w if align == "right" else x
    canvas.setFillColor(colors.black)
    canvas.roundRect(x0, y - 3, w, 12, 2, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor(TLP_COLORS.get(label, "#FFFFFF")))
    canvas.drawString(x0 + 5, y, label)
    canvas.restoreState()


def _page(canvas, doc, ctx, status: str, rid: str):
    canvas.saveState()
    w, h = A4
    if status == "DRAFT":
        canvas.saveState()
        canvas.setFillColor(colors.Color(0.55, 0.55, 0.6))
        canvas.setFillAlpha(0.08)
        canvas.setFont("Helvetica-Bold", 110)
        canvas.translate(w / 2, h / 2)
        canvas.rotate(40)
        canvas.drawCentredString(0, 0, "DRAFT")
        canvas.restoreState()
    if doc.page == 1:
        canvas.setFillColor(NAVY)
        canvas.rect(0, h - 78 * mm, w, 78 * mm, fill=1, stroke=0)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, h - 80 * mm, w, 2 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 28)
        canvas.drawString(20 * mm, h - 36 * mm, "TraceForge")
        canvas.setFont("Helvetica", 13)
        canvas.drawString(20 * mm, h - 46 * mm, "Incident Reconstruction & IOC Correlation Report")
        canvas.setFont("Helvetica", 9)
        canvas.drawString(20 * mm, h - 58 * mm, f"Case: {_plain(ctx.case_name)}")
        canvas.drawString(20 * mm, h - 64 * mm, f"Analyst: {_plain(ctx.analyst)}" + (f"  |  {_plain(ctx.organization)}" if ctx.organization else ""))
        canvas.drawString(20 * mm, h - 70 * mm, f"Report ID: {rid}  |  Generated: {ctx.generated:%Y-%m-%d %H:%M} UTC")
        _tlp_badge(canvas, w - 20 * mm, h - 36 * mm, ctx.tlp, "right")
    else:
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(SLATE)
        canvas.drawString(18 * mm, h - 11 * mm, f"TraceForge incident report - {_plain(ctx.case_name)}  |  {rid}  |  {status}")
        _tlp_badge(canvas, w - 18 * mm, h - 11.5 * mm, ctx.tlp, "right")
        canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
        canvas.line(18 * mm, h - 14 * mm, w - 18 * mm, h - 14 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(SLATE)
    canvas.drawString(18 * mm, 10 * mm, f"Generated by TraceForge v{__version__} from imported evidence only. Findings require analyst validation.")
    _tlp_badge(canvas, w / 2 + 38 * mm, 14.2 * mm, ctx.tlp)
    canvas.restoreState()


def _plain(x) -> str:
    return _ascii_punct(str(x)).encode("latin-1", "replace").decode("latin-1")


def build_pdf(ctx: ReportContext) -> bytes:
    st = _styles()
    st["h1x"] = ParagraphStyle("h1x", parent=st["h1"])
    st["inc"] = ParagraphStyle("inc", parent=st["h1"], fontSize=13, leading=17, spaceBefore=4)
    buf = io.BytesIO()
    status, reasons = report_status(ctx)
    rid = report_id(ctx)
    doc = _Doc(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm, bottomMargin=19 * mm,
               title=f"TraceForge - {ctx.case_name}", author=ctx.analyst, subject=f"{rid} {ctx.tlp}")
    W = A4[0] - 36 * mm

    # ------------------------------------------------------------------ cover: document control, status, handling, contents
    s: list = [Spacer(1, 66 * mm)]
    ctl = [[Paragraph("Report ID", st["cellb"]), Paragraph(rid, st["cell"]), Paragraph("Status", st["cellb"]), Paragraph(f"<b>{status}</b>", st["cell"])],
           [Paragraph("Case", st["cellb"]), Paragraph(_cell(ctx.case_name), st["cell"]), Paragraph("Classification", st["cellb"]), Paragraph(_cell(ctx.tlp), st["cell"])],
           [Paragraph("Prepared by", st["cellb"]), Paragraph(_cell(ctx.analyst) + (f", {_t(ctx.organization)}" if ctx.organization else ""), st["cell"]),
            Paragraph("Generated", st["cellb"]), Paragraph(f"{ctx.generated:%Y-%m-%d %H:%M} UTC", st["cell"])],
           [Paragraph("Tool", st["cellb"]), Paragraph(f"TraceForge v{__version__}", st["cell"]), Paragraph("Evidence", st["cellb"]),
            Paragraph(f"{len(ctx.quality)} file(s); SHA-256 listed in section 2", st["cell"])],
           [Paragraph("Redaction", st["cellb"]), Paragraph(_cell(ctx.redaction or "None applied"), st["cell"]), "", ""]]
    s.append(_table(ctl, [24 * mm, W / 2 - 24 * mm, 24 * mm, W / 2 - 24 * mm], header=False,
                    extra=[("BACKGROUND", (0, 0), (0, -1), LIGHT), ("BACKGROUND", (2, 0), (2, -3), LIGHT), ("SPAN", (1, 4), (3, 4))]))
    s.append(Spacer(1, 6))
    banner_col = colors.HexColor("#fff4d6") if status == "DRAFT" else colors.HexColor("#dcfce7")
    msg = ("<b>DRAFT - not reviewed.</b> " + " ".join(_t(r) for r in reasons)) if status == "DRAFT" else "<b>FINAL.</b> Every incident has an analyst verdict and all integrity checks passed."
    s.append(_table([[Paragraph(msg, st["body"])]], [W], header=False, extra=[("BACKGROUND", (0, 0), (-1, -1), banner_col)]))
    s.append(Spacer(1, 6))
    s.append(Paragraph(f"<b>Handling ({_t(ctx.tlp)}).</b> {_t(TLP_HANDLING.get(ctx.tlp, ''))}", st["body"]))
    s.append(Spacer(1, 8))
    s.append(Paragraph("Contents", st["h1x"]))
    toc = TableOfContents()
    toc.levelStyles = [ParagraphStyle("toc0", fontName="Helvetica-Bold", fontSize=9, leading=13), ParagraphStyle("toc1", fontName="Helvetica", fontSize=8.5, leading=12, leftIndent=12)]
    s.append(toc)

    # ------------------------------------------------------------------ 1. executive summary
    s += [PageBreak(), Paragraph("1. Executive summary", st["h1"])]
    sev_top = max((i.severity for i in ctx.incidents), key=lambda x: SEVERITY_ORDER[x]) if ctx.incidents else "none"
    ev = ctx.events
    period = _when(ev["timestamp"].min(), ev["timestamp"].max()) if len(ev) else "-"
    real_tactics = {t for t in ctx.findings["tactic"] if t in TACTIC_ORDER and t != "Threat Intel Match"} if len(ctx.findings) else set()
    glance = [[Paragraph("Highest severity", st["cellb"]), _sev_chip(sev_top, st) if sev_top != "none" else Paragraph("none", st["cell"]),
               Paragraph("Incidents / findings", st["cellb"]), Paragraph(f"{len(ctx.incidents)} / {len(ctx.findings)}", st["cell"])],
              [Paragraph("Events analysed", st["cellb"]), Paragraph(f"{len(ev):,} from {ev['source'].nunique() if len(ev) else 0} source(s)", st["cell"]),
               Paragraph("ATT&amp;CK tactics observed", st["cellb"]), Paragraph(str(len(real_tactics)), st["cell"])],
              [Paragraph("Evidence period", st["cellb"]), Paragraph(period, st["cell"]), Paragraph("IOCs recorded", st["cellb"]), Paragraph(str(len(ctx.iocs)), st["cell"])]]
    s.append(_table(glance, [32 * mm, W / 2 - 32 * mm, 38 * mm, W / 2 - 38 * mm], header=False, extra=[("BACKGROUND", (0, 0), (0, -1), LIGHT), ("BACKGROUND", (2, 0), (2, -1), LIGHT)]))
    if ctx.incidents:
        top = ctx.incidents[0]
        sc, vd, ov = _eff(top, ctx)
        s.append(Paragraph(f"Highest priority is <b>{top.incident_id}</b> - {_t(top.title)} (confidence {_label(sc)}, {sc}/100{', analyst override' if ov else ''}; verdict: {_t(vd)}).", st["body"]))
    obs = key_observations(ctx)
    if obs:
        s.append(Paragraph("Key observations", st["h2"]))
        rows = [[Paragraph(h, st["hdr"]) for h in ("Stage (ATT&amp;CK tactic)", "Severity", "What was observed", "Refs")]]
        for o in obs:
            rows.append([Paragraph(_t(o["tactic"]), st["cellb"]), _sev_chip(o["severity"], st), Paragraph(_t(o["text"], 230), st["cell"]), Paragraph(_t(o["refs"]), st["cell"])])
        s.append(_table(rows, [30 * mm, 17 * mm, W - 30 * mm - 17 * mm - 26 * mm, 26 * mm]))
    else:
        s.append(Paragraph("No rule findings were produced from the imported evidence. This does not prove the absence of malicious activity.", st["body"]))
    if ctx.incidents:
        s.append(Paragraph("Incident overview", st["h2"]))
        rows = [[Paragraph(h, st["hdr"]) for h in ("Incident", "Severity", "Confidence", "Window (UTC)", "Verdict", "Title")]]
        for i in ctx.incidents:
            sc, vd, _ = _eff(i, ctx)
            a, b = (f"{i.start:%Y-%m-%d %H:%M}", f"{i.end:%Y-%m-%d %H:%M}")
            rows.append([Paragraph(i.incident_id, st["cellb"]), _sev_chip(i.severity, st), Paragraph(f"{_label(sc)} ({sc})", st["cell"]),
                         Paragraph(f"{a}<br/>to {b}", st["cell"]), Paragraph(_t(vd), st["cell"]), Paragraph(_t(i.title, 90), st["cell"])])
        s.append(_table(rows, [17 * mm, 17 * mm, 20 * mm, 30 * mm, 22 * mm, W - 106 * mm]))
    chart = _timeline_chart(ctx)
    if chart:
        s += [Spacer(1, 8), Image(chart, width=W, height=W * 2.9 / 7.4)]

    # ------------------------------------------------------------------ 2. scope and evidence integrity
    s += [PageBreak(), Paragraph("2. Scope and evidence integrity", st["h1"]),
          Paragraph("SHA-256 hashes identify the exact files analysed. Rows without a parseable timestamp are dropped, never guessed.", st["body"]), Spacer(1, 4)]
    rows = [[Paragraph(h, st["hdr"]) for h in ("File", "SHA-256", "Rows read", "Kept", "Bad time", "Bad IP")]]
    for q in ctx.quality:
        rows.append([Paragraph(_t(q.filename, 30), st["cell"]), Paragraph(f'<font face="Courier" size="6.2">{q.sha256}</font>', st["cell"]),
                     str(q.rows_read), str(q.rows_kept), str(q.bad_timestamp), str(q.invalid_ips)])
    s.append(_table(rows, [30 * mm, W - 30 * mm - 56 * mm, 14 * mm, 14 * mm, 14 * mm, 14 * mm]))
    s.append(Paragraph("Field mapping detected per file", st["h2"]))
    for q in ctx.quality:
        mp = ", ".join(f"{k} &lt;- {_t(v)}" for k, v in q.mapped_fields.items())
        s.append(Paragraph(f"<b>{_t(q.filename)}</b>: {mp}", st["small"]))
    s.append(Paragraph("Integrity and audit status", st["h2"]))
    for line in integrity_lines(ctx) or ["No integrity information was recorded for this report."]:
        s.append(Paragraph(_t(line), st["small"]))

    # ------------------------------------------------------------------ 3. affected assets
    assets = affected_assets(ctx)
    s += [Paragraph("3. Affected assets", st["h1"])]
    if assets:
        rows = [[Paragraph(h, st["hdr"]) for h in ("Type", "Entity", "Incidents", "Events")]]
        shown = 0
        per_type: dict[str, int] = {}
        for a in assets:
            per_type[a["type"]] = per_type.get(a["type"], 0) + 1
            if per_type[a["type"]] > 12:
                continue
            shown += 1
            rows.append([Paragraph(a["type"], st["cell"]), Paragraph(f'<font face="Courier" size="7">{_t(a["value"], 60)}</font>', st["cell"]), Paragraph(_t(a["incidents"]), st["cell"]), str(a["events"])])
        s.append(_table(rows, [26 * mm, W - 26 * mm - 48 * mm, 30 * mm, 18 * mm]))
        if shown < len(assets):
            s.append(Paragraph(f"{len(assets) - shown} further entities are listed in the incident sections.", st["small"]))
    else:
        s.append(Paragraph("No entities were associated with incidents.", st["body"]))

    # ------------------------------------------------------------------ 4. incident analysis
    s += [PageBreak(), Paragraph("4. Incident analysis", st["h1"])]
    if not ctx.incidents:
        s.append(Paragraph("No incidents to report.", st["body"]))
    for n, inc in enumerate(ctx.incidents):
        if n:
            s.append(PageBreak() if len(ctx.incidents[n - 1].finding_ids) >= 4 else Spacer(1, 14))
        sc, vd, ov = _eff(inc, ctx)
        s.append(Paragraph(f"4.{n + 1} {inc.incident_id} - {_t(inc.title)}", st["inc"]))
        for line in _summary_lines(inc):
            s.append(Paragraph(_t(line), st["body"]))
        s.append(Spacer(1, 3))
        ents = inc.entities
        info = [[Paragraph("Severity", st["cellb"]), _sev_chip(inc.severity, st), Paragraph("Confidence", st["cellb"]), Paragraph(f"{_label(sc)} ({sc}/100){' - analyst override' if ov else ''}", st["cell"])],
                [Paragraph("Window", st["cellb"]), Paragraph(_when(inc.start, inc.end, "%H:%M:%S"), st["cell"]), Paragraph("Verdict", st["cellb"]), Paragraph(_cell(vd), st["cell"])],
                [Paragraph("IP addresses", st["cellb"]), Paragraph(_cell(", ".join(ents["ip"][:8]) + (" ..." if len(ents["ip"]) > 8 else "")), st["cell"]),
                 Paragraph("Accounts", st["cellb"]), Paragraph(_cell(", ".join(ents["user"][:8])), st["cell"])],
                [Paragraph("Hosts", st["cellb"]), Paragraph(_cell(", ".join(ents["host"][:8])), st["cell"]), Paragraph("ATT&amp;CK", st["cellb"]), Paragraph(_cell(", ".join(inc.techniques)), st["cell"])],
                [Paragraph("Log sources", st["cellb"]), Paragraph(_cell(", ".join(inc.sources)), st["cell"]), Paragraph("Evidence", st["cellb"]), Paragraph(f"{len(inc.event_ids)} events, {len(inc.finding_ids)} findings", st["cell"])]]
        s.append(_table(info, [24 * mm, W / 2 - 24 * mm, 22 * mm, W / 2 - 22 * mm], header=False, extra=[("BACKGROUND", (0, 0), (0, -1), LIGHT), ("BACKGROUND", (2, 0), (2, -1), LIGHT)]))

        s.append(Paragraph("Reconstructed timeline", st["h2"]))
        rows = [[Paragraph(h, st["hdr"]) for h in ("Time (UTC)", "Stage", "Observation", "Ref")]]
        for ts, tactic, summary, ref in _narr_rows(inc):
            rows.append([Paragraph(ts[:10] + "<br/>" + ts[11:19], st["cell"]), Paragraph(_t(tactic), st["cell"]), Paragraph(_t(summary), st["cell"]), Paragraph(_t(ref), st["cell"])])
        s.append(_table(rows, [20 * mm, 26 * mm, W - 20 * mm - 26 * mm - 12 * mm, 12 * mm]))

        s.append(Paragraph("Why this confidence score", st["h2"]))
        rows = [[Paragraph(h, st["hdr"]) for h in ("Factor", "Points")]] + [[Paragraph(_t(t), st["cell"]), f"{p:+d}"] for t, p in inc.confidence_factors]
        s.append(_table(rows, [W - 20 * mm, 20 * mm]))
        s.append(Paragraph("Heuristic score, not a probability. Treat it as a prompt for validation.", st["small"]))

        s.append(Paragraph("Supporting evidence (first 25 events)", st["h2"]))
        evs = ctx.events[ctx.events["event_id"].isin(inc.event_ids)].sort_values("timestamp")
        multi_day = len(evs) and evs["timestamp"].dt.date.nunique() > 1
        rows = [[Paragraph(h, st["hdr"]) for h in ("Event", "Time (UTC)", "Type", "Source IP", "Account", "Host", "Detail")]]
        for _, e in evs.head(25).iterrows():
            when = f"{e['timestamp']:%m-%d %H:%M:%S}" if multi_day else f"{e['timestamp']:%H:%M:%S}"
            rows.append([Paragraph(e["event_id"], st["cell"]), Paragraph(when, st["cell"]), Paragraph(_cell(e["event_type"]), st["cell"]), Paragraph(_cell(e["src_ip"]), st["cell"]),
                         Paragraph(_cell(e["user"]), st["cell"]), Paragraph(_cell(e["host"]), st["cell"]), Paragraph(_cell(_t(_detail(e), 90) and _detail(e)[:90]), st["cell"])])
        s.append(_table(rows, [15 * mm, 22 * mm if multi_day else 15 * mm, 21 * mm, 24 * mm, 16 * mm, 14 * mm, W - (15 + (22 if multi_day else 15) + 21 + 24 + 16 + 14) * mm]))
        if len(evs) > 25:
            s.append(Paragraph(f"{len(evs) - 25} further events are listed in the evidence CSV export.", st["small"]))

        notes = ctx.notes[ctx.notes["incident_id"] == inc.incident_id] if len(ctx.notes) else ctx.notes
        if len(notes):
            s.append(Paragraph("Analyst notes", st["h2"]))
            for _, nrow in notes.iterrows():
                s.append(Paragraph(f"<b>{_t(nrow['created_utc'])} - {_t(nrow['author'])}:</b> {_t(nrow['note'])}", st["body"]))

        s.append(Paragraph("Response actions", st["h2"]))
        rows, extra = [[Paragraph(h, st["hdr"]) for h in ("Action", "Owner", "Done")]], []
        for phase, steps in _phased(inc.remediation):
            extra += [("SPAN", (0, len(rows)), (-1, len(rows))), ("BACKGROUND", (0, len(rows)), (-1, len(rows)), colors.HexColor("#e0f2fe"))]
            rows.append([Paragraph(f"<b>{_t(phase)}</b>", st["cell"]), "", ""])
            rows += [[Paragraph(_t(x), st["cell"]), "", Paragraph("[  ]", st["cell"])] for x in steps]
        s.append(_table(rows, [W - 52 * mm, 34 * mm, 18 * mm], extra=extra))

    # ------------------------------------------------------------------ 5. IOCs
    s += [PageBreak(), Paragraph("5. Indicators of compromise", st["h1"])]
    if len(ctx.iocs):
        rows = [[Paragraph(h, st["hdr"]) for h in ("Type", "Value", "Source", "Note", "Added (UTC)")]]
        for _, r in ctx.iocs.iterrows():
            rows.append([Paragraph(_cell(r["ioc_type"]), st["cell"]), Paragraph(f'<font face="Courier" size="7">{_t(r["value"], 90)}</font>', st["cell"]),
                         Paragraph(_cell(r["source"]), st["cell"]), Paragraph(_cell(_t(r["note"], 80)), st["cell"]), Paragraph(_cell(r["added_utc"]), st["cell"])])
        s.append(_table(rows, [16 * mm, 56 * mm, 20 * mm, W - 16 * mm - 56 * mm - 20 * mm - 28 * mm, 28 * mm]))
    else:
        s.append(Paragraph("No IOCs were recorded for this case.", st["body"]))
    s.append(Paragraph("Candidate indicators suggested by incidents (not yet recorded)", st["h2"]))
    recorded = set(ctx.iocs["value"].str.lower()) if len(ctx.iocs) else set()
    cands = {(c["ioc_type"], c["value"]): c["note"] for i in ctx.incidents for c in i.ioc_candidates if c["value"].lower() not in recorded}
    if cands:
        for (t, v), note in list(cands.items())[:20]:
            s.append(Paragraph(f'{_t(t)}: <font face="Courier">{_t(v)}</font> - {_t(note)}', st["bullet"], bulletText="-"))
    else:
        s.append(Paragraph("None outstanding.", st["body"]))

    # ------------------------------------------------------------------ appendices
    s += [PageBreak(), Paragraph("Appendix A. Findings register", st["h1"])]
    if len(ctx.findings):
        imap = _finding_incident_map(ctx)
        rows = [[Paragraph(h, st["hdr"]) for h in ("ID", "Start (UTC)", "Rule and observation", "Severity", "ATT&amp;CK", "Events", "Incident")]]
        for _, f in ctx.findings.sort_values("start").iterrows():
            rows.append([Paragraph(f["finding_id"], st["cellb"]), Paragraph(f"{f['start']:%Y-%m-%d}<br/>{f['start']:%H:%M:%S}", st["cell"]),
                         Paragraph(f"<b>{_t(f['rule_name'])}</b><br/>{_t(f['summary'], 120)}", st["cell"]), _sev_chip(f["severity"], st),
                         Paragraph(_cell(f["technique"]), st["cell"]), str(int(f["count"])), Paragraph(imap.get(f["finding_id"], "-"), st["cell"])])
        s.append(_table(rows, [13 * mm, 20 * mm, W - 13 * mm - 20 * mm - 17 * mm - 28 * mm - 12 * mm - 16 * mm, 17 * mm, 28 * mm, 12 * mm, 16 * mm]))
    else:
        s.append(Paragraph("No findings.", st["body"]))
    techs = _techniques(ctx)
    s.append(Paragraph("Appendix B. MITRE ATT&amp;CK techniques observed", st["h1"]))
    if techs:
        rows = [[Paragraph(h, st["hdr"]) for h in ("Technique", "Name", "Stage", "Findings")]] + \
               [[Paragraph(t["id"], st["cellb"]), Paragraph(_cell(t["name"]), st["cell"]), Paragraph(_cell(t["tactics"]), st["cell"]), str(t["findings"])] for t in techs]
        s.append(_table(rows, [24 * mm, W - 24 * mm - 50 * mm - 18 * mm, 50 * mm, 18 * mm]))
    else:
        s.append(Paragraph("No techniques were mapped.", st["body"]))
    s.append(Paragraph("Appendix C. Methodology, definitions and limitations", st["h1"]))
    for m in _methodology(ctx):
        s.append(Paragraph(_t(m), st["bullet"], bulletText="-"))
    s.append(Paragraph("Severity (indicative meaning)", st["h2"]))
    s.append(_table([[Paragraph(h, st["hdr"]) for h in ("Level", "Meaning")]] + [[Paragraph(f"<b>{a}</b>", st["cell"]), Paragraph(_t(b), st["cell"])] for a, b in SEVERITY_DEFINITIONS], [26 * mm, W - 26 * mm]))
    s.append(Paragraph("Confidence", st["h2"]))
    s.append(Paragraph("A heuristic score from 5 to 95 built from the factors listed under each incident: High is 70 or more, Medium 40 to 69, Low below 40. It reflects how much independent evidence supports the finding, not the probability that it is malicious.", st["body"]))
    s.append(Paragraph("Sign-off", st["h2"]))
    sign = [[Paragraph(h, st["hdr"]) for h in ("Role", "Name", "Signature", "Date")],
            [Paragraph("Prepared by", st["cell"]), Paragraph(_cell(ctx.analyst), st["cell"]), "", ""], [Paragraph("Reviewed by", st["cell"]), "", "", ""], [Paragraph("Approved by", st["cell"]), "", "", ""]]
    s.append(_table(sign, [30 * mm, 55 * mm, W - 30 * mm - 55 * mm - 28 * mm, 28 * mm], extra=[("TOPPADDING", (0, 1), (-1, -1), 9), ("BOTTOMPADDING", (0, 1), (-1, -1), 9)]))
    doc.multiBuild(s, canvasmaker=_NumberedCanvas, onFirstPage=lambda c, d: _page(c, d, ctx, status, rid), onLaterPages=lambda c, d: _page(c, d, ctx, status, rid))
    return buf.getvalue()


# ============================================================================== Markdown / JSON
def build_markdown(ctx: ReportContext) -> str:
    status, reasons = report_status(ctx)
    L = [f"# TraceForge Incident Report - {ctx.case_name}", "",
         "| | |", "|---|---|", f"| Report ID | {report_id(ctx)} |", f"| Status | **{status}** |", f"| Classification | {ctx.tlp} - {TLP_HANDLING.get(ctx.tlp, '')} |",
         f"| Prepared by | {ctx.analyst}{', ' + ctx.organization if ctx.organization else ''} |", f"| Generated | {ctx.generated:%Y-%m-%d %H:%M} UTC |", f"| Tool | TraceForge v{__version__} |", ""]
    if reasons:
        L += [f"> **DRAFT - not reviewed.** {' '.join(reasons)}", ""]
    L += ["## 1. Executive summary", ""] + [f"- {p}" for p in executive_points(ctx)]
    obs = key_observations(ctx)
    if obs:
        L += ["", "### Key observations", "", "| Stage | Severity | Observation | Refs |", "|---|---|---|---|"] + [f"| {o['tactic']} | {o['severity']} | {o['text']} | {o['refs']} |" for o in obs]
    L += ["", "## 2. Scope and evidence integrity", ""] + [f"- {x}" for x in integrity_lines(ctx)] + ["", "| File | SHA-256 | Rows kept |", "|---|---|---|"]
    L += [f"| {q.filename} | `{q.sha256}` | {q.rows_kept}/{q.rows_read} |" for q in ctx.quality]
    assets = affected_assets(ctx)
    if assets:
        L += ["", "## 3. Affected assets", "", "| Type | Entity | Incidents | Events |", "|---|---|---|---|"] + [f"| {a['type']} | `{a['value']}` | {a['incidents']} | {a['events']} |" for a in assets]
    L += ["", "## 4. Incident analysis"]
    for inc in ctx.incidents:
        sc, vd, ov = _eff(inc, ctx)
        e = inc.entities
        L += ["", f"### {inc.incident_id} - {inc.title}", "", " ".join(_summary_lines(inc)),
              f"- **Severity:** {inc.severity}  |  **Confidence:** {_label(sc)} ({sc}/100{', override' if ov else ''})  |  **Verdict:** {vd}",
              f"- **Window:** {_when(inc.start, inc.end, '%H:%M:%S')}", f"- **IP addresses:** {', '.join(e['ip']) or '-'}", f"- **Accounts:** {', '.join(e['user']) or '-'}",
              f"- **Hosts:** {', '.join(e['host']) or '-'}", f"- **ATT&CK:** {', '.join(inc.techniques) or '-'}", "", "#### Timeline", "", "| Time (UTC) | Stage | Observation | Ref |", "|---|---|---|---|"]
        L += [f"| {ts} | {tactic} | {summary} | {ref} |" for ts, tactic, summary, ref in _narr_rows(inc)]
        L += ["", "#### Confidence factors", ""] + [f"- {t}: {p:+d}" for t, p in inc.confidence_factors]
        L += ["", "#### Response actions"]
        for phase, steps in _phased(inc.remediation):
            L += ["", f"**{phase}**", ""] + [f"- [ ] {r}" for r in steps]
        notes = ctx.notes[ctx.notes["incident_id"] == inc.incident_id] if len(ctx.notes) else ctx.notes
        if len(notes):
            L += ["", "#### Analyst notes", ""] + [f"- {r['created_utc']} {r['author']}: {r['note']}" for _, r in notes.iterrows()]
    L += ["", "## 5. Indicators of compromise", "", "| Type | Value | Note |", "|---|---|---|"] + [f"| {r['ioc_type']} | `{r['value']}` | {r['note']} |" for _, r in ctx.iocs.iterrows()]
    if len(ctx.findings):
        imap = _finding_incident_map(ctx)
        L += ["", "## Appendix A. Findings register", "", "| ID | Start (UTC) | Rule | Severity | ATT&CK | Events | Incident |", "|---|---|---|---|---|---|---|"]
        L += [f"| {f['finding_id']} | {f['start']:%Y-%m-%d %H:%M:%S} | {f['rule_name']} - {f['summary']} | {f['severity']} | {f['technique']} | {int(f['count'])} | {imap.get(f['finding_id'], '-')} |"
              for _, f in ctx.findings.sort_values("start").iterrows()]
    techs = _techniques(ctx)
    if techs:
        L += ["", "## Appendix B. MITRE ATT&CK techniques observed", "", "| Technique | Name | Stage | Findings |", "|---|---|---|---|"] + [f"| {t['id']} | {t['name']} | {t['tactics']} | {t['findings']} |" for t in techs]
    L += ["", "## Appendix C. Methodology, definitions and limitations", ""] + [f"- {m}" for m in _methodology(ctx)]
    L += ["", "**Severity (indicative):** " + " ".join(f"*{a}* - {b}" for a, b in SEVERITY_DEFINITIONS)]
    return "\n".join(L) + "\n"


def build_json(ctx: ReportContext) -> str:
    def inc_dict(i):
        sc, vd, ov = _eff(i, ctx)
        d = {k: (v.isoformat() if isinstance(v, pd.Timestamp) else v) for k, v in i.__dict__.items()}
        d.update(effective_confidence=sc, verdict=vd, response_actions=[{"phase": p, "steps": st_} for p, st_ in _phased(i.remediation)])
        return d
    status, reasons = report_status(ctx)
    return json.dumps({
        "tool": f"TraceForge {__version__}", "report_id": report_id(ctx), "status": status, "status_reasons": reasons,
        "case": ctx.case_name, "analyst": ctx.analyst, "generated_utc": ctx.generated.isoformat(),
        "evidence_files": [q.as_dict() for q in ctx.quality], "incidents": [inc_dict(i) for i in ctx.incidents],
        "key_observations": key_observations(ctx), "affected_assets": affected_assets(ctx), "techniques": _techniques(ctx),
        "findings": json.loads(ctx.findings.drop(columns=["entities"]).to_json(orient="records", date_format="iso")) if len(ctx.findings) else [],
        "iocs": ctx.iocs.to_dict("records"), "tlp": ctx.tlp, "handling": TLP_HANDLING.get(ctx.tlp, ""), "redaction": ctx.redaction or None,
        "evidence_verification": ctx.integrity, "audit_log": ctx.audit,
    }, indent=2, default=str)
