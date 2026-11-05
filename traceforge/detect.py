"""Configurable, explainable detection rules.

Rules are deliberately simple and transparent: every finding lists the exact event IDs that
triggered it, so an analyst can verify (or reject) the conclusion from the evidence.
"""
from __future__ import annotations

import re
from typing import Callable
from urllib.parse import unquote_plus

import numpy as np
import pandas as pd

from . import sigma as sigma_mod
from .config import RULES, SEVERITY_ORDER, merged_config
from .ingest import is_internal

_EPOCH = pd.Timestamp("1970-01-01", tz="UTC")
FINDING_COLUMNS = [
    "finding_id", "rule_id", "rule_name", "tactic", "technique", "severity", "start", "end",
    "count", "summary", "entities", "event_ids", "src_ip", "user", "host",
]

PAYLOAD_PATTERNS = {
    "SQL injection": r"(\bunion\b.{0,30}\bselect\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1|sleep\(\d+\)|benchmark\(|information_schema|;\s*drop\s+table|xp_cmdshell)",
    "Cross-site scripting": r"(<script|javascript:|onerror\s*=|onload\s*=)",
    "Path traversal": r"(\.\./|\.\.\\|/etc/passwd|boot\.ini|win\.ini)",
    "Command injection": r"(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|powershell|cmd)\b",
    "JNDI / Log4Shell": r"\$\{jndi:(ldap|ldaps|rmi|dns)",
}
COMMAND_PATTERNS = {
    "Encoded PowerShell": (r"powershell(\.exe)?.*\s-(e|enc|encodedcommand)\s+[a-za-z0-9+/=]{20,}", "high"),
    "Download cradle / LOLBin transfer": (r"(invoke-webrequest|\biwr\b|downloadstring|net\.webclient|certutil.*-urlcache|bitsadmin.*/transfer|curl[^|]*\|\s*(ba)?sh|wget[^|]*\|\s*(ba)?sh)", "high"),
    "Credential dumping": (r"(mimikatz|sekurlsa|procdump.*lsass|reg\s+save\s+hklm\\(sam|system)|ntdsutil|comsvcs\.dll.*minidump)", "critical"),
    "Backup / shadow-copy destruction": (r"(vssadmin.*delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no)", "critical"),
    "Reverse shell / remote exec": (r"(nc(\.exe)?\s+.*-e\s|bash\s+-i\s+>&\s*/dev/tcp|/dev/tcp/|mshta\s+http|rundll32.*javascript)", "high"),
    "Discovery / enumeration": (r"(net\s+(user|group|localgroup)\s+.*/domain|whoami\s+/(all|priv)|nltest\s+/dclist|adfind)", "medium"),
}
REMOTE_EXEC_PATTERNS = {
    "PsExec / remote service execution": r"(\bpsexec(64)?(\.exe)?\b|\bpsexesvc\b|\bpaexec\b)",
    "WMI remote execution": r"(wmic(\.exe)?\s+/node:|invoke-wmimethod|win32_process.*\bcreate\b)",
    "WinRM / PowerShell remoting": r"(\bwinrs(\.exe)?\s+-r:|\benter-pssession\b|\bnew-pssession\b|invoke-command\s+.*-computername)",
    "Admin share / remote service creation": r"(\\\\[\w.\-]+\\(admin\$|c\$|ipc\$)|\bsc(\.exe)?\s+\\\\[\w.\-]+\s+create\b)",
    "Remote scheduled task": r"schtasks(\.exe)?\s+.*\s/s\s+\S+",
}
PERSISTENCE_PATTERNS = {
    "Scheduled task created": r"(schtasks(\.exe)?\s+.*/create|\bregister-scheduledtask\b|\bnew-scheduledtask\b)",
    "Service installed": r"(\bsc(\.exe)?\s+(\\\\\S+\s+)?create\b|\bnew-service\b)",
    "Autorun registry key": r"(reg(\.exe)?\s+add\s+.*\\(currentversion\\run(once)?|winlogon)|\\currentversion\\run(once)?\\|image file execution options|\\winlogon\\(shell|userinit))",
}
OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
          "msbuild.exe", "certutil.exe", "bitsadmin.exe", "bash.exe", "wmic.exe"}
_PARENT_CHILD_RE = re.compile(r"image=(?P<child>.*?)\s+parentimage=(?P<parent>.*?)(?:\s+parentcommandline=|$)", re.S)
SENSITIVE_LABELS = {
    "account_created": ("Account created", "high"),
    "group_add": ("Added to privileged group", "high"),
    "log_cleared": ("Audit log cleared", "critical"),
}


# ----------------------------------------------------------------------------- helpers
def _bmap(series: pd.Series, fn) -> pd.Series:
    """Element-wise predicate -> real boolean mask (Series.map can return str dtype in pandas 3)."""
    return pd.Series([bool(fn(x)) for x in series], index=series.index, dtype=bool)


def _match(series: pd.Series, rx: str) -> pd.Series:
    """Boolean mask of regex matches (avoids pandas' capture-group warning)."""
    pat = re.compile(rx)
    return _bmap(series, lambda x: pat.search(x))


def _secs(s: pd.Series) -> np.ndarray:
    return (s - _EPOCH).dt.total_seconds().to_numpy()


def _dur(a, b) -> str:
    s = int((b - a).total_seconds())
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {(s % 3600) // 60:02d}m"


def _bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return str(n)


def _bursts(g: pd.DataFrame, gap_min: float) -> list[pd.DataFrame]:
    """Split events into bursts separated by more than gap_min minutes of silence."""
    g = g.sort_values("timestamp")
    if g.empty:
        return []
    t = _secs(g["timestamp"])
    cuts = np.where(np.diff(t) > gap_min * 60)[0] + 1
    return [g.iloc[idx] for idx in np.split(np.arange(len(g)), cuts)]


def _max_in_window(t: np.ndarray, window_min: float) -> int:
    if len(t) == 0:
        return 0
    ends = np.searchsorted(t, t + window_min * 60, side="right")
    return int((ends - np.arange(len(t))).max())


def _ents(ev, ip=True, user=False, host=False, dst_ext=False) -> list[str]:
    s: set[str] = set()
    if ip:
        s |= {f"ip:{v}" for v in ev["src_ip"].dropna().unique()[:20]}
    if user:
        s |= {f"user:{v}" for v in ev["user"].dropna().unique()[:20]}
    if host:
        s |= {f"host:{v}" for v in ev["host"].replace("", pd.NA).dropna().unique()[:20]}
    if dst_ext:
        s |= {f"ip:{v}" for v in ev["dst_ip"].dropna().unique() if not is_internal(v)}
    return sorted(s)


def _first(ev, col):
    vals = ev[col].replace("", pd.NA).dropna() if ev[col].dtype == object else ev[col].dropna()
    return str(vals.iloc[0]) if len(vals) else ""


def _finding(rule_id, ev, summary, entities, severity=None) -> dict:
    meta = RULES[rule_id]
    return {
        "rule_id": rule_id, "rule_name": meta["name"], "tactic": meta["tactic"],
        "technique": meta["technique"], "severity": severity or meta["severity"],
        "start": ev["timestamp"].min(), "end": ev["timestamp"].max(), "count": len(ev),
        "summary": summary, "entities": entities, "event_ids": ev["event_id"].tolist(),
        "src_ip": _first(ev, "src_ip"), "user": _first(ev, "user"), "host": _first(ev, "host"),
    }


def _bump(sev: str, steps: int = 1) -> str:
    names = sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get)
    return names[min(len(names) - 1, names.index(sev) + steps)]


# ------------------------------------------------------------------------------ rules
def r_brute_force(ev, cfg, iocs):
    c, spray = cfg["brute_force"], cfg["password_spray"]
    out = []
    fails = ev[(ev["event_type"] == "login_failure") & ev["src_ip"].notna()]
    for ip, g in fails.groupby("src_ip"):
        for b in _bursts(g, c["window_minutes"]):
            users = b["user"].nunique()
            if spray["enabled"] and users >= spray["distinct_users"]:
                continue  # reported as password spraying instead
            if _max_in_window(_secs(b["timestamp"]), c["window_minutes"]) >= c["failures"]:
                sev = _bump("medium") if len(b) >= 3 * c["failures"] else "medium"
                out.append(_finding("brute_force", b,
                    f"{len(b)} failed logins from {ip} against {max(users, 1)} account(s) over {_dur(b['timestamp'].min(), b['timestamp'].max())}.",
                    _ents(b), sev))
    return out


def r_password_spray(ev, cfg, iocs):
    c = cfg["password_spray"]
    out = []
    fails = ev[(ev["event_type"] == "login_failure") & ev["src_ip"].notna() & ev["user"].notna()]
    for ip, g in fails.groupby("src_ip"):
        for b in _bursts(g, c["window_minutes"]):
            users = b["user"].nunique()
            if users >= c["distinct_users"]:
                out.append(_finding("password_spray", b,
                    f"{ip} failed against {users} distinct accounts ({len(b)} attempts) over {_dur(b['timestamp'].min(), b['timestamp'].max())}.",
                    _ents(b)))
    return out


def r_success_after_failures(ev, cfg, iocs):
    c, priv = cfg["success_after_failures"], set(cfg["privileged_users"])
    fails = ev[ev["event_type"] == "login_failure"].sort_values("timestamp")
    succ = ev[ev["event_type"] == "login_success"]
    if fails.empty or succ.empty:
        return []
    ft = _secs(fails["timestamp"])
    groups: dict = {}
    for _, r in succ.iterrows():
        t = (r["timestamp"] - _EPOCH).total_seconds()
        cand = fails.iloc[np.searchsorted(ft, t - c["lookback_minutes"] * 60, "left"):np.searchsorted(ft, t, "right")]
        if cand.empty:
            continue
        same_ip = (cand["src_ip"] == r["src_ip"]) if pd.notna(r["src_ip"]) else pd.Series(False, index=cand.index)
        same_user = (cand["user"] == r["user"]) if pd.notna(r["user"]) else pd.Series(False, index=cand.index)
        cand = cand[same_ip | same_user]
        if len(cand) >= c["failures"]:
            key = (r["src_ip"], r["user"])
            groups.setdefault(key, set()).update(cand["event_id"].tolist() + [r["event_id"]])
    out = []
    for (ip, user), ids in groups.items():
        b = ev[ev["event_id"].isin(ids)].sort_values("timestamp")
        nf = int((b["event_type"] == "login_failure").sum())
        sev = "critical" if user in priv else "high"
        out.append(_finding("success_after_failures", b,
            f"Account '{user}' logged in from {ip} after {nf} failed attempts within {c['lookback_minutes']} min.",
            _ents(b, user=True), sev))
    return out


def r_multi_ip_login(ev, cfg, iocs):
    w = cfg["multi_ip_login"]["window_minutes"]
    out = []
    s = ev[(ev["event_type"] == "login_success") & ev["user"].notna() & ev["src_ip"].notna()]
    for user, g in s.groupby("user"):
        for b in _bursts(g, w):
            ips = sorted(b["src_ip"].unique())
            if len(ips) >= 2 and any(not is_internal(i) for i in ips):
                out.append(_finding("multi_ip_login", b,
                    f"Account '{user}' authenticated from {len(ips)} IPs ({', '.join(ips[:4])}) within {w} min.",
                    _ents(b, user=True)))
    return out


def r_off_hours_login(ev, cfg, iocs):
    c, priv = cfg["off_hours_login"], set(cfg["privileged_users"])
    s = ev[(ev["event_type"] == "login_success") & ev["user"].notna()].copy()
    if s.empty:
        return []
    hour, wd = s["timestamp"].dt.hour, s["timestamp"].dt.weekday
    off = (hour < c["business_start_hour"]) | (hour >= c["business_end_hour"])
    if c["weekends_are_off_hours"]:
        off |= wd >= 5
    s = s[off]
    if c["external_only"]:
        s = s[_bmap(s["src_ip"], lambda i: pd.notna(i) and not is_internal(i)) | s["user"].isin(priv)]
    out = []
    s = s.assign(day=s["timestamp"].dt.date, ipk=s["src_ip"].fillna("unknown"))
    for (user, ip, day), b in s.groupby(["user", "ipk", "day"]):
        out.append(_finding("off_hours_login", b,
            f"'{user}' logged in from {ip} at {b['timestamp'].min():%H:%M} UTC on {day} (outside {c['business_start_hour']:02d}:00-{c['business_end_hour']:02d}:00 UTC).",
            _ents(b, user=True)))
    return out


def r_sensitive_activity(ev, cfg, iocs):
    out = []
    for etype, (label, sev) in SENSITIVE_LABELS.items():
        s = ev[ev["event_type"] == etype]
        for host, g in s.assign(hk=s["host"].replace("", "unknown-host")).groupby("hk"):
            for b in _bursts(g, 10):
                msg = _first(b, "message")[:120]
                out.append(_finding("sensitive_activity", b,
                    f"{label} on {host} ({len(b)} event(s)): {msg}", _ents(b, user=True, host=True), sev))
    return out


def r_web_scan(ev, cfg, iocs):
    c = cfg["web_scan"]
    out = []
    w = ev[(ev["event_type"] == "web_request") & ev["src_ip"].notna() & ev["status_code"].isin(c["status_codes"])]
    for ip, g in w.groupby("src_ip"):
        for b in _bursts(g, c["window_minutes"]):
            if _max_in_window(_secs(b["timestamp"]), c["window_minutes"]) >= c["errors"]:
                out.append(_finding("web_scan", b,
                    f"{len(b)} client-error responses ({', '.join(str(int(x)) for x in sorted(b['status_code'].unique()))}) for {ip} against {', '.join(sorted(set(b['host']) - {''})[:2]) or 'web server'} in {_dur(b['timestamp'].min(), b['timestamp'].max())}.",
                    _ents(b)))
    return out


def r_web_attack_payload(ev, cfg, iocs):
    sub = ev[(ev["url"] != "") & ev["src_ip"].notna()]
    if sub.empty:
        return []
    text = (sub["url"].map(lambda u: unquote_plus(unquote_plus(u))) + " " + sub["message"]).str.lower()
    out = []
    for label, rx in PAYLOAD_PATTERNS.items():
        hit = sub[_match(text, rx)]
        for ip, g in hit.groupby("src_ip"):
            for b in _bursts(g, 30):
                ok = int(b["status_code"].between(200, 299).sum())
                note = f" {ok} returned HTTP 2xx - verify whether the payload had any effect." if ok else " No 2xx responses seen."
                out.append(_finding("web_attack_payload", b,
                    f"{label} pattern in {len(b)} request(s) from {ip}.{note}", _ents(b)))
    return out


def r_suspicious_command(ev, cfg, iocs):
    sub = ev[(ev["command"] != "") | (ev["event_type"] == "process_exec")]
    if sub.empty:
        return []
    text = (sub["command"] + " " + sub["message"]).str.lower()
    out = []
    for label, (rx, sev) in COMMAND_PATTERNS.items():
        hit = sub[_match(text, rx)]
        for host, g in hit.assign(hk=hit["host"].replace("", "unknown-host")).groupby("hk"):
            for b in _bursts(g, 30):
                sample = (_first(b, "command") or _first(b, "message"))[:90]
                out.append(_finding("suspicious_command", b,
                    f"{label} on {host}: {sample}", _ents(b, user=True, host=True), sev))
    return out


def r_large_outbound(ev, cfg, iocs):
    c = cfg["large_outbound"]
    s = ev[ev["bytes_out"].notna() & ev["dst_ip"].notna()]
    s = s[_bmap(s["dst_ip"], lambda i: not is_internal(i))].copy()
    s["actor"] = s["src_ip"].fillna(s["host"].replace("", pd.NA)).fillna("unknown")
    out = []
    for (actor, dst), g in s.groupby(["actor", "dst_ip"]):
        for b in _bursts(g, c["window_minutes"]):
            total = float(b["bytes_out"].sum())
            if total >= c["megabytes"] * 1_000_000:
                out.append(_finding("large_outbound", b,
                    f"{_bytes(total)} sent from {actor} to external {dst} over {_dur(b['timestamp'].min(), b['timestamp'].max())} ({len(b)} flow(s)).",
                    _ents(b, host=True, dst_ext=True)))
    return out


def r_port_scan(ev, cfg, iocs):
    c = cfg["port_scan"]
    s = ev[ev["dst_port"].notna() & ev["src_ip"].notna()]
    out = []
    for ip, g in s.groupby("src_ip"):
        for b in _bursts(g, c["window_minutes"]):
            ports = b["dst_port"].nunique()
            if ports >= c["distinct_ports"]:
                out.append(_finding("port_scan", b,
                    f"{ip} probed {ports} distinct ports on {b['dst_ip'].nunique()} destination(s) in {_dur(b['timestamp'].min(), b['timestamp'].max())}.",
                    _ents(b)))
    return out


def r_ioc_match(ev, cfg, iocs):
    if iocs is None or len(iocs) == 0:
        return []
    out = []
    blob = (ev["url"] + " " + ev["message"] + " " + ev["command"] + " " + ev["host"] + " " + ev["raw"]).str.lower()
    for _, ioc in iocs.iterrows():
        v, t = str(ioc["value"]).strip().lower(), str(ioc["ioc_type"])
        if not v:
            continue
        if t in ("ipv4", "ipv6"):
            m = (ev["src_ip"] == v) | (ev["dst_ip"] == v)
        elif t == "username":
            m = ev["user"] == v
        else:
            m = blob.str.contains(v, regex=False, na=False)
        hit = ev[m]
        if len(hit):
            ents = _ents(hit, user=(t == "username"), dst_ext=True)
            out.append(_finding("ioc_match", hit, f"IOC {t} '{v}' appears in {len(hit)} event(s)" + (f" - note: {ioc.get('note')}" if ioc.get("note") else "") + ".", ents))
    return out


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip())[-1].strip().lower()


def _distinct_windows(t: np.ndarray, labels: list, window_s: float, need: int) -> list[tuple[int, int]]:
    """Index ranges [a, b) of sorted events in which at least `need` distinct labels occur within window_s seconds."""
    n, counts, j, hits = len(t), {}, 0, []
    for i in range(n):
        while j < n and t[j] - t[i] <= window_s:
            counts[labels[j]] = counts.get(labels[j], 0) + 1
            j += 1
        if len(counts) >= need:
            hits.append((i, j))
        left = counts[labels[i]] - 1
        if left:
            counts[labels[i]] = left
        else:
            del counts[labels[i]]
    merged: list[tuple[int, int]] = []
    for a, b in hits:
        if merged and a < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def r_lateral_movement(ev, cfg, iocs):
    c = cfg["lateral_movement"]
    out = []
    logins = ev[(ev["event_type"] == "login_success") & (ev["host"] != "")].copy()
    if len(logins):
        logins["actor"] = logins["src_ip"].fillna(logins["user"]).astype(object)
        logins = logins[logins["actor"].notna()]
        for actor, g in logins.groupby("actor"):
            g = g.sort_values("timestamp")
            for a, b in _distinct_windows(_secs(g["timestamp"]), g["host"].tolist(), c["window_minutes"] * 60, c["hosts"]):
                w = g.iloc[a:b]
                hosts = sorted(set(w["host"]))
                out.append(_finding("lateral_movement", w,
                    f"'{actor}' logged in to {len(hosts)} different hosts ({', '.join(hosts[:4])}{'...' if len(hosts) > 4 else ''}) within {_dur(w['timestamp'].min(), w['timestamp'].max())}.",
                    _ents(w, user=True, host=True)))
    sub = ev[(ev["command"] != "") | (ev["event_type"] == "process_exec")]
    if len(sub):
        text = (sub["command"] + " " + sub["message"]).str.lower()
        for label, rx in REMOTE_EXEC_PATTERNS.items():
            hit = sub[_match(text, rx)]
            for host, g in hit.assign(hk=hit["host"].replace("", "unknown-host")).groupby("hk"):
                for b in _bursts(g, 30):
                    sample = (_first(b, "command") or _first(b, "message"))[:90]
                    out.append(_finding("lateral_movement", b, f"{label} on {host}: {sample}", _ents(b, user=True, host=True)))
    return out


def r_persistence_mechanism(ev, cfg, iocs):
    text = (ev["command"] + " " + ev["message"]).str.lower()
    out = []
    labelled = pd.Series("", index=ev.index, dtype=object)
    for label, rx in PERSISTENCE_PATTERNS.items():
        is_cmd = (ev["command"] != "") | (ev["event_type"] == "process_exec")
        m = is_cmd & _match(text, rx) & (labelled == "")
        labelled[m] = label
    reg = (ev["event_type"] == "registry_set") & _match(text, PERSISTENCE_PATTERNS["Autorun registry key"]) & (labelled == "")
    labelled[reg] = "Autorun registry key"
    labelled[(ev["event_type"] == "service_install") & (labelled == "")] = "Service installed"
    labelled[(ev["event_type"] == "scheduled_task") & (labelled == "")] = "Scheduled task created"
    hit = ev[labelled != ""].assign(lab=labelled[labelled != ""], hk=lambda d: d["host"].replace("", "unknown-host"))
    for (label, host), g in hit.groupby(["lab", "hk"]):
        for b in _bursts(g, 10):
            sample = (_first(b, "command") or _first(b, "message"))[:90]
            out.append(_finding("persistence_mechanism", b, f"{label} on {host} ({len(b)} event(s)): {sample}", _ents(b, user=True, host=True)))
    return out


def r_mfa_fatigue(ev, cfg, iocs):
    c = cfg["mfa_fatigue"]
    out = []
    den = ev[(ev["event_type"] == "mfa_denied") & ev["user"].notna()]
    ok = ev[(ev["event_type"] == "login_success") & ev["user"].notna()]
    for user, g in den.groupby("user"):
        for b in _bursts(g, c["window_minutes"]):
            if _max_in_window(_secs(b["timestamp"]), c["window_minutes"]) < c["denials"]:
                continue
            after = ok[(ok["user"] == user) & (ok["timestamp"] >= b["timestamp"].min()) & (ok["timestamp"] <= b["timestamp"].max() + pd.Timedelta(minutes=15))]
            evidence = pd.concat([b, after]).sort_values("timestamp") if len(after) else b
            tail = f" A login for '{user}' succeeded within 15 minutes afterwards, so a prompt may have been approved." if len(after) else " No login followed within 15 minutes."
            out.append(_finding("mfa_fatigue", evidence,
                f"{len(b)} denied MFA prompts for '{user}' over {_dur(b['timestamp'].min(), b['timestamp'].max())}.{tail}",
                _ents(evidence, user=True), "critical" if len(after) else None))
    return out


def r_office_spawns_shell(ev, cfg, iocs):
    sub = ev[(ev["event_type"] == "process_exec") & (ev["message"] != "")]
    if sub.empty:
        return []
    pairs = {}
    for idx, msg in zip(sub.index, sub["message"].str.lower()):
        m = _PARENT_CHILD_RE.search(msg)
        if m and _basename(m["parent"]) in OFFICE_APPS and _basename(m["child"]) in SHELLS:
            pairs[idx] = (_basename(m["parent"]), _basename(m["child"]))
    out = []
    if not pairs:
        return out
    hit = ev.loc[list(pairs)].assign(parent=lambda d: [pairs[i][0] for i in d.index], child=lambda d: [pairs[i][1] for i in d.index],
                                      hk=lambda d: d["host"].replace("", "unknown-host"))
    for (host, parent, child), g in hit.groupby(["hk", "parent", "child"]):
        for b in _bursts(g, 30):
            sample = (_first(b, "command") or "")[:80]
            out.append(_finding("office_spawns_shell", b,
                f"{parent} started {child} on {host} ({len(b)} event(s)){': ' + sample if sample else ''}.",
                _ents(b, user=True, host=True)))
    return out


def r_beaconing(ev, cfg, iocs):
    c = cfg["beaconing"]
    s = ev[ev["dst_ip"].notna()].copy()
    s = s[_bmap(s["dst_ip"], lambda i: not is_internal(i))]
    if s.empty:
        return []
    s["actor"] = s["host"].replace("", pd.NA).fillna(s["src_ip"]).fillna("unknown")
    s["port"] = s["dst_port"].fillna(0).astype(int)
    out = []
    lo, hi, jit = c["min_interval_seconds"], c["max_interval_minutes"] * 60, c["max_jitter_pct"] / 100.0
    for (actor, dst, port), g in s.groupby(["actor", "dst_ip", "port"]):
        if len(g) < c["connections"]:
            continue
        g = g.sort_values("timestamp")
        d = np.diff(_secs(g["timestamp"]))
        med = float(np.median(d))
        if med <= 0 or not (lo <= med <= hi):
            continue
        within = float((np.abs(d - med) <= jit * med).mean())
        if within >= 0.8:
            port_txt = f":{port}" if port else ""
            out.append(_finding("beaconing", g,
                f"{actor} contacted external {dst}{port_txt} {len(g)} times at a steady rhythm: median gap {med:.0f}s, {within * 100:.0f}% of gaps within +/-{c['max_jitter_pct']}%.",
                _ents(g, host=True, dst_ext=True)))
    return out


RULE_FUNCS: dict[str, Callable] = {
    "brute_force": r_brute_force, "password_spray": r_password_spray,
    "success_after_failures": r_success_after_failures, "multi_ip_login": r_multi_ip_login,
    "off_hours_login": r_off_hours_login, "sensitive_activity": r_sensitive_activity,
    "web_scan": r_web_scan, "web_attack_payload": r_web_attack_payload,
    "suspicious_command": r_suspicious_command, "large_outbound": r_large_outbound,
    "port_scan": r_port_scan, "ioc_match": r_ioc_match,
    "lateral_movement": r_lateral_movement, "persistence_mechanism": r_persistence_mechanism, "mfa_fatigue": r_mfa_fatigue,
    "office_spawns_shell": r_office_spawns_shell, "beaconing": r_beaconing,
}


def sigma_findings(events: pd.DataFrame, rules: list, diagnostics: list | None = None) -> list[dict]:
    """Findings for imported Sigma rules. A rule that fails is reported in `diagnostics` and the others still run."""
    out: list[dict] = []
    cache: dict = {}
    for rule in rules:
        try:
            hit = sigma_mod.match_events(rule, events, cache)
        except Exception as exc:  # noqa: BLE001 - one bad rule must not blank the analysis
            if diagnostics is None:
                raise
            diagnostics.append({"rule_id": "sigma_match", "rule_name": f"Sigma: {rule.title}", "error": f"{type(exc).__name__}: {exc}"})
            continue
        if hit.empty:
            continue
        actor = hit["host"].replace("", pd.NA).fillna(hit["src_ip"]).fillna("unknown")
        for key, g in hit.assign(actor=actor).groupby("actor"):
            for b in _bursts(g, 30):
                f = _finding("sigma_match", b, f"Sigma rule '{rule.title}' ({rule.level}) matched {len(b)} event(s) on {key}.",
                             _ents(b, user=True, host=True), rule.severity)
                f.update(rule_name=f"Sigma: {rule.title}", tactic=rule.tactic, technique=" / ".join(rule.techniques) or "n/a")
                out.append(f)
    return out


def run_detections(events: pd.DataFrame, config: dict | None = None, iocs: pd.DataFrame | None = None,
                   diagnostics: list | None = None, sigma_rules: list | None = None) -> pd.DataFrame:
    """Run all enabled rules; returns one row per finding, ordered by time.

    A rule that raises is skipped and reported in `diagnostics` so one bad log format cannot blank the whole analysis.
    `sigma_rules` are compiled rules from traceforge.sigma (imported by the analyst).
    """
    cfg = merged_config(config)
    rows: list[dict] = []
    if len(events):
        for rule_id, fn in RULE_FUNCS.items():
            if cfg.get(rule_id, {}).get("enabled", True):
                try:
                    rows.extend(fn(events, cfg, iocs))
                except Exception as exc:  # noqa: BLE001 - isolate rule failures
                    if diagnostics is None:
                        raise
                    diagnostics.append({"rule_id": rule_id, "rule_name": RULES[rule_id]["name"], "error": f"{type(exc).__name__}: {exc}"})
        if sigma_rules and cfg.get("sigma_match", {}).get("enabled", True):
            rows.extend(sigma_findings(events, sigma_rules, diagnostics))
    df = pd.DataFrame(rows, columns=[c for c in FINDING_COLUMNS if c != "finding_id"])
    if df.empty:
        return pd.DataFrame(columns=FINDING_COLUMNS)
    df = df.sort_values(["start", "rule_id"]).reset_index(drop=True)
    df.insert(0, "finding_id", [f"F{i + 1:03d}" for i in range(len(df))])
    return df
