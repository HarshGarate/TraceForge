"""Import and normalize JSON / CSV security logs into one canonical event schema."""
from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from . import formats
from .hardening import MAX_COLUMNS, MAX_JSON_LEVEL, MAX_ROWS_PER_FILE, PARSE_TIMEOUT_SECONDS, Deadline

CANONICAL = [
    "timestamp", "src_ip", "dst_ip", "dst_port", "user", "event_type", "host",
    "message", "status_code", "url", "bytes_out", "command",
]

ALIASES = {
    "timestamp": ["timestamp", "time", "@timestamp", "datetime", "date", "eventtime", "event_time", "_time", "ts", "timecreated", "created", "epoch", "epoch_time", "unix_time", "unixtime"],
    "src_ip": ["src_ip", "source_ip", "srcip", "src", "client_ip", "clientip", "remote_ip", "remote_addr", "ipaddress", "ip", "sourceaddress", "c-ip", "sourcenetworkaddress", "sourceipaddress", "id.orig_h", "orig_h"],
    "dst_ip": ["dst_ip", "dest_ip", "destination_ip", "dstip", "dst", "destinationaddress", "server_ip", "destinationip", "id.resp_h", "resp_h"],
    "dst_port": ["dst_port", "dest_port", "destination_port", "dport", "port", "destinationport", "id.resp_p", "resp_p"],
    "user": ["user", "username", "user_name", "account", "accountname", "targetusername", "usr", "cs-username", "userid"],
    "event_type": ["event_type", "eventtype", "event", "action", "eventid", "event_id", "event_name", "category", "activity", "type"],
    "host": ["host", "hostname", "computer", "device", "server", "machine", "host_name", "computername"],
    "message": ["message", "msg", "description", "details", "log", "text", "raw"],
    "status_code": ["status_code", "http_status", "response_code", "sc-status", "statuscode", "status"],
    "url": ["url", "uri", "request_uri", "request", "path", "cs-uri-stem"],
    "bytes_out": ["bytes_out", "bytes_sent", "sent_bytes", "out_bytes", "orig_bytes", "sc-bytes", "bytes"],
    "command": ["command", "commandline", "command_line", "cmdline", "process_command_line"],
}

_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7")]
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Order matters: first matching pattern wins.
EVENT_PATTERNS = [
    ("log_cleared", r"\b1102\b|log[_ ]?clear|audit log (was )?cleared|clear[_ ]?eventlog"),
    ("account_created", r"\b4720\b|account[_ ]?(was )?creat|user[_ ]?(added|creat)|useradd|net user .* /add|new user"),
    ("group_add", r"\bgroup_add\b|\b(4728|4732|4756)\b|added to .*(admin|group)|\badd\b.*\bto group\b|group[_ ]?member[_ ]?add|usermod -a?g|admin(istrators)? group"),
    ("login_failure", r"\b4625\b|fail(ed)?[_ ](password|login|logon|auth)|(login|logon)[_ ]?fail|auth(entication)?[_ ]?fail|invalid (user|password)|bad password|wrong password"),
    ("login_success", r"\b4624\b|accepted (password|publickey)|(login|logon)[_ ]?succe|auth(entication)?[_ ]?succe|successful (login|logon)"),
    ("process_exec", r"\b4688\b|process[_ ]?(create|start)|command[_ ]?exec"),
    ("firewall_block", r"^(deny|denied|drop|dropped|block|blocked|reject)$|firewall.*(deny|drop|block)"),
    ("firewall_allow", r"^(allow|allowed|accept|permit)$"),
    ("service_install", r"\bservice_install\b|\b(4697|7045)\b|service[_ ]?install|new service was installed"),
    ("scheduled_task", r"\bscheduled_task\b|\b4698\b|scheduled[_ ]?task[_ ]?creat|schtasks.*/create"),
    ("mfa_denied", r"\bmfa_denied\b|\b(mfa|2fa|otp|duo|push|authenticator)\b.{0,60}\b(denied|deny|rejected|reject|failed|failure|fraud|declined|timeout|timed out)\b|\b(denied|rejected|declined)\b.{0,40}\b(mfa|2fa|push)\b"),
]


def is_internal(ip) -> bool:
    """RFC1918 / loopback / link-local. Documentation ranges count as external on purpose."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS)


def _valid_ip(value):
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return pd.NA
    s = str(value).strip().strip("[]")
    if s.lower() in ("", "-", "nan", "none", "null"):
        return pd.NA
    s = s.split("%")[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return pd.NA


def _clean_user(value):
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return pd.NA
    s = str(value).strip().lower()
    if s in ("", "-", "nan", "none", "null", "n/a"):
        return pd.NA
    if "\\" in s:
        s = s.split("\\")[-1]
    if "@" in s:
        s = s.split("@")[0]
    return s or pd.NA


def _strip_key(key: str) -> str:
    return re.sub(r"[^a-z0-9\-@_]", "", str(key).lower().replace(".", "_")).replace("_", "")


# ------------------------------------------------------------------ plain-text logs (.log / .txt)
_APACHE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)[^"]*" (?P<status>\d{3}) (?P<bytes>\d+|-)')
_ISO_RE = re.compile(r"^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]?\s*(.*)$")
_SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(?:(\d{4})\s+)?(\S+)\s+(.*)$")
_KV_RE = re.compile(r'([A-Za-z_][\w.\-]*)=("[^"]*"|\S*)')
_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_KV_FIELDS = {
    "src_ip": ("src", "srcip", "src_ip", "source", "sip", "client", "clientip", "saddr"),
    "dst_ip": ("dst", "dstip", "dst_ip", "dest", "dip", "daddr", "destination"),
    "dst_port": ("dpt", "dport", "dst_port", "destport", "dp"),
    "user": ("user", "username", "usr", "suser", "acct", "account", "name"),
    "bytes_out": ("bytes", "sent", "bytes_out", "bytes_sent", "orig_bytes"),
    "command": ("cmd", "command", "commandline", "cmdline", "exe"),
}
_SYSLOG_USER = re.compile(r"(?:for (?:invalid user )?|user[= ]|invalid user |session opened for user |add '|new user: name=)([\w.\-\\$@]+)", re.I)
_SYSLOG_FROM = re.compile(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39})\b")
_FW_ACTION = re.compile(r"\b(block(?:ed)?|drop(?:ped)?|deny|denied|reject(?:ed)?)\b", re.I)
_FW_ALLOW = re.compile(r"\b(allow(?:ed)?|accept(?:ed)?|permit(?:ted)?)\b", re.I)


def _syslog_ts(mon: str, day: str, clock: str, year: str | None) -> str | None:
    """Classic syslog has no year: assume the current one, or the previous one if that would land in the future."""
    if mon not in _MONTHS:
        return None
    now = datetime.now(timezone.utc)
    y = int(year) if year else now.year
    try:
        ts = datetime(y, _MONTHS[mon], int(day), *map(int, clock.split(":")), tzinfo=timezone.utc)
    except ValueError:
        return None
    if not year and ts > now + pd.Timedelta(days=1):
        ts = ts.replace(year=y - 1)
    return ts.isoformat()


def _looks_like_csv(text: str) -> bool:
    head = [ln for ln in text.splitlines()[:5] if ln.strip()]
    if not head:
        return False
    first = head[0].lower()
    return first.count(",") >= 2 and any(a in first for a in ALIASES["timestamp"]) and not _ISO_RE.match(head[0])


def parse_text_log(text: str, deadline: Deadline | None = None) -> pd.DataFrame:
    """Best-effort parser for raw logs: Apache/nginx access logs, syslog / auth.log, firewall key=value lines and any
    line that starts with an ISO timestamp. Lines it cannot date are skipped (and counted by the quality report)."""
    rows = []
    for n, line in enumerate(text.splitlines()):
        if n % 2000 == 0 and deadline:
            deadline.check()
        if len(rows) > MAX_ROWS_PER_FILE:
            break
        line = line.strip()
        if not line:
            continue
        row = {"timestamp": None, "message": line}
        m = _APACHE_RE.match(line)
        if m:
            try:
                row["timestamp"] = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).isoformat()
            except ValueError:
                pass
            row.update(src_ip=m["ip"], user=None if m["user"] == "-" else m["user"], url=m["url"], status_code=m["status"],
                       bytes_out=None if m["bytes"] == "-" else m["bytes"], event_type="web_request")
            rows.append(row)
            continue
        rest, host = line, None
        iso = _ISO_RE.match(line)
        if iso:
            row["timestamp"], rest = iso.group(1).replace(",", "."), iso.group(2)
        else:
            sm = _SYSLOG_RE.match(line)
            if sm:
                row["timestamp"], host, rest = _syslog_ts(sm.group(1), sm.group(2), sm.group(3), sm.group(4)), sm.group(5), sm.group(6)
        if host:
            row["host"] = host
        kv = {k.lower(): v.strip('",;') for k, v in _KV_RE.findall(rest)}
        for canon, keys in _KV_FIELDS.items():
            for k in keys:
                if k in kv and kv[k]:
                    row[canon] = kv[k]
                    break
        if not row.get("src_ip"):
            fm = _SYSLOG_FROM.search(rest)
            if fm:
                row["src_ip"] = fm.group(1)
        if not row.get("user"):
            um = _SYSLOG_USER.search(rest)
            if um and um.group(1).lower() not in ("from", "invalid", "user"):
                row["user"] = um.group(1)
        if row.get("src_ip") and ("src" in kv or "dpt" in kv or "dst" in kv):
            if _FW_ACTION.search(rest):
                row["event_type"] = "firewall_block"
            elif _FW_ALLOW.search(rest):
                row["event_type"] = "firewall_allow"
        rows.append(row)
    cols = ["timestamp", "src_ip", "dst_ip", "dst_port", "user", "event_type", "host", "message", "status_code", "url", "bytes_out", "command"]
    return pd.DataFrame(rows, columns=cols)


def _json_loads(text: str):
    try:
        return json.loads(text)
    except RecursionError as exc:
        raise ValueError("the JSON is nested too deeply to be a log file.") from exc


def _read_table(raw: bytes, filename: str, deadline: Deadline | None = None) -> pd.DataFrame:
    name = filename.lower()
    text = raw.decode("utf-8-sig", errors="replace")
    stripped = text.lstrip()
    head = stripped[:1]
    if formats.looks_like_zeek_tsv(stripped):
        return formats.parse_zeek_tsv(stripped, deadline)
    if head == "<":
        if not formats.looks_like_windows_xml(stripped):
            raise ValueError("is an XML file but not Windows Event XML (export with: wevtutil qe Security /f:xml).")
        return formats.parse_windows_xml(stripped, deadline)
    if name.endswith((".json", ".jsonl", ".ndjson")) or (head and head in "[{"):
        text = stripped.rstrip()
        try:
            data = _json_loads(text)
            if isinstance(data, dict):
                for key in ("events", "records", "logs", "data", "hits", "Records"):
                    if isinstance(data.get(key), list):
                        data = data[key]
                        break
                else:
                    data = [data]
        except json.JSONDecodeError:  # NDJSON
            data = []
            for i, line in enumerate(text.splitlines()):
                if i % 5000 == 0 and deadline:
                    deadline.check()
                if line.strip():
                    data.append(_json_loads(line))
                if len(data) > MAX_ROWS_PER_FILE:
                    break
        if not isinstance(data, list) or any(not isinstance(x, dict) for x in data[:1000]):
            raise ValueError("must contain JSON objects (one per event).")
        df = pd.json_normalize(data, sep=".", max_level=MAX_JSON_LEVEL)
        return formats.enrich_cloudtrail(df) if formats.looks_like_cloudtrail(df) else df
    if name.endswith((".log", ".txt")) and not _looks_like_csv(text):
        return parse_text_log(text, deadline)
    return pd.read_csv(io.StringIO(text), sep=None, engine="python", dtype=str, on_bad_lines="skip", nrows=MAX_ROWS_PER_FILE + 1)


def _map_columns(df: pd.DataFrame) -> tuple[dict, list]:
    """Return {canonical: original_column} using alias matching on full key then last segment."""
    keyed = {}
    for col in df.columns:
        keyed.setdefault(_strip_key(col), col)
        keyed.setdefault(_strip_key(str(col).split(".")[-1]), col)
    mapping, used = {}, set()
    for canon, aliases in ALIASES.items():
        for alias in aliases:
            col = keyed.get(_strip_key(alias))
            if col is not None and col not in used:
                mapping[canon] = col
                used.add(col)
                break
    return mapping, [c for c in df.columns if c not in used]


def _parse_timestamps(series: pd.Series) -> pd.Series:
    num = pd.to_numeric(series, errors="coerce")
    if num.notna().mean() > 0.9:
        unit = "ms" if num.dropna().median() > 1e11 else "s"
        return pd.to_datetime(num, unit=unit, utc=True, errors="coerce")
    try:
        return pd.to_datetime(series, utc=True, errors="coerce", format="mixed")
    except (TypeError, ValueError):
        return pd.to_datetime(series, utc=True, errors="coerce")


def classify_event(event_type: str, message: str) -> str:
    et = (event_type or "").strip().lower().replace("-", "_")
    for label, pattern in EVENT_PATTERNS:
        if re.search(pattern, et):
            return label
    text = f"{et} {(message or '').lower().replace('-', '_')}"
    for label, pattern in EVENT_PATTERNS:
        if label.startswith("firewall"):
            continue
        if re.search(pattern, text):
            return label
    return re.sub(r"[^a-z0-9]+", "_", et).strip("_") or "other"


@dataclass
class Quality:
    filename: str
    sha256: str
    rows_read: int = 0
    rows_kept: int = 0
    bad_timestamp: int = 0
    invalid_ips: int = 0
    mapped_fields: dict = field(default_factory=dict)
    unmapped_columns: list = field(default_factory=list)
    truncated: bool = False

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def normalize_file(raw: bytes, filename: str, timeout: float = PARSE_TIMEOUT_SECONDS) -> tuple[pd.DataFrame, Quality]:
    """Parse one log file into the canonical schema. Never fabricates data: rows without a
    parseable timestamp are dropped and counted in the quality report. Parsing is limited by a time budget."""
    deadline = Deadline(timeout)
    q = Quality(filename=filename, sha256=hashlib.sha256(raw).hexdigest())
    df = _read_table(raw, filename, deadline)
    deadline.check()
    if df.shape[1] > MAX_COLUMNS:
        raise ValueError(f"has {df.shape[1]} columns; the limit is {MAX_COLUMNS}. Remove unneeded columns and upload again.")
    q.rows_read = len(df)
    if len(df) > MAX_ROWS_PER_FILE:
        df, q.truncated = df.iloc[:MAX_ROWS_PER_FILE].copy(), True
    mapping, q.unmapped_columns = _map_columns(df)
    q.mapped_fields = {k: str(v) for k, v in mapping.items()}
    if "timestamp" not in mapping:
        raise ValueError(f"{filename}: no timestamp column found. TraceForge needs a column named timestamp, time, @timestamp, datetime or _time, so it can place each row on the timeline.")

    out = pd.DataFrame(index=df.index)
    for canon in CANONICAL:
        out[canon] = df[mapping[canon]] if canon in mapping else pd.NA
    for col in ("src_ip", "dst_ip", "user", "dst_port", "status_code", "bytes_out"):
        out[col] = out[col].astype(object)  # all-empty columns arrive as float64 and refuse string fallbacks (pandas 3)
    out["timestamp"] = _parse_timestamps(out["timestamp"])
    q.bad_timestamp = int(out["timestamp"].isna().sum())
    out = out[out["timestamp"].notna()].copy()

    for col in ("message", "event_type", "url", "command", "host"):
        out[col] = out[col].astype("object").where(out[col].notna(), "").astype(str).str.strip()
    out["host"] = out["host"].str.lower()

    # Fallbacks from free text when structured fields are missing (best effort, only IPv4)
    missing_ip = out["src_ip"].isna() | (out["src_ip"].astype(str).str.strip() == "")
    if missing_ip.any():
        out.loc[missing_ip, "src_ip"] = out.loc[missing_ip, "message"].str.extract(f"({_IPV4_RE.pattern})")[0]
    missing_user = out["user"].isna()
    if missing_user.any():
        out.loc[missing_user, "user"] = out.loc[missing_user, "message"].str.extract(
            r"\bfor (?:invalid user )?([\w.\-\\$@]+) from", expand=False)

    before = out[["src_ip", "dst_ip"]].notna().sum().sum()
    out["src_ip"] = out["src_ip"].map(_valid_ip)
    out["dst_ip"] = out["dst_ip"].map(_valid_ip)
    q.invalid_ips = int(before - out[["src_ip", "dst_ip"]].notna().sum().sum())
    out["user"] = out["user"].map(_clean_user)
    out["status_code"] = pd.to_numeric(out["status_code"], errors="coerce")
    out["bytes_out"] = pd.to_numeric(out["bytes_out"], errors="coerce")
    out["dst_port"] = pd.to_numeric(out["dst_port"], errors="coerce")

    out["event_type"] = [classify_event(e, m) for e, m in zip(out["event_type"], out["message"])]
    web = (out["event_type"].isin(["other", ""]) | out["event_type"].str.fullmatch(r"\d+")) & (out["url"] != "") & out["status_code"].notna()
    out.loc[web, "event_type"] = "web_request"
    cmd = out["event_type"].isin(["other", ""]) & (out["command"] != "")
    out.loc[cmd, "event_type"] = "process_exec"
    net = out["event_type"].isin(["other", "", "firewall_allow"]) & out["bytes_out"].notna() & out["dst_ip"].notna()
    out.loc[net, "event_type"] = out.loc[net, "event_type"].replace({"other": "network_flow", "": "network_flow", "firewall_allow": "network_flow"})
    out.loc[out["event_type"] == "", "event_type"] = "other"

    deadline.check()
    out["source"] = filename
    out["raw"] = df.loc[out.index].apply(lambda r: json.dumps({k: formats.json_safe(v) for k, v in r.items()}, ensure_ascii=False), axis=1)
    deadline.check()
    q.rows_kept = len(out)
    return out.reset_index(drop=True), q


def build_dataset(files: list[tuple[str, bytes]]) -> tuple[pd.DataFrame, list[Quality]]:
    """Normalize several files, merge them chronologically and assign stable event IDs."""
    frames, reports = [], []
    for name, raw in files:
        df, q = normalize_file(raw, name)
        frames.append(df)
        reports.append(q)
    events = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=CANONICAL + ["source", "raw"])
    events = events.sort_values(["timestamp", "source"], kind="stable").reset_index(drop=True)
    events.insert(0, "event_id", [f"E{i + 1:06d}" for i in range(len(events))])
    return events, reports
