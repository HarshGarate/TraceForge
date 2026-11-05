"""Parsers for structured log formats that need more than column aliasing:

* Windows Event Log XML (Security, System, Sysmon) as produced by ``wevtutil qe /f:xml`` or Event Viewer export
* Zeek TSV logs (conn, dns, http and others)
* AWS CloudTrail records (after JSON flattening)

Each parser returns a DataFrame whose first columns are the canonical TraceForge fields; the original fields are
kept in extra columns so they appear in the raw event view and can be matched by Sigma rules.
"""
from __future__ import annotations

import ipaddress
import json
import re
import xml.etree.ElementTree as ET

import numpy as np
import pandas as pd

from .hardening import MAX_ROWS_PER_FILE, Deadline

CANON_COLS = ["timestamp", "src_ip", "dst_ip", "dst_port", "user", "event_type", "host", "message", "status_code", "url", "bytes_out", "command"]

LOGON_TYPES = {"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock", "8": "network cleartext",
               "9": "new credentials", "10": "remote interactive (RDP)", "11": "cached interactive"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _frame(rows: list[dict], extra_prefix: bool = False) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    ordered = CANON_COLS + [c for c in df.columns if c not in CANON_COLS]
    for c in CANON_COLS:
        if c not in df.columns:
            df[c] = None
    return df[ordered]


# ============================================================================= Windows XML
def looks_like_windows_xml(text: str) -> bool:
    head = text[:4000]
    return head.lstrip().startswith("<") and "<EventID" in head and "<System" in head


def _win_fields(eid: str, channel: str, provider: str, d: dict[str, str]) -> dict:
    g = lambda k: (d.get(k) or "").strip()  # noqa: E731
    sysmon = "sysmon" in f"{channel} {provider}".lower()
    r: dict = {"event_type": f"windows_event_{eid}", "message": f"Windows event {eid}"}
    if sysmon:
        if eid == "1":
            r.update(event_type="process_exec", command=g("CommandLine"), user=g("User"),
                     message=f"Image={g('Image')} ParentImage={g('ParentImage')} ParentCommandLine={g('ParentCommandLine')}")
        elif eid == "3":
            r.update(event_type="network_flow", src_ip=g("SourceIp"), dst_ip=g("DestinationIp"), dst_port=g("DestinationPort"), user=g("User"),
                     message=f"Image={g('Image')} Protocol={g('Protocol')}")
        elif eid == "11":
            r.update(event_type="file_create", user=g("User"), message=f"Image={g('Image')} TargetFilename={g('TargetFilename')}")
        elif eid in ("12", "13", "14"):
            r.update(event_type="registry_set", user=g("User"),
                     message=f"Image={g('Image')} TargetObject={g('TargetObject')} Details={g('Details')}")
        elif eid == "22":
            r.update(event_type="dns_query", user=g("User"), message=f"Image={g('Image')} QueryName={g('QueryName')}")
        else:
            r.update(event_type=f"sysmon_event_{eid}", message=f"Sysmon event {eid} Image={g('Image')}")
        return r
    if eid == "4624":
        lt = g("LogonType")
        r.update(event_type="login_success", user=g("TargetUserName"), src_ip=g("IpAddress"),
                 message=f"Logon type {lt} ({LOGON_TYPES.get(lt, 'other')}) workstation={g('WorkstationName')} process={g('ProcessName')}")
    elif eid == "4625":
        lt = g("LogonType")
        r.update(event_type="login_failure", user=g("TargetUserName"), src_ip=g("IpAddress"),
                 message=f"Failed logon type {lt} ({LOGON_TYPES.get(lt, 'other')}) status={g('Status')}/{g('SubStatus')} workstation={g('WorkstationName')}")
    elif eid == "4688":
        r.update(event_type="process_exec", user=g("SubjectUserName"), command=g("CommandLine"),
                 message=f"Image={g('NewProcessName')} ParentImage={g('ParentProcessName')}")
    elif eid == "4720":
        r.update(event_type="account_created", user=g("TargetUserName"), message=f"Account {g('TargetUserName')} created by {g('SubjectUserName')}")
    elif eid in ("4728", "4732", "4756"):
        member = g("MemberName")
        m = re.match(r"CN=([^,]+)", member, re.I)
        r.update(event_type="group_add", user=(m.group(1) if m else member) or g("TargetUserName"),
                 message=f"{(m.group(1) if m else member)} added to group {g('TargetUserName')} by {g('SubjectUserName')}")
    elif eid in ("1102", "104"):
        r.update(event_type="log_cleared", user=g("SubjectUserName") or g("UserName"), message="The audit log was cleared")
    elif eid in ("4697", "7045"):
        r.update(event_type="service_install", user=g("SubjectUserName") or g("AccountName"), command=g("ServiceFileName") or g("ImagePath"),
                 message=f"Service installed: {g('ServiceName')}")
    elif eid == "4698":
        content = d.get("TaskContent") or ""
        cmd = re.search(r"<Command>(.*?)</Command>", content, re.S)
        args = re.search(r"<Arguments>(.*?)</Arguments>", content, re.S)
        r.update(event_type="scheduled_task", user=g("SubjectUserName"), command=" ".join(x.group(1).strip() for x in (cmd, args) if x),
                 message=f"Scheduled task created: {g('TaskName')}")
    return r


def parse_windows_xml(text: str, deadline: Deadline | None = None) -> pd.DataFrame:
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.I):
        raise ValueError("XML files that declare a DOCTYPE or ENTITY are not accepted (entity-expansion protection).")
    body = re.sub(r"<\?xml[^>]*\?>", "", text)
    try:
        root = ET.fromstring(f"<Events>{body}</Events>")
    except ET.ParseError as exc:
        raise ValueError(f"could not be read as Windows Event XML ({exc}).") from exc
    rows: list[dict] = []
    for n, ev in enumerate(e for e in root.iter() if _local(e.tag) == "Event"):
        if n and n % 2000 == 0 and deadline:
            deadline.check()
        if n >= MAX_ROWS_PER_FILE + 1:
            break
        eid = ts = computer = channel = provider = ""
        data: dict[str, str] = {}
        for child in ev:
            ln = _local(child.tag)
            if ln == "System":
                for e in child:
                    el = _local(e.tag)
                    if el == "EventID":
                        eid = (e.text or "").strip()
                    elif el == "TimeCreated":
                        ts = e.get("SystemTime", "")
                    elif el == "Computer":
                        computer = (e.text or "").strip()
                    elif el == "Channel":
                        channel = (e.text or "").strip()
                    elif el == "Provider":
                        provider = e.get("Name", "")
            elif ln == "EventData":
                for i, dnode in enumerate(child):
                    data[dnode.get("Name") or f"Data{i}"] = dnode.text or ""
            elif ln == "UserData":
                for sub in child.iter():
                    if len(sub) == 0 and sub.text and sub is not child:
                        data[_local(sub.tag)] = sub.text
        row = {"timestamp": ts, "host": computer, **_win_fields(eid, channel, provider, data)}
        row.update({"System.EventID": eid, "System.Channel": channel, "System.Provider": provider})
        row.update({f"EventData.{k}": v for k, v in data.items()})
        rows.append(row)
    if not rows:
        raise ValueError("contains no <Event> records.")
    return _frame(rows)


# ============================================================================= Zeek
def looks_like_zeek_tsv(text: str) -> bool:
    return text.startswith("#separator") or ("#fields" in text[:4000] and "\t" in text[:4000])


def _zeek_sep(token: str) -> str:
    return chr(int(token[2:], 16)) if token.startswith("\\x") else token


def parse_zeek_tsv(text: str, deadline: Deadline | None = None) -> pd.DataFrame:
    sep, fields, path = "\t", None, ""
    rows: list[dict] = []
    for n, line in enumerate(text.splitlines()):
        if n % 5000 == 0 and deadline:
            deadline.check()
        if line.startswith("#"):
            if line.startswith("#separator"):
                parts = line.split(" ", 1)
                if len(parts) == 2 and parts[1].strip():
                    sep = _zeek_sep(parts[1].strip())
            elif line.startswith("#fields"):
                fields = line.split(sep)[1:]
            elif line.startswith("#path"):
                path = line.split(sep)[-1].strip()
            continue
        if not line.strip() or not fields:
            continue
        vals = line.split(sep)
        rec = {f: (None if v in ("-", "(empty)", "") else v) for f, v in zip(fields, vals)}
        rows.append(rec)
        if len(rows) > MAX_ROWS_PER_FILE:
            break
    if not rows:
        raise ValueError("contains no Zeek records (is the #fields header missing?).")
    out = []
    for r in rows:
        base = {"timestamp": r.get("ts"), "src_ip": r.get("id.orig_h"), "dst_ip": r.get("id.resp_h"), "dst_port": r.get("id.resp_p")}
        if path == "conn":
            base.update(event_type="network_flow", bytes_out=r.get("orig_bytes"), message=f"conn {r.get('proto')}/{r.get('service')} state={r.get('conn_state')}")
        elif path == "http":
            base.update(event_type="web_request", url=r.get("uri"), status_code=r.get("status_code"), user=r.get("username"),
                        message=f"{r.get('method')} host={r.get('host')} ua={r.get('user_agent')}")
        elif path == "dns":
            base.update(event_type="dns_query", message=f"query={r.get('query')} qtype={r.get('qtype_name')} rcode={r.get('rcode_name')} answers={r.get('answers')}")
        else:
            base.update(event_type=path or "zeek_event", message=" ".join(f"{k}={v}" for k, v in list(r.items())[:8] if v))
        out.append({**base, **{f"zeek.{k}": v for k, v in r.items() if k != "ts"}})
    return _frame(out)


# ============================================================================= CloudTrail
def looks_like_cloudtrail(df: pd.DataFrame) -> bool:
    return {"eventTime", "eventName", "eventSource"} <= set(df.columns)


_PRIV_POLICIES = ("administratoraccess", "iamfullaccess", "poweruseraccess")


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", str(name)).lower()


def enrich_cloudtrail(df: pd.DataFrame) -> pd.DataFrame:
    """Add canonical columns to flattened CloudTrail records (original columns are kept)."""
    df = df.copy()

    def col(name):
        return df[name].tolist() if name in df.columns else [None] * len(df)

    names, sources, errs, consoles, mfas = col("eventName"), col("eventSource"), col("errorCode"), col("responseElements.ConsoleLogin"), col("additionalEventData.MFAUsed")
    pol = col("requestParameters.policyArn")
    arns, unames, ips, uas = col("userIdentity.arn"), col("userIdentity.userName"), col("sourceIPAddress"), col("userAgent")
    def txt(v) -> str:
        return "" if v is None or (isinstance(v, float) and np.isnan(v)) else str(v)

    ev_type, msg, user, srcip, host = [], [], [], [], []
    for i in range(len(df)):
        n, err = txt(names[i]), txt(errs[i])
        if n == "ConsoleLogin":
            t = "login_success" if str(consoles[i]) == "Success" else "login_failure"
        elif n == "CreateUser":
            t = "account_created"
        elif n == "AddUserToGroup" or (n in ("AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy") and any(p in txt(pol[i]).lower() for p in _PRIV_POLICIES)):
            t = "group_add"
        elif n in ("StopLogging", "DeleteTrail"):
            t = "log_cleared"
        elif "accessdenied" in err.lower() or "unauthorized" in err.lower():
            t = "access_denied"
        else:
            t = _snake(n) or "other"
        ev_type.append(t)
        m = f"{txt(sources[i])} {n}" + (f" error={err}" if err else "") + (f" MFA={txt(mfas[i])}" if txt(mfas[i]) else "")
        msg.append(m + (f" ua={txt(uas[i])[:60]}" if txt(uas[i]) else ""))
        u = txt(unames[i]) or (txt(arns[i]).rsplit("/", 1)[-1] if txt(arns[i]) else None)
        user.append(u)
        try:
            srcip.append(str(ipaddress.ip_address(txt(ips[i]))))
        except ValueError:
            srcip.append(None)
        host.append(txt(sources[i]).lower())
    df["event_type"], df["message"], df["user"], df["src_ip"], df["host"] = ev_type, msg, user, srcip, host
    return df


def json_safe(v) -> str | None:
    """String form of a cell for the raw-event view (containers become JSON, missing values None)."""
    if isinstance(v, (list, dict, tuple)):
        return json.dumps(v, ensure_ascii=False, default=str)
    try:
        if v is None or pd.isna(v):
            return None
    except (TypeError, ValueError):
        pass
    return str(v)
