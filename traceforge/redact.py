"""Sharing redaction: mask internal identifiers in reports and exports according to the TLP marking.

Pseudonyms are deterministic for a given case (user-01, host-01, internal-ip-01 ...), so a redacted report still tells
a coherent story: the same account is always the same token. External (attacker) IP addresses are kept because they
are the shareable indicators.

Policy by marking (mode "auto"):
  TLP:CLEAR          usernames, hostnames, internal IPs, analyst notes and organisation name are removed
  TLP:GREEN          usernames, hostnames and internal IPs are masked
  AMBER / STRICT / RED   nothing is masked
Mode "on" applies the GREEN policy to any marking; mode "off" masks nothing.
"""
from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass

import pandas as pd

from .ingest import is_internal

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
NOTES_WITHHELD = "[analyst notes withheld under this marking]"


@dataclass(frozen=True)
class Policy:
    users: bool = False
    hosts: bool = False
    internal_ips: bool = False
    notes: bool = False
    org: bool = False

    @property
    def active(self) -> bool:
        return any(dataclasses.astuple(self))


POLICIES = {
    "TLP:CLEAR": Policy(True, True, True, True, True),
    "TLP:GREEN": Policy(True, True, True, False, False),
}
IDENTIFIERS_ONLY = Policy(True, True, True, False, False)
NO_REDACTION = Policy()


def policy_for(tlp: str, mode: str = "auto") -> Policy:
    mode = (mode or "auto").lower()
    if mode == "off":
        return NO_REDACTION
    if mode == "on":
        return POLICIES.get(tlp, IDENTIFIERS_ONLY) if tlp in POLICIES else IDENTIFIERS_ONLY
    return POLICIES.get(tlp, NO_REDACTION)


def _alternation(values: set[str]) -> str:
    return "|".join(re.escape(v) for v in sorted(values, key=lambda v: (-len(v), v)))


class Redactor:
    def __init__(self, policy: Policy, users=(), hosts=(), ips=()):
        self.policy = policy
        self.users = {u for u in users if u and len(u) > 1}
        self.hosts = {h for h in hosts if h and len(h) > 1}
        self._ip_tokens: dict[str, str] = {}
        for ip in sorted({i for i in ips if i and is_internal(i)}, key=lambda s: (":" in s, s)):
            self._ip_tokens[ip] = f"internal-ip-{len(self._ip_tokens) + 1:02d}"
        self._user_tokens = {u: f"user-{n:02d}" for n, u in enumerate(sorted(self.users), 1)}
        self._host_tokens = {h: f"host-{n:02d}" for n, h in enumerate(sorted(self.hosts), 1)}
        self._user_re = re.compile(rf"(?<![\w.\-])({_alternation(self.users)})(?![\w\-]|\.\w)", re.I) if policy.users and self.users else None
        self._host_re = re.compile(rf"(?<![\w.\-])({_alternation(self.hosts)})(?:\.[\w\-]+)*(?![\w\-])", re.I) if policy.hosts and self.hosts else None
        self._ipv6 = re.compile("|".join(re.escape(i) for i in self._ip_tokens if ":" in i), re.I) if any(":" in i for i in self._ip_tokens) else None

    # ------------------------------------------------------------------ construction
    @classmethod
    def for_case(cls, policy: Policy, events: pd.DataFrame, incidents=(), iocs: pd.DataFrame | None = None) -> "Redactor":
        users, hosts, ips = set(), set(), set()
        if len(events):
            users |= set(events["user"].dropna().astype(str))
            hosts |= {h for h in events["host"].dropna().astype(str) if h}
            ips |= set(events["src_ip"].dropna().astype(str)) | set(events["dst_ip"].dropna().astype(str))
        for inc in incidents:
            users |= set(inc.entities.get("user", []))
            hosts |= set(inc.entities.get("host", []))
        if iocs is not None and len(iocs):
            users |= set(iocs.loc[iocs["ioc_type"] == "username", "value"].astype(str))
        hosts |= {h.split(".")[0] for h in hosts if "." in h and not h.replace(".", "").isdigit()}
        return cls(policy, users, hosts, ips)

    # ------------------------------------------------------------------ text / structures
    def text(self, s: str) -> str:
        if not isinstance(s, str) or not s:
            return s
        if self.policy.internal_ips:
            s = _IPV4.sub(lambda m: self._ip(m.group(0)), s)
            if self._ipv6:
                s = self._ipv6.sub(lambda m: self._ip_tokens[m.group(0).lower()] if m.group(0).lower() in self._ip_tokens else m.group(0), s)
        if self._host_re:
            s = self._host_re.sub(lambda m: self._host_tokens.get(m.group(1).lower(), "host-xx"), s)
        if self._user_re:
            s = self._user_re.sub(lambda m: self._user_tokens.get(m.group(1).lower(), "user-xx"), s)
        return s

    def _ip(self, ip: str) -> str:
        if ip in self._ip_tokens:
            return self._ip_tokens[ip]
        if is_internal(ip):
            self._ip_tokens[ip] = f"internal-ip-{len(self._ip_tokens) + 1:02d}"
            return self._ip_tokens[ip]
        return ip

    def walk(self, v):
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, list):
            return [self.walk(x) for x in v]
        if isinstance(v, tuple):
            return tuple(self.walk(x) for x in v)
        if isinstance(v, dict):
            return {k: self.walk(x) for k, x in v.items()}
        return v

    def frame(self, df: pd.DataFrame, bulk: bool = False) -> pd.DataFrame:
        """Redacted copy. bulk=True maps each distinct string once (for large event tables)."""
        if df is None or df.empty or not self.policy.active:
            return df
        out = df.copy()
        for col in out.columns:
            if str(out[col].dtype) in ("object", "str", "string"):
                if bulk:
                    cache = {v: self.text(v) for v in out[col].dropna().unique() if isinstance(v, str)}
                    out[col] = out[col].map(lambda v: cache.get(v, v) if isinstance(v, str) else v)
                else:
                    out[col] = out[col].map(self.walk)
        return out

    # ------------------------------------------------------------------ report context
    def apply(self, ctx):
        """Return a redacted copy of a report.ReportContext."""
        if not self.policy.active:
            return ctx
        c = dataclasses.replace(ctx)
        c.events = self.frame(ctx.events.drop(columns=["raw"], errors="ignore"), bulk=True)
        c.findings = self.frame(ctx.findings)
        c.iocs = self.frame(ctx.iocs)
        c.incidents = [dataclasses.replace(i, **{f.name: self.walk(getattr(i, f.name)) for f in dataclasses.fields(i)
                                                  if f.name not in ("start", "end", "key", "incident_id", "severity", "confidence", "confidence_label", "event_ids", "finding_ids")})
                       for i in ctx.incidents]
        notes = ctx.notes
        if len(notes):
            notes = notes.assign(note=NOTES_WITHHELD) if self.policy.notes else self.frame(notes)
            if self.policy.users:
                notes = notes.assign(author="analyst")
        c.notes = notes
        if self.policy.org and ctx.organization:
            c.organization = "[removed]"
        c.redaction = self.describe()
        return c

    def describe(self) -> str:
        parts = []
        if self.policy.users:
            parts.append(f"usernames ({len(self._user_tokens)})")
        if self.policy.hosts:
            parts.append(f"hostnames ({len(self._host_tokens)})")
        if self.policy.internal_ips:
            parts.append(f"internal IP addresses ({len(self._ip_tokens)})")
        if self.policy.notes:
            parts.append("analyst notes withheld")
        if self.policy.org:
            parts.append("organisation name removed")
        return "Redacted for sharing: " + ", ".join(parts) + ". External IP addresses and indicators are unchanged." if parts else ""
