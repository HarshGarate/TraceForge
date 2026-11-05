"""Sigma rule import (a documented subset) and evaluation against TraceForge events.

Supported
  * detection selections: field maps (AND), lists of field maps (OR), keyword lists
  * modifiers: contains, startswith, endswith, re, all, cidr, lt, lte, gt, gte, windash
  * wildcards (* and ?) in plain values, null values
  * conditions: and / or / not / parentheses / "1 of x*" / "all of x*" / "1 of them" / "all of them"
Not supported (the rule is skipped and the reason is shown): aggregation (``| count()``), ``near``, ``timeframe``,
base64 / utf16 / expand / fieldref modifiers, correlation rules.

Rules are written by the analyst, not taken from evidence, so they are trusted input; they are still parsed with
yaml.safe_load, YAML aliases are refused, and regular expressions are length-limited.
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field

import pandas as pd
import yaml

from .config import TACTIC_ORDER

MAX_RULE_BYTES = 256 * 1024
MAX_RULES = 200
MAX_REGEX_LEN = 300

LEVELS = {"informational": "info", "info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
TACTIC_TAGS = {t.lower().replace(" ", "_"): t for t in TACTIC_ORDER if t != "Threat Intel Match"}
CANONICAL_FIELDS = {
    "commandline": "command", "sourceip": "src_ip", "src_ip": "src_ip", "c-ip": "src_ip", "clientip": "src_ip",
    "destinationip": "dst_ip", "dst_ip": "dst_ip", "destinationport": "dst_port", "dst_port": "dst_port",
    "computername": "host", "computer": "host", "hostname": "host", "url": "url", "c-uri": "url", "cs-uri-stem": "url",
    "sc-status": "status_code", "message": "message",
}
SUPPORTED_MODS = {"contains", "startswith", "endswith", "re", "all", "cidr", "lt", "lte", "gt", "gte", "windash"}


class SigmaError(ValueError):
    """The rule cannot be used; the message says why."""


@dataclass
class Test:
    field: str
    op: str
    values: list
    match_all: bool = False


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    severity: str
    level: str
    description: str
    tactic: str
    techniques: list[str]
    tags: list[str]
    falsepositives: list[str]
    selections: dict[str, list[list[Test]]]      # name -> alternatives (OR) of AND-ed tests
    condition: str
    yaml_text: str
    sha256: str = ""
    fields: set = field(default_factory=set)

    def as_dict(self) -> dict:
        return {"id": self.rule_id, "title": self.title, "level": self.level, "tactic": self.tactic, "techniques": self.techniques,
                "description": self.description, "falsepositives": self.falsepositives, "sha256": self.sha256}


# ----------------------------------------------------------------------------- parsing
def _refuse_aliases(text: str) -> None:
    try:
        for ev in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(ev, yaml.AliasEvent):
                raise SigmaError("YAML anchors and aliases are not supported in imported rules.")
    except yaml.YAMLError as exc:
        raise SigmaError(f"is not valid YAML ({str(exc).splitlines()[0]}).") from exc


def _compile_selection(name: str, body) -> list[list[Test]]:
    def tests_from_map(m: dict) -> list[Test]:
        tests = []
        for key, val in m.items():
            fname, *mods = str(key).split("|")
            bad = [x for x in mods if x not in SUPPORTED_MODS]
            if bad:
                raise SigmaError(f"selection '{name}' uses the unsupported modifier '{bad[0]}'.")
            ops = [x for x in mods if x in ("contains", "startswith", "endswith", "re", "cidr", "lt", "lte", "gt", "gte")]
            if len(ops) > 1:
                raise SigmaError(f"selection '{name}' combines several match modifiers on '{fname}'.")
            values = val if isinstance(val, list) else [val]
            if "windash" in mods:
                values = [x for v in values for x in ((v, str(v).replace(" -", " /")) if isinstance(v, str) else (v,))]
            if "re" in mods:
                for v in values:
                    if len(str(v)) > MAX_REGEX_LEN or re.search(r"\([^)]*[+*][^)]*\)[+*{]", str(v)):
                        raise SigmaError(f"selection '{name}' has a regular expression that is too long or may backtrack catastrophically.")
                    try:
                        re.compile(str(v))
                    except re.error as exc:
                        raise SigmaError(f"selection '{name}' has an invalid regular expression ({exc}).") from exc
            tests.append(Test(fname, ops[0] if ops else "eq", values, "all" in mods))
        return tests

    if isinstance(body, dict):
        return [tests_from_map(body)]
    if isinstance(body, list):
        if all(isinstance(x, dict) for x in body):
            return [tests_from_map(x) for x in body]
        if all(isinstance(x, (str, int, float)) for x in body):
            return [[Test("*", "contains", [str(x) for x in body])]]
    raise SigmaError(f"selection '{name}' has an unsupported shape.")


def _tags(tags) -> tuple[str, list[str]]:
    tactic_hits, techniques = [], []
    for t in tags or []:
        t = str(t).lower()
        if not t.startswith("attack."):
            continue
        tail = t[len("attack."):]
        if re.fullmatch(r"t\d{4}(\.\d{3})?", tail):
            techniques.append(tail.upper())
        elif tail in TACTIC_TAGS:
            tactic_hits.append(TACTIC_TAGS[tail])
    # the first tactic tag is the rule author's primary tactic
    return (tactic_hits[0] if tactic_hits else "Uncategorised"), techniques


def _from_doc(doc: dict, text: str) -> SigmaRule:
    if not isinstance(doc, dict) or "detection" not in doc:
        raise SigmaError("has no 'detection' section (is this a Sigma rule?).")
    if {"action", "correlation"} & set(doc):
        raise SigmaError("is a Sigma collection or correlation document, which is not supported.")
    det = doc["detection"]
    if not isinstance(det, dict) or "condition" not in det:
        raise SigmaError("has no detection condition.")
    if "timeframe" in det:
        raise SigmaError("uses 'timeframe', which is not supported.")
    cond = det["condition"]
    if isinstance(cond, list):
        if len(cond) != 1:
            raise SigmaError("has several conditions; only one is supported.")
        cond = cond[0]
    cond = str(cond)
    if "|" in cond or re.search(r"\bnear\b", cond):
        raise SigmaError("uses an aggregation or 'near' condition, which is not supported.")
    sels = {str(k): _compile_selection(str(k), v) for k, v in det.items() if k not in ("condition", "timeframe")}
    if not sels:
        raise SigmaError("has no selections.")
    _parse_condition(cond, set(sels))               # validates the condition now, not at match time
    level = LEVELS.get(str(doc.get("level", "medium")).lower(), "medium")
    tactic, techniques = _tags(doc.get("tags"))
    fields = {t.field.lower() for alts in sels.values() for alt in alts for t in alt if t.field != "*"}
    canon = json.dumps(doc, sort_keys=True, default=str)
    sha = hashlib.sha256(canon.encode()).hexdigest()
    fps = doc.get("falsepositives") or []
    return SigmaRule(rule_id=str(doc.get("id") or sha[:16]), title=str(doc.get("title") or "Untitled Sigma rule")[:160], severity=level, level=str(doc.get("level", "medium")),
                     description=str(doc.get("description") or "")[:600], tactic=tactic, techniques=techniques, tags=[str(t) for t in doc.get("tags") or []],
                     falsepositives=[str(x) for x in (fps if isinstance(fps, list) else [fps])], selections=sels, condition=cond,
                     yaml_text=yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), sha256=sha, fields=fields)


def parse_rules(raw: bytes | str, filename: str = "rule.yml") -> tuple[list[SigmaRule], list[dict]]:
    """Parse one YAML file (possibly several documents). Returns (usable rules, skipped=[{name, reason}])."""
    data = raw if isinstance(raw, bytes) else raw.encode("utf-8")
    if len(data) > MAX_RULE_BYTES:
        return [], [{"name": filename, "reason": f"is larger than {MAX_RULE_BYTES // 1024} KB."}]
    text = data.decode("utf-8-sig", errors="replace")
    rules, skipped = [], []
    try:
        _refuse_aliases(text)
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except SigmaError as exc:
        return [], [{"name": filename, "reason": str(exc)}]
    except yaml.YAMLError as exc:
        return [], [{"name": filename, "reason": f"is not valid YAML ({str(exc).splitlines()[0]})."}]
    for i, doc in enumerate(docs):
        label = filename if len(docs) == 1 else f"{filename} (document {i + 1})"
        try:
            rules.append(_from_doc(doc, text))
        except SigmaError as exc:
            skipped.append({"name": label, "reason": str(exc)})
    return rules, skipped


# ----------------------------------------------------------------------------- condition language
def _tokenize(cond: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", cond)


def _parse_condition(cond: str, names: set[str]):
    toks, pos = _tokenize(cond), [0]

    def peek():
        return toks[pos[0]].lower() if pos[0] < len(toks) else None

    def take():
        pos[0] += 1
        return toks[pos[0] - 1]

    def expr():
        node = and_()
        while peek() == "or":
            take()
            node = ("or", node, and_())
        return node

    def and_():
        node = not_()
        while peek() == "and":
            take()
            node = ("and", node, not_())
        return node

    def not_():
        if peek() == "not":
            take()
            return ("not", not_())
        return atom()

    def atom():
        t = peek()
        if t is None:
            raise SigmaError("has an incomplete condition.")
        if t == "(":
            take()
            node = expr()
            if peek() != ")":
                raise SigmaError("has unbalanced parentheses in its condition.")
            take()
            return node
        if t in ("1", "all", "any") and pos[0] + 2 < len(toks) + 0 and toks[pos[0] + 1].lower() == "of":
            q = take().lower()
            take()
            target = take()
            matched = [n for n in sorted(names) if (target.lower() == "them" and not n.startswith("_")) or (target.lower() != "them" and fnmatch.fnmatchcase(n, target))]
            if not matched:
                raise SigmaError(f"has a condition that refers to '{target}', which matches no selection.")
            return ("all_of" if q == "all" else "any_of", matched)
        name = take()
        if name not in names:
            raise SigmaError(f"has a condition that refers to unknown selection '{name}'.")
        return ("sel", name)

    tree = expr()
    if pos[0] != len(toks):
        raise SigmaError(f"has an unexpected '{toks[pos[0]]}' in its condition.")
    return tree


# ----------------------------------------------------------------------------- evaluation
def _glob(v: str) -> str:
    return "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in v)


def _match(vals: pd.Series, t: Test) -> pd.Series:
    masks = []
    for v in t.values:
        if v is None:
            masks.append(vals == "")
            continue
        sv = str(v).lower()
        if t.op == "eq":
            masks.append(vals.str.fullmatch(_glob(sv)))
        elif t.op == "contains":
            masks.append(vals.str.contains(_glob(sv), regex=True) if ("*" in sv or "?" in sv) else vals.str.contains(sv, regex=False))
        elif t.op == "startswith":
            masks.append(vals.str.match(_glob(sv)))
        elif t.op == "endswith":
            masks.append(vals.str.contains(_glob(sv) + r"$", regex=True))
        elif t.op == "re":
            masks.append(vals.str.contains(str(v), regex=True, flags=re.IGNORECASE))
        elif t.op == "cidr":
            try:
                net = ipaddress.ip_network(str(v), strict=False)
            except ValueError as exc:
                raise SigmaError(f"invalid CIDR '{v}'.") from exc
            masks.append(vals.map(lambda x: _in_net(x, net)))
        else:  # lt lte gt gte
            num, ref = pd.to_numeric(vals, errors="coerce"), float(v)
            masks.append({"lt": num < ref, "lte": num <= ref, "gt": num > ref, "gte": num >= ref}[t.op].fillna(False))
    out = masks[0]
    for m in masks[1:]:
        out = (out & m) if t.match_all else (out | m)
    return out.astype(bool)


def _in_net(x: str, net) -> bool:
    try:
        return ipaddress.ip_address(x) in net
    except ValueError:
        return False


def extract_fields(events: pd.DataFrame, names: set[str]) -> dict[str, pd.Series]:
    """Lower-cased string value of each Sigma field for every event (raw record first, canonical column as fallback)."""
    out: dict[str, list] = {n: [] for n in names}
    if names and len(events):
        for raw in events["raw"].tolist():
            try:
                rec = json.loads(raw)
            except (TypeError, ValueError):
                rec = {}
            low = {str(k).lower(): v for k, v in rec.items()}
            for k, v in rec.items():
                low.setdefault(str(k).lower().rsplit(".", 1)[-1], v)
            for n in names:
                out[n].append(low.get(n))
    res = {}
    for n in names:
        s = pd.Series(out[n], index=events.index, dtype=object) if len(events) else pd.Series([], dtype=object)
        canon = CANONICAL_FIELDS.get(n)
        if canon and canon in events.columns:
            s = s.where(s.notna(), events[canon])
        res[n] = s.fillna("").astype(str).str.lower()
    return res


def _eval(node, sel_masks: dict[str, pd.Series]) -> pd.Series:
    kind = node[0]
    if kind == "sel":
        return sel_masks[node[1]]
    if kind == "not":
        return ~_eval(node[1], sel_masks)
    if kind == "and":
        return _eval(node[1], sel_masks) & _eval(node[2], sel_masks)
    if kind == "or":
        return _eval(node[1], sel_masks) | _eval(node[2], sel_masks)
    masks = [sel_masks[n] for n in node[1]]
    out = masks[0]
    for m in masks[1:]:
        out = (out & m) if kind == "all_of" else (out | m)
    return out


def match_events(rule: SigmaRule, events: pd.DataFrame, cache: dict | None = None) -> pd.DataFrame:
    """Events matched by the rule (a view of `events`)."""
    if events.empty:
        return events
    fields = cache if cache is not None else {}
    missing = {f for f in rule.fields if f not in fields}
    if missing:
        fields.update(extract_fields(events, missing))
    blob = None
    sel_masks = {}
    for name, alts in rule.selections.items():
        alt_masks = []
        for alt in alts:
            m = pd.Series(True, index=events.index)
            for t in alt:
                if t.field == "*":
                    if blob is None:
                        blob = events["raw"].fillna("").astype(str).str.lower()
                    m &= _match(blob, t)
                else:
                    m &= _match(fields[t.field.lower()], t)
            alt_masks.append(m)
        sel_masks[name] = pd.concat(alt_masks, axis=1).any(axis=1) if len(alt_masks) > 1 else alt_masks[0]
    return events[_eval(_parse_condition(rule.condition, set(rule.selections)), sel_masks)]
