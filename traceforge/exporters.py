"""Standards-based exports: STIX 2.1 indicator bundle and MITRE ATT&CK Navigator layer."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pandas as pd

_NS = uuid.UUID("5c6f8a7e-3b1d-4c2a-9a55-7a1e0d1c9f00")      # fixed namespace: the same IOC always gets the same id
# OASIS-defined TLP 1.0 marking definitions (STIX has no TLP 2.0 objects; CLEAR maps to WHITE, AMBER+STRICT to AMBER).
TLP_MARKING = {
    "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:AMBER+STRICT": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def _q(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(ioc_type: str, value: str) -> str | None:
    v = _q(value)
    return {
        "ipv4": f"[ipv4-addr:value = '{v}']", "ipv6": f"[ipv6-addr:value = '{v}']", "domain": f"[domain-name:value = '{v}']",
        "url": f"[url:value = '{v}']", "email": f"[email-addr:value = '{v}']", "username": f"[user-account:account_login = '{v}']",
        "md5": f"[file:hashes.MD5 = '{v}']", "sha1": f"[file:hashes.'SHA-1' = '{v}']", "sha256": f"[file:hashes.'SHA-256' = '{v}']",
    }.get(ioc_type)


def _ts(s: str) -> str:
    try:
        return datetime.strptime(str(s), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def stix_bundle(iocs: pd.DataFrame, tlp: str = "TLP:AMBER", case_name: str = "") -> str:
    objects = []
    marking = TLP_MARKING.get(tlp)
    for _, r in iocs.iterrows():
        pattern = stix_pattern(str(r["ioc_type"]), str(r["value"]))
        if not pattern:
            continue
        when = _ts(r["added_utc"])
        key = f"{r['ioc_type']}|{r['value']}"
        obj = {"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid5(_NS, key)}",
               "created": when, "modified": when, "name": f"{r['ioc_type']}: {r['value']}"[:200],
               "description": (str(r["note"]) if r["note"] else f"Indicator recorded in TraceForge case '{case_name}'")[:500],
               "indicator_types": ["malicious-activity"], "pattern": pattern, "pattern_type": "stix", "valid_from": when}
        if marking:
            obj["object_marking_refs"] = [marking]
        objects.append(obj)
    return json.dumps({"type": "bundle", "id": f"bundle--{uuid.uuid5(_NS, case_name + str(len(objects)))}", "objects": objects}, indent=2)


def navigator_layer(findings: pd.DataFrame, case_name: str = "TraceForge case") -> str:
    """ATT&CK Navigator layer (v4.5): technique score = number of findings that mapped to it."""
    from .service import _techs   # local import: avoids a cycle at module load

    scores: dict[str, dict] = {}
    for _, f in findings.iterrows():
        for t in _techs([f["technique"]]):
            s = scores.setdefault(t["id"], {"score": 0, "rules": set()})
            s["score"] += 1
            s["rules"].add(f["rule_name"])
    techniques = [{"techniqueID": tid, "score": v["score"], "comment": "; ".join(sorted(v["rules"]))[:500]} for tid, v in sorted(scores.items())]
    layer = {
        "name": f"TraceForge - {case_name}"[:120], "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"}, "domain": "enterprise-attack",
        "description": "Techniques mapped from TraceForge findings. Score = number of findings. Adjust the ATT&CK version in Navigator if needed.",
        "sorting": 3, "layout": {"layout": "side", "showName": True, "showID": True}, "hideDisabled": False,
        "techniques": techniques, "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": max([t["score"] for t in techniques] + [1])},
        "legendItems": [], "metadata": [], "showTacticRowBackground": False, "selectTechniquesAcrossTactics": True,
    }
    return json.dumps(layer, indent=2)
