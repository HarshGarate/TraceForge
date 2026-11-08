"""TLP redaction, Sigma import/matching, STIX and ATT&CK Navigator exports, case encryption."""
import io
import json
import re
import uuid

import pytest

from traceforge import sigma
from traceforge.casecrypt import CaseCryptoError, decrypt_case, encrypt_case, is_encrypted_case
from traceforge.exporters import navigator_layer, stix_bundle, stix_pattern
from traceforge.ingest import build_dataset
from traceforge.redact import Redactor, policy_for
from traceforge.service import Workspace
from pathlib import Path

FX = Path(__file__).parent / "fixtures"


# ------------------------------------------------------------------------------ redaction
def test_policy_by_marking():
    assert policy_for("TLP:CLEAR").notes and policy_for("TLP:CLEAR").org
    g = policy_for("TLP:GREEN")
    assert g.users and g.hosts and g.internal_ips and not g.notes
    for t in ("TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"):
        assert not policy_for(t).active
    assert policy_for("TLP:RED", "on").users and not policy_for("TLP:CLEAR", "off").active


def test_masking_is_consistent_and_leaves_external_ips_alone():
    r = Redactor(policy_for("TLP:GREEN"), users={"jsmith", "admin"}, hosts={"web01.corp.local", "web01"}, ips={"10.0.1.5", "203.0.113.9"})
    out = r.text(r"CORP\jsmith from 10.0.1.5 to web01.corp.local; JSmith@corp.local; attacker 203.0.113.9; Administrators; 10.0.9.9")
    assert "jsmith" not in out.lower() and "web01" not in out and "10.0.1.5" not in out and "10.0.9.9" not in out
    assert "203.0.113.9" in out and "Administrators" in out                      # not a substring match on "admin"
    assert out.count("user-02") == 2 and re.search(r"internal-ip-0\d", out)       # same account -> same token (case-insensitive)
    assert r.text("host web01.corp.local ok") == r.text("host web01.corp.local ok")
    assert Redactor(policy_for("TLP:RED"), users={"jsmith"}).text("jsmith") == "jsmith"


def test_ipv6_internal_addresses_are_masked():
    r = Redactor(policy_for("TLP:GREEN"), ips={"fd12:3456::1", "2606:4700::1111"})          # unique-local is internal, a public address is not
    out = r.text("from fd12:3456::1 and 2606:4700::1111")
    assert "fd12:3456::1" not in out and "internal-ip-01" in out and "2606:4700::1111" in out


@pytest.fixture(scope="module")
def loaded_ws():
    ws = Workspace(":memory:")
    ws.load_sample()
    ws.add_note("INC-001", "user-01 confirmed on 10.0.1.27", )
    ws.add_iocs(["198.51.100.77", "user-01", "10.0.1.27"], None, "t", "analyst")
    return ws


def test_clear_marking_removes_identifiers_from_every_report_format(loaded_ws):
    ws = loaded_ws
    ws.set_case({"tlp": "TLP:CLEAR", "organization": "Acme Corp", "analyst": "Ana"})
    names = {u for u in ws.events["user"].dropna().unique() if len(u) > 3}
    md, js = ws.markdown(), ws.json_report()
    for text in (md, js, ws.evidence_csv(), ws.iocs_csv()):
        assert "10.0.1.27" not in text and not any(re.search(rf"(?<![\w.-]){re.escape(u)}(?![\w-]|\.\w)", text) for u in names), text[:200]
    assert "198.51.100.77" in md and "withheld" in md and "Redacted for sharing" in md
    pdf_text = " ".join(__import__("pypdf").PdfReader(io.BytesIO(ws.pdf())).pages[i].extract_text() for i in range(3))
    assert "user-01" not in pdf_text and re.search(r"user-(1[1-9]|[2-9]\d)", pdf_text)   # pseudonyms never reuse a real account name
    ws.set_case({"tlp": "TLP:AMBER"})
    assert "user-01" in ws.markdown() and "user-01" not in ws.markdown("on")
    assert "user-01" in ws.markdown("off")


def test_shareable_iocs_drop_usernames_and_internal_ips_when_masking(loaded_ws):
    ws = loaded_ws
    ws.set_case({"tlp": "TLP:GREEN"})
    values = {o["id"] and o["pattern"].split("'")[1] for o in json.loads(ws.iocs_stix())["objects"]}
    assert values == {"198.51.100.77"}
    ws.set_case({"tlp": "TLP:AMBER"})
    assert len(json.loads(ws.iocs_stix())["objects"]) == 3


# ------------------------------------------------------------------------------ STIX / Navigator
def test_stix_bundle_is_stable_and_escaped():
    import pandas as pd
    df = pd.DataFrame([{"ioc_type": "url", "value": "http://x/a'b\\c", "note": "", "added_utc": "2026-03-13 10:00:00"},
                       {"ioc_type": "sha256", "value": "a" * 64, "note": "dropper", "added_utc": "2026-03-13 10:00:00"},
                       {"ioc_type": "weird", "value": "zzz", "note": "", "added_utc": "x"}])
    b1, b2 = json.loads(stix_bundle(df, "TLP:AMBER", "case")), json.loads(stix_bundle(df, "TLP:AMBER", "case"))
    assert [o["id"] for o in b1["objects"]] == [o["id"] for o in b2["objects"]] and len(b1["objects"]) == 2
    for o in b1["objects"]:
        assert o["spec_version"] == "2.1" and o["type"] == "indicator" and uuid.UUID(o["id"].split("--")[1])
        assert o["object_marking_refs"] == ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"]
    assert b1["objects"][0]["pattern"] == r"[url:value = 'http://x/a\'b\\c']"
    assert stix_pattern("sha256", "ab") == "[file:hashes.'SHA-256' = 'ab']" and stix_pattern("nope", "x") is None


def test_navigator_layer_scores_techniques_by_finding_count(loaded_ws):
    layer = json.loads(navigator_layer(loaded_ws.findings, "Case"))
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    ids = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert any(i.startswith("T1110") for i in ids) and all(re.fullmatch(r"T\d{4}(\.\d{3})?", i) for i in ids)
    assert layer["gradient"]["maxValue"] == max(ids.values())


# ------------------------------------------------------------------------------ Sigma
RULE = r"""
title: Encoded PowerShell from Office
id: 11111111-2222-3333-4444-555555555555
tags: [attack.execution, attack.t1059.001]
level: high
falsepositives: [Admin scripts]
detection:
  parent:
    ParentImage|endswith: ['\excel.exe', '\winword.exe']
  child:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all: [' -enc', '-nop']
  filter:
    User: 'CORP\admin'
  condition: parent and child and not filter
"""


@pytest.fixture(scope="module")
def win_events():
    return build_dataset([("windows_events.xml", (FX / "windows_events.xml").read_bytes())])[0]


def _match(yaml_text, events):
    rules, skipped = sigma.parse_rules(yaml_text, "r.yml")
    assert not skipped, skipped
    return sigma.match_events(rules[0], events)


def test_sigma_rule_metadata_and_matching(win_events):
    rule = sigma.parse_rules(RULE, "r.yml")[0][0]
    assert rule.severity == "high" and rule.tactic == "Execution" and rule.techniques == ["T1059.001"]
    assert len(sigma.match_events(rule, win_events)) == 1
    assert len(_match(RULE.replace("CORP\\admin", "CORP\\mchen"), win_events)) == 0           # the filter now excludes the match


@pytest.mark.parametrize("body,expected", [
    ("sel: {EventID: 4624, LogonType: 3}\n  condition: sel", 5),
    ("a: {EventID: 4624}\n  b: {LogonType|re: '^(3|10)$'}\n  condition: a and b", 5),
    ("a: {IpAddress|cidr: 10.0.2.0/24}\n  condition: a", 5),
    ("sel1: {EventID: 4624}\n  sel2: {EventID: 4625}\n  condition: 1 of sel*", 6),
    ("sel1: {EventID: 4624}\n  sel2: {LogonType: 3}\n  condition: all of sel*", 5),
    ("sel: {EventID: 4624}\n  condition: not sel and (sel or sel)", 0),
    ("k: ['upd.exe']\n  condition: k", 2),
    ("sel: {TargetUserName: 'svc-*'}\n  condition: sel", 5),
    ("sel: {EventID|gte: 4697, DestinationPort: null}\n  condition: sel", 4),
])
def test_sigma_conditions_and_modifiers(win_events, body, expected):
    assert len(_match(f"title: t\ndetection:\n  {body}\n", win_events)) == expected


@pytest.mark.parametrize("doc,reason", [
    ("title: x\ndetection:\n  s: {a: 1}\n  condition: s | count() > 3\n", "aggregation"),
    ("title: x\ndetection:\n  s: {a: 1}\n  timeframe: 5m\n  condition: s\n", "timeframe"),
    ("title: x\ndetection:\n  s: {a|base64: 1}\n  condition: s\n", "unsupported modifier"),
    ("title: x\ndetection:\n  s: {a: 1}\n  condition: nope\n", "unknown selection"),
    ("title: x\ndetection:\n  s: {a: 1}\n  condition: 1 of zz*\n", "matches no selection"),
    ("title: x\ndetection:\n  s: {a: 1}\n  condition: (s\n", "parentheses"),
    ("title: x\ndetection:\n  s: {a|re: '(a+)+$'}\n  condition: s\n", "backtrack"),
    ("title: x\ndetection:\n  s: {a|re: '['}\n  condition: s\n", "invalid regular"),
    ("title: x\nlogsource: {}\n", "no 'detection'"),
    ("a: &x 1\nb: *x\n", "anchors"),
    ("{{{{ not yaml", "not valid YAML"),
])
def test_unsupported_or_unsafe_rules_are_skipped_with_a_reason(doc, reason):
    rules, skipped = sigma.parse_rules(doc, "bad.yml")
    assert not rules and reason in skipped[0]["reason"]


def test_multi_document_files_and_size_limit():
    rules, skipped = sigma.parse_rules(RULE + "\n---\ntitle: bad\n", "multi.yml")
    assert len(rules) == 1 and len(skipped) == 1
    assert sigma.parse_rules(b"x" * (sigma.MAX_RULE_BYTES + 1), "big.yml")[1][0]["reason"].endswith("KB.")


def test_sigma_findings_in_workspace_with_persistence(tmp_path):
    db = str(tmp_path / "t.db")
    ws = Workspace(db)
    ws.load_files([("windows_events.xml", (FX / "windows_events.xml").read_bytes())])
    res = ws.sigma_import([("r.yml", RULE.encode()), ("bad.yml", b"title: x\ndetection:\n  s: {a: 1}\n  condition: s | count() > 1\n")])
    assert res["added"] == ["Encoded PowerShell from Office"] and "aggregation" in res["skipped"][0]["reason"]
    f = ws.findings[ws.findings["rule_id"] == "sigma_match"]
    assert len(f) == 1 and f.iloc[0]["rule_name"] == "Sigma: Encoded PowerShell from Office" and f.iloc[0]["tactic"] == "Execution" and f.iloc[0]["severity"] == "high"
    assert ws.sigma_import([("r.yml", RULE.encode())])["skipped"][0]["reason"].endswith("already imported.")
    ws.store.conn.close()
    again = Workspace(db)
    assert len(again.sigma_list()["rules"]) == 1 and again.sigma_list()["rules"][0]["matches"] == 1
    again.sigma_delete(again.sigma_list()["rules"][0]["id"])
    assert (again.findings["rule_id"] == "sigma_match").sum() == 0


def test_a_failing_sigma_rule_is_reported_not_fatal(win_events):
    from traceforge.detect import run_detections
    rules = sigma.parse_rules("title: t\ndetection:\n  s: {a|cidr: 'not-a-network'}\n  condition: s\n", "x.yml")[0]
    diag = []
    run_detections(win_events, diagnostics=diag, sigma_rules=rules)
    assert diag and diag[0]["rule_id"] == "sigma_match"


# ------------------------------------------------------------------------------ case encryption
def test_case_encryption_roundtrip_and_failure_modes():
    blob = encrypt_case(b'{"secret": 1}', "correct horse battery")
    assert is_encrypted_case(blob) and not is_encrypted_case('{"format": "traceforge-case"}') and not is_encrypted_case("junk")
    assert b"secret" not in blob.encode() and decrypt_case(blob, "correct horse battery") == b'{"secret": 1}'
    assert encrypt_case(b"x", "correct horse battery") != encrypt_case(b"x", "correct horse battery")      # fresh salt and nonce
    with pytest.raises(CaseCryptoError):
        decrypt_case(blob, "wrong passphrase!!")
    env = json.loads(blob)
    for field, value in (("n", 2**16), ("salt", "AAAA"), ("version", 2)):
        bad = {**env, field: value}
        with pytest.raises(CaseCryptoError):
            decrypt_case(json.dumps(bad), "correct horse battery")
    with pytest.raises(CaseCryptoError, match="unsupported key-derivation"):
        decrypt_case(json.dumps({**env, "n": 2**30}), "correct horse battery")                          # refuses a memory-exhaustion request
    with pytest.raises(CaseCryptoError, match="damaged"):
        decrypt_case("not json", "correct horse battery")
    with pytest.raises(CaseCryptoError, match="at least 10"):
        encrypt_case(b"x", "short")


def test_techniques_ignore_placeholders_such_as_n_a():
    from traceforge.service import _techs
    assert [t["id"] for t in _techs(["n/a", "T1110.001 / T1110.003", "T1021", "garbage"])] == ["T1110.001", "T1110.003", "T1021"]


def test_pseudonyms_never_collide_with_real_identifiers():
    """Anonymised datasets often use user-01 / host-01 style names; the masking tokens must not reuse them."""
    r = Redactor(policy_for("TLP:GREEN"), users={"user-01", "user-02", "alice"}, hosts={"host-01", "dc01"}, ips={"10.0.0.5", "internal-ip-01"})
    out = r.text("user-01 alice host-01 dc01 10.0.0.5")
    tokens = out.split()
    assert len(set(tokens)) == 5                                   # five distinct originals stay five distinct tokens
    assert not ({"user-01", "user-02", "host-01"} & set(tokens))   # none of the tokens is a real identifier
    assert r.text(out) == out                                      # masking is idempotent: tokens are not re-masked
