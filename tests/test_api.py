"""End-to-end tests of the HTTP API (what the browser console calls)."""
import io

import pytest
from fastapi.testclient import TestClient

from traceforge.config import RULES
from traceforge.security import SecurityConfig
from traceforge.server import create_app
from traceforge.service import Workspace


@pytest.fixture()
def client():
    return TestClient(create_app(Workspace(":memory:"), SecurityConfig.for_tests()))


@pytest.fixture()
def loaded(client):
    assert client.post("/api/sample").json()["events"] == 555
    return client


def test_empty_workspace_and_static_ui(client):
    m = client.get("/api/meta").json()
    assert m["has_data"] is False and m["events"] == 0
    page = client.get("/")
    assert page.status_code == 200 and "TRACEFORGE" in page.text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/api/export/pdf").status_code == 400  # needs evidence first
    assert page.headers["x-content-type-options"] == "nosniff"


def test_sample_produces_expected_incidents(loaded):
    cards = loaded.get("/api/incidents").json()["incidents"]
    assert [c["id"] for c in cards] == ["INC-001", "INC-002", "INC-003", "INC-004"]
    assert cards[0]["severity"] == "critical" and cards[0]["alerted_events"] > 90
    d = loaded.get("/api/dashboard").json()
    assert d["findings"] == 16 and d["diagnostics"] == [] and d["histogram"]["buckets"]


def test_incident_detail_summary_is_a_list_the_ui_can_render(loaded):
    d = loaded.get("/api/incidents/INC-001").json()
    assert isinstance(d["summary"], list) and d["summary"][1].startswith("Observed")
    assert d["remediation"] and d["techniques"] and d["confidence_factors"]
    ev = loaded.get("/api/incidents/INC-001/events?scope=alerted").json()
    assert ev["total"] == d["alerted_events"] and ev["histogram"]["buckets"]
    assert loaded.get("/api/incidents/INC-001/events?q=whoami").json()["total"] >= 1
    raw = loaded.get(f"/api/events/{ev['events'][0]['id']}").json()
    assert raw["raw"] and raw["finding_details"]


def test_analyst_work_persists_and_survives_threshold_changes(loaded):
    assert loaded.put("/api/incidents/INC-001/state", json={"verdict": "Investigating"}).json()["state"] == "INVESTIGATING"
    loaded.post("/api/incidents/INC-001/notes", json={"note": "VPN account disabled"})
    step = loaded.get("/api/incidents/INC-001").json()["remediation"][0]["step"]
    loaded.put("/api/incidents/INC-001/remediation", json={"step": step, "done": True})
    d = loaded.get("/api/incidents/INC-001").json()
    assert d["verdict"] == "Investigating" and d["notes"][0]["note"] == "VPN account disabled" and d["remediation"][0]["done"]
    # change correlation window: incident ids may be renumbered but the stable key keeps the analyst's work attached
    loaded.put("/api/settings", json={"correlation": {"max_gap_minutes": "60"}, "brute_force": {"failures": "6"}})
    again = loaded.get("/api/incidents").json()["incidents"]
    assert any(c["key"] == d["key"] and c["verdict"] == "Investigating" for c in again)
    assert loaded.put("/api/incidents/INC-001/state", json={"verdict": "Bogus"}).status_code == 400


def test_ioc_lifecycle_creates_findings(loaded):
    before = loaded.get("/api/meta").json()["findings"]
    r = loaded.post("/api/iocs", json={"values": ["198.51.100.77", "198.51.100.77", "evil.example.com"]}).json()
    assert r == {"added": 2, "duplicates": 1}
    rows = loaded.get("/api/iocs").json()["iocs"]
    hit = next(i for i in rows if i["value"] == "198.51.100.77")
    assert hit["type"] == "ipv4" and hit["matches"] > 0
    assert loaded.get("/api/meta").json()["findings"] > before
    loaded.delete(f"/api/iocs/{hit['id']}")
    assert all(i["value"] != "198.51.100.77" for i in loaded.get("/api/iocs").json()["iocs"])


def test_settings_validation_and_effect(loaded):
    s = loaded.get("/api/settings").json()
    assert len(s["rules"]) == len(RULES)
    r = loaded.put("/api/settings", json={"brute_force": {"enabled": True, "failures": "99999"}, "bogus": {"x": 1}}).json()
    bf = next(x for x in r["settings"]["rules"] if x["id"] == "brute_force")
    assert next(p for p in bf["params"] if p["key"] == "failures")["value"] == 500  # clamped
    assert not any(f["rule_id"] == "brute_force" for f in loaded.get("/api/findings").json()["findings"])
    loaded.post("/api/settings/reset")
    assert any(f["rule_id"] == "brute_force" for f in loaded.get("/api/findings").json()["findings"])


def test_upload_raw_text_logs_and_bad_files(client):
    nginx = b'203.0.113.9 - - [13/Mar/2026:22:03:10 +0000] "GET /a?id=1%20UNION%20SELECT%20NULL HTTP/1.1" 200 5 "-" "x"\n'
    auth = b"".join(b"Mar 13 22:15:%02d vpn01 sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 22 ssh2\n" % i for i in range(8))
    r = client.post("/api/upload", files=[("files", ("access.log", io.BytesIO(nginx))), ("files", ("auth.log", io.BytesIO(auth)))])
    assert r.status_code == 200 and r.json()["events"] == 9
    rules = {f["rule_id"] for f in client.get("/api/findings").json()["findings"]}
    assert {"web_attack_payload", "brute_force"} <= rules
    bad = client.post("/api/upload", files=[("files", ("empty.csv", io.BytesIO(b"  ")))])
    assert bad.status_code == 400 and "empty" in bad.json()["error"]
    bad = client.post("/api/upload", files=[("files", ("x.csv", io.BytesIO(b"a,b\n1,2\n")))])
    assert bad.status_code == 400 and "timestamp" in bad.json()["error"]


def test_exports_and_case_roundtrip(loaded):
    pdf = loaded.get("/api/export/pdf")
    assert pdf.content.startswith(b"%PDF") and "attachment" in pdf.headers["content-disposition"]
    assert "INC-001" in loaded.get("/api/export/markdown").text
    assert loaded.get("/api/export/json").json()["incidents"]
    assert loaded.get("/api/export/evidence.csv").text.startswith("event_id")
    loaded.put("/api/case", json={"name": "Lab 01", "analyst": "Ana", "tlp": "TLP:RED"})
    loaded.post("/api/incidents/INC-002/notes", json={"note": "spray only"})
    case = loaded.get("/api/export/case").content
    loaded.post("/api/clear")
    assert loaded.get("/api/meta").json()["has_data"] is False
    loaded.post("/api/sample")
    res = loaded.post("/api/import/case", files={"file": ("case.json", io.BytesIO(case))}).json()
    assert res["notes"] == 1
    assert loaded.get("/api/incidents/INC-002").json()["notes"][0]["note"] == "spray only"
    assert loaded.post("/api/import/case", files={"file": ("x.json", io.BytesIO(b"not json"))}).status_code == 400


def test_timeline_and_events_pages(loaded):
    t = loaded.get("/api/timeline?lane=user&flagged=true").json()
    assert t["points"] and t["incidents"] and t["lanes"]
    p = loaded.get("/api/events?page=2&size=100&types=login_failure").json()
    assert p["total"] > 0 and all(e["type"] == "login_failure" for e in p["events"])


def test_recording_iocs_does_not_orphan_analyst_work(loaded):
    key = loaded.get("/api/incidents/INC-001").json()["key"]
    loaded.put("/api/incidents/INC-001/state", json={"verdict": "True positive"})
    loaded.post("/api/iocs", json={"values": ["203.0.113.45", "198.51.100.77", "user-01"]})  # the earliest-seen attacker IP included
    cards = {c["key"]: c for c in loaded.get("/api/incidents").json()["incidents"]}
    assert cards[key]["verdict"] == "True positive"


NGINX = b'203.0.113.9 - - [13/Mar/2026:22:03:10 +0000] "GET /a HTTP/1.1" 200 5 "-" "x"\n'
AUTH = b"Mar 13 22:15:00 vpn01 sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 22 ssh2\n"


def _up(client, *named, **kw):
    return client.post("/api/upload" + ("?replace=true" if kw.get("replace") else ""), files=[("files", (n, io.BytesIO(b))) for n, b in named])


def test_files_can_be_added_one_after_another_and_listed(client):
    assert _up(client, ("access.log", NGINX)).json()["files_added"] == 1
    r = _up(client, ("auth.log", AUTH)).json()          # the second upload must ADD, not replace or fail
    assert r["files_added"] == 1 and r["events"] == 2
    files = client.get("/api/meta").json()["files"]
    assert [f["name"] for f in files] == ["access.log", "auth.log"]
    assert files[0]["events"] == 1 and files[0]["start"] and files[0]["mapped"] and len(files[0]["sha256"]) == 64


def test_mixed_batch_keeps_good_files_and_reports_the_bad(client):
    r = _up(client, ("good.log", NGINX), ("bad.csv", b"a,b\n1,2\n"), ("empty.log", b"   ")).json()
    assert r["added"] == ["good.log"] and {x["name"] for x in r["rejected"]} == {"bad.csv", "empty.log"}
    assert "timestamp" in next(x["error"] for x in r["rejected"] if x["name"] == "bad.csv")
    assert client.get("/api/meta").json()["events"] == 1


def test_duplicates_are_skipped_and_same_name_is_kept_apart(client):
    _up(client, ("a.log", NGINX))
    r = _up(client, ("a.log", NGINX)).json()
    assert r["files_added"] == 0 and r["duplicates"] == ["a.log"]
    r = _up(client, ("a.log", AUTH)).json()               # same name, different content
    assert r["added"] == ["a (2).log"]


def test_remove_one_file_and_then_all(client):
    _up(client, ("access.log", NGINX), ("auth.log", AUTH))
    sha = client.get("/api/meta").json()["files"][0]["sha256"]
    m = client.delete(f"/api/files/{sha}").json()
    assert m["events"] == 1 and [f["name"] for f in m["files"]] == ["auth.log"]
    sha2 = m["files"][0]["sha256"]
    m = client.delete(f"/api/files/{sha2}").json()
    assert m["has_data"] is False and m["files"] == []
    assert client.delete("/api/files/" + "0" * 64).status_code == 400


def test_sample_flag_and_new_investigation(loaded):
    assert loaded.get("/api/meta").json()["sample"] is True
    loaded.put("/api/case", json={"name": "Old case"})
    loaded.post("/api/iocs", json={"values": ["198.51.100.77"]})
    loaded.post("/api/incidents/INC-001/notes", json={"note": "x"})
    m = loaded.post("/api/case/new", json={"name": "Phishing - Finance", "analyst": "Ana", "tlp": "TLP:RED", "clear_iocs": False}).json()
    assert m["has_data"] is False and m["case"]["name"] == "Phishing - Finance" and m["case"]["tlp"] == "TLP:RED" and m["iocs"] == 1
    m = loaded.post("/api/case/new", json={"name": "   ", "clear_iocs": True}).json()
    assert m["case"]["name"] == "Untitled investigation" and m["iocs"] == 0


def test_investigation_details_survive_a_restart(tmp_path):
    db = str(tmp_path / "t.db")
    ws = Workspace(db)
    ws.set_case({"name": "Lab 7", "analyst": "Ana", "organization": "Acme", "tlp": "TLP:GREEN"})
    ws.store.conn.close()
    again = Workspace(db)
    assert again.case == {"name": "Lab 7", "analyst": "Ana", "organization": "Acme", "tlp": "TLP:GREEN"}


# ---------------------------------------------------------------------------------- access control
def _locked_client(**kw):
    cfg = SecurityConfig(allowed_hosts={"testserver", "localhost", "127.0.0.1"}, token="T0KEN", reusable_token=False, **kw)
    return TestClient(create_app(Workspace(":memory:"), cfg))


def test_token_gate_and_session_cookie():
    c = _locked_client()
    assert c.get("/api/meta").status_code == 401 and "Access token required" in c.get("/").text
    assert c.get("/healthz").json() == {"status": "ok"}
    r = c.get("/?token=T0KEN", follow_redirects=False)
    assert r.status_code == 303 and "HttpOnly" in r.headers["set-cookie"] and "SameSite=Strict" in r.headers["set-cookie"]
    assert c.get("/api/meta").status_code == 200
    assert _locked_client().get("/?token=wrong", follow_redirects=False).status_code == 401


def test_foreign_host_and_cross_origin_requests_are_refused(client):
    assert client.get("/api/meta", headers={"host": "evil.example.com"}).status_code == 400
    assert client.post("/api/clear", headers={"origin": "http://evil.example.com"}).status_code == 403
    assert client.post("/api/clear", headers={"origin": "null"}).status_code == 403
    assert client.post("/api/clear", headers={"origin": "http://testserver"}).status_code == 200


def test_security_headers_present(client):
    h = client.get("/api/meta").headers
    assert "frame-ancestors 'none'" in h["content-security-policy"] and h["x-frame-options"] == "DENY" and h["referrer-policy"] == "no-referrer"


def test_oversized_upload_is_refused_with_413():
    cfg = SecurityConfig.for_tests()
    cfg.max_request_bytes = 2000
    c = TestClient(create_app(Workspace(":memory:"), cfg))
    assert c.post("/api/upload", files=[("files", ("big.csv", io.BytesIO(b"a" * 5000)))]).status_code == 413


# ---------------------------------------------------------------------------------- audit, integrity, redaction, standards
def test_audit_and_integrity_endpoints(loaded):
    loaded.post("/api/incidents/INC-001/notes", json={"note": "x"})
    a = loaded.get("/api/audit").json()
    assert a["head"]["entries"] >= 3 and a["entries"][0]["action"] == "note_added"
    v = loaded.get("/api/audit/verify").json()
    assert v["ok"] and v["head_hash"] == a["head"]["head_hash"]
    assert loaded.get("/api/audit?action=evidence_added").json()["entries"][0]["action"] == "evidence_added"
    assert loaded.post("/api/integrity/verify").json()["ok"] is True
    csv = loaded.get("/api/export/audit.csv")
    assert csv.status_code == 200 and csv.text.startswith("seq,timestamp_utc")
    about = loaded.get("/api/about").json()
    assert about["token_required"] is False and "No data leaves this computer" in about["privacy"]
    assert loaded.get("/api/meta").json()["integrity"]["ok"] is True


def test_redaction_follows_the_marking_and_can_be_overridden(loaded):
    loaded.put("/api/case", json={"tlp": "TLP:CLEAR"})
    md = loaded.get("/api/export/markdown").text
    assert "user-01" not in md and "Redacted for sharing" in md
    assert "user-01" in loaded.get("/api/export/markdown?redact=off").text
    assert loaded.get("/api/export/markdown?redact=bogus").status_code == 422
    assert loaded.get("/api/export/pdf").content.startswith(b"%PDF")
    assert loaded.get("/api/report/preview").json()["redaction_auto"]


def test_stix_and_attack_layer_exports(loaded):
    loaded.post("/api/iocs", json={"values": ["198.51.100.77"]})
    bundle = loaded.get("/api/export/iocs.stix.json").json()
    assert bundle["type"] == "bundle" and bundle["objects"][0]["pattern"] == "[ipv4-addr:value = '198.51.100.77']"
    layer = loaded.get("/api/export/attack-layer.json").json()
    assert layer["domain"] == "enterprise-attack" and layer["techniques"]


def test_encrypted_case_file_roundtrip_over_http(loaded):
    loaded.post("/api/iocs", json={"values": ["203.0.113.45"]})
    enc = loaded.post("/api/export/case/encrypted", json={"passphrase": "a long passphrase"})
    assert enc.status_code == 200 and b"203.0.113.45" not in enc.content
    assert loaded.post("/api/export/case/encrypted", json={"passphrase": "short"}).status_code == 400
    loaded.delete("/api/iocs/1")
    bad = loaded.post("/api/import/case", files={"file": ("c.tfcase", enc.content)}, data={"passphrase": "wrong wrong wrong"})
    assert bad.status_code == 400 and "Wrong passphrase" in bad.json()["error"]
    ok = loaded.post("/api/import/case", files={"file": ("c.tfcase", enc.content)}, data={"passphrase": "a long passphrase"})
    assert ok.status_code == 200 and ok.json()["iocs_added"] == 1 and ok.json()["encrypted"] is True


def test_sigma_import_over_http(loaded):
    rule = b"title: Whoami\nlevel: low\ntags: [attack.discovery, attack.t1033]\ndetection:\n  s:\n    CommandLine|contains: whoami\n  condition: s\n"
    r = loaded.post("/api/sigma", files=[("files", ("w.yml", io.BytesIO(rule)))]).json()
    assert r["added"] == ["Whoami"] and r["meta"]["sigma_rules"] == 1
    listing = loaded.get("/api/sigma").json()["rules"]
    assert listing[0]["tactic"] == "Discovery"
    assert loaded.delete(f"/api/sigma/{listing[0]['id']}").json()["meta"]["sigma_rules"] == 0
    assert loaded.delete("/api/sigma/999").status_code == 400


def test_zip_upload_is_expanded_and_names_are_flattened(client):
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../x/auth.csv", b"timestamp,src_ip,user,event_type\n2026-03-11T10:00:00Z,203.0.113.5,a,login_failure\n")
    r = client.post("/api/upload", files=[("files", ("logs.zip", buf.getvalue()))]).json()
    assert r["added"] == ["logs.zip/auth.csv"]
