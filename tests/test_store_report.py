import json

from traceforge.report import ReportContext, build_json, build_markdown, build_pdf
from traceforge.store import Store, classify_ioc


def test_classify_ioc():
    assert classify_ioc("1.2.3.4") == "ipv4"
    assert classify_ioc("a" * 64) == "sha256"
    assert classify_ioc("https://evil.example/x") == "url"
    assert classify_ioc("evil.example.com") == "domain"
    assert classify_ioc("someuser") == "username"


def test_store_roundtrip():
    s = Store()
    assert s.add_ioc("203.0.113.45") and not s.add_ioc("203.0.113.45")
    s.add_note("INC-001", "checked firewall", "me")
    s.set_verdict("INC-001", "True positive", 80)
    s.set_verdict("INC-001", "True positive", None)
    assert s.verdict("INC-001") == {"verdict": "True positive", "confidence_override": None}
    t = Store()
    res = t.import_case(s.export_case())
    assert res["iocs_added"] == 1 and len(t.notes()) == 1 and t.verdict("INC-001")["verdict"] == "True positive"


def _ctx(sample):
    events, quality, findings, incidents = sample
    s = Store()
    s.add_ioc("198.51.100.77")
    s.add_note(incidents[0].incident_id, "Confirmed with firewall team", "tester")
    return ReportContext(case_name="Test <case> & co", analyst="Tester", events=events, findings=findings, incidents=incidents,
                         iocs=s.iocs(), notes=s.notes(), quality=quality,
                         verdicts={incidents[0].incident_id: {"verdict": "True positive", "confidence_override": 88}})


def test_pdf_builds_and_contains_key_facts(sample, tmp_path):
    pdf = build_pdf(_ctx(sample))
    assert pdf.startswith(b"%PDF") and len(pdf) > 20_000
    (tmp_path / "r.pdf").write_bytes(pdf)
    from pypdf import PdfReader
    text = " ".join(p.extract_text() for p in PdfReader(str(tmp_path / "r.pdf")).pages)
    for needle in ("INC-001", "True positive", "88/100", "Confirmed with firewall team", sample[1][0].sha256[:16]):
        assert needle in text


def test_markdown_and_json(sample):
    ctx = _ctx(sample)
    assert "INC-001" in build_markdown(ctx)
    data = json.loads(build_json(ctx))
    assert len(data["incidents"]) == 4 and data["incidents"][0]["effective_confidence"] == 88


def test_csv_formula_injection_is_neutralised():
    import pandas as pd
    from traceforge.report import csv_safe
    out = csv_safe(pd.DataFrame({"a": ["=cmd|' /C calc'!A0", "+1", "ok", "-5"], "n": [1, -2, 3, 4]}))
    assert out["a"].tolist()[:2] == ["'=cmd|' /C calc'!A0", "'+1"] and out["a"][2] == "ok" and out["n"].tolist() == [1, -2, 3, 4]
