"""Report structure and data-hygiene checks (industry-style incident report)."""
import io
import json
import re

import pytest
from pypdf import PdfReader

from traceforge.report import (_phase, _phased, _when, affected_assets, key_observations, report_id, report_status)
from traceforge.service import Workspace
import pandas as pd


@pytest.fixture(scope="module")
def ws():
    w = Workspace(":memory:")
    w.load_sample()
    w.set_case({"name": "Suspicious Logs", "analyst": "Den Mark", "tlp": "TLP:AMBER"})
    return w


def _pdf_text(ws):
    return [p.extract_text() for p in PdfReader(io.BytesIO(ws.pdf())).pages]


def test_no_missing_value_markers_or_broken_entities_leak_into_the_pdf(ws):
    text = " ".join(_pdf_text(ws))
    assert "<NA>" not in text and "ATT&CK;" not in text and "nan" not in re.findall(r"\b\w+\b", text)


def test_pdf_has_the_standard_sections_in_order(ws):
    text = " ".join(_pdf_text(ws))
    sections = ["Contents", "1. Executive summary", "2. Scope and evidence integrity", "3. Affected assets", "4. Incident analysis",
                "5. Indicators of compromise", "Appendix A. Findings register", "Appendix B.", "Appendix C. Methodology", "Sign-off"]
    pos = [text.index(s, text.index("1. Executive summary") if s != "Contents" else 0) for s in sections]
    assert pos == sorted(pos)
    assert re.search(r"Page 1 of \d+", text) and "Report ID" in text and "Handling (TLP:AMBER)" in text


def test_draft_status_until_every_incident_has_a_verdict():
    w = Workspace(":memory:")
    w.load_sample()
    status, reasons = report_status(w.report_context("off"))
    assert status == "DRAFT" and "4 of 4" in reasons[0]
    for inc in w.incidents:
        w.set_state(inc.incident_id, "True positive", None)
    assert report_status(w.report_context("off"))[0] == "FINAL"
    assert "DRAFT" not in " ".join(PdfReader(io.BytesIO(w.pdf())).pages[1].extract_text().split("Executive")[0:1])


def test_report_id_is_stable_for_the_same_evidence(ws):
    a, b = ws.report_context("off"), ws.report_context("off")
    assert report_id(a).startswith("TF-") and report_id(a)[-8:] == report_id(b)[-8:]


def test_windows_never_drop_the_end_date():
    s, e = pd.Timestamp("2026-03-13 08:06"), pd.Timestamp("2026-03-14 03:14")
    assert _when(s, e) == "2026-03-13 08:06 to 2026-03-14 03:14 UTC"
    assert _when(s, pd.Timestamp("2026-03-13 11:20")) == "2026-03-13 08:06 to 11:20 UTC"


def test_ioc_pseudo_tactic_is_not_presented_as_an_attack_tactic(ws):
    ctx = ws.report_context("off")
    assert all(o["tactic"] != "Threat Intel Match" for o in key_observations(ctx))
    assert "Threat Intel Match" not in " ".join(_pdf_text(ws))


def test_response_actions_are_grouped_into_phases():
    assert _phase("Block the source IP") == 0 and _phase("Scope the activity: search logs") == 1 and _phase("Enable MFA") == 2
    phases = _phased(["Enable MFA", "Block the IP", "Hunt for the same command"])
    assert [p for p, _ in phases] == ["Immediate containment", "Investigation and scoping", "Recovery and hardening"]


def test_affected_assets_cover_accounts_hosts_and_both_ip_kinds(ws):
    kinds = {a["type"] for a in affected_assets(ws.report_context("off"))}
    assert {"Account", "Host", "Internal IP", "External IP"} <= kinds


def test_json_and_markdown_carry_the_same_structure(ws):
    data = json.loads(ws.json_report())
    assert data["status"] == "DRAFT" and data["report_id"].startswith("TF-") and data["key_observations"] and data["affected_assets"]
    assert data["incidents"][0]["response_actions"][0]["phase"] == "Immediate containment"
    md = ws.markdown()
    assert "**DRAFT" in md and "Appendix A. Findings register" in md and "Immediate containment" in md and "<NA>" not in md


def test_severity_escalation_ignores_the_ioc_pseudo_tactic():
    from traceforge.correlate import build_incidents
    from traceforge.detect import run_detections
    from traceforge.ingest import build_dataset
    from traceforge.store import Store
    from rule_cases import brute_force
    ev, _ = build_dataset([("b.csv", brute_force())])
    st = Store()
    st.add_ioc("203.0.113.50")
    inc = build_incidents(run_detections(ev, iocs=st.iocs()), ev)
    assert inc[0].severity != "critical"           # one real tactic (+ IOC match) must not reach "three tactics"


def test_cli_analyze_writes_all_outputs(tmp_path):
    from pathlib import Path

    from traceforge import cli
    sample = sorted(str(p) for p in (Path(__file__).parent.parent / "traceforge" / "sample_data").glob("*"))
    rc = cli.main(["analyze", *sample, "--case", "CLI", "--tlp", "TLP:GREEN", "--pdf", str(tmp_path / "r.pdf"), "--md", str(tmp_path / "r.md"),
                   "--json", str(tmp_path / "r.json"), "--stix", str(tmp_path / "s.json"), "--attack-layer", str(tmp_path / "l.json")])
    assert rc == 0 and (tmp_path / "r.pdf").read_bytes().startswith(b"%PDF")
    assert "Redacted for sharing" in (tmp_path / "r.md").read_text() and json.loads((tmp_path / "l.json").read_text())["techniques"]
