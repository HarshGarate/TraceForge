"""Pins the bundled demo so edits to sample data (or to the tests that depend on it) are caught with a clear message."""
from traceforge.service import Workspace


def test_bundled_demo_headline_numbers(sample_files):
    assert sorted(n for n, _ in sample_files) == ["endpoint_events.json", "firewall.csv", "vpn_auth.csv", "web_access.json"], (
        "traceforge/sample_data was modified; restore it with `python scripts/generate_sample_data.py`")
    ws = Workspace(":memory:")
    ws.load_sample()
    assert len(ws.events) == 555
    assert len(ws.findings) == 16
    assert [i.incident_id for i in ws.incidents] == ["INC-001", "INC-002", "INC-003", "INC-004"]
    assert ws.incidents[0].severity == "critical" and "user-01" in ws.incidents[0].entities["user"]
