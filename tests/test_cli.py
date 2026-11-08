import json

import pytest

from traceforge.cli import EXIT_GATE_TRIGGERED, main


@pytest.fixture()
def sample_paths(tmp_path):
    from pathlib import Path

    import traceforge
    return [str(p) for p in sorted((Path(traceforge.__file__).parent / "sample_data").glob("*"))]


def test_analyze_writes_requested_outputs(sample_paths, tmp_path, capsys):
    md, js, stix, layer = (tmp_path / n for n in ("r.md", "r.json", "i.json", "l.json"))
    rc = main(["analyze", *sample_paths, "--md", str(md), "--json", str(js), "--stix", str(stix), "--attack-layer", str(layer), "--tlp", "TLP:GREEN"])
    out = capsys.readouterr().out
    assert rc == 0 and "555 events | 16 findings | 4 incidents" in out
    assert md.read_text(encoding="utf-8").startswith("# TraceForge Incident Report")
    assert json.loads(layer.read_text(encoding="utf-8"))["techniques"]


@pytest.mark.parametrize("level,expected", [("critical", EXIT_GATE_TRIGGERED), ("high", EXIT_GATE_TRIGGERED), ("low", EXIT_GATE_TRIGGERED)])
def test_fail_on_trips_when_the_demo_contains_that_severity(sample_paths, level, expected, capsys):
    assert main(["analyze", *sample_paths, "--fail-on", level]) == expected
    assert "gate:" in capsys.readouterr().err


def test_fail_on_passes_when_nothing_reaches_the_threshold(tmp_path, capsys):
    quiet = tmp_path / "quiet.csv"
    quiet.write_text("timestamp,src_ip,user,event_type\n2026-03-13T09:00:00Z,10.0.0.5,user-01,login_success\n", encoding="utf-8")
    assert main(["analyze", str(quiet), "--fail-on", "low"]) == 0
    assert "gate:" not in capsys.readouterr().err


def test_without_the_flag_findings_never_change_the_exit_status(sample_paths):
    assert main(["analyze", *sample_paths]) == 0
