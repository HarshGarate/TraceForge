"""The lab_data scenario pack: deterministic, parseable in every supported format, and covering every detection rule."""
import gzip
import importlib.util
import sys
import zipfile
from collections import Counter
from pathlib import Path

import pytest

from traceforge import sigma
from traceforge.cli import _read_inputs, main
from traceforge.config import RULES, merged_config
from traceforge.detect import run_detections
from traceforge.ingest import build_dataset
from traceforge.store import Store

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "lab_data"


def _store():
    st = Store()
    for line in (PACK / "iocs.txt").read_text(encoding="utf-8").split():
        st.add_ioc(line, source="pack")
    return st


def _rules():
    out = []
    for f in sorted((PACK / "sigma_rules").glob("*.yml")):
        found, _ = sigma.parse_rules(f.read_bytes(), f.name)
        out += found
    return out


def _analyse(name):
    events, quality = build_dataset(_read_inputs([str(PACK / name)]))
    findings = run_detections(events, merged_config(), _store().iocs(), sigma_rules=_rules())
    return events, quality, Counter(findings["rule_id"]) if len(findings) else Counter()


def test_pack_is_reproducible(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("gen_pack", ROOT / "scripts" / "generate_scenario_pack.py")
    gen = importlib.util.module_from_spec(spec)
    sys.modules["gen_pack"] = gen
    spec.loader.exec_module(gen)
    monkeypatch.setattr(gen, "OUT", tmp_path / "lab_data")
    gen.main()
    def snapshot(root):
        # compressed bytes differ between zlib builds (Linux, Windows, zlib-ng), so compare what is inside the archives
        out = {}
        for p in root.rglob("*"):
            if not p.is_file() or p.name == "README.md":
                continue
            if p.suffix == ".zip":
                with zipfile.ZipFile(p) as z:
                    out[p.relative_to(root)] = {n: z.read(n) for n in sorted(z.namelist())}
            elif p.suffix == ".gz":
                out[p.relative_to(root)] = gzip.decompress(p.read_bytes())
            else:
                out[p.relative_to(root)] = p.read_bytes()
        return out

    fresh, shipped = snapshot(tmp_path / "lab_data"), snapshot(PACK)
    assert fresh == shipped, "lab_data is out of date: run `python scripts/generate_scenario_pack.py`"


def test_one_csv_triggers_every_rule():
    events, quality, rules = _analyse("01_all_scenarios.csv")
    assert set(rules) == set(RULES), f"never fired: {sorted(set(RULES) - set(rules))}"
    assert len(events) == 152 and quality[0].bad_timestamp == 0


@pytest.mark.parametrize("name,expected", [
    ("02_web_access.log", {"web_scan", "web_attack_payload"}),
    ("03_ssh_auth_syslog.log", {"brute_force", "password_spray", "success_after_failures", "sensitive_activity"}),
    ("04_firewall_keyvalue.log", {"port_scan", "large_outbound"}),
    ("05_windows_security_sysmon.xml", {"brute_force", "lateral_movement", "persistence_mechanism", "sensitive_activity", "suspicious_command", "office_spawns_shell", "beaconing"}),
    ("06_zeek_conn.log", {"beaconing", "port_scan"}),
    ("07_cloudtrail.json", {"brute_force", "success_after_failures", "sensitive_activity"}),
    ("08_ecs_nested.ndjson", {"brute_force", "success_after_failures"}),
    ("09_splunk_style_epoch.csv", {"port_scan", "brute_force", "large_outbound"}),
    ("11_bundle.zip", {"web_scan", "web_attack_payload", "port_scan", "large_outbound"}),
    ("12_ssh_auth_syslog.log.gz", {"brute_force", "password_spray", "success_after_failures", "sensitive_activity"}),
])
def test_each_format_triggers_its_documented_rules(name, expected):
    _, quality, rules = _analyse(name)
    assert expected <= set(rules), f"{name}: missing {sorted(expected - set(rules))}"
    assert all(q.rows_kept == q.rows_read for q in quality)       # nothing in a clean file is dropped


def test_archive_and_gzip_match_their_plain_originals():
    assert _analyse("12_ssh_auth_syslog.log.gz")[2] == _analyse("03_ssh_auth_syslog.log")[2]


def test_edge_case_file_reports_what_it_drops():
    events, quality, rules = _analyse("10_data_quality_edge_cases.csv")
    q = quality[0]
    assert (q.rows_read, q.rows_kept, q.bad_timestamp, q.invalid_ips) == (13, 9, 4, 1)
    assert {"extra_notes", "ticket_id"} <= set(q.unmapped_columns)
    assert "user-09" in set(events["user"]) and not rules          # whitespace/case normalised; benign content raises no finding


def test_unsupported_sigma_rule_is_skipped_with_a_reason():
    found, skipped = sigma.parse_rules((PACK / "sigma_rules" / "unsupported_aggregation.yml").read_bytes(), "x.yml")
    assert not found and skipped and "aggregation" in skipped[0]["reason"]


def test_cli_runs_the_whole_pack(capsys):
    rc = main(["analyze", str(PACK / "01_all_scenarios.csv"), "--ioc-file", str(PACK / "iocs.txt"), "--sigma", str(PACK / "sigma_rules"), "--fail-on", "critical"])
    out = capsys.readouterr()
    assert rc == 2 and "152 events | 42 findings | 18 incidents" in out.out and "unsupported_aggregation.yml" in out.err
