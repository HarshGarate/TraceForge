import copy

from traceforge.config import DEFAULT_CONFIG
from traceforge.correlate import build_incidents
from traceforge.detect import run_detections
from traceforge.ingest import build_dataset
from traceforge.store import Store

EXPECTED = {"brute_force", "password_spray", "success_after_failures", "multi_ip_login", "off_hours_login", "sensitive_activity",
            "web_scan", "web_attack_payload", "suspicious_command", "large_outbound", "port_scan"}


def test_all_expected_rules_fire_on_sample(sample):
    _, _, findings, _ = sample
    assert EXPECTED <= set(findings["rule_id"])


def test_findings_reference_real_events(sample):
    events, _, findings, _ = sample
    ids = set(events["event_id"])
    assert all(set(e) <= ids and len(e) == c for e, c in zip(findings["event_ids"], findings["count"]))


def test_thresholds_are_configurable(sample):
    events, *_ = sample
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["brute_force"]["failures"] = 500
    cfg["large_outbound"]["megabytes"] = 5000
    ids = set(run_detections(events, cfg)["rule_id"])
    assert "brute_force" not in ids and "large_outbound" not in ids


def test_benign_noise_alone_produces_no_findings(sample):
    events, *_ = sample
    quiet = events[(events["timestamp"].dt.hour >= 8) & (events["timestamp"].dt.hour < 10) & events["source"].isin(["vpn_auth.csv"])]
    assert run_detections(quiet.reset_index(drop=True)).empty


def test_ioc_match_creates_finding(sample):
    events, *_ = sample
    s = Store()
    s.add_ioc("198.51.100.77")
    f = run_detections(events, None, s.iocs())
    hit = f[f["rule_id"] == "ioc_match"]
    assert len(hit) == 1 and hit.iloc[0]["count"] == 6


def test_incident_reconstruction(sample):
    events, _, findings, incidents = sample
    assert len(incidents) == 4
    main = incidents[0]
    assert main.severity == "critical" and main.incident_id == "INC-001"
    assert {"Reconnaissance", "Credential Access", "Persistence", "Exfiltration"} <= set(main.tactics)
    assert "203.0.113.45" in main.entities["ip"] and "user-01" in main.entities["user"]
    # the 03:10 spray and the unrelated scans must NOT be merged into the main incident
    assert "198.51.100.23" not in main.entities["ip"] and "192.0.2.50" not in main.entities["ip"]
    assert main.narrative == sorted(main.narrative)


def test_confidence_is_explained(sample):
    *_, incidents = sample
    for inc in incidents:
        assert inc.confidence == max(5, min(95, sum(p for _, p in inc.confidence_factors)))
        assert 5 <= inc.confidence <= 95


def test_empty_input_is_handled():
    csv = b"timestamp,src_ip\n2026-01-01T00:00:00Z,1.1.1.1\n"
    events, _ = build_dataset([("e.csv", csv)])
    f = run_detections(events)
    assert f.empty and build_incidents(f, events) == []
