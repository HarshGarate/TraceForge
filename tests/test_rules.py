"""Every built-in rule fires on its synthetic case, and the new rules stay quiet on near-misses."""
import pytest
from rule_cases import CASES, IOCS, _csv, _t

from traceforge.config import RULES, TECHNIQUE_NAMES
from traceforge.detect import run_detections
from traceforge.ingest import build_dataset
from traceforge.store import Store


def _run(csv_bytes, cfg=None, iocs=()):
    ev, _ = build_dataset([("case.csv", csv_bytes)])
    st = Store()
    for v in iocs:
        st.add_ioc(v)
    diag = []
    f = run_detections(ev, cfg, st.iocs(), diagnostics=diag)
    assert diag == []
    return f


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_on_its_case(rule_id):
    f = _run(CASES[rule_id](), iocs=IOCS.get(rule_id, ()))
    assert rule_id in set(f["rule_id"])


def test_every_rule_has_a_case_and_complete_metadata():
    assert set(CASES) | {"sigma_match"} == set(RULES)
    for rid, meta in RULES.items():
        assert meta["false_positives"].strip(), rid
        assert meta["remediation"] and meta["description"] and meta["technique"], rid
        if rid not in ("sigma_match", "ioc_match"):          # these two carry no fixed ATT&CK technique
            ids = [t for t in meta["technique"].replace("/", " ").split() if t.startswith("T")]
            assert ids and all(i in TECHNIQUE_NAMES for i in ids), (rid, ids)


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_can_be_disabled(rule_id):
    f = _run(CASES[rule_id](), cfg={rule_id: {"enabled": False}}, iocs=IOCS.get(rule_id, ()))
    assert rule_id not in set(f["rule_id"])


def test_lateral_movement_needs_enough_distinct_hosts():
    rows = [dict(timestamp=_t(i), src_ip="10.0.2.55", user="svc", event_type="login_success", host=f"srv{i}") for i in range(3)]
    assert "lateral_movement" not in set(_run(_csv(rows))["rule_id"])
    slow = [dict(timestamp=_t(i * 20 % 60, hour=10 + i // 3), src_ip="10.0.2.55", user="svc", event_type="login_success", host=f"srv{i}") for i in range(6)]
    assert "lateral_movement" not in set(_run(_csv(slow))["rule_id"])      # same hosts spread over hours


def test_lateral_movement_detects_remote_execution_tools():
    f = _run(_csv([dict(timestamp=_t(0), user="a", event_type="process_exec", host="ws1", command=r"PsExec.exe \\srv01 -s cmd.exe")]))
    assert "PsExec" in f[f["rule_id"] == "lateral_movement"].iloc[0]["summary"]


def test_mfa_fatigue_severity_rises_when_a_login_follows():
    rows = [dict(timestamp=_t(i), src_ip="203.0.113.60", user="asmith", event_type="mfa_denied") for i in range(6)]
    quiet = _run(_csv(rows))
    assert quiet[quiet["rule_id"] == "mfa_fatigue"].iloc[0]["severity"] == "high"
    loud = _run(_csv(rows + [dict(timestamp=_t(8), src_ip="203.0.113.60", user="asmith", event_type="login_success")]))
    assert loud[loud["rule_id"] == "mfa_fatigue"].iloc[0]["severity"] == "critical"
    few = _run(_csv(rows[:3]))
    assert "mfa_fatigue" not in set(few["rule_id"])


def test_office_rule_ignores_normal_parents():
    msg = r"Image=C:\Windows\System32\cmd.exe ParentImage=C:\Windows\explorer.exe"
    f = _run(_csv([dict(timestamp=_t(0), event_type="process_exec", host="ws", command="cmd.exe", message=msg)]))
    assert "office_spawns_shell" not in set(f["rule_id"])


def test_beaconing_ignores_irregular_and_internal_traffic():
    irregular = [dict(timestamp=_t(m), src_ip="10.0.1.42", dst_ip="198.51.100.77", dst_port=443, host="ws3", event_type="network_flow") for m in (0, 1, 7, 8, 21, 22, 40, 41, 55, 56)]
    assert "beaconing" not in set(_run(_csv(irregular))["rule_id"])
    internal = [dict(timestamp=_t(i), src_ip="10.0.1.42", dst_ip="10.0.9.9", dst_port=443, host="ws3", event_type="network_flow") for i in range(10)]
    assert "beaconing" not in set(_run(_csv(internal))["rule_id"])
    few = [dict(timestamp=_t(i), src_ip="10.0.1.42", dst_ip="198.51.100.77", dst_port=443, host="ws3", event_type="network_flow") for i in range(5)]
    assert "beaconing" not in set(_run(_csv(few))["rule_id"])


def test_beaconing_tolerates_some_jitter():
    secs = [0, 61, 119, 182, 241, 300, 362, 420, 481, 540]
    rows = [dict(timestamp=_t(s // 60, sec=s % 60), src_ip="10.0.1.42", dst_ip="198.51.100.77", dst_port=443, host="ws3", event_type="network_flow") for s in secs]
    assert "beaconing" in set(_run(_csv(rows))["rule_id"])


def test_persistence_covers_service_task_and_run_key():
    rows = [dict(timestamp=_t(0), event_type="process_exec", host="a", command="sc.exe create Updater binPath= C:\\x.exe"),
            dict(timestamp=_t(1), event_type="process_exec", host="b", command=r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v u /d C:\x.exe")]
    summaries = " ".join(_run(_csv(rows)).query("rule_id == 'persistence_mechanism'")["summary"])
    assert "Service installed" in summaries and "Autorun registry key" in summaries
