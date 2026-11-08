"""Audit hash chain, evidence vault, and what the workspace writes to both."""
import io
import os
import sqlite3
import zipfile

import pytest

from traceforge.audit import GENESIS, AuditLog
from traceforge.evidence import EvidenceVault, IntegrityError
from traceforge.service import UserError, Workspace


def _log(n=5):
    conn = sqlite3.connect(":memory:")
    log = AuditLog(conn)
    for i in range(n):
        log.append("ana", "note_added", f"INC-00{i}", {"chars": i})
    return conn, log


def test_chain_verifies_and_links_entries():
    _, log = _log()
    v = log.verify()
    assert v["ok"] and v["entries"] == 5 and v["head_hash"] == log.entries(1)[0]["entry_hash"]
    first = log.entries(newest_first=False)[0]
    assert first["prev_hash"] == GENESIS and first["seq"] == 1
    assert AuditLog(sqlite3.connect(":memory:")).verify()["ok"]            # an empty log is valid


def test_triggers_block_update_and_delete():
    conn, _ = _log()
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE audit SET actor='x' WHERE seq=2")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM audit WHERE seq=2")


def test_editing_with_triggers_removed_is_detected():
    conn, log = _log()
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("UPDATE audit SET actor='mallory' WHERE seq=2")
    v = log.verify()
    assert not v["ok"] and v["first_bad_seq"] == 2 and "modified" in v["problem"]


def test_deleting_or_relinking_is_detected():
    conn, log = _log()
    conn.execute("DROP TRIGGER audit_no_delete")
    conn.execute("DELETE FROM audit WHERE seq=3")
    v = log.verify()
    assert not v["ok"] and v["first_bad_seq"] == 3 and "missing" in v["problem"]
    conn2, log2 = _log()
    conn2.execute("DROP TRIGGER audit_no_update")
    conn2.execute("UPDATE audit SET prev_hash=? WHERE seq=4", ("f" * 64,))
    assert "link" in log2.verify()["problem"]


def test_csv_export_neutralises_formulas_and_details_are_bounded():
    _, log = _log(1)
    log.append("=HYPERLINK(x)", "export", "+cmd", {"big": "x" * 5000})
    csv_text = log.export_csv()
    assert "'=HYPERLINK(x)" in csv_text and "'+cmd" in csv_text
    assert len(log.entries(1)[0]["detail"]["big"]) == 300                       # long strings are clipped
    log.append("ana", "export", "", {f"k{i}": "y" * 300 for i in range(20)})   # an oversized record is replaced, not stored
    assert log.entries(1)[0]["detail"] == {"truncated": True} and log.verify()["ok"]


def test_vault_roundtrip_and_tamper_detection(tmp_path):
    import hashlib
    v = EvidenceVault(tmp_path / "ev")
    raw = b"hello evidence"
    sha = hashlib.sha256(raw).hexdigest()
    v.put(sha, raw)
    assert v.read(sha) == raw and v.check(sha, len(raw)) is None
    assert not os.access(v.path(sha), os.W_OK) or os.geteuid() == 0         # stored read-only (root can always write)
    os.chmod(v.path(sha), 0o600)
    v.path(sha).write_bytes(raw + b"!")
    assert "modified" in v.check(sha)
    with pytest.raises(IntegrityError):
        v.read(sha)
    v.put(sha, raw)                                                        # re-import repairs a damaged copy
    assert v.check(sha) is None
    v.delete(sha)
    assert "missing" in v.check(sha)
    with pytest.raises(ValueError):
        v.path("../../etc/passwd")
    assert not EvidenceVault(None).enabled and EvidenceVault(None).check("0" * 64) is None


def test_evidence_survives_restart_and_is_listed_in_manifest(tmp_path):
    db = str(tmp_path / "data" / "t.db")
    ws = Workspace(db)
    assert ws.load_sample()["events"] == 555
    ws.set_state("INC-001", "Investigating", None)
    ws.store.conn.close()
    again = Workspace(db)
    m = again.meta()
    assert m["events"] == 555 and len(m["files"]) == 4 and m["integrity"]["ok"] and m["persistent"]
    assert again.incident_detail("INC-001")["verdict"] == "Investigating"
    assert len(again.store.evidence_manifest()) == 4
    assert all(f.suffix == ".bin" for f in (tmp_path / "data" / "evidence").iterdir())


def test_tampered_stored_file_is_flagged_excluded_and_repairable(tmp_path):
    db = str(tmp_path / "t.db")
    ws = Workspace(db)
    files = ws.load_sample() and list(ws.files)
    ws.store.conn.close()
    victim = sorted((tmp_path / "evidence").glob("*.bin"))[0]
    os.chmod(victim, 0o600)
    victim.write_bytes(victim.read_bytes() + b"x")
    again = Workspace(db)
    assert len(again.files) == 3 and not again.integrity["ok"] and again.integrity["problems"][0]["sha256"] == victim.stem
    assert any(e["action"] == "integrity_failure" for e in again.store.audit.entries(50))
    name = again.integrity["problems"][0]["name"]
    again.load_files([(n, r) for n, r in files if n == name])                # original re-uploaded
    assert again.verify_integrity()["ok"] and again.meta()["events"] == 555


def test_removing_and_clearing_delete_stored_copies(tmp_path):
    ws = Workspace(str(tmp_path / "t.db"))
    ws.load_sample()
    sha = ws.meta()["files"][0]["sha256"]
    ws.remove_file(sha)
    assert not (tmp_path / "evidence" / f"{sha}.bin").exists() and len(list((tmp_path / "evidence").glob("*.bin"))) == 3
    ws.clear()
    assert list((tmp_path / "evidence").glob("*.bin")) == [] and ws.store.evidence_manifest() == []


def test_memory_workspace_stores_nothing_on_disk(tmp_path):
    ws = Workspace(":memory:")
    ws.load_sample()
    assert not ws.vault.enabled and ws.verify_integrity()["ok"]


def test_analyst_actions_are_audited_with_the_right_detail():
    ws = Workspace(":memory:")
    ws.load_sample()
    ws.set_case({"name": "Lab", "analyst": "Ana", "tlp": "TLP:GREEN"})
    ws.set_state("INC-001", "True positive", 80)
    ws.add_note("INC-001", "secret note text")
    ws.set_check("INC-001", ws.incident_detail("INC-001")["remediation"][0]["step"], True)
    ws.add_iocs(["198.51.100.77"], None, "c2", "analyst")
    ioc_id = ws.iocs_list()["iocs"][0]["id"]
    ws.delete_ioc(ioc_id)
    ws.set_config({"brute_force": {"failures": 9}})
    ws.markdown()
    log = {e["action"]: e for e in reversed(ws.store.audit.entries(200))}
    for a in ("app_started", "evidence_added", "case_updated", "verdict_set", "note_added", "checklist_changed", "ioc_added", "ioc_deleted", "settings_changed", "export"):
        assert a in log, a
    assert log["verdict_set"]["detail"]["verdict"] == "True positive" and log["verdict_set"]["detail"]["previous"] == "Unreviewed"
    assert log["verdict_set"]["actor"] == "Ana"
    assert "secret note text" not in str(ws.store.audit.entries(200))         # only a hash and length of the note are logged
    assert log["note_added"]["detail"]["chars"] == 16 and len(log["note_added"]["detail"]["sha256"]) == 64
    assert log["settings_changed"]["detail"]["changed"] == ["brute_force"]
    assert log["export"]["target"] == "report.md" and ws.audit_status()["ok"]


def test_rejected_files_and_archives_are_audited():
    ws = Workspace(":memory:")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("ok.csv", b"timestamp,src_ip,user,event_type\n2026-03-11T10:00:00Z,203.0.113.5,a,login_failure\n")
    ws.load_files([("bundle.zip", buf.getvalue())])
    with pytest.raises(UserError):
        ws.load_files([("bad.csv", b"a,b\n1,2\n")])
    actions = [e["action"] for e in ws.store.audit.entries(50)]
    assert "archive_expanded" in actions and "evidence_rejected" in actions
    assert ws.meta()["files"][0]["name"] == "bundle.zip/ok.csv"


def test_case_file_roundtrip_with_and_without_passphrase():
    ws = Workspace(":memory:")
    ws.load_sample()
    ws.add_note("INC-002", "n", )
    ws.add_iocs(["203.0.113.45"], None, "x", "analyst")
    plain, enc = ws.export_case(), ws.export_case("a long passphrase")
    assert "203.0.113.45" in plain and "203.0.113.45" not in enc
    fresh = Workspace(":memory:")
    fresh.load_sample()
    r = fresh.import_case(enc.encode(), "a long passphrase")
    assert r["encrypted"] and r["iocs_added"] == 1 and r["evidence_check"]["missing"] == []
    with pytest.raises(UserError, match="passphrase"):
        fresh.import_case(enc.encode(), "")
    with pytest.raises(UserError, match="Wrong passphrase"):
        fresh.import_case(enc.encode(), "not the right one!")
    with pytest.raises(UserError, match="Not a valid"):
        fresh.import_case(b"[1,2,3]")
    with pytest.raises(UserError, match="at least 10"):
        ws.export_case("short")
    empty = Workspace(":memory:")
    assert empty.import_case(plain.encode())["evidence_check"]["missing"]      # evidence the case expected but has not been loaded
