"""Windows/Sysmon XML, Zeek, CloudTrail parsing and XML safety."""
from pathlib import Path

import pytest

from traceforge.ingest import normalize_file

FX = Path(__file__).parent / "fixtures"


def _load(name):
    return normalize_file((FX / name).read_bytes(), name)


def test_windows_security_and_sysmon_events():
    df, q = _load("windows_events.xml")
    t = df["event_type"].value_counts().to_dict()
    assert t["login_success"] == 5 and t["login_failure"] == 1 and t["process_exec"] == 2
    assert t["service_install"] == 1 and t["scheduled_task"] == 1 and t["network_flow"] == 10 and t["log_cleared"] == 1
    assert q.bad_timestamp == 0 and q.rows_kept == q.rows_read == len(df)
    logon = df[df["event_type"] == "login_success"].iloc[0]
    assert logon["src_ip"] == "10.0.2.55" and logon["user"] == "svc-backup" and logon["host"].endswith(".example.test")
    flow = df[df["event_type"] == "network_flow"].iloc[0]
    assert flow["dst_ip"] == "198.51.100.77" and int(flow["dst_port"]) == 443
    task = df[df["event_type"] == "scheduled_task"].iloc[0]
    assert task["command"] == r"C:\ProgramData\upd.exe -s"
    member = df[df["event_type"] == "group_add"].iloc[0]
    assert member["user"] == "support$admin"
    assert df[df["event_type"] == "log_cleared"].iloc[0]["user"] == "svc-backup"          # UserData block


def test_windows_raw_view_keeps_original_fields():
    df, _ = _load("windows_events.xml")
    assert "EventData.ParentImage" in df["raw"].iloc[0] or any("EventData.ParentImage" in r for r in df["raw"])


@pytest.mark.parametrize("payload", [
    b'<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY a "aaaa">]><Events><Event><System><EventID>1</EventID></System></Event></Events>',
    b'<Event><!ENTITY x "y"><System><EventID>4624</EventID></System></Event>',
])
def test_xml_with_doctype_or_entities_is_refused(payload):
    with pytest.raises(ValueError, match="DOCTYPE or ENTITY"):
        normalize_file(payload, "evil.xml")


def test_non_windows_xml_and_broken_xml_are_rejected_clearly():
    with pytest.raises(ValueError, match="not Windows Event XML"):
        normalize_file(b"<root><a>1</a></root>", "x.xml")
    with pytest.raises(ValueError, match="could not be read"):
        normalize_file(b'<Event><System><EventID>4624</System>', "x.xml")


def test_zeek_conn_log():
    df, q = _load("zeek_conn.log")
    assert len(df) == 11 and (df["event_type"] == "network_flow").all()
    row = df.iloc[0]
    assert row["src_ip"] == "10.0.1.42" and row["dst_ip"] == "198.51.100.77" and int(row["dst_port"]) == 8443 and row["bytes_out"] == 300
    assert str(df["timestamp"].iloc[0]).startswith("2026-03-1")
    assert q.invalid_ips == 0


def test_zeek_without_header_is_rejected():
    with pytest.raises(ValueError):
        normalize_file(b"#separator \\x09\n#path\tconn\n1773439200.0\tC1\n", "conn.log")


def test_cloudtrail_maps_console_logins_and_risky_calls():
    df, _ = _load("cloudtrail.json")
    types = df["event_type"].tolist()
    assert types.count("login_failure") == 1 and types.count("login_success") == 1
    assert "account_created" in types and "group_add" in types and "log_cleared" in types and "access_denied" in types
    assert not df["message"].str.contains("nan").any()
    assert df[df["event_type"] == "login_failure"].iloc[0]["user"] == "devops1"
    assert df["src_ip"].notna().sum() == 5                     # the S3 call came from a service name, not an IP


def test_cloudtrail_list_cells_do_not_break_the_raw_view():
    df, _ = _load("cloudtrail.json")
    assert "ARN" in df["raw"].iloc[0]
