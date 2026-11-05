import json

import pandas as pd
import pytest

from traceforge.ingest import classify_event, is_internal, normalize_file


def test_alias_mapping_and_normalisation():
    csv = b"Time,SourceIP,TargetUserName,EventID,Computer\n2026-01-01T10:00:00Z,10.0.0.5,CORP\\Alice,4625,DC01\n"
    df, q = normalize_file(csv, "a.csv")
    row = df.iloc[0]
    assert row["user"] == "alice" and row["src_ip"] == "10.0.0.5" and row["host"] == "dc01"
    assert row["event_type"] == "login_failure"
    assert str(row["timestamp"].tzinfo) == "UTC"
    assert q.rows_kept == 1 and len(q.sha256) == 64


def test_epoch_seconds_and_millis():
    df, _ = normalize_file(b"epoch,src\n1773446400,1.2.3.4\n", "f.csv")
    assert df.iloc[0]["timestamp"].year == 2026
    df, _ = normalize_file(b"epoch,src\n1773446400000,1.2.3.4\n", "f.csv")
    assert df.iloc[0]["timestamp"].year == 2026


def test_nested_json_and_ndjson():
    obj = {"@timestamp": "2026-01-01T00:00:00Z", "source": {"ip": "8.8.8.8"}, "user": {"name": "user@example.test"}, "event": {"action": "login-failed"}}
    for payload in (json.dumps([obj]), json.dumps({"events": [obj]}), json.dumps(obj) + "\n" + json.dumps(obj)):
        df, _ = normalize_file(payload.encode(), "x.json")
        assert df.iloc[0]["src_ip"] == "8.8.8.8" and df.iloc[0]["user"] == "bob"
        assert df.iloc[0]["event_type"] == "login_failure"


def test_bad_rows_are_counted_not_invented():
    csv = b"timestamp,src_ip\nnot-a-date,1.1.1.1\n2026-01-01T00:00:00Z,999.1.1.1\n2026-01-01T00:00:01Z,1.1.1.1\n"
    df, q = normalize_file(csv, "b.csv")
    assert q.bad_timestamp == 1 and q.invalid_ips == 1 and len(df) == 2
    assert pd.isna(df.iloc[0]["src_ip"])


def test_missing_timestamp_column_raises():
    with pytest.raises(ValueError):
        normalize_file(b"a,b\n1,2\n", "c.csv")


def test_event_classification():
    assert classify_event("", "Failed password for invalid user root") == "login_failure"
    assert classify_event("Accepted password", "") == "login_success"
    assert classify_event("deny", "") == "firewall_block"
    assert classify_event("", "The audit log was cleared") == "log_cleared"


def test_is_internal():
    assert is_internal("10.1.2.3") and is_internal("192.168.0.1")
    assert not is_internal("203.0.113.45")  # documentation range is treated as external


def test_plain_text_logs_are_parsed():
    from traceforge.ingest import normalize_file
    nginx = b'203.0.113.9 - bob [13/Mar/2026:22:03:11 +0200] "GET /admin HTTP/1.1" 404 - "-" "curl/8"\n'
    df, q = normalize_file(nginx, "access.log")
    r = df.iloc[0]
    assert r["event_type"] == "web_request" and r["src_ip"] == "203.0.113.9" and r["user"] == "bob" and r["status_code"] == 404
    assert str(r["timestamp"]) == "2026-03-13 20:03:11+00:00"  # +02:00 converted to UTC

    auth = (b"Mar 13 22:15:00 vpn01 sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 5 ssh2\n"
            b"Mar 13 22:15:05 vpn01 sshd[1]: Accepted password for user-01 from 203.0.113.9 port 6 ssh2\n"
            b"Mar 13 22:20:01 vpn01 useradd[9]: new user: name=svc_backup2, UID=1002\n")
    df, _ = normalize_file(auth, "auth.log")
    assert df["event_type"].tolist() == ["login_failure", "login_success", "account_created"]
    assert df["user"].tolist() == ["admin", "user-01", "svc_backup2"] and df["host"].iloc[0] == "vpn01"

    ufw = (b"Mar 13 22:00:01 fw1 kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.50 DST=10.0.0.5 PROTO=TCP DPT=22\n"
           b"2026-03-13T22:00:02Z action=allow src=10.0.0.9 dst=198.51.100.77 dpt=443 bytes=73000000\n")
    df, _ = normalize_file(ufw, "fw.log")
    assert df["event_type"].tolist() == ["firewall_block", "network_flow"] and df["dst_port"].tolist() == [22, 443]

    df, q = normalize_file(b"2026-03-13 22:31:12 user=mallory login failed from 203.0.113.9\nundated junk line\n", "app.txt")
    assert len(df) == 1 and q.bad_timestamp == 1 and df["event_type"].iloc[0] == "login_failure"
