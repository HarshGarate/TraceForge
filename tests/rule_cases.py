"""One synthetic, minimal data set per built-in rule that must make that rule fire.

Kept free of pytest imports so scripts/generate_coverage.py can read it. The same cases back the
"Proven by" column in docs/DETECTION_COVERAGE.md.
"""
from __future__ import annotations

COLS = "timestamp,src_ip,dst_ip,dst_port,user,event_type,host,message,status_code,url,bytes_out,command"


def _csv(rows: list[dict]) -> bytes:
    cols = COLS.split(",")
    out = [COLS]
    for r in rows:
        out.append(",".join('"' + str(r.get(c, "")).replace('"', '""') + '"' for c in cols))
    return ("\n".join(out) + "\n").encode()


def _t(minute: int, hour: int = 10, sec: int = 0, day: int = 11) -> str:     # 2026-03-11 is a Wednesday
    return f"2026-03-{day:02d}T{hour:02d}:{minute:02d}:{sec:02d}Z"


def brute_force():
    return _csv([dict(timestamp=_t(i), src_ip="203.0.113.50", user="jsmith", event_type="login_failure", message="Failed password") for i in range(6)])


def password_spray():
    return _csv([dict(timestamp=_t(i), src_ip="203.0.113.51", user=f"user{i}", event_type="login_failure", message="Failed password") for i in range(6)])


def success_after_failures():
    rows = [dict(timestamp=_t(i), src_ip="203.0.113.52", user="mchen", event_type="login_failure", message="Failed password") for i in range(3)]
    return _csv(rows + [dict(timestamp=_t(5), src_ip="203.0.113.52", user="mchen", event_type="login_success", message="Accepted password")])


def multi_ip_login():
    return _csv([dict(timestamp=_t(i * 10), src_ip=ip, user="asmith", event_type="login_success", message="Accepted") for i, ip in enumerate(("203.0.113.60", "198.51.100.61", "192.0.2.62"))])


def off_hours_login():
    return _csv([dict(timestamp=_t(0, hour=3), src_ip="203.0.113.70", user="bjones", event_type="login_success", message="Accepted")])


def sensitive_activity():
    return _csv([dict(timestamp=_t(0), user="svc", event_type="account_created", host="dc01", message="Account backdoor created"),
                 dict(timestamp=_t(1), user="backdoor", event_type="group_add", host="dc01", message="added to Administrators"),
                 dict(timestamp=_t(2), user="svc", event_type="log_cleared", host="dc01", message="The audit log was cleared")])


def web_scan():
    return _csv([dict(timestamp=_t(i // 6, sec=(i % 6) * 10), src_ip="198.51.100.80", event_type="web_request", host="web01", status_code=404, url=f"/admin{i}") for i in range(16)])


def web_attack_payload():
    return _csv([dict(timestamp=_t(0), src_ip="198.51.100.81", event_type="web_request", host="web01", status_code=200, url="/item?id=1' UNION SELECT username,password FROM users--")])


def suspicious_command():
    return _csv([dict(timestamp=_t(0), user="mchen", event_type="process_exec", host="ws01", command="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")])


def large_outbound():
    return _csv([dict(timestamp=_t(i), src_ip="10.0.1.20", dst_ip="198.51.100.90", dst_port=443, event_type="network_flow", bytes_out=30_000_000) for i in range(3)])


def port_scan():
    return _csv([dict(timestamp=_t(0, sec=i), src_ip="192.0.2.99", dst_ip="10.0.1.5", dst_port=1000 + i, event_type="firewall_block") for i in range(20)])


def lateral_movement():
    return _csv([dict(timestamp=_t(i), src_ip="10.0.2.55", user="svc-backup", event_type="login_success", host=f"srv{i:02d}", message="Logon type 3") for i in range(5)])


def persistence_mechanism():
    return _csv([dict(timestamp=_t(0), user="svc", event_type="process_exec", host="srv01", command='schtasks /create /tn Updater /tr C:\\ProgramData\\u.exe /sc minute')])


def mfa_fatigue():
    return _csv([dict(timestamp=_t(i), src_ip="203.0.113.60", user="asmith", event_type="mfa_denied", message="Push denied") for i in range(6)])


def office_spawns_shell():
    return _csv([dict(timestamp=_t(0), user="mchen", event_type="process_exec", host="ws02", command="cmd.exe /c whoami",
                      message=r"Image=C:\Windows\System32\cmd.exe ParentImage=C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")])


def beaconing():
    return _csv([dict(timestamp=_t(i), src_ip="10.0.1.42", dst_ip="198.51.100.77", dst_port=8443, host="ws03", event_type="network_flow") for i in range(10)])


def ioc_match():
    return _csv([dict(timestamp=_t(0), src_ip="198.51.100.77", user="x", event_type="login_failure", message="Failed")])


IOCS = {"ioc_match": ["198.51.100.77"]}

CASES = {
    "brute_force": brute_force, "password_spray": password_spray, "success_after_failures": success_after_failures,
    "multi_ip_login": multi_ip_login, "off_hours_login": off_hours_login, "sensitive_activity": sensitive_activity,
    "web_scan": web_scan, "web_attack_payload": web_attack_payload, "suspicious_command": suspicious_command,
    "large_outbound": large_outbound, "port_scan": port_scan, "ioc_match": ioc_match,
    "lateral_movement": lateral_movement, "persistence_mechanism": persistence_mechanism, "mfa_fatigue": mfa_fatigue,
    "office_spawns_shell": office_spawns_shell, "beaconing": beaconing,
}
