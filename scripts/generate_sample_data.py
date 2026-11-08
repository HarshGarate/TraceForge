"""Generate the synthetic 'Friday-night intrusion' scenario used by the demo and the tests.

All IPs come from RFC 5737 documentation ranges (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24)
and all hostnames/accounts are fictional. The data is deterministic (fixed seed).
"""
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "traceforge" / "sample_data"
rnd = random.Random(7)
D = datetime(2026, 3, 13, tzinfo=timezone.utc)  # a Friday


def at(h, m=0, s=0):
    return D + timedelta(hours=h, minutes=m, seconds=s)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


USERS = [f"user-{n:02d}" for n in range(1, 11)]   # neutral synthetic account names; user-01 is the compromised account, user-02 the benign multi-IP user
auth, web, endpoint, fw = [], [], [], []
HOME = {u: f"10.0.{1 + i % 4}.{20 + i}" for i, u in enumerate(USERS)}  # each user has one usual internal IP

# ---------------- benign background noise
for _ in range(90):
    t = at(8) + timedelta(seconds=rnd.randint(0, 9 * 3600))
    u = rnd.choice(USERS)
    auth.append((t, "vpn-gw", u, HOME[u], "login_success", f"{u} authenticated via SSO"))
for _ in range(6):  # occasional typos, far below any threshold
    t = at(8) + timedelta(seconds=rnd.randint(0, 9 * 3600))
    u = rnd.choice(USERS)
    auth.append((t, "vpn-gw", u, HOME[u], "login_failed", "Failed password (typo)"))
paths = ["/", "/index.html", "/products", "/about", "/contact", "/login", "/static/app.js", "/static/site.css", "/api/items"]
for _ in range(260):
    t = at(7) + timedelta(seconds=rnd.randint(0, 14 * 3600))
    st = rnd.choices([200, 304, 404], [88, 8, 4])[0]
    web.append((t, f"192.0.2.{rnd.randint(10, 30)}", "GET", rnd.choice(paths), st, rnd.randint(300, 40000), "web01"))
for i in range(40):
    t = at(8) + timedelta(seconds=rnd.randint(0, 9 * 3600))
    fw.append((t, f"10.0.{rnd.randint(1, 4)}.{rnd.randint(10, 60)}", f"192.0.2.{rnd.randint(40, 60)}", 443, "allow", rnd.randint(2_000, 900_000)))

# ---------------- Benign-but-noisy: user-02 from two IPs (analyst should triage -> likely false positive)
auth.append((at(11, 2), "vpn-gw", "user-02", HOME["user-02"], "login_success", "user-02 authenticated via SSO"))
auth.append((at(11, 20), "vpn-gw", "user-02", "192.0.2.77", "login_success", "user-02 authenticated via SSO (mobile hotspot)"))

# ---------------- Port scan from 192.0.2.50 (blocked at the perimeter)
for p in range(1, 41):
    fw.append((at(14, 20, p), "192.0.2.50", "10.0.1.5", p * 23, "deny", 0))

# ---------------- MAIN INTRUSION by 203.0.113.45 (Friday night)
ATT = "203.0.113.45"
for i in range(62):  # recon: forced browsing
    web.append((at(21, 58, i * 3), ATT, "GET", rnd.choice(["/admin", "/backup.zip", "/.git/config", "/wp-login.php", "/phpmyadmin/", f"/old/{i}"]), 404, 196, "web01"))
payloads = ["/products?id=1' OR '1'='1", "/products?id=1 UNION SELECT username,password FROM users--", "/search?q=<script>alert(1)</script>",
            "/download?file=../../../../etc/passwd", "/products?id=1;SELECT sleep(5)", "/products?id=1 UNION SELECT NULL,@@version--", "/api/items?id=1' AND 1=1--"]
for i, pth in enumerate(payloads):
    web.append((at(22, 3, 10 + i * 20), ATT, "GET", pth, 200 if i == 1 else 500, rnd.randint(500, 9000), "web01"))
for i in range(22):  # credential attack on a single account
    auth.append((at(22, 15, i * 12), "vpn-gw", "user-01", ATT, "login_failed", "Failed password for user-01"))
auth.append((at(22, 20, 11), "vpn-gw", "user-01", ATT, "login_success", "user-01 authenticated (password only, no MFA)"))

def ep(t, cmd, msg, action="process_created"):
    endpoint.append({"@timestamp": iso(t), "host": {"name": "DC01"}, "user": {"name": "CORP\\user-01"}, "source": {"ip": "10.0.5.20"},
                     "event": {"action": action}, "process": {"command_line": cmd}, "message": msg})

ep(at(22, 24, 40), "whoami /all", "Process created: whoami.exe")
ep(at(22, 25, 5), 'net group "Domain Admins" /domain', "Process created: net.exe")
ep(at(22, 27, 3), "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", "Process created: powershell.exe")
ep(at(22, 31, 12), "", "A user account was created: svc_backup2", "user_account_created")
ep(at(22, 31, 40), "", "svc_backup2 was added to the Administrators group", "group_member_added")
ep(at(23, 52, 20), "", "The audit log was cleared", "audit_log_cleared")
for i in range(6):  # ~72 MB leaves DC01 for an attacker-controlled server
    fw.append((at(23, 10 + i * 6, rnd.randint(0, 30)), "10.0.5.20", "198.51.100.77", 443, "allow", 12_000_000 + rnd.randint(0, 900_000)))

# ---------------- Separate password-spray (no success) at 03:10 next day
for i, u in enumerate(USERS + ["root", "admin", "backup"]):
    auth.append((at(27, 10, i * 20), "vpn-gw", u, "198.51.100.23", "login_failed", f"Failed password for {u}"))

# ---------------- write files (deliberately different schemas per source)
OUT.mkdir(exist_ok=True)
with open(OUT / "vpn_auth.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp", "hostname", "username", "client_ip", "event", "message"])
    for r in sorted(auth):
        w.writerow([iso(r[0]), *r[1:]])
with open(OUT / "web_access.json", "w", newline="\n") as f:
    json.dump({"events": [{"time": iso(t), "client_ip": ip, "method": m, "uri": u, "status": s, "response_bytes": b, "host": h}
                          for t, ip, m, u, s, b, h in sorted(web)]}, f, indent=1)
with open(OUT / "endpoint_events.json", "w", newline="\n") as f:
    for e in sorted(endpoint, key=lambda e: e["@timestamp"]):
        f.write(json.dumps(e) + "\n")  # NDJSON
with open(OUT / "firewall.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["epoch", "src", "dst", "dport", "action", "bytes_sent"])
    for r in sorted(fw):
        w.writerow([int(r[0].timestamp()), *r[1:]])
print("wrote", [p.name for p in sorted(OUT.iterdir())])
