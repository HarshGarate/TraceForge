"""Rule catalogue, default thresholds and shared constants.

Every detection threshold lives in DEFAULT_CONFIG so analysts can tune it from the UI,
a JSON file, or the CLI without touching code.
"""
from __future__ import annotations

import copy
import json

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLORS = {
    "info": "#6b7280", "low": "#3b82f6", "medium": "#f59e0b",
    "high": "#f97316", "critical": "#ef4444",
}

# MITRE ATT&CK tactics in kill-chain order (used to order timelines and score coverage)
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Credential Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact", "Threat Intel Match",
]

DEFAULT_CONFIG: dict = {
    "brute_force": {"enabled": True, "failures": 5, "window_minutes": 10},
    "password_spray": {"enabled": True, "distinct_users": 5, "window_minutes": 15},
    "success_after_failures": {"enabled": True, "failures": 3, "lookback_minutes": 30},
    "multi_ip_login": {"enabled": True, "window_minutes": 60},
    "off_hours_login": {
        "enabled": True, "business_start_hour": 7, "business_end_hour": 19,
        "weekends_are_off_hours": True, "external_only": True,
    },
    "sensitive_activity": {"enabled": True},
    "web_scan": {"enabled": True, "errors": 15, "window_minutes": 5, "status_codes": [401, 403, 404]},
    "web_attack_payload": {"enabled": True},
    "suspicious_command": {"enabled": True},
    "large_outbound": {"enabled": True, "megabytes": 50, "window_minutes": 60},
    "port_scan": {"enabled": True, "distinct_ports": 15, "window_minutes": 5},
    "ioc_match": {"enabled": True},
    "lateral_movement": {"enabled": True, "hosts": 4, "window_minutes": 15},
    "persistence_mechanism": {"enabled": True},
    "mfa_fatigue": {"enabled": True, "denials": 5, "window_minutes": 10},
    "office_spawns_shell": {"enabled": True},
    "beaconing": {"enabled": True, "connections": 8, "max_jitter_pct": 20, "min_interval_seconds": 5, "max_interval_minutes": 120},
    "sigma_match": {"enabled": True},
    "correlation": {"max_gap_minutes": 120},
    "privileged_users": ["root", "administrator", "admin"],
}

# Rule catalogue: display name, ATT&CK mapping, base severity and response guidance.
RULES: dict = {
    "brute_force": {
        "name": "Repeated failed logins (brute force)", "tactic": "Credential Access",
        "false_positives": "Users who mistype passwords repeatedly, expired service-account credentials, and monitoring tools probing a login page.",
        "technique": "T1110", "severity": "medium",
        "description": "Many failed logins from one source IP inside a short window.",
        "remediation": [
            "Block or rate-limit the source IP at the firewall / WAF.",
            "Enforce account lockout and MFA on the targeted service.",
        ],
    },
    "password_spray": {
        "name": "Password spraying", "tactic": "Credential Access",
        "false_positives": "Shared NAT or VPN egress addresses where many different users legitimately fail at the same time (for example after a password-policy change).",
        "technique": "T1110.003", "severity": "high",
        "description": "One source IP failing against many different usernames.",
        "remediation": [
            "Block the source IP and review all accounts it targeted.",
            "Force password reset for any targeted account that later logged in successfully.",
            "Enable MFA and smart-lockout on the authentication endpoint.",
        ],
    },
    "success_after_failures": {
        "name": "Successful login after failures", "tactic": "Initial Access",
        "false_positives": "A legitimate user who forgets a password and then remembers it; password-manager sync problems.",
        "technique": "T1078", "severity": "high",
        "description": "A login succeeded shortly after failed attempts from the same IP or against the same account.",
        "remediation": [
            "Treat the account as potentially compromised: disable it and revoke active sessions/tokens.",
            "Reset credentials and re-enrol MFA after the account is verified with its owner.",
            "Review everything the account did after the successful login.",
        ],
    },
    "multi_ip_login": {
        "name": "Account used from multiple IPs", "tactic": "Initial Access",
        "false_positives": "Mobile hotspots, VPN reconnects and users who move between office and home within the window. No GeoIP is used.",
        "technique": "T1078", "severity": "medium",
        "description": "Same account authenticated from several IPs (at least one external) in a short window. No GeoIP is used, so this is a heuristic.",
        "remediation": ["Confirm with the user whether both locations are legitimate.", "Revoke sessions and require re-authentication if not."],
    },
    "off_hours_login": {
        "name": "Off-hours login", "tactic": "Initial Access",
        "false_positives": "On-call staff, shift workers and users in other time zones (business hours are configured in UTC).",
        "technique": "T1078", "severity": "low",
        "description": "Successful login outside configured business hours.",
        "remediation": ["Verify the login with the account owner or on-call roster."],
    },
    "sensitive_activity": {
        "name": "Sensitive account / audit activity", "tactic": "Persistence",
        "false_positives": "Approved joiner/leaver changes, admin maintenance windows and log rotation that is logged as a clear event.",
        "technique": "T1136 / T1098 / T1070.001", "severity": "high",
        "description": "Account creation, privileged group changes or audit-log clearing.",
        "remediation": [
            "Disable any account or group membership that was not change-approved.",
            "Preserve the affected host's logs/disk image before cleanup (evidence).",
            "Restore audit logging and forward logs off-host so they cannot be wiped locally.",
        ],
    },
    "web_scan": {
        "name": "Web scanning / forced browsing", "tactic": "Reconnaissance",
        "false_positives": "Broken links or a missing asset requested by a busy page; uptime monitors and authorised vulnerability scanners.",
        "technique": "T1595.002", "severity": "medium",
        "description": "Burst of 401/403/404 responses to one client IP.",
        "remediation": ["Rate-limit or block the scanning IP.", "Confirm no discovered path exposes sensitive content."],
    },
    "web_attack_payload": {
        "name": "Web attack payload in request", "tactic": "Initial Access",
        "false_positives": "Security scanners, penetration tests and applications that legitimately carry SQL-like text in parameters.",
        "technique": "T1190", "severity": "high",
        "description": "Request contains SQL injection, XSS, path traversal, command injection or JNDI patterns.",
        "remediation": [
            "Block the source at the WAF and review responses (HTTP 200 on a payload warrants deeper review).",
            "Patch or harden the targeted application and review its database/app logs.",
        ],
    },
    "suspicious_command": {
        "name": "Suspicious command line", "tactic": "Execution",
        "false_positives": "Administrators and deployment tools that use encoded PowerShell, certutil or curl-pipe-to-shell installers.",
        "technique": "T1059", "severity": "high",
        "description": "Command line matches known living-off-the-land or credential-theft patterns.",
        "remediation": [
            "Isolate the host from the network (EDR containment) pending triage.",
            "Collect the process tree, memory and the decoded payload for analysis.",
            "Hunt for the same command pattern on other hosts.",
        ],
    },
    "large_outbound": {
        "name": "Large outbound transfer", "tactic": "Exfiltration",
        "false_positives": "Backups, cloud sync and software distribution to external storage; the rule cannot see what the data was.",
        "technique": "T1048", "severity": "high",
        "description": "Outbound data volume to an external IP exceeds the threshold inside the window.",
        "remediation": [
            "Block the destination IP/domain and capture network evidence.",
            "Identify what data was on the source host and assess breach-notification duties.",
        ],
    },
    "port_scan": {
        "name": "Port scan", "tactic": "Reconnaissance",
        "false_positives": "Authorised vulnerability scans, load-balancer health checks and service-discovery tools.",
        "technique": "T1046", "severity": "medium",
        "description": "One source touching many distinct destination ports in a short window.",
        "remediation": ["Block the scanning IP.", "Review which scanned services must be exposed at all."],
    },
    "lateral_movement": {
        "name": "Lateral movement (remote services)", "tactic": "Lateral Movement",
        "technique": "T1021", "severity": "high",
        "false_positives": "Jump-host administrators, patching and inventory tools that touch many servers, and help-desk remote support sessions.",
        "description": "One account or source address logging in to many different hosts in a short window, or remote-execution tooling (PsExec, WMI, WinRM, admin shares) in a command line.",
        "remediation": [
            "Identify the source host and account, and confirm whether an administrator or tool was expected to touch these hosts.",
            "Disable the account or isolate the source host if the activity is not approved, then review each destination host.",
            "Restrict remote administration (RDP, SMB, WinRM) to jump hosts and enforce tiered administration.",
        ],
    },
    "persistence_mechanism": {
        "name": "New service, scheduled task or autorun", "tactic": "Persistence",
        "technique": "T1543.003 / T1053.005 / T1547.001", "severity": "high",
        "false_positives": "Software installers, patch agents and configuration-management tools that create services or tasks.",
        "description": "A service was installed, a scheduled task was created, or a command added an autorun registry key.",
        "remediation": [
            "Check the service, task or registry value against change records and the publisher of the binary it launches.",
            "Remove the persistence item and collect the referenced binary or script for analysis.",
            "Hunt for the same service, task name or path on other hosts.",
        ],
    },
    "mfa_fatigue": {
        "name": "MFA prompt flooding (MFA fatigue)", "tactic": "Credential Access",
        "technique": "T1621", "severity": "high",
        "false_positives": "A user with a broken authenticator app or a misconfigured integration that retries push notifications.",
        "description": "Many denied, rejected or timed-out MFA prompts for one account in a short window. Severity rises when an approved login follows.",
        "remediation": [
            "Contact the user out-of-band and confirm whether they were trying to sign in.",
            "Reset the password and revoke sessions if any prompt was approved after the flood.",
            "Switch to number-matching or phishing-resistant MFA and limit the number of push attempts.",
        ],
    },
    "office_spawns_shell": {
        "name": "Office application starts a shell", "tactic": "Execution",
        "technique": "T1204.002 / T1059", "severity": "high",
        "false_positives": "Macros or add-ins that deliberately launch scripts, and some document-automation tools.",
        "description": "A Word, Excel, PowerPoint, Outlook or OneNote process created PowerShell, cmd, a script host or a LOLBin. This is a common macro-malware pattern.",
        "remediation": [
            "Isolate the host and retrieve the document that was opened (email attachment or download).",
            "Block Office child-process creation with an attack-surface-reduction rule and disable macros from the internet.",
            "Search mail and proxy logs for other recipients of the same document.",
        ],
    },
    "beaconing": {
        "name": "Periodic outbound connections (beaconing)", "tactic": "Command and Control",
        "technique": "T1071 / T1571", "severity": "medium",
        "false_positives": "Software update checks, telemetry agents, NTP, monitoring probes and chat clients all call home on a timer.",
        "description": "One host contacting the same external address and port at a steady rhythm, which is how many implants check in with their controller.",
        "remediation": [
            "Identify the process behind the connections on the source host and check the destination reputation.",
            "Block the destination at the firewall or proxy and isolate the host if the process is unknown.",
            "Search other hosts for connections to the same destination.",
        ],
    },
    "sigma_match": {
        "name": "Imported Sigma rule match", "tactic": "Execution",
        "technique": "n/a", "severity": "medium",
        "false_positives": "Depends on the imported rule; read the rule's own falsepositives section.",
        "description": "An event matched a Sigma detection rule that you imported. The finding carries the rule's own title, level and ATT&CK tags.",
        "remediation": ["Follow the response guidance in the Sigma rule itself and validate the matched events."],
    },
    "ioc_match": {
        "name": "Event matches recorded IOC", "tactic": "Threat Intel Match",
        "false_positives": "Indicators that are shared infrastructure (CDNs, NAT gateways) or that were added with the wrong type.",
        "technique": "n/a", "severity": "high",
        "description": "Imported evidence contains an indicator you recorded in the IOC list.",
        "remediation": ["Scope the activity: search all other log sources for the same indicator."],
    },
}


def merged_config(overrides: dict | None = None) -> dict:
    """Return DEFAULT_CONFIG with (possibly partial) overrides merged in."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    for key, val in (overrides or {}).items():
        if isinstance(val, dict) and isinstance(cfg.get(key), dict):
            cfg[key].update(val)
        else:
            cfg[key] = val
    return cfg


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return merged_config(json.load(fh))


TECHNIQUE_NAMES = {
    "T1110": "Brute Force", "T1110.003": "Password Spraying", "T1078": "Valid Accounts",
    "T1136": "Create Account", "T1098": "Account Manipulation", "T1070.001": "Clear Windows Event Logs",
    "T1595.002": "Vulnerability Scanning", "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter", "T1048": "Exfiltration Over Alternative Protocol",
    "T1046": "Network Service Discovery",
    "T1021": "Remote Services", "T1021.001": "Remote Desktop Protocol", "T1021.002": "SMB / Windows Admin Shares",
    "T1569.002": "Service Execution", "T1543.003": "Windows Service", "T1053.005": "Scheduled Task",
    "T1547.001": "Registry Run Keys / Startup Folder", "T1621": "MFA Request Generation",
    "T1204.002": "Malicious File", "T1071": "Application Layer Protocol", "T1571": "Non-Standard Port",
}

# Editable parameters per rule: (config key, label, kind, min, max). kind: "int" | "bool".
PARAMS: dict = {
    "brute_force": [("failures", "Failed logins to trigger", "int", 2, 500), ("window_minutes", "Within (minutes)", "int", 1, 1440)],
    "password_spray": [("distinct_users", "Distinct accounts", "int", 2, 500), ("window_minutes", "Within (minutes)", "int", 1, 1440)],
    "success_after_failures": [("failures", "Prior failures required", "int", 1, 500), ("lookback_minutes", "Look back (minutes)", "int", 1, 1440)],
    "multi_ip_login": [("window_minutes", "Within (minutes)", "int", 1, 1440)],
    "off_hours_login": [("business_start_hour", "Business day starts (UTC hour)", "int", 0, 23), ("business_end_hour", "Business day ends (UTC hour)", "int", 1, 24),
                        ("weekends_are_off_hours", "Weekends count as off-hours", "bool", 0, 1), ("external_only", "Only external IPs / privileged users", "bool", 0, 1)],
    "web_scan": [("errors", "Error responses to trigger", "int", 2, 5000), ("window_minutes", "Within (minutes)", "int", 1, 1440)],
    "large_outbound": [("megabytes", "Megabytes sent externally", "int", 1, 1_000_000), ("window_minutes", "Within (minutes)", "int", 1, 1440)],
    "port_scan": [("distinct_ports", "Distinct ports", "int", 2, 65535), ("window_minutes", "Within (minutes)", "int", 1, 1440)],
    "lateral_movement": [("hosts", "Distinct hosts to trigger", "int", 2, 500), ("window_minutes", "Within (minutes)", "int", 1, 1440)],
    "mfa_fatigue": [("denials", "Denied prompts to trigger", "int", 2, 500), ("window_minutes", "Within (minutes)", "int", 1, 1440)],
    "beaconing": [("connections", "Connections to trigger", "int", 5, 10000), ("max_jitter_pct", "Max timing jitter (%)", "int", 1, 100),
                  ("min_interval_seconds", "Min average interval (seconds)", "int", 1, 3600), ("max_interval_minutes", "Max average interval (minutes)", "int", 1, 1440)],
}


def _coerce_bool(v) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)


def sanitize_config(overrides: dict | None) -> dict:
    """Validate UI/API input: unknown keys are ignored, numbers are coerced and clamped to sane bounds."""
    cfg = merged_config()
    for rid, body in (overrides or {}).items():
        if rid == "privileged_users":
            if isinstance(body, str):
                body = body.split(",")
            if isinstance(body, list):
                cfg["privileged_users"] = [str(u).strip().lower() for u in body if str(u).strip()][:50]
            continue
        if rid == "correlation" and isinstance(body, dict):
            try:
                cfg["correlation"]["max_gap_minutes"] = max(5, min(2880, int(float(body.get("max_gap_minutes", 120)))))
            except (TypeError, ValueError):
                pass
            continue
        if rid not in cfg or not isinstance(body, dict) or not isinstance(cfg[rid], dict):
            continue
        if "enabled" in body:
            cfg[rid]["enabled"] = _coerce_bool(body["enabled"])
        for key, _label, kind, lo, hi in PARAMS.get(rid, []):
            if key not in body:
                continue
            if kind == "bool":
                cfg[rid][key] = _coerce_bool(body[key])
            else:
                try:
                    cfg[rid][key] = max(lo, min(hi, int(float(body[key]))))
                except (TypeError, ValueError):
                    pass
    return cfg
