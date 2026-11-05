# Changelog

## 1.1.0

### Security
- Host and Origin checks (always on) plus an optional access token exchanged for an HttpOnly, SameSite=Strict session cookie. No login on localhost by default; the token is automatic for Docker and non-localhost binds.
- Hash-chained, append-only audit log of analyst actions, with verification, CSV export and an Audit page.
- Evidence vault: read-only copies of every file, re-verified against SHA-256 at start-up and on demand; failures are flagged and excluded.
- Upload hardening: safe ZIP/gzip expansion, column and depth limits, parse-time budget, request size cap, XML entity refusal.
- TLP-driven sharing redaction (usernames, hostnames, internal IPs, notes, organisation) for PDF, Markdown, JSON and CSV.
- Passphrase-encrypted case files (AES-256-GCM, scrypt).
- Stricter headers (frame-ancestors none, COOP/CORP), hardened Docker image, CodeQL, Dependabot, bandit and pip-audit in CI.
- THREAT_MODEL.md.

### Analysis
- Five new rules: lateral movement, persistence mechanisms, MFA fatigue, Office spawning a shell, beaconing.
- Sigma rule import (documented subset).
- New formats: Windows Event XML and Sysmon, Zeek, AWS CloudTrail.
- STIX 2.1 indicator export and ATT&CK Navigator layer export.
- Generated detection coverage table (docs/DETECTION_RULES.md).

### Reports
- Incident report restructured to a standard layout: document control, DRAFT/FINAL status, TLP marking and handling statement, contents, key observations, affected assets, per-incident response actions grouped by phase with owner/done columns, findings register, ATT&CK appendix, definitions and sign-off. Page X of Y.
- Fixed: raw `<NA>` values, windows losing the end date, "Threat Intel Match" shown as a tactic, cryptic event details.
- Fixed: the IOC pseudo-tactic counted as a kill-chain stage when raising severity to Critical.

### Other
- Evidence and case state persist across restarts; `pip install` and a `traceforge` command; sample data moved into the package.
- Fixed: placeholder technique "n/a" was split into junk technique tags.

## 1.0.0
Initial release.
