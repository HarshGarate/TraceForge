# Changelog

## 1.2.0

### Added
- `lab_data/` scenario pack and `scripts/generate_scenario_pack.py`: 12 deterministic files covering every supported format (CSV, Apache, syslog, key=value firewall, Windows Event XML with Sysmon, Zeek, CloudTrail, nested NDJSON, aliased epoch CSV, zip, gzip) and one combined CSV that triggers all 17 built-in rules, plus IOC and Sigma helpers and a data-quality edge-case file. Locked by `tests/test_scenario_pack.py` and a CI drift check.
- `traceforge analyze --ioc-file PATH` loads indicators from a text file (one per line).
- `traceforge analyze --fail-on {low,medium,high,critical}`: exits with status 2 when any incident reaches the chosen severity, so scheduled jobs and CI/CD pipelines can gate on results (status 1 remains "error").
- Redaction tokens (`user-NN`, `host-NN`, `internal-ip-NN`) are now guaranteed never to equal a real identifier in the case, which keeps masked reports unambiguous for datasets that already use pseudonymous names.
- Synthetic demo accounts are neutral (`user-01` ... `user-10`); the generated data keeps the same shape (555 events, 4 sources, 16 findings, 4 incidents).
- `tests/test_cli.py`, `tests/test_demo_dataset.py` (pins the demo's headline numbers) and a collision regression test for the redactor.
- Repository tooling: CI matrix (Ubuntu and Windows, Python 3.11-3.13) with a 90 % coverage gate, wheel/sdist build check, Docker build check, generated-file drift check, tag-driven release workflow, `Makefile`, pre-commit, `.editorconfig`, `.gitattributes` (LF line endings), CODEOWNERS, CODE_OF_CONDUCT and CITATION.
- `docs/USE_CASE.md`: a worked SOC triage scenario, from raw logs to a shareable report.

### Fixed
- pandas deprecation (`Series.dt.weekday` -> `Series.dt.day_of_week`) that emitted ~70 warnings on pandas 3.x and breaks on pandas 4.
- Sigma `re` modifier no longer emits a pandas "match groups" warning for rules that use capture groups; the Starlette `TestClient` notice is filtered in pytest config.
- bandit: SHA-1 used only as an identifier is marked `usedforsecurity=False`; the remaining medium findings were false positives and are annotated with the reason.
- `docs/ARCHITECTURE.md` now matches the current module set.

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
