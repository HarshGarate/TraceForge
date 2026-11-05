# TraceForge

**Incident reconstruction and IOC correlation workbench.** Load logs from several sources, and TraceForge normalises them, detects suspicious behaviour, stitches findings into incidents with a kill-chain timeline, lets you triage and annotate, and exports an evidence-linked report. It runs entirely on your machine: **no data leaves this computer**.

## Quick start

The included sample logs and test fixtures use synthetic, anonymised identifiers. Do not commit real production logs, credentials, tokens, or customer data.

```bash
pip install .            # or: pip install -r requirements.txt
traceforge serve         # or: python run.py
```
TraceForge opens in your browser at `http://127.0.0.1:8000`, with no login. Click **Load sample data** to try it. (Add `--require-token` if you want an access link.)

Headless:
```bash
traceforge analyze logs/* --tlp TLP:GREEN --pdf report.pdf --md report.md --stix iocs.json --attack-layer layer.json
```

## What it does
- **Inputs:** CSV, JSON/NDJSON, plain text logs, Windows Event XML and Sysmon, Zeek, AWS CloudTrail, and `.zip` / `.gz` bundles. Rows without a parseable timestamp are dropped and counted, never invented.
- **Detection:** 17 built-in rules mapped to MITRE ATT&CK (brute force, spraying, lateral movement, persistence, MFA fatigue, Office-to-shell, beaconing, exfiltration, scans and more) plus **Sigma rule import**. See the generated [coverage table](docs/DETECTION_RULES.md), which lists the test that proves each rule and its known false positives.
- **Correlation:** findings that share entities become incidents with severity, an explainable confidence score, a timeline and remediation steps.
- **Analyst workflow:** verdicts, notes, checklists, IOC tracking, event search and timeline.
- **Output:** PDF, Markdown, JSON, CSV, STIX 2.1 indicators, ATT&CK Navigator layer, and a passphrase-encrypted case file.

## Security of the tool itself
TraceForge handles sensitive logs, so it defends itself. Details and the tests behind each control are in [THREAT_MODEL.md](THREAT_MODEL.md).

| Control | What it gives you |
|---|---|
| Host/Origin checks (always on) + optional access token | A malicious web page or DNS-rebinding site cannot drive your local console; the token is automatic for Docker/network use |
| Evidence vault + SHA-256 re-checks | Imported files are read-only copies, verified at every start; tampering is flagged |
| Hash-chained audit log | Tamper-evident record of who changed which verdict, note or IOC, and every export |
| Upload hardening | Size, row, column and nesting limits, parse time budget, safe ZIP/gzip, XML entity refusal |
| TLP-driven redaction | TLP:CLEAR/GREEN reports mask usernames, hostnames and internal IPs |
| Encrypted case files | AES-256-GCM with scrypt; lost laptop does not expose your notes |
| CI security scanning | CodeQL, bandit, pip-audit, Dependabot; hardened non-root Docker image |

Known limits (no user accounts, plain HTTP, unencrypted database) are stated in the threat model.

## Documentation
[User guide](docs/USER_GUIDE.md) · [Architecture](docs/ARCHITECTURE.md) · [Detection rules and coverage](docs/DETECTION_RULES.md) · [Deployment](docs/DEPLOYMENT.md) · [Threat model](THREAT_MODEL.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md)

## Development
```bash
pip install -r requirements-dev.txt
python -m pytest
ruff check .
```
Sample data is synthetic and reproducible: `python scripts/generate_sample_data.py`.

## Not included (yet)
GeoIP/impossible-travel, attack-graph view, EVTX binary parsing (export to XML first), multi-user roles. Detections are heuristics to support an analyst, not verdicts.

Licensed under the MIT License.
