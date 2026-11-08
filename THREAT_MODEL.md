# TraceForge threat model

TraceForge is a **single-analyst, local** tool that ingests sensitive logs. This page lists what could go wrong, what the tool does about it, where the control is tested, and what is deliberately **not** protected.

## Assets
Evidence files and the events parsed from them; analyst notes, verdicts and IOCs; generated reports; the audit log.

## Trust boundaries
| Input | Trusted? |
|---|---|
| Uploaded log files and archives | **Untrusted** (may be malformed or hostile) |
| Browser requests | Only from this site, carrying the session cookie |
| Sigma rules | Analyst-supplied, parsed defensively |
| The local operating system account and disk | Trusted; see "Not protected" |

## Threats and mitigations
| # | Threat | Mitigation | Test |
|---|---|---|---|
| T1 | A malicious web page in another tab sends requests to the local server (e.g. "clear evidence") | Origin must equal the site; `Sec-Fetch-Site: cross-site` refused for state-changing calls; SameSite=Strict cookie; access token | `test_security.py::test_cross_origin_requests_are_refused` |
| T2 | DNS rebinding makes an attacker domain resolve to 127.0.0.1 | Host header allow-list (IP literals cannot be rebinding names) | `test_foreign_host_header_is_refused_dns_rebinding` |
| T3 | Another local user or process opens the console, or it is exposed to the network | Binds to localhost by default; optional access token (`--require-token`) with a single-use launch link exchanged for an HttpOnly cookie; the token is switched on automatically for any non-localhost bind and in Docker | `test_token_is_required_exchanged_once_and_cookie_is_locked_down` |
| T4 | Malicious log file exhausts memory or CPU (huge, wide, deeply nested, slow to parse) | 50 MB per file, row/column/nesting limits, 60 s parse budget, request size cap | `test_hardening.py` |
| T5 | Decompression bomb, path traversal or nested archive in a ZIP/gzip | Streaming capped reads, member count and total caps, ratio check, base names only (nothing is extracted to disk), nested/encrypted/tar refused | `test_hardening.py` |
| T6 | XML entity expansion in Windows event files | Any DOCTYPE/ENTITY is refused before parsing | `test_formats.py::test_xml_with_doctype_or_entities_is_refused` |
| T7 | Spreadsheet formula injection from log content in CSV exports | Cells starting with `= + - @` are neutralised | `test_store_report.py`, `test_audit_evidence.py` |
| T8 | Evidence is altered after import | Read-only vault copies named by SHA-256, re-verified at start and on demand; failures are flagged and excluded; hash manifest in reports | `test_tampered_stored_file_is_flagged_excluded_and_repairable` |
| T9 | An analyst action is edited or deleted afterwards | Hash-chained append-only audit log; triggers block casual edits; the chain exposes edits made by removing them | `test_editing_with_triggers_removed_is_detected` |
| T10 | Sensitive identifiers leak when a report is shared | TLP-driven masking of usernames, hostnames, internal IPs, notes, organisation, applied to PDF/MD/JSON/CSV/STIX | `test_clear_marking_removes_identifiers_from_every_report_format` |
| T11 | Saved case file is lost or stolen | Optional passphrase encryption (AES-256-GCM, scrypt, tamper-evident) | `test_case_encryption_roundtrip_and_failure_modes` |
| T12 | Clickjacking, MIME sniffing, referrer leakage | CSP with `frame-ancestors 'none'`, X-Frame-Options, nosniff, no-referrer, COOP/CORP | `test_security_headers_replace_weaker_ones_and_forbid_framing` |
| T13 | Unsafe Sigma YAML (aliases, catastrophic regex) | `safe_load`, aliases refused, regex length and nesting checks, unsupported constructs rejected | `test_sigma` cases in `test_redact_sigma_export.py` |
| T14 | Vulnerable dependencies or insecure code patterns | pip-audit, bandit, CodeQL, Dependabot in CI; container runs as non-root, read-only filesystem | `.github/` |

## Not protected (be explicit with reviewers)
- **No user accounts or roles, and no login by default on localhost.** Any process on the same computer that can reach the port can use the console unless `--require-token` is set. When a token is used it grants full access. Do not expose the console to a team; use a reverse proxy with real authentication if you must share it.
- **Analyst names are not identities.** The audit log records the name typed into the investigation details.
- **Audit truncation.** A hash chain cannot show that the *newest* entries were removed. Record the head hash (shown on the Audit page and in every report) somewhere else.
- **A user with write access to the data directory** can replace evidence together with its manifest and rebuild the audit chain. Use full-disk encryption and file permissions; the database itself is **not** encrypted (only exported case files are).
- **No transport encryption.** Traffic is plain HTTP on localhost. Put TLS in front of any non-local deployment.
- **Detections are heuristics.** Absence of a finding is not proof of absence of an attack.
- **Redaction is pattern-based.** It masks known users, hosts and internal IPs; review shared reports before publishing. External IP addresses are kept on purpose.
- **Parse timeouts are cooperative.** A single pandas call on a very large file cannot be interrupted; the 50 MB cap bounds it.
