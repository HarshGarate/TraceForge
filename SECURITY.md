# Security

## Reporting a vulnerability
Please open a private security advisory on the repository (Security tab) or email the maintainer. Do not post exploit details in public issues. Expect an acknowledgement within a few days.

## What the tool does to protect itself
See [THREAT_MODEL.md](THREAT_MODEL.md) for the full list, the tests that prove each control, and the limits.
In short: localhost binding, Host/Origin checks, an access token (automatic for network use, opt-in on localhost) with a SameSite=Strict session cookie, upload and archive hardening, a hash-chained audit log, an evidence vault with SHA-256 re-verification, TLP-based redaction, optional encrypted case files, strict response headers, and security scanning in CI.

## Handling real evidence
- Use full-disk encryption; the database and evidence folder (`traceforge_data/`) are not encrypted.
- Never commit real logs. `traceforge_data/`, `logs/` and `evidence/` are git-ignored.
- TraceForge makes no outbound network requests and has no telemetry.
- Treat generated reports according to their TLP marking; review redacted output before sharing.
