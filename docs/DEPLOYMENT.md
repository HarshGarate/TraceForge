# Deployment

## Local (recommended)
```bash
pip install .            # or: pip install -r requirements.txt
traceforge serve         # or: python run.py
```
The console opens at `http://127.0.0.1:8000` with no login. Host and Origin checks are always on, so other websites cannot drive it. Case state and evidence are kept in `./traceforge_data/` (override with `--db`).

Useful options: `--port`, `--no-browser`, `--require-token` (random single-use access link even on localhost), `--reusable-token`, `--token VALUE` (fixed token), `--allow-host NAME` (extra Host names). Binding to anything other than localhost (for example `--host 0.0.0.0`) switches the access token on automatically.

## Docker
```bash
export TRACEFORGE_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
docker compose up --build
# open http://127.0.0.1:8000/?token=$TRACEFORGE_TOKEN
```
The image runs as a non-root user with a read-only root filesystem, dropped capabilities and `no-new-privileges`; data lives in the `traceforge-data` volume. The port is published on localhost only.

## Sharing with a team
TraceForge has no accounts. If several people must use it, put it behind a reverse proxy that provides TLS and real authentication, set `--allow-host` to the proxy's name, and keep the token enabled. See THREAT_MODEL.md.

## Ephemeral hosts
If the host's disk is not persistent, use **Reports -> Save & restore** (or the encrypted case file) to keep notes, verdicts, IOCs and Sigma rules between sessions.
