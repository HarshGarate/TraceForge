"""HTTP layer (FastAPI). All logic lives in service.Workspace; this module only validates and routes."""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import Body, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .security import SecurityConfig, SecurityMiddleware
from .service import UserError, Workspace

WEB = Path(__file__).resolve().parent / "web"


def REDACT():  # noqa: N802 - used like a dependency default; a fresh Query per endpoint
    return Query("auto", pattern="^(auto|on|off)$", description="Sharing redaction: auto (by TLP marking), on, or off")


def create_app(workspace: Workspace | None = None, security: SecurityConfig | None = None) -> FastAPI:
    ws = workspace or Workspace()
    cfg = security or SecurityConfig.from_env()
    if cfg.on_event is None:
        cfg.on_event = ws.log_event            # new sessions and blocked access attempts land in the audit log
    app = FastAPI(title="TraceForge", version=__version__, docs_url="/api/docs", redoc_url=None)
    app.state.ws = ws
    app.add_middleware(SecurityMiddleware, config=cfg)

    @app.exception_handler(UserError)
    async def _user_error(_: Request, exc: UserError):
        return JSONResponse({"error": str(exc)}, status_code=400)

    # ---------------------------------------------------------------- state
    @app.get("/api/meta")
    def meta():
        return ws.meta()

    @app.get("/api/about")
    def about():
        return {**ws.about(), "token_required": cfg.token is not None}

    @app.put("/api/case")
    def set_case(body: dict = Body(...)):
        ws.set_case(body)
        return ws.meta()

    @app.get("/api/dashboard")
    def dashboard():
        return ws.dashboard()

    # ---------------------------------------------------------------- evidence
    @app.post("/api/upload")
    async def upload(files: list[UploadFile] = File(...), replace: bool = Query(False)):
        blobs = [(Path(f.filename or "upload").name, await f.read()) for f in files]
        return {**ws.load_files(blobs, replace=replace), "meta": ws.meta()}

    @app.post("/api/sample")
    def sample():
        return {**ws.load_sample(), "meta": ws.meta()}

    @app.delete("/api/files/{sha256}")
    def remove_file(sha256: str):
        return ws.remove_file(sha256)

    @app.post("/api/integrity/verify")
    def verify_integrity():
        return ws.verify_integrity()

    @app.post("/api/case/new")
    def new_case(body: dict = Body(...)):
        ws.new_investigation(body, clear_iocs=bool(body.get("clear_iocs", True)))
        return ws.meta()

    @app.post("/api/clear")
    def clear():
        ws.clear()
        return ws.meta()

    # ---------------------------------------------------------------- audit log
    @app.get("/api/audit")
    def audit(limit: int = Query(200, ge=1, le=5000), action: str = ""):
        return {"entries": ws.store.audit.entries(limit=limit, action=action), "head": ws.store.audit.head()}

    @app.get("/api/audit/verify")
    def audit_verify():
        return ws.audit_status()

    # ---------------------------------------------------------------- incidents
    @app.get("/api/incidents")
    def incidents():
        return ws.incident_cards()

    @app.get("/api/incidents/{iid}")
    def incident(iid: str):
        return ws.incident_detail(iid)

    @app.get("/api/incidents/{iid}/events")
    def incident_events(iid: str, sev: str = "all", q: str = "", scope: str = "all", t0: str | None = None, t1: str | None = None):
        return ws.incident_events(iid, sev, q, scope, t0, t1)

    @app.put("/api/incidents/{iid}/state")
    def incident_state(iid: str, body: dict = Body(...)):
        ov = body.get("confidence_override")
        try:
            override = None if ov in (None, "") else int(ov)
        except (TypeError, ValueError) as exc:
            raise UserError("Confidence override must be a whole number.") from exc
        return ws.set_state(iid, str(body.get("verdict", "")), override)

    @app.post("/api/incidents/{iid}/notes")
    def incident_note(iid: str, body: dict = Body(...)):
        ws.add_note(iid, str(body.get("note", "")))
        return ws.incident_detail(iid)

    @app.put("/api/incidents/{iid}/remediation")
    def incident_check(iid: str, body: dict = Body(...)):
        ws.set_check(iid, str(body.get("step", "")), bool(body.get("done")))
        return {"ok": True}

    @app.post("/api/incidents/{iid}/iocs")
    def incident_iocs(iid: str, body: dict = Body(...)):
        n = ws.add_candidate_iocs(iid, [str(v) for v in body.get("values", [])])
        return {"added": n}

    @app.get("/api/events/{eid}")
    def event(eid: str):
        return ws.event_detail(eid)

    @app.get("/api/events")
    def events(page: int = 1, size: int = 100, q: str = "", types: str = "", source: str = "", flagged: bool = False):
        return ws.events_page(page, size, q, [t for t in types.split(",") if t], source, flagged)

    @app.get("/api/timeline")
    def timeline(lane: str = "src_ip", q: str = "", types: str = "", flagged: bool = False):
        return ws.timeline(lane, q, [t for t in types.split(",") if t], flagged)

    # ---------------------------------------------------------------- findings / iocs / settings / sigma
    @app.get("/api/findings")
    def findings():
        return {"findings": ws.findings_list()}

    @app.get("/api/findings/{fid}")
    def finding(fid: str):
        return ws.finding_detail(fid)

    @app.get("/api/iocs")
    def iocs():
        return ws.iocs_list()

    @app.post("/api/iocs")
    def add_iocs(body: dict = Body(...)):
        values = body.get("values") or re.split(r"[\r\n]+", str(body.get("value", "")))
        return ws.add_iocs([str(v) for v in values], body.get("type") or None, str(body.get("note", "")), "analyst")

    @app.delete("/api/iocs/{ioc_id}")
    def del_ioc(ioc_id: int):
        ws.delete_ioc(ioc_id)
        return {"ok": True}

    @app.get("/api/settings")
    def settings():
        return ws.settings()

    @app.put("/api/settings")
    def put_settings(body: dict = Body(...)):
        ws.set_config(body)
        return {"settings": ws.settings(), "meta": ws.meta()}

    @app.post("/api/settings/reset")
    def reset_settings():
        ws.set_config(None)
        return {"settings": ws.settings(), "meta": ws.meta()}

    @app.get("/api/sigma")
    def sigma_list():
        return ws.sigma_list()

    @app.post("/api/sigma")
    async def sigma_import(files: list[UploadFile] = File(...)):
        res = ws.sigma_import([(Path(f.filename or "rule.yml").name, await f.read()) for f in files])
        return {**res, "meta": ws.meta()}

    @app.delete("/api/sigma/{rule_id}")
    def sigma_delete(rule_id: int):
        ws.sigma_delete(rule_id)
        return {"ok": True, "meta": ws.meta()}

    # ---------------------------------------------------------------- reports & exports
    @app.get("/api/report/preview")
    def report_preview():
        return ws.report_preview()

    def _download(make, name: str, mime: str, needs_data: bool = True):
        if needs_data and not ws.has_data:
            raise HTTPException(400, "Load evidence first.")
        safe = re.sub(r"[^A-Za-z0-9]+", "_", ws.case["name"]).strip("_") or "case"
        return Response(make(), media_type=mime, headers={"Content-Disposition": f'attachment; filename="traceforge_{safe}_{name}"'})

    @app.get("/api/export/pdf")
    def export_pdf(redact: str = REDACT()):
        return _download(lambda: ws.pdf(redact), "report.pdf", "application/pdf")

    @app.get("/api/export/markdown")
    def export_md(redact: str = REDACT()):
        return _download(lambda: ws.markdown(redact), "report.md", "text/markdown")

    @app.get("/api/export/json")
    def export_json(redact: str = REDACT()):
        return _download(lambda: ws.json_report(redact), "report.json", "application/json")

    @app.get("/api/export/evidence.csv")
    def export_evidence(redact: str = REDACT()):
        return _download(lambda: ws.evidence_csv(redact), "evidence.csv", "text/csv")

    @app.get("/api/export/events.csv")
    def export_events(redact: str = REDACT()):
        return _download(lambda: ws.events_csv(redact), "events.csv", "text/csv")

    @app.get("/api/export/iocs.csv")
    def export_iocs(redact: str = REDACT()):
        return _download(lambda: ws.iocs_csv(redact), "iocs.csv", "text/csv", needs_data=False)

    @app.get("/api/export/iocs.stix.json")
    def export_stix(redact: str = REDACT()):
        return _download(lambda: ws.iocs_stix(redact), "iocs.stix.json", "application/json", needs_data=False)

    @app.get("/api/export/attack-layer.json")
    def export_layer():
        return _download(ws.attack_layer, "attack_layer.json", "application/json")

    @app.get("/api/export/audit.csv")
    def export_audit():
        return _download(ws.audit_csv, "audit_log.csv", "text/csv", needs_data=False)

    @app.get("/api/export/case")
    def export_case():
        return _download(ws.export_case, "case.json", "application/json", needs_data=False)

    @app.post("/api/export/case/encrypted")
    def export_case_encrypted(body: dict = Body(...)):
        return _download(lambda: ws.export_case(str(body.get("passphrase", ""))), "case.tfcase", "application/json", needs_data=False)

    @app.post("/api/import/case")
    async def import_case(file: UploadFile = File(...), passphrase: str = Form("")):
        return ws.import_case(await file.read(), passphrase)

    # ---------------------------------------------------------------- front end
    app.mount("/static", StaticFiles(directory=WEB), name="static")

    @app.get("/")
    def index():
        return FileResponse(WEB / "index.html")

    return app


def __getattr__(name: str):
    """`uvicorn traceforge.server:app` still works; the app is built lazily so importing this module has no side effects."""
    if name == "app":
        global _APP
        if _APP is None:
            _APP = create_app()
        return _APP
    raise AttributeError(name)


_APP = None
