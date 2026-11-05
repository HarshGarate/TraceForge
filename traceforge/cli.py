"""Command line:

    traceforge serve                                   start the web console
    traceforge analyze logs/* --pdf report.pdf         headless analysis and report export
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from . import sigma as sigma_mod
from .config import RULES, load_config, merged_config
from .correlate import build_incidents
from .detect import run_detections
from .exporters import navigator_layer, stix_bundle
from .hardening import UploadRejected, expand_upload
from .ingest import build_dataset
from .redact import Redactor, policy_for
from .report import ReportContext, build_json, build_markdown, build_pdf
from .store import Store

TLPS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]


def _read_inputs(paths: list[str]) -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    for path in paths:
        raw = Path(path).read_bytes()
        try:
            members, _info = expand_upload(os.path.basename(path), raw)
        except UploadRejected as exc:
            raise SystemExit(f"{path}: {exc}") from exc
        files.extend(members)
    return files


def _load_sigma(paths: list[str]) -> list:
    rules = []
    for p in paths:
        target = Path(p)
        for f in sorted(target.rglob("*.y*ml")) if target.is_dir() else [target]:
            found, skipped = sigma_mod.parse_rules(f.read_bytes(), f.name)
            rules.extend(found)
            for s in skipped:
                print(f"  skipped Sigma rule {s['name']}: {s['reason']}", file=sys.stderr)
    return rules


def analyze(args) -> int:
    cfg = load_config(args.config) if args.config else merged_config()
    events, quality = build_dataset(_read_inputs(args.files))
    store = Store()
    for v in args.ioc:
        store.add_ioc(v, source="cli")
    sigma_rules = _load_sigma(args.sigma)
    findings = run_detections(events, cfg, store.iocs(), sigma_rules=sigma_rules)
    incidents = build_incidents(findings, events, cfg)
    ctx = ReportContext(case_name=args.case, analyst=args.analyst, tlp=args.tlp, events=events, findings=findings, incidents=incidents,
                        iocs=store.iocs(), notes=store.notes(), quality=quality, rules_enabled=[r for r in RULES if cfg.get(r, {}).get("enabled", True)],
                        sigma_titles=[r.title for r in sigma_rules])
    ctx = Redactor.for_case(policy_for(args.tlp, args.redact), events, incidents, store.iocs()).apply(ctx)
    print(f"{len(events)} events | {len(findings)} findings | {len(incidents)} incidents")
    for i in ctx.incidents:
        print(f"  {i.incident_id} [{i.severity}] confidence={i.confidence} {i.title}")
    if ctx.redaction:
        print("  " + ctx.redaction)
    for path, make, mode in ((args.pdf, build_pdf, "wb"), (args.md, build_markdown, "w"), (args.json, build_json, "w")):
        if path:
            with open(path, mode, **({} if mode == "wb" else {"encoding": "utf-8"})) as fh:
                fh.write(make(ctx))
    if args.stix:
        Path(args.stix).write_text(stix_bundle(store.iocs(), args.tlp, args.case), encoding="utf-8")
    if args.attack_layer:
        Path(args.attack_layer).write_text(navigator_layer(findings, args.case), encoding="utf-8")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(prog="traceforge", description="TraceForge incident reconstruction and IOC correlation")
    ap.add_argument("--version", action="version", version=f"traceforge {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("serve", help="start the web console")
    from .launcher import add_arguments
    add_arguments(sv)
    a = sub.add_parser("analyze", help="analyze log files and write reports")
    a.add_argument("files", nargs="+", help="log files (CSV, JSON, NDJSON, text, Windows XML, Zeek, CloudTrail, .zip, .gz)")
    a.add_argument("--case", default="CLI case")
    a.add_argument("--analyst", default="CLI")
    a.add_argument("--config", help="JSON file with threshold overrides")
    a.add_argument("--ioc", action="append", default=[], help="IOC value (repeatable)")
    a.add_argument("--sigma", action="append", default=[], metavar="PATH", help="Sigma rule file or folder (repeatable)")
    a.add_argument("--tlp", default="TLP:AMBER", choices=TLPS)
    a.add_argument("--redact", default="auto", choices=["auto", "on", "off"], help="mask internal identifiers (auto = by TLP marking)")
    a.add_argument("--pdf"), a.add_argument("--md"), a.add_argument("--json")
    a.add_argument("--stix", help="write recorded IOCs as a STIX 2.1 bundle")
    a.add_argument("--attack-layer", help="write an ATT&CK Navigator layer")
    args = ap.parse_args(argv)
    if args.cmd == "serve":
        from .launcher import main as serve
        return serve(argv[1:])
    return analyze(args)


if __name__ == "__main__":
    sys.exit(main())
