import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from traceforge.correlate import build_incidents  # noqa: E402
from traceforge.detect import run_detections  # noqa: E402
from traceforge.ingest import build_dataset  # noqa: E402


@pytest.fixture(scope="session")
def sample_files():
    return [(p.name, p.read_bytes()) for p in sorted((ROOT / "traceforge" / "sample_data").glob("*"))]


@pytest.fixture(scope="session")
def sample(sample_files):
    events, quality = build_dataset(sample_files)
    findings = run_detections(events)
    return events, quality, findings, build_incidents(findings, events)
