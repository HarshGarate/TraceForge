# Contributing

1. Fork, then `pip install -r requirements-dev.txt`.
2. Add or change a rule in `traceforge/detect.py` (see `docs/DETECTION_RULES.md` for the checklist) and add a test in `tests/`.
3. Run `python -m pytest -q`. If you change `scripts/generate_sample_data.py`, regenerate `sample_data/` and the sample report.
4. Open a pull request describing the detection logic and its false-positive risk.

Never commit real logs, credentials or personal data. Sample data must use documentation IP ranges (RFC 5737) and fictional accounts.


## Checks before a pull request
```bash
pip install -r requirements-dev.txt
ruff check .
python scripts/generate_sample_data.py      # must leave traceforge/sample_data unchanged
python scripts/generate_rule_docs.py        # regenerates docs/DETECTION_RULES.md
python -m pytest
```
New detection rules need a firing case in `tests/rule_cases.py`, a near-miss test, a `false_positives` note and a CHANGELOG line.
