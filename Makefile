.DEFAULT_GOAL := help
PY ?= python

help:            ## list targets
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

install:         ## install runtime + dev dependencies
	$(PY) -m pip install -r requirements-dev.txt && $(PY) -m pip install -e . --no-deps

run:             ## start the local console
	traceforge serve

test:            ## run the test-suite with coverage
	$(PY) -m pytest -q --cov=traceforge --cov-report=term-missing

lint:            ## ruff
	ruff check .

security:        ## bandit + dependency audit
	bandit -r traceforge -ll && pip-audit -r requirements.txt

sync:            ## regenerate sample data, rule docs and the scenario pack (CI fails if they drift)
	$(PY) scripts/generate_sample_data.py && $(PY) scripts/generate_rule_docs.py && $(PY) scripts/generate_scenario_pack.py

pack:            ## regenerate the lab_data scenario pack
	$(PY) scripts/generate_scenario_pack.py

demo:            ## analyse the bundled data headlessly
	traceforge analyze traceforge/sample_data/* --tlp TLP:GREEN --md demo_report.md --pdf demo_report.pdf

check: lint test security   ## everything CI runs locally

docker:          ## build the hardened image
	docker build -t traceforge .

.PHONY: help install run test lint security sync pack demo check docker
