.PHONY: validate test quality compare serve docker-build

PYTHON ?= python3
export PYTHONDONTWRITEBYTECODE := 1

validate:
	$(PYTHON) -m ransomware_twin validate

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

quality:
	ruff check src tests scripts
	ruff format --check src tests scripts
	mypy src/ransomware_twin
	$(PYTHON) -m compileall -q src tests scripts
	$(PYTHON) scripts/safety_static_gate.py
	$(PYTHON) scripts/quality_gate.py
	$(PYTHON) scripts/verify_golden.py

compare:
	$(PYTHON) -m ransomware_twin compare --output-dir out/comparison

serve:
	$(PYTHON) -m ransomware_twin serve --host 127.0.0.1 --port 8080

docker-build:
	docker build --tag ransomware-digital-twin:local .
