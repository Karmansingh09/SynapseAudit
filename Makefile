PYTHON ?= .venv/bin/python

.PHONY: setup test run

setup:
	python3 -m venv .venv
	$(PYTHON) -m pip install --requirement requirements.lock

test:
	$(PYTHON) -m unittest discover --start-directory tests --top-level-directory . --verbose

run:
	$(PYTHON) -m synapseaudit.cli fixtures/compose.vulnerable.yml
