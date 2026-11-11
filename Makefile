# Convenience targets. Every one of them is a thin wrapper around a tool, so CI
# and a human run exactly the same commands.
.DEFAULT_GOAL := help
PY ?= python3
GATES ?=

.PHONY: help install dev gates test unit bench single check lint fmt docs docker clean all

help:                       ## show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:                    ## install the package
	$(PY) -m pip install .

dev:                        ## editable install with the dev extras
	$(PY) -m pip install -e ".[dev]"
	pre-commit install

gates:                      ## run every integration gate (GATES="v8 probes" for a subset)
	$(PY) tools/run_gates.py $(GATES)

unit:                       ## run the unit suite
	PYTHONPATH=src $(PY) -m pytest tests/unit -q

test: gates unit             ## gates + unit tests

bench:                      ## the hardest-obfuscation benchmark
	PYTHONPATH=src $(PY) tests/benchmarks/bench_obf_bench.py

single:                     ## build dist/pydecomp.py
	$(PY) tools/build_single.py

check:                      ## everything CI checks, in order
	$(PY) tools/check_static_only.py
	$(PY) tools/gen_opcode_tables.py --check
	$(PY) tools/make_fixtures.py --check
	$(PY) tools/build_single.py --check
	$(PY) tools/run_gates.py
	PYTHONPATH=src $(PY) -m pytest tests/unit -q
	$(PY) examples/run_examples.py

lint:                       ## ruff + mypy
	ruff check .
	ruff format --check .
	mypy src/pydecomp --ignore-missing-imports || true

fmt:                        ## format the tree
	ruff format .
	ruff check --fix .

docs:                       ## serve the docs locally
	$(PY) -m mkdocs serve

docker:                     ## build the image and smoke-test it
	docker build -t pydecomp .
	printf 'import base64\nexec(base64.b64decode("cHJpbnQoMSk="))\n' > /tmp/s.py
	docker run --rm --network=none -v /tmp:/w -w /w pydecomp s.py --no-color --no-anim

fixtures:                   ## regenerate the text fixtures
	$(PY) tools/make_fixtures.py

native-fixtures:            ## regenerate the compiled fixtures (needs cython + gcc)
	$(PY) tests/fixtures/native/make_native_fixtures.py

release:                    ## VERSION=8.2.0 make release
	$(PY) tools/bump_version.py $(VERSION)

all: check single           ## check + build the single file

clean:                      ## drop caches and build output
	rm -rf build dist site .pytest_cache .ruff_cache .mypy_cache .cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
