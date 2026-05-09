# Integration tests — per-language Docker smokes.
#
# Each smoke:
#   1. Registers USER_CREATED.
#   2. init() with FASTEN_SERVICE_ID, FASTEN_NODE_ID set.
#   3. log.info("startup_ok", ...) — produces sys row.
#   4. emit(USER_CREATED, ...) with PII detail — produces audit row.
#
# verify.py reads container stdout and asserts the wire contract.
#
# Targets:
#   make build            # build all images
#   make test             # run all smokes (build + run + verify)
#   make test-<lang>      # one language only (python|go|node|rust|cpp)
#   make clean            # remove all images

ROOT       := $(realpath ../..)
VERIFY     := python3 verify.py
LANGS      := python go node rust cpp

.PHONY: all build test clean $(addprefix test-,$(LANGS)) $(addprefix build-,$(LANGS))

all: test

build: $(addprefix build-,$(LANGS))

test: $(addprefix test-,$(LANGS))
	@echo ""
	@echo "=== ALL LANGUAGES PASSED ==="

$(addprefix build-,$(LANGS)): build-%:
	@echo "==> Building fasten-itest-$* (base: see Dockerfile)"
	docker build -f $*/Dockerfile -t fasten-itest-$* $(ROOT)

$(addprefix test-,$(LANGS)): test-%: build-%
	@echo ""
	@echo "==> Running fasten-itest-$*"
	docker run --rm fasten-itest-$* | $(VERIFY)

# Python is the only SDK that currently emits api rows; gate the api-stream
# assertion via FASTEN_VERIFY_REQUIRE_API=1 (P1-20). This explicit target
# overrides the pattern rule above for python only.
test-python: build-python
	@echo ""
	@echo "==> Running fasten-itest-python"
	docker run --rm fasten-itest-python | env FASTEN_VERIFY_REQUIRE_API=1 $(VERIFY)

clean:
	-docker rmi $(addprefix fasten-itest-,$(LANGS)) 2>/dev/null || true
