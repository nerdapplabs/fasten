# Per-language Docker smoke tests.
#
# Each smoke registers USER_CREATED, calls init(), writes a sys row with
# log.info("startup_ok", ...) and an audit row with emit(USER_CREATED, ...)
# whose detail includes fields that must be redacted.
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

# Only the Python smoke writes api rows, so only it sets
# FASTEN_VERIFY_REQUIRE_API=1. This rule overrides the pattern rule above.
test-python: build-python
	@echo ""
	@echo "==> Running fasten-itest-python"
	docker run --rm fasten-itest-python | env FASTEN_VERIFY_REQUIRE_API=1 $(VERIFY)

clean:
	-docker rmi $(addprefix fasten-itest-,$(LANGS)) 2>/dev/null || true
