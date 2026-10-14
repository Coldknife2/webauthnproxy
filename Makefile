BIN      := webauthnproxy
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
RUNTIME  ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)

.PHONY: build test vet fmt check e2e examples image-examples compare bench bench-go bench-langs image clean help

help: ## List targets
	@grep -E '^[a-z0-9-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

build: ## Build the binary
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o $(BIN) .

test: ## Unit tests (with the race detector)
	go test -race ./...

vet: ## go vet
	go vet ./...

fmt: ## Check formatting (fails if gofmt has changes to make)
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt required"; exit 1; }

check: fmt vet test ## Everything CI checks except e2e

e2e: build ## End-to-end tests (Chromium + Traefik in a container)
	cd test/e2e && npm install && npx playwright install chromium && RUNTIME=$(RUNTIME) npm test

image-examples: ## Build the image the examples run (localhost/webauthnproxy:examples)
	$(RUNTIME) build $(if $(findstring podman,$(RUNTIME)),--format docker) --build-arg VERSION=$(VERSION) -t localhost/webauthnproxy:examples .

examples: image-examples ## Run the two complete examples (examples/) with Chromium (needs compose)
	cd test/e2e && npm install >/dev/null && RUNTIME=$(RUNTIME) node ../examples/run.cjs

compare: ## Experiment: does one Tinyauth login cover an unrelated domain? (needs podman/docker, Chromium)
	cd test/e2e && npm install >/dev/null && RUNTIME=$(RUNTIME) node ../compare/tinyauth-crossdomain.cjs

bench: ## Footprint benchmark vs Authelia (needs the local image; ~3 min)
	RUNTIME=$(RUNTIME) python3 test/bench/bench.py

bench-go: ## Go micro-benchmarks of the hot path
	go test -run xxx -bench . -benchmem

bench-langs: ## Hot path in Go/Rust/.NET/Node/Python (builds 5 prototype images; ~8 min)
	for d in go rust dotnet node python; do $(RUNTIME) build -t lang-$$d test/bench/langs/$$d || exit 1; done
	RUNTIME=$(RUNTIME) python3 test/bench/langs.py

image: ## Build the container image
	$(RUNTIME) build --build-arg VERSION=$(VERSION) -t $(BIN) .

clean:
	rm -f $(BIN)
