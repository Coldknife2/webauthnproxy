BIN      := webauthnproxy
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
RUNTIME  ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)

.PHONY: build test vet fmt check e2e image clean help

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

image: ## Build the container image
	$(RUNTIME) build --build-arg VERSION=$(VERSION) -t $(BIN) .

clean:
	rm -f $(BIN)
