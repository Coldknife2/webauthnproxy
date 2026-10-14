BIN      := webauthnproxy
RUNTIME  ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)

.PHONY: build test vet fmt check e2e image clean help

help: ## Liste les cibles
	@grep -E '^[a-z0-9-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

build: ## Compile le binaire
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN) .

test: ## Tests unitaires (avec détecteur de race)
	go test -race ./...

vet: ## go vet
	go vet ./...

fmt: ## Vérifie le formatage (échoue si gofmt a des changements à faire)
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt requis"; exit 1; }

check: fmt vet test ## Tout ce que la CI vérifie hors e2e

e2e: build ## Tests de bout en bout (Chromium + Traefik en conteneur)
	cd test/e2e && npm install && npx playwright install chromium && RUNTIME=$(RUNTIME) npm test

image: ## Construit l'image de conteneur
	$(RUNTIME) build -t $(BIN) .

clean:
	rm -f $(BIN)
