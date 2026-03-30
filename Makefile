GO ?= go
CC ?= cc
DOCKER ?= docker
GOLANGCI_LINT ?= golangci-lint
BIN_DIR ?= bin
IMAGE ?= bbox-agent
TAG ?= latest
IMAGE_REF := $(IMAGE):$(TAG)

.PHONY: build docker-build lint release-snapshot release-snapshot-multiarch generate-embedded-launchers

build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 $(GO) build -trimpath -o $(BIN_DIR)/bbox ./cmd/bbox
	CGO_ENABLED=1 $(GO) build -trimpath -o $(BIN_DIR)/bbox-helper ./cmd/bbox-helper
	$(CC) -O2 -o $(BIN_DIR)/bbox-seccomp-launcher ./cmd/bbox-seccomp-launcher/main.c

generate-embedded-launchers:
	./scripts/generate-embedded-launchers.sh

release-snapshot:
	./scripts/release-snapshot.sh

release-snapshot-multiarch:
	./scripts/release-multiarch-snapshot.sh

docker-build:
	$(DOCKER) build -t $(IMAGE_REF) .

lint:
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { echo "$(GOLANGCI_LINT) not found on PATH; run lint inside the Docker image or install it locally."; exit 1; }
	@FILES="$$(rg --files -g '*.go')"; \
	OUT="$$(gofmt -l $$FILES)"; \
	if [ -n "$$OUT" ]; then \
		echo "gofmt reported unformatted files:"; \
		echo "$$OUT"; \
		exit 1; \
	fi
	$(GOLANGCI_LINT) run --enable-only govet --enable-only ineffassign --enable-only unused ./...
