BIN          := tarpit-honeypot
PKG          := github.com/rom/tarpit-honeypot
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT       ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS      := -s -w \
                -X $(PKG)/internal/version.Version=$(VERSION) \
                -X $(PKG)/internal/version.Commit=$(COMMIT) \
                -X $(PKG)/internal/version.BuildDate=$(BUILD_DATE)

GO           := go
GOFLAGS      := -trimpath
CMD          := ./cmd/$(BIN)

# v0.1 has no cgo dependencies; lock it off so builds are always static.
# When v0.3 adds libpcap on the pcap-capture path, we'll flip this per-target.
export CGO_ENABLED := 0

.PHONY: all build test vet fmt clean cross install-dev

all: build

build:
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(BIN) $(CMD)

test:
	$(GO) test $(GOFLAGS) ./...

# Race-detector run. CGO is required for -race so we override the default
# CGO_ENABLED=0 just for this target.
race:
	CGO_ENABLED=1 $(GO) test $(GOFLAGS) -race ./...

# Coverage: write a profile + a per-function summary, and a best-effort
# HTML render (which needs the source visible to `go tool cover -html`).
cover:
	$(GO) test $(GOFLAGS) -coverprofile=coverage.out ./...
	-$(GO) tool cover -func=coverage.out > coverage.summary
	-tail -1 coverage.summary
	-$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "summary: coverage.summary; HTML: coverage.html (if rendered)"

# Run all FuzzXxx tests for a few seconds each. CI should run a longer
# pass via `go test -fuzz=^FuzzXxx$ ./internal/<pkg>` per-package.
fuzz:
	$(GO) test -run='^$$' -fuzz='Fuzz' -fuzztime=10s ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -rf bin dist

# Cross-compile for the full Linux matrix. Windows is intentionally absent
# from `cross` until v0.8 — the sniffer and fanotify code paths are
# linux-only and Windows packaging needs the service installer first.
cross:
	mkdir -p dist
	GOOS=linux GOARCH=amd64               $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-linux-amd64  $(CMD)
	GOOS=linux GOARCH=arm64               $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-linux-arm64  $(CMD)
	GOOS=linux GOARCH=arm GOARM=7         $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-linux-armv7  $(CMD)
	GOOS=linux GOARCH=arm GOARM=6         $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-linux-armv6  $(CMD)
