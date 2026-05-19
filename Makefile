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

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -rf bin dist

# Cross-compile targets for v0.1 (linux amd64 + arm64).
# Wider matrix (armv6/armv7, windows) lands in v0.3 once cgo decisions are final.
cross:
	mkdir -p dist
	GOOS=linux  GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-linux-amd64  $(CMD)
	GOOS=linux  GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-linux-arm64  $(CMD)
