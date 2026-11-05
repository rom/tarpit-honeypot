BIN          := tarpit-honeypot
PKG          := github.com/rom/tarpit-honeypot
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 1.0.1)
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

.PHONY: all build test vet fmt clean cross install-dev deb rpm sbom checksums release-artifacts govulncheck

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

# Cross-compile for Linux (full matrix) + macOS + Windows. The macOS and
# Windows builds carry every feature except the raw-L2 layers: ARP/ICMP/
# LLDP responders, AF_PACKET sniffer, fanotify OPEN-event detection, and
# Linux TUN adapter are linux-only (they no-op elsewhere). The TCP/UDP
# protocol emulators, correlators, web UI, and file canaries (via fsnotify)
# all run. See docs/usage.md "Platform support".
cross:
	mkdir -p dist
	GOOS=linux   GOARCH=amd64       $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-linux-amd64    $(CMD)
	GOOS=linux   GOARCH=arm64       $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-linux-arm64    $(CMD)
	GOOS=linux   GOARCH=arm GOARM=7 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-linux-armv7    $(CMD)
	GOOS=linux   GOARCH=arm GOARM=6 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-linux-armv6    $(CMD)
	GOOS=darwin  GOARCH=amd64       $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-darwin-amd64   $(CMD)
	GOOS=darwin  GOARCH=arm64       $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-darwin-arm64   $(CMD)
	GOOS=windows GOARCH=amd64       $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-windows-amd64.exe $(CMD)
	GOOS=windows GOARCH=arm64       $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(BIN)-windows-arm64.exe $(CMD)

# CycloneDX SBOM for the application + its full module graph. Pinned tool
# version so the SBOM is reproducible. Output is dist/sbom.cdx.json.
sbom:
	mkdir -p dist
	$(GO) run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.7.0 \
		app -json -licenses -main $(CMD) -output dist/sbom.cdx.json .

# SHA-256 checksums over every cross-compiled artifact (run after `cross`).
checksums:
	cd dist && sha256sum $(BIN)-* > checksums.txt && cat checksums.txt

# Vulnerability scan of the module graph + reachable symbols.
govulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Everything a release needs locally (no signing): cross binaries + SBOM +
# checksums. CI (release.yml / goreleaser) additionally cosign-signs these.
release-artifacts: cross sbom checksums

# Build a .deb. Requires dpkg-deb on the host.
deb:
	ARCH=$${ARCH:-amd64} packaging/debian/build.sh

# Build an .rpm. Requires rpmbuild on the host.
rpm:
	ARCH=$${ARCH:-amd64} packaging/rpm/build.sh
