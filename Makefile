# gatecontrol-agent — build, test, packages
#   make build          dist/<goarch>/gatecontrol-agent for amd64, arm64, arm (armhf, GOARM=7)
#   make test lint
#   make packages       .deb (amd64, arm64, armhf), .pkg.tar.zst (x86_64, aarch64), .rpm (amd64, arm64) in dist/
# The version lives in the file VERSION; the release workflow raises it (never by hand).
VERSION ?= $(shell cat VERSION 2>/dev/null)
ifeq ($(VERSION),)
VERSION := 0.0.0
endif
PKG     := github.com/CallMeTechie/gatecontrol-linux-agent
LDFLAGS := -s -w -buildid= -X $(PKG)/internal/version.Version=$(VERSION)
NFPM    ?= nfpm

.PHONY: build test lint packages clean
build: dist/amd64/gatecontrol-agent dist/arm64/gatecontrol-agent dist/arm/gatecontrol-agent

dist/%/gatecontrol-agent: $(shell find . -name '*.go' -not -path './dist/*') go.mod go.sum VERSION
	CGO_ENABLED=0 GOOS=linux GOARCH=$* GOARM=7 go build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/gatecontrol-agent

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

# nfpm arch names: deb amd64/arm64/armhf · archlinux/rpm get amd64/arm64 (nfpm maps them to x86_64/aarch64)
# pkg <goarch> <nfpm arch> <packager>: stage the binary, then nfpm
define pkg
	mkdir -p dist/stage && cp dist/$(1)/gatecontrol-agent dist/stage/gatecontrol-agent
	VERSION=$(VERSION) NFPM_ARCH=$(2) $(NFPM) package -p $(3) -t dist/
endef

packages: build
	$(call pkg,amd64,amd64,deb)
	$(call pkg,arm64,arm64,deb)
	$(call pkg,arm,armhf,deb)
	$(call pkg,amd64,amd64,archlinux)
	$(call pkg,arm64,arm64,archlinux)
	$(call pkg,amd64,amd64,rpm)
	$(call pkg,arm64,arm64,rpm)
	rm -rf dist/stage

clean:
	rm -rf dist
