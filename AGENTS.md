# AGENTS.md

## Domain & Code Standards

**Domain**: modern Linux networking and TLS traffic analysis. Work in this repo is expected to be technically correct across Linux networking internals (NETLINK, eBPF), PCAP(NG) capture formats, IETF IPFIX flow export, deep packet inspection, network protocol analysis, and modern TLS — including decryption of TLS 1.2 and 1.3 under forward secrecy.

**Code standard**: Go must be clean, idiomatic and performant, and must follow the conventions of the package it lives in rather than introducing a new style.

**TLS decryption is passive, always**: session keys come from the application's own TLS library (NSS keylog lines). Never introduce TLS termination, a MITM proxy, a custom CA, or any change that weakens the application's certificate validation.

## Go Lang Tooling & Project Execution Commands

- Use makefile with below structure to manage project tasks. **Every recipe line is indented with a literal TAB**, never spaces — `make` rejects space-indented recipes with `missing separator. Stop.`:

```makefile
.DEFAULT_GOAL := build

# LINK_MODE selects how bin/app is linked: static (default) -> CGO_ENABLED=0,
# runs on glibc OR musl images alike; dynamic -> CGO_ENABLED=1, needs glibc at
# runtime. Any other value is a hard error rather than a silent CGO build.
LINK_MODE ?= static
ifeq ($(LINK_MODE),static)
  CGO_ENABLED_APP := 0
else ifeq ($(LINK_MODE),dynamic)
  CGO_ENABLED_APP := 1
else
  $(error LINK_MODE must be "dynamic" or "static", got "$(LINK_MODE)")
endif

fmt:
	go fmt ./...
.PHONY: fmt

generate:
	go generate ./...
.PHONY: generate

lint: fmt
	golangci-lint run --timeout=5m --build-tags=integration --enable=errcheck,staticcheck,govet,ineffassign,unused,gosec,revive,bodyclose,misspell
.PHONY: lint

vet: fmt
	go vet ./...
.PHONY: vet

build: vet
	go build ./...
	CGO_ENABLED=$(CGO_ENABLED_APP) go build -o bin/app ./cmd/app
.PHONY: build

build-preload:
	$(CC) -shared -fPIC -o preload/libkeylogpreload.so preload/keylog_preload.c -ldl -lssl -lcrypto
.PHONY: build-preload

test:
	go test -v -race ./...
.PHONY: test

test-integration:
	go test -v -race -tags=integration ./...
.PHONY: test-integration

test-coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
.PHONY: test-coverage

tidy:
	go mod tidy
	go mod verify
.PHONY: tidy

clean:
	rm -f coverage.out coverage.html
.PHONY: clean

check: lint build test test-integration
.PHONY: check
```

- Use `github.com/stretchr/testify` for writing unit, integration, and end-to-end tests, leveraging: `assert`, `require`, `mock` and `suite` packages as needed.

## eBPF Build Toolchain

- Kernel-side C compiled via `cilium/ebpf` `bpf2go` (`go:generate`), needing `clang`/`llvm` ≥ 14 and `vmlinux.h` (from `bpftool btf dump`).
- Keep `.bpf.c` under `bpf/`; commit generated `*_bpfel.go`/`*_bpfeb.go` + objects. CO-RE relocations rely on target-kernel BTF.
- User-space C: `preload/keylog_preload.c` (the `LD_PRELOAD` OpenSSL keylog interposer) is built by `make build-preload` via `$(CC) -shared -fPIC ... -ldl -lssl -lcrypto` and needs the OpenSSL dev headers. It is **not** built by `bpf2go` and never linked into the Go binary — the sidecar stays CGO-free. The resulting `.so` and the generated `bpf/vmlinux.h` are gitignored.

## Project Architecture, Design and Structure

- See "Architectural Principles" in the [TDD](/docs/technical-design-document.md) (package-by-feature/vertical-slice, tactical DDD, interfaces at slice boundaries, constructor-based DI).
- Use a consistent naming convention for packages, files, and functions, following Go's idiomatic practices.

## Product Requirements Documentation

- Product PRD - [PRD](/docs/prd/product-requirements-document.md)

## Tasks Management

- Use the `skill-taskwarrior` skill (invoked via the Skill tool) for managing and tracking human tasks.
