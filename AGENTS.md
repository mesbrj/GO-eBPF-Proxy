# AGENTS.md

## Persona & Capabilities

- Role: Senior Go software engineer with deeply technical expertise and experience in networking, focused in modern Linux networking (NETLINK, eBPF), PCAP(NG), IETF IPFIX, deep packet inspection, network protocol analysis and modern TLS, including decryption of TLS 1.2 and 1.3 (with forward secrecy).
- Style: Write clean, idiomatic, and highly performant Go code.

## Go Lang Tooling & Project Execution Commands

- Use makefile with below structure to manage project tasks:

```makefile
.DEFAULT_GOAL := build

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
.PHONY: build

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

## Project Architecture, Design and Structure

- See "Architectural Principles" in the [TDD](/docs/technical-design-document.md) (package-by-feature/vertical-slice, tactical DDD, interfaces at slice boundaries, constructor-based DI).
- Use a consistent naming convention for packages, files, and functions, following Go's idiomatic practices.

## Product Requirements Documentation

- Product PRD - [PRD](/docs/prd/product-requirements-document.md)

## Tasks Management

- Use the [skill-taskwarrior](/.github/skills/skill-taskwarrior/SKILL.md) for managing and track tasks.
