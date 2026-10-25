.DEFAULT_GOAL := build

# LINK_MODE selects how bin/app is linked:
#   static (default)   - CGO_ENABLED=0, statically linked; no runtime
#                        dependency on any libc, so it runs on glibc OR
#                        musl images alike (required for musl, e.g. the
#                        alpine sidecar image in deploy/podman/pod-up.sh).
#                        This project uses no cgo (no `import "C"`, no
#                        os/user, etc.), so this has no functional downside.
#   dynamic            - CGO_ENABLED=1, dynamically linked against glibc;
#                        matches this toolchain's ambient default (a C
#                        compiler is present on this host). Requires glibc
#                        to be present at runtime (e.g. debian/ubuntu
#                        images) -- will NOT exec on a musl image (e.g.
#                        alpine).
LINK_MODE ?= static
ifeq ($(LINK_MODE),static)
  CGO_ENABLED_APP := 0
else ifeq ($(LINK_MODE),dynamic)
  CGO_ENABLED_APP := 1
else
  $(error LINK_MODE must be "dynamic" or "static", got "$(LINK_MODE)")
endif

# Development tools that are not module dependencies run at the exact version
# held below (AD-028): `go run <pkg>@<version>` or `uvx <tool>@<version>`, never
# @latest and never a `tool` directive in go.mod. Dependabot does not read these
# variables, so they are bumped by hand. Override one on the command line, e.g.
# `make vuln GOVULNCHECK_VERSION=v1.9.1`.
ACTIONLINT_VERSION := v1.7.12
ZIZMOR_VERSION := 1.31.1
GOVULNCHECK_VERSION := v1.9.0

fmt:
	go fmt ./...
.PHONY: fmt

generate:
	go generate ./...
.PHONY: generate

lint: fmt
	golangci-lint run --timeout=5m --build-tags=integration --enable=errcheck,staticcheck,govet,ineffassign,unused,gosec,revive,bodyclose,misspell
.PHONY: lint

lint-workflows:
	go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION) .github/workflows/*.yml
	uvx zizmor@$(ZIZMOR_VERSION) .github/workflows/
.PHONY: lint-workflows

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
.PHONY: vuln

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

check: lint lint-workflows vuln build test test-integration
.PHONY: check
