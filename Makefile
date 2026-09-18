.DEFAULT_GOAL := build

# LINK_MODE selects how bin/app is linked:
#   dynamic (default) - CGO_ENABLED=1, dynamically linked against glibc;
#                        preserves this toolchain's ambient default (a C
#                        compiler is present on this host) for local/non-
#                        container use. Requires glibc to be present at
#                        runtime (e.g. debian/ubuntu images) -- will NOT
#                        exec on a musl image (e.g. alpine).
#   static             - CGO_ENABLED=0, statically linked; no runtime
#                        dependency on any libc, so it runs on glibc OR
#                        musl images alike (required for musl, e.g. the
#                        alpine sidecar image in deploy/podman/pod-up.sh).
#                        This project uses no cgo (no `import "C"`, no
#                        os/user, etc.), so "static" has no functional
#                        downside -- "dynamic" is the default only to avoid
#                        silently changing `make build`'s prior output.
LINK_MODE ?= dynamic
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
