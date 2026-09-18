.DEFAULT_GOAL := build

# LINK_MODE selects how bin/app is linked:
#   dynamic (default) - CGO_ENABLED=1, dynamically linked against glibc;
#                        for glibc-based container images (e.g. debian/ubuntu).
#   static             - CGO_ENABLED=0, statically linked; required for
#                        musl-based container images (e.g. alpine), which
#                        have no glibc interpreter/libc.so.6 to exec against
#                        (see deploy/podman/pod-up.sh's sidecar image).
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
