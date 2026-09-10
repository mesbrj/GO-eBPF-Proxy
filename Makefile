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
