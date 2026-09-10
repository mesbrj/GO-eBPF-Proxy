.DEFAULT_GOAL := build

fmt:
	go fmt ./...
.PHONY: fmt

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

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
.PHONY: test-coverage
