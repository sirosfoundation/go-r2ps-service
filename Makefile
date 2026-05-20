.PHONY: all build build-lib test test-short coverage coverage-cli fmt vet lint check tidy setup clean help

BINARY_NAME := r2ps-server
CMD_DIR := ./cmd/server

## all: Run tests then build
all: test build

## build: Build the server binary
build:
	go build -o bin/$(BINARY_NAME) $(CMD_DIR)

## build-lib: Compile all packages
build-lib:
	go build ./...

## test: Run all tests with race detector
test:
	go test -v -race -count=1 ./...

## test-short: Run tests in short mode
test-short:
	go test -short ./...

## coverage: Generate HTML coverage report
coverage:
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## coverage-cli: Show coverage in terminal
coverage-cli:
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out

## fmt: Format all Go files
fmt:
	go fmt ./...

## vet: Run go vet
vet:
	go vet ./...

## lint: Run golangci-lint (install: https://golangci-lint.run/welcome/install/)
lint:
	golangci-lint run --timeout=5m --tests=false ./...

## check: Format, lint, and test
check: fmt lint test

## tidy: Tidy go.mod
tidy:
	go mod tidy

## setup: Set up development environment
setup:
	bash scripts/setup-dev.sh

## clean: Remove build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f *.log

## help: Show this help
help:
	@echo "Available targets:"
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/## /  /'
