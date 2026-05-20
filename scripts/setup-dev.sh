#!/usr/bin/env bash
# Set up the development environment for go-r2ps-service

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Setting up go-r2ps-service development environment..."

echo "Configuring git hooks..."
cd "$PROJECT_ROOT"
git config core.hooksPath .githooks
chmod +x .githooks/*
echo "✓ Git hooks configured"

echo "Downloading dependencies..."
go mod download
echo "✓ Dependencies downloaded"

echo "Verifying build..."
go build ./...
echo "✓ Build OK"

echo "Running tests..."
go test -short ./...
echo "✓ Tests passed"

echo ""
echo "Development environment ready!"
echo "Run 'make help' to see available commands."
