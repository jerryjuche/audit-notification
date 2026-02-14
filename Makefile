.PHONY: help run build test clean install dev docker-build docker-run

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install dependencies
	go mod download
	go mod tidy

run: ## Run the server
	go run cmd/server/main.go

build: ## Build the binary
	go build -o bin/audit-server cmd/server/main.go

test: ## Run tests
	go test -v ./...

clean: ## Clean build artifacts and database
	rm -f bin/audit-server
	rm -f notifications.db

dev: ## Run with live reload (requires air)
	air

docker-build: ## Build Docker image
	docker build -t audit-notification-system .

docker-run: ## Run Docker container
	docker run -p 8080:8080 audit-notification-system

lint: ## Run linter (requires golangci-lint)
	golangci-lint run ./...

fmt: ## Format code
	go fmt ./...
	gofmt -s -w .

check: fmt lint test ## Run all checks

.DEFAULT_GOAL := help
