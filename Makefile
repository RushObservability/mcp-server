.DEFAULT_GOAL := help

CARGO ?= cargo

.PHONY: help fmt fmt-check lint test build release ci install docker

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

fmt: ## Format Rust source
	$(CARGO) fmt --all

fmt-check: ## Verify formatting without changing files
	$(CARGO) fmt --all -- --check

lint: ## Run Clippy and reject warnings
	$(CARGO) clippy --locked --all-targets --all-features -- -D warnings

test: ## Run the test suite
	$(CARGO) test --locked

build: ## Build every target in debug mode
	$(CARGO) build --locked --all-targets

release: ## Build the optimized rush-mcp binary
	$(CARGO) build --locked --release

ci: fmt-check lint test build ## Run all pull-request checks locally

install: ## Install rush-mcp from this checkout
	$(CARGO) install --locked --path .

docker: ## Build the container image
	docker build -t rush-mcp:dev .
