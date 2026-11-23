.DEFAULT_GOAL := help

CARGO ?= cargo
DOCKER ?= docker
GITLEAKS_IMAGE := ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f

.PHONY: help fmt fmt-check lint test build release ci install docker security security-secrets security-audit security-policy

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

release: security ## Run security checks, then build the optimized rush-mcp binary
	$(CARGO) build --locked --release

ci: fmt-check lint test build ## Run all pull-request checks locally

# Local release prerequisites: Docker and the dependency scanners.
# cargo +stable install --locked cargo-audit --version 0.22.2
# cargo +stable install --locked cargo-deny --version 0.20.2
security: security-secrets security-audit security-policy ## Run release security checks without building

security-secrets: ## Scan Git history for secrets using Docker
	$(DOCKER) run --rm --volume "$(CURDIR):/repo:ro" $(GITLEAKS_IMAGE) git /repo --redact --no-banner

security-audit: ## Scan Cargo.lock against RustSec with cargo-audit
	$(CARGO) audit

security-policy: ## Enforce dependency, advisory, license and source policy
	$(CARGO) deny check --hide-inclusion-graph advisories bans licenses sources

install: ## Install rush-mcp from this checkout
	$(CARGO) install --locked --path .

docker: ## Build the container image
	$(DOCKER) build -t rush-mcp:dev .
