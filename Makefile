# Variables
CARGO      := cargo
RELEASE_DIR:= release
DEBUG_DIR  := debug
MAN_DIR    := pkg/common/manpages
BINARIES   := couic couicctl couic-report
DOCKER := $(shell if groups $(USER) | grep -q '\bdocker\b'; then echo docker; else echo sudo docker; fi)

# Default target
.PHONY: all
all: debug

# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------
.PHONY: setup
setup: ## Configure the build environment
	rustup toolchain install stable
	rustup toolchain install nightly --component rust-src
	rustup target add --toolchain nightly aarch64-unknown-linux-gnu
	rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
	rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
	$(CARGO) install cargo-binstall --locked
	$(CARGO) binstall --no-confirm bpf-linker
	$(CARGO) install git-cliff
	$(CARGO) install cargo-deb
	$(CARGO) install cargo-generate-rpm

# -----------------------------------------------------------------------------
# Builds
# -----------------------------------------------------------------------------
.PHONY: debug
debug: ## Build the project in debug mode
	$(CARGO) build
	mkdir -p $(DEBUG_DIR)
	$(foreach bin,$(BINARIES),cp target/debug/$(bin) $(DEBUG_DIR)/$(bin);)

.PHONY: release
release: ## Build the project in release mode
	$(CARGO) build --release
	mkdir -p $(RELEASE_DIR)
	$(foreach bin,$(BINARIES),cp target/release/$(bin) $(RELEASE_DIR)/$(bin);)
	$(CARGO) deb --no-build -p couic
	$(CARGO) deb --no-build -p couic-report
	cp target/debian/couic* $(RELEASE_DIR)
	cargo-generate-rpm --metadata-overwrite=pkg/rpm/couic/scriptlets.toml -p couic
	cargo-generate-rpm --metadata-overwrite=pkg/rpm/couic-report/scriptlets.toml -p couic-report
	cp target/generate-rpm/*.rpm $(RELEASE_DIR)

.PHONY: release-arm64
release-arm64: ## Cross-compile for ARM64 (dynamic)
	$(CARGO) build --release --target=aarch64-unknown-linux-gnu
	mkdir -p $(RELEASE_DIR)
	$(foreach bin,$(BINARIES),cp target/aarch64-unknown-linux-gnu/release/$(bin) $(RELEASE_DIR)/$(bin)-arm64;)
	$(CARGO) deb --no-build -p couic
	$(CARGO) deb --no-build -p couic-report
	cp target/debian/couic* $(RELEASE_DIR)
	cargo-generate-rpm --target=aarch64-unknown-linux-gnu --metadata-overwrite=pkg/rpm/couic/scriptlets.toml -p couic
	cargo-generate-rpm --target=aarch64-unknown-linux-gnu --metadata-overwrite=pkg/rpm/couic-report/scriptlets.toml -p couic-report
	cp target/aarch64-unknown-linux-gnu/generate-rpm/*.rpm $(RELEASE_DIR)

.PHONY: release-static
release-static: ## Build statically linked release
	$(CARGO) build --release --target=x86_64-unknown-linux-musl
	mkdir -p $(RELEASE_DIR)
	$(foreach bin,$(BINARIES),cp target/x86_64-unknown-linux-musl/release/$(bin) $(RELEASE_DIR)/$(bin)-static;)
	$(CARGO) deb --no-build --target=x86_64-unknown-linux-musl -p couic
	$(CARGO) deb --no-build --target=x86_64-unknown-linux-musl -p couic-report
	cp target/debian/couic* $(RELEASE_DIR)
	cargo-generate-rpm --target=x86_64-unknown-linux-musl --metadata-overwrite=pkg/rpm/couic/scriptlets.toml -p couic
	cargo-generate-rpm --target=x86_64-unknown-linux-musl --metadata-overwrite=pkg/rpm/couic-report/scriptlets.toml -p couic-report
	cp target/x86_64-unknown-linux-musl/generate-rpm/*.rpm $(RELEASE_DIR)

.PHONY: release-static-arm64
release-static-arm64: ## Cross-compile statically for ARM64
	$(CARGO) build --release --target=aarch64-unknown-linux-musl
	mkdir -p $(RELEASE_DIR)
	$(foreach bin,$(BINARIES),cp target/aarch64-unknown-linux-musl/release/$(bin) $(RELEASE_DIR)/$(bin)-arm64-static;)
	$(CARGO) deb --no-build --target=aarch64-unknown-linux-musl -p couic
	$(CARGO) deb --no-build --target=aarch64-unknown-linux-musl -p couic-report
	cp target/debian/couic* $(RELEASE_DIR)
	cargo-generate-rpm --target=aarch64-unknown-linux-musl --metadata-overwrite=pkg/rpm/couic/scriptlets.toml -p couic
	cargo-generate-rpm --target=aarch64-unknown-linux-musl --metadata-overwrite=pkg/rpm/couic-report/scriptlets.toml -p couic-report
	cp target/aarch64-unknown-linux-musl/generate-rpm/*.rpm $(RELEASE_DIR)

# -----------------------------------------------------------------------------
# Docs
# -----------------------------------------------------------------------------
.PHONY: manpages
manpages: ## Build manpages
	$(CARGO) build --bin mangen
	mkdir -p $(MAN_DIR)
	OUT_DIR=$(MAN_DIR) ./target/debug/mangen
	find $(MAN_DIR) -type f -name "*.1" -exec gzip -9f {} \;
	$(CARGO) build -p couicctl
	./target/debug/couicctl --markdown-help > website/content/docs/reference/couicctl.md

.PHONY: docs
docs: manpages ## Build documentation with Hugo
	cd website && hugo --minify

.PHONY: docs-serve
docs-serve: ## Serve documentation locally with live reload
	cd website && hugo server -D

.PHONY: docs-clean
docs-clean: ## Clean generated documentation
	rm -rf website/public

.PHONY: changelog
changelog: ## Generate changelog using git-cliff
	git-cliff -o CHANGELOG.md

# -----------------------------------------------------------------------------
# Tests & QA
# -----------------------------------------------------------------------------
.PHONY: test
test: ## Run tests
	$(CARGO) test

.PHONY: integration-test
integration-test: release-static ## Run integration tests in Docker
	$(DOCKER) build -t couic-integration-test -f tests/integration/Dockerfile .
	$(DOCKER) run --privileged --rm -v .:/mnt couic-integration-test bash -c "sh /tmp/run.sh"

.PHONY: fmt
fmt: ## Format code
	$(CARGO) fmt

.PHONY: check
check: ## Check formatting
	$(CARGO) fmt -- --check

.PHONY: lint
lint: ## Run linter
	$(CARGO) clippy --all-targets --all-features

# -----------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------
.PHONY: run
run: ## Run in debug mode
	$(CARGO) run

.PHONY: run-release
run-release: ## Run in release mode
	$(CARGO) run --release

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------
.PHONY: clean
clean: ## Clean build artifacts
	$(CARGO) clean
	rm -rf $(RELEASE_DIR) $(DEBUG_DIR)

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
.PHONY: help
help: ## Show this help message
	@echo "Makefile for couic project"
	@echo
	@grep -E '^[a-zA-Z0-9_-]+:.*?##' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'
