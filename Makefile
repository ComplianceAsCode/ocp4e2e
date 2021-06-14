PROFILE?=
# Defines the product that the test aims to test
# Since we already have test for RHCOS4, this is the default for now.
PRODUCT?=rhcos4
CONTENT_IMAGE?=quay.io/complianceascode/ocp4:latest
ROOT_DIR?=
TEST_FLAGS?=-v -timeout 120m
# Should the test attempt to install the operator?
INSTALL_OPERATOR?=true

GOLANGCI_LINT_VERSION = v1.40.1
BUILD_DIR := build

.PHONY: all
all: e2e

.PHONY: e2e
e2e: ## Run the e2e tests. This requires that the PROFILE and PRODUCT environment variables be set.
	go test $(TEST_FLAGS) . -profile="$(PROFILE)" -product="$(PRODUCT)" -content-image="$(CONTENT_IMAGE)" -install-operator=$(INSTALL_OPERATOR)

.PHONY: help
help: ## Show this help screen
	@echo 'Usage: make <OPTIONS> ... <TARGETS>'
	@echo ''
	@echo 'Available targets are:'
	@echo ''
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


.PHONY: verify
verify: verify-go-lint ## Run all verification targets


.PHONY: verify-go-lint
verify-go-lint: $(BUILD_DIR)/golangci-lint ## Verify the golang code by linting
	$(BUILD_DIR)/golangci-lint run

$(BUILD_DIR)/golangci-lint: $(BUILD_DIR)
	export \
		VERSION=$(GOLANGCI_LINT_VERSION) \
		URL=https://raw.githubusercontent.com/golangci/golangci-lint \
		BINDIR=$(BUILD_DIR) && \
	curl -sfL $$URL/$$VERSION/install.sh | sh -s $$VERSION
	$(BUILD_DIR)/golangci-lint version
	$(BUILD_DIR)/golangci-lint linters

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)
