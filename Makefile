PROFILE?=
# Defines the product that the test aims to test
# Since we already have test for RHCOS4, this is the default for now.
PRODUCT?=rhcos4
PLATFORM?=ocp4
ROOT_DIR?=
TEST_FLAGS?=-v -timeout 120m
# Should the test attempt to install the operator?
INSTALL_OPERATOR?=true
BYPASS_REMEDIATIONS?=false
# Type of rules to test: platform, node, or all
TEST_TYPE?=all

GOLANGCI_LINT_VERSION=latest
BUILD_DIR := build
PLATFORM?=ocp

.PHONY: all
all: e2e

.PHONY: e2e
e2e: ## Run the e2e tests. This requires that the PROFILE and PRODUCT environment variables be set.
## idp_fix.patch is used to fix route destination cert for keycloak IdP deployment
	set -o pipefail; go test $(TEST_FLAGS) . -platform="$(PLATFORM)" -profile="$(PROFILE)" -product="$(PRODUCT)" -install-operator=$(INSTALL_OPERATOR) -bypass-remediations="$(BYPASS_REMEDIATIONS)" -test-type="$(TEST_TYPE)" | tee .e2e-test-results.out

.PHONY: e2e-platform
e2e-platform: ## Run only platform compliance tests
	set -o pipefail; go test $(TEST_FLAGS) . -product="$(PRODUCT)"  -install-operator=$(INSTALL_OPERATOR) -bypass-remediations="$(BYPASS_REMEDIATIONS)" -test-type="platform" | tee .e2e-platform-test-results.out

.PHONY: e2e-node
e2e-node: ## Run only node compliance tests
	set -o pipefail; go test $(TEST_FLAGS) . -install-operator=$(INSTALL_OPERATOR) -bypass-remediations="$(BYPASS_REMEDIATIONS)" -test-type="node" | tee .e2e-node-test-results.out

.PHONY: e2e-profile
e2e-profile: ## Run TestProfile test only
	set -o pipefail; go test $(TEST_FLAGS) . -run=TestProfile -profile="$(PROFILE)" -product="$(PRODUCT)" -install-operator=$(INSTALL_OPERATOR) | tee .e2e-profile-test-results.out

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

.PHONY: fmt
fmt: ## Format Go code using gofmt
	find . -name '*.go' -not -path './vendor/*' -exec gofmt -s -w {} \;

.PHONY: fumpt
fumpt: $(BUILD_DIR)/gofumpt ## Format Go code using gofumpt (stricter than gofmt)
	find . -name '*.go' -not -path './vendor/*' -exec $(BUILD_DIR)/gofumpt -w {} \;

$(BUILD_DIR)/golangci-lint: $(BUILD_DIR)
	export \
		VERSION=$(GOLANGCI_LINT_VERSION) \
		URL=https://raw.githubusercontent.com/golangci/golangci-lint \
		BINDIR=$(BUILD_DIR) && \
	curl -sfL $$URL/HEAD/install.sh | sh -s $$VERSION
	$(BUILD_DIR)/golangci-lint version
	$(BUILD_DIR)/golangci-lint linters

$(BUILD_DIR)/gofumpt: $(BUILD_DIR)
	GOBIN=$(PWD)/$(BUILD_DIR) go install mvdan.cc/gofumpt@latest

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)
