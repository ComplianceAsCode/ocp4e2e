PROFILE?=
# Defines the product that the test aims to test
# Since we already have test for RHCOS4, this is the default for now.
PRODUCT?=rhcos4
CONTENT_IMAGE?=quay.io/complianceascode/ocp4:latest
ROOT_DIR?=
TEST_FLAGS?=-v -timeout 120m
# Should the test attempt to install the operator?
INSTALL_OPERATOR?=true

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
