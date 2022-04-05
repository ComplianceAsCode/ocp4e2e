# Compliance Operator Functional Tests

This repository contains end-to-end tests that exercise the
compliance-operator in Kubernetes deployments.

These tests require that you have a cluster deploy and available. These tests
will change the configuration of your deployment since they scan and remediate
issues in the cluster. Please be aware of the cluster you're running these
tests against as the tests do not restore the cluster or undo remediations
executed as part of the test.

## Parameters

- `PROFILE`: The profile to test. This value must match an existing profile in
  [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content/),
  typically ending in a `.profile` file extension (required).
- `PRODUCT`: The product to test (default: `rhcos4`).
- `CONTENT_IMAGE`: An image registry and image where the content is located
  (default: `quay.io/complianceascode/ocp4:latest`)
- `ROOT_DIR`: File path of the
  [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content/). By
  default, the tests will clone the repository into a `/tmp` directory.
  Providing the file path to the content will reduce the time it takes by not
  cloning the repository.
- `TEST_FLAGS`: Optional `go test` flags (default: `-v -timeout 120m`)
- `INSTALL_OPERATOR`: If true, the tests will attempt to install the
  compliance-operator in the provided cluster (default: `true`).

## Usage

You can use a dedicate Makefile target for running the tests

```console
$ PROFILE=high make e2e 
```
