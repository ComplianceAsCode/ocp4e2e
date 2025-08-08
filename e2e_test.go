package ocp4e2e

import (
	"flag"
	"log"
	"os"
	"testing"

	dynclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ComplianceAsCode/ocp4e2e/config"
	"github.com/ComplianceAsCode/ocp4e2e/helpers"
)

var testContext *e2econtext

// TestMain handles the setup and teardown for all tests.
func TestMain(m *testing.M) {
	// Define flags
	config.DefineFlags()

	flag.Parse()

	// Validate required flags
	if err := config.ValidateFlags(); err != nil {
		log.Printf("Flag validation failed: %v", err)
		os.Exit(1)
	}

	tc := config.NewTestConfig()
	// Setup phase
	err := helpers.Setup(tc)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	// Run tests
	testResult := m.Run()

	// Teardown phase
	err = helpers.Teardown(tc)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	// Exit with test result
	os.Exit(testResult)
}

func TestE2e(t *testing.T) {
	// Determine which tests to run based on testType
	runPlatformTests := testContext.testType == "platform" || testContext.testType == "all"
	runNodeTests := testContext.testType == "node" || testContext.testType == "all"

	tc := config.NewTestConfig()
	c, err := helpers.GenerateKubeConfig()
	if err != nil {
		t.Fatalf("Failed to generate kube config: %s", err)
	}

	if runPlatformTests {
		t.Run("Platform compliance tests", runPlatformComplianceTests(tc, c))
	}

	if runNodeTests {
		t.Run("Node compliance tests", runNodeComplianceTests(tc, c))
	}

	if !runPlatformTests && !runNodeTests {
		t.Fatalf("Invalid test-type: %s. Must be 'platform', 'node', or 'all'", testContext.testType)
	}
}

func runPlatformComplianceTests(tc *config.TestConfig, c dynclient.Client) func(*testing.T) {
	return func(t *testing.T) {
		// Create platform tailored profile
		err := helpers.CreatePlatformTailoredProfile(tc, c)
		if err != nil {
			t.Fatalf("Failed to create platform tailored profile: %s", err)
		}

		// Create scan setting binding and run platform scan
		platformBindingName := "platform-scan-binding"
		platformBindingErr := helpers.CreatePlatformScanBinding(tc, c)
		if platformBindingErr != nil {
			t.Fatalf("Failed to create %s scan binding: %s", platformBindingName, platformBindingErr)
		}

		err = helpers.WaitForComplianceSuite(tc, c, platformBindingName)
		if err != nil {
			t.Fatalf("Failed to wait for compliance suite: %s", err)
		}

		err = helpers.VerifyPlatformScanResults(tc, c, platformBindingName)
		if err != nil {
			t.Fatalf("Failed to verify platform scan results: %s", err)
		}
	}
}

func runNodeComplianceTests(tc *config.TestConfig, c dynclient.Client) func(*testing.T) {
	return func(t *testing.T) {
		// Create node tailored profile
		err := helpers.CreateNodeTailoredProfile(tc, c)
		if err != nil {
			t.Fatalf("Failed to create node tailored profile: %s", err)
		}

		// Create scan setting binding and run node scan
		nodeBindingName := "node-scan-binding"
		nodeBindingErr := helpers.CreateNodeScanBinding(tc, c)
		if nodeBindingErr != nil {
			t.Fatalf("Failed to create %s scan binding: %s", nodeBindingName, nodeBindingErr)
		}

		err = helpers.WaitForComplianceSuite(tc, c, nodeBindingName)
		if err != nil {
			t.Fatalf("Failed to wait for compliance suite: %s", err)
		}

		err = helpers.VerifyNodeScanResults(tc, c, nodeBindingName)
		if err != nil {
			t.Fatalf("Failed to verify node scan results: %s", err)
		}
	}
}
