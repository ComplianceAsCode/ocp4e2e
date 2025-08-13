package ocp4e2e

import (
	"flag"
	"log"
	"os"
	"testing"

	"github.com/ComplianceAsCode/ocp4e2e/config"
	"github.com/ComplianceAsCode/ocp4e2e/helpers"
)

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

func TestPlatformCompliance(t *testing.T) {
	tc := config.NewTestConfig()

	// Skip if test type doesn't include platform tests
	if tc.TestType != "platform" && tc.TestType != "all" {
		t.Skipf("Skipping platform tests: -test-type is %s", tc.TestType)
	}

	c, err := helpers.GenerateKubeConfig()
	if err != nil {
		t.Fatalf("Failed to generate kube config: %s", err)
	}

	// Create platform tailored profile
	err = helpers.CreatePlatformTailoredProfile(tc, c)
	if err != nil {
		t.Fatalf("Failed to create platform tailored profile: %s", err)
	}

	// Create scan setting binding and run platform scan
	platformBindingName := "platform-scan-binding"
	err = helpers.CreatePlatformScanBinding(tc, c)
	if err != nil {
		t.Fatalf("Failed to create %s scan binding: %s", platformBindingName, err)
	}

	err = helpers.WaitForComplianceSuite(tc, c, platformBindingName)
	if err != nil {
		t.Fatalf("Failed to wait for compliance suite: %s", err)
	}

	err = helpers.VerifyPlatformScanResults(tc, c, platformBindingName)
	if err != nil {
		t.Fatalf("Failed to verify platform scan results: %s", err)
	}

	// Exit early if bypassing remediations
	if tc.BypassRemediations {
		t.Log("Bypassing remediation application and rescan")
		return
	}

	// Apply remediations with dependency resolution (includes rescanning)
	err = helpers.ApplyRemediationsWithDependencies(tc, c, platformBindingName)
	if err != nil {
		t.Fatalf("Failed to apply platform remediations: %s", err)
	}

	// Verify results after remediation
	err = helpers.VerifyPlatformScanResults(tc, c, platformBindingName)
	if err != nil {
		t.Fatalf("Failed to verify platform scan results after remediation: %s", err)
	}
}

func TestNodeCompliance(t *testing.T) {
	tc := config.NewTestConfig()

	// Skip if test type doesn't include node tests
	if tc.TestType != "node" && tc.TestType != "all" {
		t.Skipf("Skipping node tests: -test-type is %s", tc.TestType)
	}

	c, err := helpers.GenerateKubeConfig()
	if err != nil {
		t.Fatalf("Failed to generate kube config: %s", err)
	}

	// Create node tailored profile
	err = helpers.CreateNodeTailoredProfile(tc, c)
	if err != nil {
		t.Fatalf("Failed to create node tailored profile: %s", err)
	}

	// Create scan setting binding and run node scan
	nodeBindingName := "node-scan-binding"
	err = helpers.CreateNodeScanBinding(tc, c)
	if err != nil {
		t.Fatalf("Failed to create %s scan binding: %s", nodeBindingName, err)
	}

	err = helpers.WaitForComplianceSuite(tc, c, nodeBindingName)
	if err != nil {
		t.Fatalf("Failed to wait for compliance suite: %s", err)
	}

	err = helpers.VerifyNodeScanResults(tc, c, nodeBindingName)
	if err != nil {
		t.Fatalf("Failed to verify node scan results: %s", err)
	}

	// Exit early if bypassing remediations
	if tc.BypassRemediations {
		t.Log("Bypassing remediation application and rescan")
		return
	}

	// Apply remediations with dependency resolution (includes rescanning)
	err = helpers.ApplyRemediationsWithDependencies(tc, c, nodeBindingName)
	if err != nil {
		t.Fatalf("Failed to apply node remediations: %s", err)
	}

	// Verify results after remediation
	err = helpers.VerifyNodeScanResults(tc, c, nodeBindingName)
	if err != nil {
		t.Fatalf("Failed to verify node scan results after remediation: %s", err)
	}
}
