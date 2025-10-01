package ocp4e2e

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"testing"
	"time"

	ctrlLog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/ComplianceAsCode/ocp4e2e/config"
	"github.com/ComplianceAsCode/ocp4e2e/helpers"
)

var (
	tc             *config.TestConfig
	assertionsPath = "/tests/assertions/ocp4/"
)

// TestMain handles the setup and teardown for all tests.
func TestMain(m *testing.M) {
	// Setup the controller-runtime logger, which is used in clients across
	// various tests. Do this here instead of in each test.
	logger := zap.New(zap.UseDevMode(true))
	ctrlLog.SetLogger(logger)

	// Define flags
	config.DefineFlags()

	flag.Parse()

	// Validate required flags
	if err := config.ValidateFlags(); err != nil {
		log.Printf("Flag validation failed: %v", err)
		os.Exit(1)
	}

	// This is a global test configuration that can be shared across tests.
	// After Setup, it should be immutable so it doesn't effect other
	// tests, but using a global test config allows us to have a single
	// content directory, either cloned or passed in explicitly by the
	// caller because the repository is handled and set once in Setup().
	tc = config.NewTestConfig()
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

	initialResults, err := helpers.CreateResultMap(tc, c, platformBindingName)
	if err != nil {
		t.Fatalf("Failed to create result map: %s", err)
	}
	err = helpers.SaveResultAsYAML(tc, initialResults, "initial-platform-results.yaml")
	if err != nil {
		t.Fatalf("Failed to save initial platform scan results.")
	}

	afterRemediation := false
	assertionFileName := fmt.Sprintf("%s-%s-%s.yml", tc.Platform, tc.Version, "platform")
	assertionFile := path.Join(tc.ContentDir, assertionsPath, assertionFileName)

	mismatchedAssertions, err := helpers.VerifyPlatformScanResults(tc, c, assertionFile, initialResults, afterRemediation)
	if err != nil {
		t.Fatalf("Failed to verify platform scan results: %s", err)
	}

	// Write any mismatched assertions to disk
	if len(mismatchedAssertions) > 0 {
		err = helpers.SaveMismatchesAsYAML(tc, mismatchedAssertions, "initial-platform-mismatches.yaml")
		if err != nil {
			t.Fatalf("Failed to save initial mismatched platform assertions: %s", err)
		}
	}

	// Exit early if bypassing remediations
	if tc.BypassRemediations {
		t.Log("Bypassing remediation application and rescan")
		err := helpers.GenerateAssertionFileFromResults(tc, c, assertionFileName, initialResults, nil)
		if err != nil {
			t.Fatalf("Failed to generate assertion file: %s", err)
		}
		return
	}

	err = helpers.ApplyManualRemediations(tc, c, initialResults)
	if err != nil {
		t.Fatalf("Failed to apply manual remediations: %s", err)
	}

	manualRemediationWaitTime := 30 * time.Second
	log.Printf("Waiting %s for manual remediations to take effect", manualRemediationWaitTime)
	time.Sleep(manualRemediationWaitTime)

	// Apply remediations with dependency resolution (includes rescanning)
	err = helpers.ApplyRemediationsWithDependencies(tc, c, platformBindingName)
	if err != nil {
		t.Fatalf("Failed to apply platform remediations: %s", err)
	}
	afterRemediation = true

	finalResults, err := helpers.CreateResultMap(tc, c, platformBindingName)
	if err != nil {
		t.Fatalf("Failed to create result map: %s", err)
	}
	err = helpers.SaveResultAsYAML(tc, finalResults, "final-platform-results.yaml")
	if err != nil {
		t.Fatalf("Failed to save final platform scan results.")
	}

	mismatchedAssertions, err = helpers.VerifyPlatformScanResults(tc, c, assertionFile, finalResults, afterRemediation)
	if err != nil {
		t.Fatalf("Failed to verify platform scan results: %s", err)
	}

	// Write any mismatched assertions to disk
	if len(mismatchedAssertions) > 0 {
		err = helpers.SaveMismatchesAsYAML(tc, mismatchedAssertions, "final-platform-mismatches.yaml")
		if err != nil {
			t.Fatalf("Failed to save final mismatched assertions: %s", err)
		}
		if err = helpers.GenerateMismatchReport(tc, c, mismatchedAssertions, platformBindingName); err != nil {
			t.Fatalf("Failed to generate test report: %s", err)
		}
		t.Fatal("Actual cluster compliance state didn't match expected state")
	}

	err = helpers.GenerateAssertionFileFromResults(tc, c, assertionFileName, initialResults, finalResults)
	if err != nil {
		t.Fatalf("Failed to generate assertion file: %s", err)
	}
}

func TestNodeCompliance(t *testing.T) {
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

	initialResults, err := helpers.CreateResultMap(tc, c, nodeBindingName)
	if err != nil {
		t.Fatalf("Failed to create result map: %s", err)
	}
	err = helpers.SaveResultAsYAML(tc, initialResults, "initial-node-results.yaml")
	if err != nil {
		t.Fatalf("Failed to save initial node scan results.")
	}

	afterRemediation := false
	assertionFileName := fmt.Sprintf("%s-%s-%s.yml", tc.Platform, tc.Version, "node")
	assertionFile := path.Join(tc.ContentDir, assertionsPath, assertionFileName)

	mismatchedAssertions, err := helpers.VerifyNodeScanResults(tc, c, assertionFile, initialResults, afterRemediation)
	if err != nil {
		t.Fatalf("Failed to verify node scan results: %s", err)
	}

	// Write any mismatched assertions to disk
	if len(mismatchedAssertions) > 0 {
		err = helpers.SaveMismatchesAsYAML(tc, mismatchedAssertions, "initial-node-mismatches.yaml")
		if err != nil {
			t.Fatalf("Failed to save initial mismatched node assertions: %s", err)
		}
	}

	// Exit early if bypassing remediations
	if tc.BypassRemediations {
		t.Log("Bypassing remediation application and rescan")
		err := helpers.GenerateAssertionFileFromResults(tc, c, assertionFileName, initialResults, nil)
		if err != nil {
			t.Fatalf("Failed to generate assertion file: %s", err)
		}
		return
	}

	err = helpers.ApplyManualRemediations(tc, c, initialResults)
	if err != nil {
		t.Fatalf("Failed to apply manual remediations: %s", err)
	}

	manualRemediationWaitTime := 30 * time.Second
	log.Printf("Waiting %s for manual remediations to take effect", manualRemediationWaitTime)
	time.Sleep(manualRemediationWaitTime)

	// Apply remediations with dependency resolution (includes rescanning)
	err = helpers.ApplyRemediationsWithDependencies(tc, c, nodeBindingName)
	if err != nil {
		t.Fatalf("Failed to apply node remediations: %s", err)
	}
	afterRemediation = true

	finalResults, err := helpers.CreateResultMap(tc, c, nodeBindingName)
	if err != nil {
		t.Fatalf("Failed to create result map: %s", err)
	}
	err = helpers.SaveResultAsYAML(tc, finalResults, "final-node-results.yaml")
	if err != nil {
		t.Fatalf("Failed to save final node scan results.")
	}

	mismatchedAssertions, err = helpers.VerifyNodeScanResults(tc, c, assertionFile, finalResults, afterRemediation)
	if err != nil {
		t.Fatalf("Failed to verify node scan results: %s", err)
	}

	// Write any mismatched assertions to disk
	if len(mismatchedAssertions) > 0 {
		err = helpers.SaveMismatchesAsYAML(tc, mismatchedAssertions, "final-node-mismatches.yaml")
		if err != nil {
			t.Fatalf("Failed to save final mismatched assertions: %s", err)
		}
		if err = helpers.GenerateMismatchReport(tc, c, mismatchedAssertions, nodeBindingName); err != nil {
			t.Fatalf("Failed to generate test report: %s", err)
		}
		t.Fatal("Actual cluster compliance state didn't match expected state")
	}

	err = helpers.GenerateAssertionFileFromResults(tc, c, assertionFileName, initialResults, finalResults)
	if err != nil {
		t.Fatalf("Failed to generate assertion file: %s", err)
	}
}

func TestProfile(t *testing.T) {
	// Require profile and product to be specified
	if tc.Profile == "" {
		t.Fatal("Profile must be specified using -profile flag or PROFILE environment variable")
	}
	if tc.Product == "" {
		t.Fatal("Product must be specified using -product flag or PRODUCT environment variable")
	}

	c, err := helpers.GenerateKubeConfig()
	if err != nil {
		t.Fatalf("Failed to generate kube config: %s", err)
	}

	// Verify the specified profile exists
	profileFQN := tc.Product + "-" + tc.Profile
	err = helpers.ValidateProfile(tc, c, profileFQN)
	if err != nil {
		t.Fatalf("Profile validation failed: %s", err)
	}

	bindingName := profileFQN + "-test-binding"

	t.Logf("Testing profile: %s", profileFQN)

	// Create scan setting binding for this profile
	err = helpers.CreateScanBinding(c, tc, bindingName, profileFQN, "Profile", "default")
	if err != nil {
		t.Fatalf("Failed to create scan binding %s for profile %s: %s", bindingName, profileFQN, err)
	}

	// Wait for the compliance suite to complete
	err = helpers.WaitForComplianceSuite(tc, c, bindingName)
	if err != nil {
		t.Fatalf("Failed to wait for compliance suite %s: %s", bindingName, err)
	}

	initialResults, err := helpers.CreateResultMap(tc, c, bindingName)
	if err != nil {
		t.Fatalf("Failed to create result map: %s", err)
	}

	afterRemediation := false
	assertionFileName := fmt.Sprintf("%s-%s.yml", profileFQN, tc.Version)
	assertionFile := path.Join(tc.ContentDir, assertionsPath, assertionFileName)
	// Verify scan results
	mismatchedAssertions, err := helpers.VerifyScanResults(tc, c, assertionFile, initialResults, afterRemediation)
	if err != nil {
		t.Fatalf("Failed to verify scan results for profile %s: %s", profileFQN, err)
	}

	// Write any mismatched assertions to disk
	mismatchedAssertionFileName := fmt.Sprintf("iniital-%s-mismatches.yaml", profileFQN)
	if len(mismatchedAssertions) > 0 {
		err = helpers.SaveMismatchesAsYAML(tc, mismatchedAssertions, mismatchedAssertionFileName)
		if err != nil {
			t.Fatalf("Failed to save initial mismatched profile assertions: %s", err)
		}
		if err = helpers.GenerateMismatchReport(tc, c, mismatchedAssertions, bindingName); err != nil {
			t.Fatalf("Failed to generate test report: %s", err)
		}
		t.Fatal("Actual cluster compliance state didn't match expected state")
	}

	err = helpers.GenerateAssertionFileFromResults(tc, c, assertionFileName, initialResults, nil)
	if err != nil {
		t.Fatalf("Failed to generate assertion file: %s", err)
	}

	// Clean up the scan binding
	err = helpers.DeleteScanBinding(tc, c, bindingName)
	if err != nil {
		t.Logf("Warning: Failed to delete scan binding %s: %s", bindingName, err)
	}

	// Wait for scan cleanup to complete
	err = helpers.WaitForScanCleanup(tc, c, bindingName)
	if err != nil {
		t.Logf("Warning: Failed to wait for scan cleanup for binding %s: %s", bindingName, err)
	}
}

func TestProfileRemediations(t *testing.T) {
	// Require profile and product to be specified
	if tc.Profile == "" {
		t.Fatal("Profile must be specified using -profile flag or PROFILE environment variable")
	}
	if tc.Product == "" {
		t.Fatal("Product must be specified using -product flag or PRODUCT environment variable")
	}

	c, err := helpers.GenerateKubeConfig()
	if err != nil {
		t.Fatalf("Failed to generate kube config: %s", err)
	}

	// Verify the specified profile exists
	profileFQN := tc.Product + "-" + tc.Profile
	err = helpers.ValidateProfile(tc, c, profileFQN)
	if err != nil {
		t.Fatalf("Profile validation failed: %s", err)
	}

	bindingName := profileFQN + "-test-binding"

	t.Logf("Testing profile: %s", profileFQN)

	// Create scan setting binding for this profile
	err = helpers.CreateScanBinding(c, tc, bindingName, profileFQN, "Profile", tc.E2eSettings)
	if err != nil {
		t.Fatalf("Failed to create scan binding %s for profile %s: %s", bindingName, profileFQN, err)
	}

	// Wait for the compliance suite to complete
	err = helpers.WaitForComplianceSuite(tc, c, bindingName)
	if err != nil {
		t.Fatalf("Failed to wait for compliance suite %s: %s", bindingName, err)
	}

	initialResults, err := helpers.CreateResultMap(tc, c, bindingName)
	if err != nil {
		t.Fatalf("Failed to create result map: %s", err)
	}
	err = helpers.SaveResultAsYAML(tc, initialResults, fmt.Sprintf("initial-%s-results.yaml", profileFQN))
	if err != nil {
		t.Fatalf("Failed to save initial %s scan results.", profileFQN)
	}

	afterRemediation := false
	assertionFileName := fmt.Sprintf("%s-%s.yml", profileFQN, tc.Version)
	assertionFile := path.Join(tc.ContentDir, assertionsPath, assertionFileName)
	// Verify scan results
	mismatchedAssertions, err := helpers.VerifyScanResults(tc, c, assertionFile, initialResults, afterRemediation)
	if err != nil {
		t.Fatalf("Failed to verify scan results for profile %s: %s", profileFQN, err)
	}

	// Write any mismatched assertions to disk
	if len(mismatchedAssertions) > 0 {
		mismatchedAssertionFileName := fmt.Sprintf("initial-%s-mismatches.yaml", profileFQN)
		err = helpers.SaveMismatchesAsYAML(tc, mismatchedAssertions, mismatchedAssertionFileName)
		if err != nil {
			t.Fatalf("Failed to save initial mismatched %s assertions: %s", profileFQN, err)
		}
	}

	err = helpers.ApplyManualRemediations(tc, c, initialResults)
	if err != nil {
		t.Fatalf("Failed to apply manual remediations: %s", err)
	}

	manualRemediationWaitTime := 30 * time.Second
	log.Printf("Waiting %s for manual remediations to take effect", manualRemediationWaitTime)
	time.Sleep(manualRemediationWaitTime)

	// Apply remediations with dependency resolution (includes rescanning)
	err = helpers.ApplyRemediationsWithDependencies(tc, c, bindingName)
	if err != nil {
		t.Fatalf("Failed to apply %s remediations: %s", profileFQN, err)
	}
	afterRemediation = true

	finalResults, err := helpers.CreateResultMap(tc, c, bindingName)
	if err != nil {
		t.Fatalf("Failed to create result map: %s", err)
	}
	err = helpers.SaveResultAsYAML(tc, finalResults, fmt.Sprintf("final-%s-results.yaml", profileFQN))
	if err != nil {
		t.Fatalf("Failed to save final %s scan results.", profileFQN)
	}

	// Verify results after remediation
	mismatchedAssertions, err = helpers.VerifyScanResults(tc, c, assertionFile, finalResults, afterRemediation)
	if err != nil {
		t.Fatalf("Failed to verify scan results for profile %s: %s", profileFQN, err)
	}

	if len(mismatchedAssertions) > 0 {
		mismatchedAssertionFileName := fmt.Sprintf("final-%s-mismatches.yaml", profileFQN)
		err = helpers.SaveMismatchesAsYAML(tc, mismatchedAssertions, mismatchedAssertionFileName)
		if err != nil {
			t.Fatalf("Failed to save final mismatched assertions: %s", err)
		}
		if err = helpers.GenerateMismatchReport(tc, c, mismatchedAssertions, bindingName); err != nil {
			t.Fatalf("Failed to generate test report: %s", err)
		}
		t.Fatal("Actual cluster compliance state didn't match expected state")
	}

	err = helpers.GenerateAssertionFileFromResults(tc, c, assertionFileName, initialResults, finalResults)
	if err != nil {
		t.Fatalf("Failed to generate assertion file: %s", err)
	}

	// Clean up the scan binding
	err = helpers.DeleteScanBinding(tc, c, bindingName)
	if err != nil {
		t.Logf("Warning: Failed to delete scan binding %s: %s", bindingName, err)
	}

	// Wait for scan cleanup to complete
	err = helpers.WaitForScanCleanup(tc, c, bindingName)
	if err != nil {
		t.Logf("Warning: Failed to wait for scan cleanup for binding %s: %s", bindingName, err)
	}
}
