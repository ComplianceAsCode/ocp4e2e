package ocp4e2e

import (
	goctx "context"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"testing"
	"time"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
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

// TestVariableCustomization tests that TailoredProfile variable customization
// affects compliance check results as expected.
func TestVariableCustomization(t *testing.T) {
	// Skip if variable testing not enabled
	if !tc.VariableTestEnabled {
		t.Skip("Skipping variable customization test: -variable-test not enabled")
	}

	c, err := helpers.GenerateKubeConfig()
	if err != nil {
		t.Fatalf("Failed to generate kube config: %s", err)
	}

	// Test configuration
	baseProfileName := "ocp4-cis"
	baselineBindingName := "baseline-scan-binding"
	customizedProfileName := "tp-variables-customized"
	customizedBindingName := "customized-scan-binding"
	testNamespace1 := "test-ns-var-74227-1"
	testNamespace2 := "test-ns-var-74227-2"
	testSCCName := "scc-test-var-74227"

	// Step 0: Create test resources to trigger compliance failures
	t.Log("Creating test resources (namespaces and SCC)...")

	// Create test namespaces (these will not have network policies, causing failures)
	err = helpers.CreateTestNamespace(c, testNamespace1)
	if err != nil {
		t.Fatalf("Failed to create test namespace %s: %s", testNamespace1, err)
	}
	defer func() {
		helpers.DeleteTestNamespace(c, testNamespace1)
	}()

	err = helpers.CreateTestNamespace(c, testNamespace2)
	if err != nil {
		t.Fatalf("Failed to create test namespace %s: %s", testNamespace2, err)
	}
	defer func() {
		helpers.DeleteTestNamespace(c, testNamespace2)
	}()

	// Create test SCC with allowed capabilities (will fail SCC check)
	err = helpers.CreateTestSCC(c, testSCCName)
	if err != nil {
		t.Fatalf("Failed to create test SCC %s: %s", testSCCName, err)
	}
	defer func() {
		helpers.DeleteTestSCC(c, testSCCName)
	}()

	// Get list of all non-control namespaces for variable value
	nonControlNamespaces, err := helpers.GetNonControlNamespaces(c)
	if err != nil {
		t.Fatalf("Failed to get non-control namespaces: %s", err)
	}

	// Build namespace exemption regex including test namespaces
	namespaceRegex := "kube-.*|openshift-.*|default"
	for _, ns := range nonControlNamespaces {
		namespaceRegex += "|" + ns
	}

	// Variables to test (from downstream tests 74227/74437)
	testVariables := []struct {
		name          string
		customValue   string
		affectedRules []string
	}{
		{
			name:        "ocp4-var-network-policies-namespaces-exempt-regex",
			customValue: namespaceRegex,
			affectedRules: []string{
				"configure-network-policies-namespaces",
			},
		},
		{
			name:        "ocp4-var-sccs-with-allowed-capabilities-regex",
			customValue: "",
			affectedRules: []string{
				"scc-limit-container-allowed-capabilities",
			},
		},
	}

	t.Log("Preparing variable custom values...")
	var variableSpecs []cmpv1alpha1.VariableValueSpec

	for i := range testVariables {
		// Get default value
		defaultValue, err := helpers.GetVariableDefaultValue(tc, c, testVariables[i].name)
		if err != nil {
			t.Logf("Warning: Failed to get default value for variable %s: %s", testVariables[i].name, err)
			defaultValue = ""
		}

		// For SCC capabilities: append test SCC pattern to default value
		if testVariables[i].customValue == "" && defaultValue != "" {
			testVariables[i].customValue = defaultValue + "|^" + testSCCName + "$"
		} else if testVariables[i].customValue == "" {
			testVariables[i].customValue = "^" + testSCCName + "$"
		}

		variableSpecs = append(variableSpecs, cmpv1alpha1.VariableValueSpec{
			Name:      testVariables[i].name,
			Rationale: "E2E test variable customization",
			Value:     testVariables[i].customValue,
		})

		t.Logf("Variable %s: default='%s', custom='%s'",
			testVariables[i].name, defaultValue, testVariables[i].customValue)
	}

	// Step 1: Run baseline scan (using base profile directly)
	t.Log("Running baseline scan with default variable values...")
	err = helpers.CreateProfileScanBinding(tc, c, baselineBindingName, baseProfileName)
	if err != nil {
		t.Fatalf("Failed to create baseline scan binding: %s", err)
	}
	defer func() {
		helpers.DeleteScanBinding(tc, c, baselineBindingName)
		helpers.WaitForScanCleanup(tc, c, baselineBindingName)
	}()

	err = helpers.WaitForComplianceSuite(tc, c, baselineBindingName)
	if err != nil {
		t.Fatalf("Failed to wait for baseline compliance suite: %s", err)
	}

	baselineResults, err := helpers.CreateResultMap(tc, c, baselineBindingName)
	if err != nil {
		t.Fatalf("Failed to create baseline result map: %s", err)
	}

	err = helpers.SaveResultAsYAML(tc, baselineResults, "baseline-variable-results.yaml")
	if err != nil {
		t.Logf("Warning: Failed to save baseline results: %s", err)
	}

	t.Logf("Baseline scan completed with %d results", len(baselineResults))

	// Step 2: Create customized TailoredProfile with variable overrides
	t.Log("Creating customized TailoredProfile with variable overrides...")
	err = helpers.CreateTailoredProfileWithVariables(
		tc, c,
		customizedProfileName,
		baseProfileName,
		nil,
		variableSpecs,
	)
	if err != nil {
		t.Fatalf("Failed to create customized tailored profile: %s", err)
	}
	defer func() {
		tp := &cmpv1alpha1.TailoredProfile{}
		tp.Name = customizedProfileName
		tp.Namespace = tc.OperatorNamespace.Namespace
		c.Delete(goctx.TODO(), tp)
	}()

	// Wait for TailoredProfile to be ready
	err = helpers.WaitForTailoredProfileReady(tc, c, customizedProfileName)
	if err != nil {
		t.Fatalf("Failed to wait for customized tailored profile: %s", err)
	}

	// Step 3: Run customized scan
	t.Log("Running customized scan with variable overrides...")
	err = helpers.CreateScanBinding(
		c, tc,
		customizedBindingName,
		customizedProfileName,
		"TailoredProfile",
		"default",
	)
	if err != nil {
		t.Fatalf("Failed to create customized scan binding: %s", err)
	}
	defer func() {
		helpers.DeleteScanBinding(tc, c, customizedBindingName)
		helpers.WaitForScanCleanup(tc, c, customizedBindingName)
	}()

	err = helpers.WaitForComplianceSuite(tc, c, customizedBindingName)
	if err != nil {
		t.Fatalf("Failed to wait for customized compliance suite: %s", err)
	}

	customizedResults, err := helpers.CreateResultMap(tc, c, customizedBindingName)
	if err != nil {
		t.Fatalf("Failed to create customized result map: %s", err)
	}

	err = helpers.SaveResultAsYAML(tc, customizedResults, "customized-variable-results.yaml")
	if err != nil {
		t.Logf("Warning: Failed to save customized results: %s", err)
	}

	t.Logf("Customized scan completed with %d results", len(customizedResults))

	// Step 4: Compare results and validate expectations
	t.Log("Comparing baseline vs. customized results...")
	differences := helpers.CompareResults(baselineResults, customizedResults)

	if len(differences) > 0 {
		t.Logf("Found %d rules with different results:", len(differences))
		for ruleName, diff := range differences {
			t.Logf("  - %s: %s → %s", ruleName, diff.BaselineResult, diff.CustomizedResult)
		}
	} else {
		t.Log("WARNING: No differences found between baseline and customized scans")
	}

	// Step 5: Validate that expected rules changed as predicted
	t.Log("Validating that variables affected expected rules...")
	var validationErrors []string

	for _, varTest := range testVariables {
		for _, expectedRule := range varTest.affectedRules {
			// Build the actual rule names with profile prefixes
			customizedRuleName := customizedProfileName + "-" + expectedRule
			baselineRuleName := baseProfileName + "-" + expectedRule

			// Check if rule exists in results
			baselineResult, baselineExists := baselineResults[baselineRuleName]
			customizedResult, customizedExists := customizedResults[customizedRuleName]

			if !baselineExists {
				validationErrors = append(validationErrors,
					fmt.Sprintf("Baseline rule %s not found", baselineRuleName))
				continue
			}

			if !customizedExists {
				validationErrors = append(validationErrors,
					fmt.Sprintf("Customized rule %s not found", customizedRuleName))
				continue
			}

			// Check if results differ
			if baselineResult == customizedResult {
				t.Logf("Variable %s did not change result for %s (both: %s)",
					varTest.name, expectedRule, baselineResult)
			} else {
				t.Logf("Variable %s changed %s: %s → %s",
					varTest.name, expectedRule, baselineResult, customizedResult)
			}
		}
	}

	// Step 6: Report validation results
	if len(validationErrors) > 0 {
		t.Errorf("Variable customization validation failed with %d errors:", len(validationErrors))
		for _, errMsg := range validationErrors {
			t.Errorf("  - %s", errMsg)
		}
		t.Fatal("Variable customization test encountered errors")
	}

	t.Log("Variable customization test completed successfully")
	t.Logf("Variables tested: %d", len(testVariables))
	t.Logf("Total result differences: %d", len(differences))
}
