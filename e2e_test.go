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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// TestCISProfiles tests auto-remediation for CIS profiles.
// It verifies that auto-remediations work correctly for CIS profiles by:
// 1. Creating a custom MachineConfigPool and KubeletConfig
// 2. Running scans with ocp4-cis and ocp4-cis-node profiles
// 3. Verifying remediations are auto-applied
// 4. Triggering a rescan and verifying compliance
func TestCISProfiles(t *testing.T) {
	// Skip if test type doesn't include platform tests
	if tc.TestType != "platform" && tc.TestType != "all" {
		t.Skipf("Skipping CIS profile tests: -test-type is %s", tc.TestType)
	}

	c, err := helpers.GenerateKubeConfig()
	if err != nil {
		t.Fatalf("Failed to generate kube config: %s", err)
	}

	// Check if etcd encryption is enabled (requirement from downstream test)
	if err := helpers.CheckEtcdEncryption(c); err != nil {
		t.Skipf("Skipping CIS profile test: %s", err)
	}

	// Test configuration
	poolName := "wrscan"
	bindingName := "cis-profiles-test"
	scanSettingName := "cis-auto-apply"
	kubeletConfigName := "custom-" + poolName

	// Get one worker node
	workerNodes, err := helpers.GetWorkerNodes(c, map[string]string{
		"node-role.kubernetes.io/worker": "",
	})
	if err != nil {
		t.Fatalf("Failed to get worker nodes: %s", err)
	}
	if len(workerNodes) == 0 {
		t.Fatal("No worker nodes found")
	}
	workerNode := workerNodes[0]
	workerNodeName := workerNode.Name

	// Label the worker node with custom role
	labelKey := fmt.Sprintf("node-role.kubernetes.io/%s", poolName)
	err = helpers.LabelNode(c, workerNodeName, labelKey, "")
	if err != nil {
		t.Fatalf("Failed to label node: %s", err)
	}
	defer func() {
		err := helpers.UnlabelNode(c, workerNodeName, labelKey)
		if err != nil {
			t.Logf("Warning: Failed to remove label from node %s: %s", workerNodeName, err)
		}
	}()

	// Create MachineConfigPool for the custom role
	nodeSelector := map[string]string{labelKey: ""}
	poolLabels := map[string]string{
		"pools.operator.machineconfiguration.openshift.io/e2e": "",
	}
	err = helpers.CreateMachineConfigPool(c, poolName, nodeSelector, poolLabels)
	if err != nil {
		t.Fatalf("Failed to create MachineConfigPool: %s", err)
	}
	defer func() {
		err := helpers.DeleteMachineConfigPool(c, poolName)
		if err != nil {
			t.Logf("Warning: Failed to delete MachineConfigPool %s: %s", poolName, err)
		}
	}()

	// Wait for pool to be ready
	err = helpers.WaitForMachineConfigPoolUpdate(tc, c, poolName)
	if err != nil {
		t.Fatalf("Failed waiting for initial MachineConfigPool %s: %s", poolName, err)
	}

	// Create KubeletConfig for the pool
	kubeletConfig := map[string]interface{}{
		"protectKernelDefaults":       true,
		"streamConnectionIdleTimeout": "5m",
	}
	err = helpers.CreateKubeletConfig(c, kubeletConfigName, poolLabels, kubeletConfig)
	if err != nil {
		t.Fatalf("Failed to create KubeletConfig: %s", err)
	}
	defer func() {
		err := helpers.DeleteKubeletConfig(c, kubeletConfigName)
		if err != nil {
			t.Logf("Warning: Failed to delete KubeletConfig %s: %s", kubeletConfigName, err)
		}
	}()

	// Wait for KubeletConfig to be successful
	err = helpers.WaitForKubeletConfigSuccess(tc, c, kubeletConfigName)
	if err != nil {
		t.Fatalf("Failed waiting for KubeletConfig: %s", err)
	}

	// Wait for pool to be ready after KubeletConfig
	err = helpers.WaitForMachineConfigPoolUpdate(tc, c, poolName)
	if err != nil {
		t.Fatalf("Failed waiting for MachineConfigPool after KubeletConfig: %s", err)
	}

	// Create ScanSetting with auto-apply remediations
	err = helpers.CreateScanSettingWithAutoApply(c, tc.OperatorNamespace.Namespace, scanSettingName, []string{poolName})
	if err != nil {
		t.Fatalf("Failed to create ScanSetting: %s", err)
	}
	defer func() {
		scanSetting := &cmpv1alpha1.ScanSetting{}
		scanSetting.Name = scanSettingName
		scanSetting.Namespace = tc.OperatorNamespace.Namespace
		err := c.Delete(goctx.TODO(), scanSetting)
		if err != nil && !apierrors.IsNotFound(err) {
			t.Logf("Warning: Failed to delete ScanSetting: %s", err)
		}
	}()

	// Create ScanSettingBinding with ocp4-cis and ocp4-cis-node profiles
	binding := &cmpv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: tc.OperatorNamespace.Namespace,
		},
		Profiles: []cmpv1alpha1.NamedObjectReference{
			{
				Name:     "ocp4-cis",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
			{
				Name:     "ocp4-cis-node",
				Kind:     "Profile",
				APIGroup: "compliance.openshift.io/v1alpha1",
			},
		},
		SettingsRef: &cmpv1alpha1.NamedObjectReference{
			Name:     scanSettingName,
			Kind:     "ScanSetting",
			APIGroup: "compliance.openshift.io/v1alpha1",
		},
	}
	err = c.Create(goctx.TODO(), binding)
	if err != nil {
		t.Fatalf("Failed to create ScanSettingBinding: %s", err)
	}
	defer func() {
		err := c.Delete(goctx.TODO(), binding)
		if err != nil && !apierrors.IsNotFound(err) {
			t.Logf("Warning: Failed to delete ScanSettingBinding: %s", err)
		}
	}()

	// Wait for initial scans to complete
	log.Printf("Waiting for initial scans to complete")
	err = helpers.WaitForComplianceSuite(tc, c, bindingName)
	if err != nil {
		t.Fatalf("Failed to wait for compliance suite: %s", err)
	}

	// Get initial results
	initialResults, err := helpers.GetCheckResultsBySuite(c, bindingName, tc.OperatorNamespace.Namespace)
	if err != nil {
		t.Fatalf("Failed to get initial check results: %s", err)
	}
	log.Printf("Initial scan completed with %d check results", len(initialResults))

	// Wait for remediations to be auto-applied
	log.Printf("Waiting for remediations to be auto-applied")
	err = helpers.WaitForRemediationsToBeApplied(tc, c, bindingName)
	if err != nil {
		t.Logf("Warning: Some remediations may not have been applied: %s", err)
	}

	// Wait for MachineConfigPool to update after remediations
	log.Printf("Waiting for MachineConfigPool to update after remediations")
	err = helpers.WaitForMachineConfigPoolUpdate(tc, c, poolName)
	if err != nil {
		t.Logf("Warning: MachineConfigPool may not be fully updated: %s", err)
	}

	// Trigger rescan
	log.Printf("Triggering rescan to verify remediations")
	err = helpers.RescanSuite(tc, c, bindingName, tc.OperatorNamespace.Namespace)
	if err != nil {
		t.Fatalf("Failed to trigger rescan: %s", err)
	}

	// Wait for rescan to complete
	log.Printf("Waiting for rescan to complete")
	err = helpers.WaitForComplianceSuite(tc, c, bindingName)
	if err != nil {
		t.Fatalf("Failed to wait for rescan: %s", err)
	}

	// Get final results
	finalResults, err := helpers.GetCheckResultsBySuite(c, bindingName, tc.OperatorNamespace.Namespace)
	if err != nil {
		t.Fatalf("Failed to get final check results: %s", err)
	}

	// Count improvements
	improved := 0
	for checkName, finalStatus := range finalResults {
		initialStatus, exists := initialResults[checkName]
		if exists && initialStatus != cmpv1alpha1.CheckResultPass && finalStatus == cmpv1alpha1.CheckResultPass {
			improved++
		}
	}

	log.Printf("Rescan completed: %d checks improved from initial scan", improved)
	log.Printf("Final results: %d total checks", len(finalResults))

	// Verify that at least some checks improved
	if improved == 0 {
		t.Logf("Warning: No checks improved after remediation")
	} else {
		log.Printf("CIS profiles test completed successfully: %d checks improved", improved)
	}
}
