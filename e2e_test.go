package ocp4e2e

import (
	"testing"
)

func TestE2e(t *testing.T) {
	ctx := newE2EContext(t)
	t.Run("Parameter setup and validation", func(t *testing.T) {
		ctx.assertRootdir(t)
		ctx.assertProfile(t)
		ctx.assertContentImage(t)
		ctx.assertKubeClient(t)
		ctx.assertVersion(t)
	})

	t.Run("Operator setup", func(t *testing.T) {
		ctx.ensureNamespaceExistsAndSet(t)
		if ctx.installOperator {
			ctx.ensureCatalogSourceExists(t)
			ctx.ensureOperatorGroupExists(t)
			ctx.ensureSubscriptionExists(t)
			ctx.waitForOperatorToBeReady(t)
		} else {
			t.Logf("Skipping operator install as requested")
		}
	})
	if t.Failed() {
		return
	}

	t.Run("Prereqs setup", func(t *testing.T) {
		ctx.ensureTestProfileBundle(t)
		ctx.waitForValidTestProfileBundle(t)
		ctx.ensureTestSettings(t)
		if err := ctx.setPoolRollingPolicy(t); err != nil {
			t.Fatalf("failed to set pool rolling policy: %s", err)
		}
	})

	t.Run("Find and categorize rules", func(t *testing.T) {
		platformRules, nodeRules := ctx.findAndCategorizeRules(t)
		t.Logf("Found %d platform rules and %d node rules", len(platformRules), len(nodeRules))

		// Store rules in context for later use
		ctx.platformRules = platformRules
		ctx.nodeRules = nodeRules
	})

	// Determine which tests to run based on testType
	runPlatformTests := ctx.testType == "platform" || ctx.testType == "all"
	runNodeTests := ctx.testType == "node" || ctx.testType == "all"

	if runPlatformTests {
		t.Run("Create platform tailored profile", func(t *testing.T) {
			ctx.createPlatformTailoredProfile(t)
		})

		t.Run("Create scan setting binding and run platform scan", func(t *testing.T) {
			suiteName := ctx.createPlatformScanBinding(t)
			ctx.waitForComplianceSuite(t, suiteName)
			ctx.verifyPlatformScanResults(t, suiteName)
		})
	}

	if runNodeTests {
		t.Run("Create node tailored profile", func(t *testing.T) {
			ctx.createNodeTailoredProfile(t)
		})

		t.Run("Create scan setting binding and run node scan", func(t *testing.T) {
			suiteName := ctx.createNodeScanBinding(t)
			ctx.waitForComplianceSuite(t, suiteName)
			ctx.verifyNodeScanResults(t, suiteName)
		})
	}

	if !runPlatformTests && !runNodeTests {
		t.Fatalf("Invalid test-type: %s. Must be 'platform', 'node', or 'all'", ctx.testType)
	}
}
