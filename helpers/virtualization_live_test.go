package helpers

import (
	"os"
	"testing"
	"time"

	testConfig "github.com/ComplianceAsCode/ocp4e2e/config"
)

// TestInstallVirtLive exercises installVirtualizationOperator against a real
// cluster (KUBECONFIG). It is opt-in: set RUN_VIRT_LIVE=1 to run. This is a
// manual/validation test, not part of the normal suite.
func TestInstallVirtLive(t *testing.T) {
	if os.Getenv("RUN_VIRT_LIVE") != "1" {
		t.Skip("set RUN_VIRT_LIVE=1 to run the live CNV install test")
	}
	c, err := GenerateKubeConfig()
	if err != nil {
		t.Fatalf("failed to build client: %s", err)
	}
	tc := &testConfig.TestConfig{
		InstallVirt:     true,
		APIPollInterval: 10 * time.Second,
	}
	if err := installVirtualizationOperator(c, tc); err != nil {
		t.Fatalf("installVirtualizationOperator failed: %s", err)
	}
}
