package helpers

import (
	"fmt"
	"log"

	dynclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ComplianceAsCode/ocp4e2e/config"
)

// Setup performs all the necessary setup for the test suite.
func Setup(tc *config.TestConfig) error {
	if err := assertContentDirectory(tc); err != nil {
		return fmt.Errorf("content directory validation failed: %w", err)
	}

	// generateKubeConfig
	c, kubeConfigErr := GenerateKubeConfig()
	if kubeConfigErr != nil {
		return fmt.Errorf("failed to generate kube config: %w", kubeConfigErr)
	}

	// setVersionInformation? Not sure if we need this in setup or not
	if tc.InstallOperator {
		if err := installOperator(c, tc); err != nil {
			return err
		}
	}

	// Optionally install OpenShift Virtualization (CNV) so the OCP-Virt
	// profiles can be scanned on a cluster that doesn't already have it.
	if err := installVirtualizationOperator(c, tc); err != nil {
		return fmt.Errorf("failed to install OpenShift Virtualization: %w", err)
	}

	// At this point, operator has created ProfileBundles with custom content image
	// (if custom image was specified, it was added to Subscription before creation)
	postCELUpdateRV, err := ensureCELContentFile(c, tc)
	if err != nil {
		return err
	}

	if err := waitForValidTestProfileBundles(c, tc, postCELUpdateRV); err != nil {
		return err
	}

	if err := ensureTestSettings(c, tc); err != nil {
		return err
	}

	if err := setPoolRollingPolicy(c); err != nil {
		return err
	}

	log.Printf("Setup completed successfully")
	return nil
}

func installOperator(c dynclient.Client, tc *config.TestConfig) error {
	if err := ensureNamespaceExists(c, tc); err != nil {
		return err
	}
	if err := ensureCatalogSourceExists(c, tc); err != nil {
		return err
	}
	if err := ensureOperatorGroupExists(c, tc); err != nil {
		return err
	}
	if err := ensureSubscriptionExists(c, tc); err != nil {
		return err
	}
	if err := waitForOperatorToBeReady(c, tc); err != nil {
		return err
	}
	return nil
}
