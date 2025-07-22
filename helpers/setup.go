package helpers

import (
	"fmt"
	"log"

	dynclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ComplianceAsCode/ocp4e2e/config"
)

// setup performs all the necessary setup for the test suite.
func Setup(tc *config.TestConfig) error {
	if err := assertContentDirectory(tc); err != nil {
		return fmt.Errorf("content directory validation failed: %w", err)
	}

	// generateKubeConfig
	c, kubeConfigErr := generateKubeConfig()
	if kubeConfigErr != nil {
		return fmt.Errorf("failed to generate kube config: %w", kubeConfigErr)
	}

	// setVersionInformation? Not sure if we need this in setup or not
	if tc.InstallOperator {
		if err := installOperator(c, tc); err != nil {
			return err
		}
	}

	// ensureTestProfileBundle
	if err := ensureTestProfileBundle(c, tc); err != nil {
		return err
	}

	if err := waitForValidTestProfileBundle(c, tc); err != nil {
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
	if err := ensureNamespaceExists(c); err != nil {
		return err
	}
	if err := ensureCatalogSourceExists(c); err != nil {
		return err
	}
	if err := ensureOperatorGroupExists(c); err != nil {
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
