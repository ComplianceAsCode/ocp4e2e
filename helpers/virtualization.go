package helpers

import (
	goctx "context"
	"fmt"
	"log"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"

	testConfig "github.com/ComplianceAsCode/ocp4e2e/config"
)

const (
	virtNamespace        = "openshift-cnv"
	virtSubscriptionName = "kubevirt-hyperconverged"
	virtPackageName      = "kubevirt-hyperconverged"
	virtChannel          = "stable"
	virtCatalogSource    = "redhat-operators"
	virtCatalogNamespace = "openshift-marketplace"
	hcoName              = "kubevirt-hyperconverged"
)

var (
	operatorGroupGVK = schema.GroupVersionKind{
		Group: "operators.coreos.com", Version: "v1", Kind: "OperatorGroup",
	}
	subscriptionGVK = schema.GroupVersionKind{
		Group: "operators.coreos.com", Version: "v1alpha1", Kind: "Subscription",
	}
	hyperConvergedGVK = schema.GroupVersionKind{
		Group: "hco.kubevirt.io", Version: "v1beta1", Kind: "HyperConverged",
	}
)

// installVirtualizationOperator installs the OpenShift Virtualization (CNV)
// operator and creates the HyperConverged CR, waiting until it is Available.
// It is idempotent: existing objects are left in place. Enabled with the
// -install-virt flag; skipped otherwise.
func installVirtualizationOperator(c dynclient.Client, tc *testConfig.TestConfig) error {
	if !tc.InstallVirt {
		return nil
	}
	log.Printf("Installing OpenShift Virtualization (CNV) operator")

	ns := &unstructured.Unstructured{}
	ns.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Namespace"})
	ns.SetName(virtNamespace)
	if err := createIfNotExists(c, ns); err != nil {
		return fmt.Errorf("failed to create %s namespace: %w", virtNamespace, err)
	}

	og := &unstructured.Unstructured{}
	og.SetGroupVersionKind(operatorGroupGVK)
	og.SetNamespace(virtNamespace)
	og.SetName("kubevirt-hyperconverged-group")
	if err := unstructured.SetNestedStringSlice(og.Object,
		[]string{virtNamespace}, "spec", "targetNamespaces"); err != nil {
		return err
	}
	if err := createIfNotExists(c, og); err != nil {
		return fmt.Errorf("failed to create CNV operator group: %w", err)
	}

	sub := &unstructured.Unstructured{}
	sub.SetGroupVersionKind(subscriptionGVK)
	sub.SetNamespace(virtNamespace)
	sub.SetName(virtSubscriptionName)
	sub.Object["spec"] = map[string]interface{}{
		"channel":             virtChannel,
		"name":                virtPackageName,
		"source":              virtCatalogSource,
		"sourceNamespace":     virtCatalogNamespace,
		"installPlanApproval": "Automatic",
	}
	if err := createIfNotExists(c, sub); err != nil {
		return fmt.Errorf("failed to create CNV subscription: %w", err)
	}

	// Wait for the operator to register the HyperConverged API before
	// creating the CR.
	if err := waitForHyperConvergedAPI(c, tc); err != nil {
		return err
	}

	hco := &unstructured.Unstructured{}
	hco.SetGroupVersionKind(hyperConvergedGVK)
	hco.SetNamespace(virtNamespace)
	hco.SetName(hcoName)
	hco.Object["spec"] = map[string]interface{}{}
	if err := createIfNotExists(c, hco); err != nil {
		return fmt.Errorf("failed to create HyperConverged CR: %w", err)
	}

	if err := waitForHCOAvailable(c, tc); err != nil {
		return err
	}
	log.Printf("OpenShift Virtualization is installed and HyperConverged is Available")
	return nil
}

func createIfNotExists(c dynclient.Client, obj *unstructured.Unstructured) error {
	err := c.Create(goctx.TODO(), obj)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	if apierrors.IsAlreadyExists(err) {
		log.Printf("Object already exists: %s/%s (%s)", obj.GetNamespace(), obj.GetName(), obj.GetKind())
	} else {
		log.Printf("Created object: %s/%s (%s)", obj.GetNamespace(), obj.GetName(), obj.GetKind())
	}
	return nil
}

// waitForHyperConvergedAPI waits until the HyperConverged kind is served by the
// API (i.e. the CNV operator's CRD is installed).
func waitForHyperConvergedAPI(c dynclient.Client, tc *testConfig.TestConfig) error {
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 240)
	return backoff.RetryNotify(func() error {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(hyperConvergedGVK)
		if err := c.List(goctx.TODO(), list, dynclient.InNamespace(virtNamespace)); err != nil {
			return err
		}
		return nil
	}, bo, func(err error, d time.Duration) {
		log.Printf("Waiting for HyperConverged API to be served after %s: %s", d.String(), err)
	})
}

// waitForHCOAvailable waits until the HyperConverged CR reports the Available
// condition with status True.
func waitForHCOAvailable(c dynclient.Client, tc *testConfig.TestConfig) error {
	key := dynclient.ObjectKey{Namespace: virtNamespace, Name: hcoName}
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 360)
	return backoff.RetryNotify(func() error {
		hco := &unstructured.Unstructured{}
		hco.SetGroupVersionKind(hyperConvergedGVK)
		if err := c.Get(goctx.TODO(), key, hco); err != nil {
			return err
		}
		conds, found, err := unstructured.NestedSlice(hco.Object, "status", "conditions")
		if err != nil || !found {
			return fmt.Errorf("HyperConverged has no status conditions yet")
		}
		for _, ci := range conds {
			cond, ok := ci.(map[string]interface{})
			if !ok {
				continue
			}
			if cond["type"] == "Available" && cond["status"] == "True" {
				return nil
			}
		}
		return fmt.Errorf("HyperConverged not yet Available")
	}, bo, func(err error, d time.Duration) {
		log.Printf("Waiting for HyperConverged to be Available after %s: %s", d.String(), err)
	})
}
