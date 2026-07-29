package helpers

import (
	goctx "context"
	"os"
	"testing"
	"time"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	backoff "github.com/cenkalti/backoff/v4"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// TestCELProfileBundleLive creates a ProfileBundle with the typed
// spec.celContentFile field (v1.9.0 API) against a real cluster and verifies it
// parses VALID. Opt-in: RUN_CEL_PB_LIVE=1, CONTENT_IMAGE=<image>,
// CEL_CONTENT_FILE=<file>. Validates the dependency bump end to end.
func TestCELProfileBundleLive(t *testing.T) {
	if os.Getenv("RUN_CEL_PB_LIVE") != "1" {
		t.Skip("set RUN_CEL_PB_LIVE=1 to run")
	}
	img := os.Getenv("CONTENT_IMAGE")
	cel := os.Getenv("CEL_CONTENT_FILE")
	if img == "" || cel == "" {
		t.Fatal("CONTENT_IMAGE and CEL_CONTENT_FILE must be set")
	}
	c, err := GenerateKubeConfig()
	if err != nil {
		t.Fatalf("client: %s", err)
	}
	ns := "openshift-compliance"
	name := "ocp4-virt-typed"

	pb := &cmpv1alpha1.ProfileBundle{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: cmpv1alpha1.ProfileBundleSpec{
			ContentImage:   img,
			ContentFile:    "ssg-ocp4-ds.xml",
			CELContentFile: cel, // <-- the field added in v1.9.0
		},
	}
	_ = c.Delete(goctx.TODO(), pb)
	if err := c.Create(goctx.TODO(), pb); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create ProfileBundle: %s", err)
	}
	t.Logf("Created ProfileBundle %s with celContentFile=%s", name, cel)

	// Wait until the bundle parses VALID.
	key := types.NamespacedName{Name: name, Namespace: ns}
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Second), 30)
	if err := backoff.RetryNotify(func() error {
		found := &cmpv1alpha1.ProfileBundle{}
		if err := c.Get(goctx.TODO(), key, found); err != nil {
			return err
		}
		if found.Status.DataStreamStatus != cmpv1alpha1.DataStreamValid {
			return &statusErr{string(found.Status.DataStreamStatus)}
		}
		// confirm the field round-tripped through the typed API
		if found.Spec.CELContentFile != cel {
			t.Fatalf("celContentFile not persisted: got %q", found.Spec.CELContentFile)
		}
		return nil
	}, bo, func(err error, d time.Duration) {
		t.Logf("waiting for ProfileBundle VALID after %s: %s", d, err)
	}); err != nil {
		t.Fatalf("ProfileBundle did not become VALID: %s", err)
	}
	t.Logf("ProfileBundle %s is VALID and celContentFile round-tripped via typed API", name)

	// Confirm the CEL profile was created from the CEL content file.
	profKey := types.NamespacedName{Name: name + "-cis-vm-extension", Namespace: ns}
	prof := &cmpv1alpha1.Profile{}
	if err := c.Get(goctx.TODO(), profKey, prof); err != nil {
		t.Fatalf("expected CEL profile %s: %s", profKey.Name, err)
	}
	scanner := prof.Annotations["compliance.openshift.io/scanner-type"]
	t.Logf("CEL profile %s created (scanner-type=%s) with %d rules", profKey.Name, scanner, len(prof.Rules))
	if scanner != "CEL" {
		t.Fatalf("expected scanner-type CEL, got %q", scanner)
	}
}

type statusErr struct{ s string }

func (e *statusErr) Error() string { return "ProfileBundle status: " + e.s }

var _ dynclient.Object = &cmpv1alpha1.ProfileBundle{}
