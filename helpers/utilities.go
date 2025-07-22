package helpers

import (
	"bufio"
	goctx "context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	cmpapis "github.com/openshift/compliance-operator/pkg/apis"
	cmpv1alpha1 "github.com/openshift/compliance-operator/pkg/apis/compliance/v1alpha1"
	mcfg "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io"
	mcfgv1 "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io/v1"
	appsv1 "k8s.io/api/apps/v1"
	extscheme "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	cgoscheme "k8s.io/client-go/kubernetes/scheme"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	testConfig "github.com/ComplianceAsCode/ocp4e2e/config"
)

var (
	operatorNamespacedName = types.NamespacedName{Name: "compliance-operator"}
	namespacePath          string
	catalogSourcePath      string
	operatorGroupPath      string
	rosaSubscriptionPath   string
	subscriptionPath       string
)

// assertContentDirectory checks that the content directory is valid and clones it if it is not set.
func assertContentDirectory(tc *testConfig.TestConfig) error {
	if tc.ContentDir == "" {
		var cloneErr error
		tc.ContentDir, cloneErr = cloneContentDir()
		if cloneErr != nil {
			return fmt.Errorf("failed to clone content directory: %w", cloneErr)
		}
	}
	dirinfo, err := os.Stat(tc.ContentDir)
	if os.IsNotExist(err) {
		return fmt.Errorf("-content-directory points to an unexistent directory")
	}
	if err != nil {
		return fmt.Errorf("failed to stat -content-directory: %w", err)
	}
	if !dirinfo.IsDir() {
		return fmt.Errorf("-content-directory must be a directory")
	}
	return nil
}

func cloneContentDir() (string, error) {
	dir, tmperr := ioutil.TempDir("", "content-*")
	if tmperr != nil {
		return "", fmt.Errorf("couldn't create tmpdir: %w", tmperr)
	}
	log.Printf("Created temporary directory: %s", dir)

	// Clone the repository
	cloneArgs := []string{"clone", "https://github.com/ComplianceAsCode/content.git", dir}
	log.Printf("Executing: git %s", strings.Join(cloneArgs, " "))
	ctx := goctx.Background()
	_, cmderr := exec.CommandContext(ctx, "/usr/bin/git", cloneArgs...).CombinedOutput()
	if cmderr != nil {
		return "", fmt.Errorf("couldn't clone content: %w", cmderr)
	}
	log.Printf("Successfully cloned ComplianceAsCode/content repository")

	// Get and log the git SHA of the cloned repository
	shaArgs := []string{"-C", dir, "rev-parse", "HEAD"}
	log.Printf("Executing: git %s", strings.Join(shaArgs, " "))
	ctx = goctx.Background()
	shaOutput, shaErr := exec.CommandContext(ctx, "/usr/bin/git", shaArgs...).Output()
	if shaErr != nil {
		log.Printf("Warning: Unable to obtain git SHA from cloned repository: %v", shaErr)
	} else {
		sha := strings.TrimSpace(string(shaOutput))
		log.Printf("Cloned repository git SHA: %s", sha)
	}

	return dir, nil
}

// generateKubeConfig generates a kube config and a dynamic client.
func generateKubeConfig() (dynclient.Client, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}

	// create dynamic client
	scheme := runtime.NewScheme()
	if err := cgoscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add cgo scheme to runtime scheme: %w", err)
	}
	if err := extscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add api extensions scheme to runtime scheme: %w", err)
	}
	if err := cmpapis.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add compliance scheme to runtime scheme: %w", err)
	}
	if err := mcfg.Install(scheme); err != nil {
		return nil, fmt.Errorf("failed to add MachineConfig scheme to runtime scheme: %w", err)
	}

	dc, err := dynclient.New(cfg, dynclient.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("failed to build the dynamic client: %w", err)
	}
	return dc, nil
}

// createObject creates an object from a given path and returns it.
func createObject(c dynclient.Client, path string) error {
	obj, err := readObjFromYAMLFilePath(path)
	if err != nil {
		return err
	}

	err = c.Create(goctx.TODO(), obj)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			log.Printf("Object already exists: %s/%s (%s)", obj.GetNamespace(), obj.GetName(), obj.GetKind())
		} else {
			return err
		}
	} else {
		log.Printf("Successfully created object: %s/%s (%s)", obj.GetNamespace(), obj.GetName(), obj.GetKind())
	}

	return nil
}

// Reads a YAML file and returns an unstructured object from it. This object
// can be taken into use by the dynamic client.
func readObjFromYAMLFilePath(mpath string) (*unstructured.Unstructured, error) {
	nsyamlfile, err := os.Open(mpath)
	if err != nil {
		return nil, err
	}
	defer nsyamlfile.Close()

	return readObjFromYAML(bufio.NewReader(nsyamlfile))
}

// Reads a YAML file and returns an unstructured object from it. This object
// can be taken into use by the dynamic client.
func readObjFromYAML(r io.Reader) (*unstructured.Unstructured, error) {
	obj := &unstructured.Unstructured{}
	dec := k8syaml.NewYAMLToJSONDecoder(r)
	err := dec.Decode(obj)
	return obj, err
}

func ensureSubscriptionExists(c dynclient.Client, tc *testConfig.TestConfig) error {
	p := subscriptionPath
	// We need to modify the default deployment through the subscription if
	// we're dealing with a ROSA cluster because we only have worker nodes
	// available to run the operator. If we don't do this, the deployment
	// will spin waiting for master nodes to schedule the operator on.
	if tc.Platform == "rosa" {
		p = rosaSubscriptionPath
	}
	err := createObject(c, p)
	if err != nil {
		return fmt.Errorf("failed to create subscription: %w", err)
	}
	return nil
}

func waitForOperatorToBeReady(c dynclient.Client, tc *testConfig.TestConfig) error {
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 30)

	retryFunc := func() error {
		od := &appsv1.Deployment{}
		err := c.Get(goctx.TODO(), operatorNamespacedName, od)
		if err != nil {
			return fmt.Errorf("getting deployment: %w", err)
		}
		if len(od.Status.Conditions) == 0 {
			return fmt.Errorf("no conditions for deployment yet")
		}
		for _, cond := range od.Status.Conditions {
			if cond.Type == appsv1.DeploymentAvailable {
				return nil
			}
		}
		return fmt.Errorf("the deployment is not ready yet")
	}

	notifyFunc := func(err error, d time.Duration) {
		log.Printf("Operator deployment not ready after %s: %s\n", d.String(), err)
	}

	err := backoff.RetryNotify(retryFunc, bo, notifyFunc)
	if err != nil {
		return fmt.Errorf("operator deployment was never created: %w", err)
	}
	return nil
}

func ensureTestProfileBundle(c dynclient.Client, tc *testConfig.TestConfig) error {
	key := types.NamespacedName{
		Name:      tc.TestProfileBundleName,
		Namespace: operatorNamespacedName.Namespace,
	}
	pb := &cmpv1alpha1.ProfileBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tc.TestProfileBundleName,
			Namespace: operatorNamespacedName.Namespace,
		},
		Spec: cmpv1alpha1.ProfileBundleSpec{
			ContentImage: tc.ContentImage,
			ContentFile:  fmt.Sprintf("ssg-%s-ds.xml", tc.Product),
		},
	}

	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 180)
	err := backoff.RetryNotify(func() error {
		found := &cmpv1alpha1.ProfileBundle{}
		if err := c.Get(goctx.TODO(), key, found); err != nil {
			if apierrors.IsNotFound(err) {
				return c.Create(goctx.TODO(), pb)
			}
			return err
		}
		// Update the spec in case it differs
		found.Spec = pb.Spec
		return c.Update(goctx.TODO(), found)
	}, bo, func(err error, d time.Duration) {
		log.Printf("Still waiting for test profile bundle to be created after %s: %s", d.String(), err)
	})
	if err != nil {
		return fmt.Errorf("failed to ensure test profile bundle exists: %w", err)
	}
	return nil
}

func waitForValidTestProfileBundle(c dynclient.Client, tc *testConfig.TestConfig) error {
	key := types.NamespacedName{
		Name:      tc.TestProfileBundleName,
		Namespace: operatorNamespacedName.Namespace,
	}

	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 180)
	err := backoff.RetryNotify(func() error {
		found := &cmpv1alpha1.ProfileBundle{}
		if err := c.Get(goctx.TODO(), key, found); err != nil {
			return err
		}
		if found.Status.DataStreamStatus != cmpv1alpha1.DataStreamValid {
			return fmt.Errorf("%s ProfileBundle is in %s state", found.Name, found.Status.DataStreamStatus)
		}
		return nil
	}, bo, func(err error, _ time.Duration) {
		log.Printf("waiting for ProfileBundle to parse: %s", err)
	})
	if err != nil {
		return fmt.Errorf("failed to ensure test PB: %w", err)
	}
	return nil
}

func ensureTestSettings(c dynclient.Client, tc *testConfig.TestConfig) error {
	defaultkey := types.NamespacedName{
		Name:      "default",
		Namespace: operatorNamespacedName.Namespace,
	}
	defaultSettings := &cmpv1alpha1.ScanSetting{}

	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 180)

	err := backoff.RetryNotify(func() error {
		return c.Get(goctx.TODO(), defaultkey, defaultSettings)
	}, bo, func(err error, d time.Duration) {
		log.Printf("Couldn't get default scanSettings after %s: %s", d.String(), err)
	})
	if err != nil {
		return fmt.Errorf("failed to get default scanSettings: %w", err)
	}

	// Ensure auto-apply
	key := types.NamespacedName{
		Name:      tc.E2eSettings,
		Namespace: operatorNamespacedName.Namespace,
	}
	autoApplySettings := defaultSettings.DeepCopy()
	// Delete Object Meta so we reset unwanted references
	autoApplySettings.ObjectMeta = metav1.ObjectMeta{
		Name:      tc.E2eSettings,
		Namespace: operatorNamespacedName.Namespace,
	}
	if !tc.BypassRemediations {
		autoApplySettings.AutoApplyRemediations = true
	}
	autoApplySettings.ShowNotApplicable = true // so that we can test if a setting goes from PASS/FAIL to N/A
	err = backoff.RetryNotify(func() error {
		found := &cmpv1alpha1.ScanSetting{}
		if err := c.Get(goctx.TODO(), key, found); err != nil {
			if apierrors.IsNotFound(err) {
				return c.Create(goctx.TODO(), autoApplySettings)
			}
			return err
		}
		// Copy references to enable updating object
		found.ObjectMeta.DeepCopyInto(&autoApplySettings.ObjectMeta)
		return c.Update(goctx.TODO(), autoApplySettings)
	}, bo, func(err error, d time.Duration) {
		log.Printf("Couldn't ensure auto-apply scansettings after %s: %s", d.String(), err)
	})
	if err != nil {
		return fmt.Errorf("failed to ensure auto-apply scanSettings: %w", err)
	}
	return nil
}

func setPoolRollingPolicy(c dynclient.Client) error {
	mcfgpools := &mcfgv1.MachineConfigPoolList{}
	if err := c.List(goctx.TODO(), mcfgpools); err != nil {
		return fmt.Errorf("error getting MachineConfigPool list: %w", err)
	}

	for i := range mcfgpools.Items {
		pool := &mcfgpools.Items[i]

		if strings.Contains(pool.Name, "master") {
			continue
		}

		if pool.Spec.MaxUnavailable == nil {
			log.Printf("Setting pool %s Rolling Policy", pool.Name)
			maxUnavailable := intstr.FromInt(2)
			pool.Spec.MaxUnavailable = &maxUnavailable
			if err := c.Update(goctx.TODO(), pool); err != nil {
				return fmt.Errorf("error updating MachineConfigPool list MaxUnavailable: %w", err)
			}
		}
	}
	return nil
}

func ensureNamespaceExists(c dynclient.Client) error {
	err := createObject(c, namespacePath)
	if err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}
	return nil
}

func ensureCatalogSourceExists(c dynclient.Client) error {
	err := createObject(c, catalogSourcePath)
	if err != nil {
		return fmt.Errorf("failed to create catalog source: %w", err)
	}
	return nil
}

func ensureOperatorGroupExists(c dynclient.Client) error {
	err := createObject(c, operatorGroupPath)
	if err != nil {
		return fmt.Errorf("failed to create operator group: %w", err)
	}
	return nil
}
