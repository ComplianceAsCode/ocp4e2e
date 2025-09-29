package helpers

import (
	"bufio"
	goctx "context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	cmpapis "github.com/ComplianceAsCode/compliance-operator/pkg/apis"
	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	backoff "github.com/cenkalti/backoff/v4"
	mcfg "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io"
	mcfgv1 "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io/v1"
	"gopkg.in/yaml.v2"
	appsv1 "k8s.io/api/apps/v1"
	extscheme "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	cgoscheme "k8s.io/client-go/kubernetes/scheme"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	testConfig "github.com/ComplianceAsCode/ocp4e2e/config"
	"github.com/ComplianceAsCode/ocp4e2e/resultparser"
)

var (
	upstreamRepo             = "https://github.com/ComplianceAsCode/content/tree/master/%s"
	resourcesPath            = "ocp-resources"
	namespaceFileName        = "compliance-operator-ns.yaml"
	catalogSourceFileName    = "compliance-operator-catalog-source.yaml"
	operatorGroupFileName    = "compliance-operator-operator-group.yaml"
	rosaSubscriptionFileName = "compliance-operator-rosa-subscription.yaml"
	subscriptionFileName     = "compliance-operator-alpha-subscription.yaml"
)

// RuleTest is the definition of the structure rule-specific e2e tests should have.
type RuleTest struct {
	DefaultResult          interface{} `yaml:"default_result"`
	ResultAfterRemediation interface{} `yaml:"result_after_remediation,omitempty"`
	ExcludeFromCount       interface{} `yaml:"exclude_from_count,omitempty"`
}

type RuleTestResults struct {
	RuleResults map[string]RuleTest `yaml:"rule_results"`
}

// AssertionMismatch represents a single assertion failure.
type AssertionMismatch struct {
	CheckResultName string      `yaml:"check_result_name"`
	ExpectedResult  interface{} `yaml:"expected_result"`
	ActualResult    string      `yaml:"actual_result"`
	ErrorMessage    string      `yaml:"error_message"`
}

// assertContentDirectory checks that the content directory is valid and clones
// it if it is not set.
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
	dir, tmperr := os.MkdirTemp("", "content-*")
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

// GenerateKubeConfig generates a kube config and a dynamic client.
func GenerateKubeConfig() (dynclient.Client, error) {
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
func createObject(c dynclient.Client, p string) error {
	obj, err := readObjFromYAMLFilePath(p)
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
	s := subscriptionFileName
	// We need to modify the default deployment through the subscription if
	// we're dealing with a ROSA cluster because we only have worker nodes
	// available to run the operator. If we don't do this, the deployment
	// will spin waiting for master nodes to schedule the operator on.
	if tc.Platform == "rosa" {
		s = rosaSubscriptionFileName
	}
	p := path.Join(tc.ContentDir, resourcesPath, s)
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
		err := c.Get(goctx.TODO(), tc.OperatorNamespace, od)
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

func ensureTestProfileBundles(c dynclient.Client, tc *testConfig.TestConfig) error {
	log.Printf("Using content image for testing: %s", tc.ContentImage)
	bundles := map[string]string{
		tc.OpenShiftBundleName: "ocp4",
		tc.RHCOSBundleName:     "rhcos4",
	}

	for bundleName, product := range bundles {
		key := types.NamespacedName{
			Name:      bundleName,
			Namespace: tc.OperatorNamespace.Namespace,
		}
		pb := &cmpv1alpha1.ProfileBundle{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bundleName,
				Namespace: tc.OperatorNamespace.Namespace,
			},
			Spec: cmpv1alpha1.ProfileBundleSpec{
				ContentImage: tc.ContentImage,
				ContentFile:  fmt.Sprintf("ssg-%s-ds.xml", product),
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
			log.Printf("Still waiting for test profile bundle %s to be created after %s: %s", bundleName, d.String(), err)
		})
		if err != nil {
			return fmt.Errorf("failed to ensure test profile bundle %s exists: %w", bundleName, err)
		}
		log.Printf("ProfileBundle %s created/updated successfully", bundleName)
	}
	return nil
}

func waitForValidTestProfileBundles(c dynclient.Client, tc *testConfig.TestConfig) error {
	bundleNames := []string{tc.OpenShiftBundleName, tc.RHCOSBundleName}

	for _, bundleName := range bundleNames {
		key := types.NamespacedName{
			Name:      bundleName,
			Namespace: tc.OperatorNamespace.Namespace,
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
			log.Printf("waiting for ProfileBundle %s to parse: %s", bundleName, err)
		})
		if err != nil {
			return fmt.Errorf("failed to ensure test ProfileBundle %s: %w", bundleName, err)
		}
		log.Printf("ProfileBundle %s is valid", bundleName)
	}
	return nil
}

func ensureTestSettings(c dynclient.Client, tc *testConfig.TestConfig) error {
	defaultkey := types.NamespacedName{
		Name:      "default",
		Namespace: tc.OperatorNamespace.Namespace,
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
		Namespace: tc.OperatorNamespace.Namespace,
	}
	autoApplySettings := defaultSettings.DeepCopy()
	// Delete Object Meta so we reset unwanted references
	autoApplySettings.ObjectMeta = metav1.ObjectMeta{
		Name:      tc.E2eSettings,
		Namespace: tc.OperatorNamespace.Namespace,
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

		maxUnavailable := intstr.FromInt(2)
		if pool.Spec.MaxUnavailable == &maxUnavailable {
			log.Printf(
				"Setting pool %s MaxUnavailable to %s for faster reboots to shorten test times",
				pool.Name, maxUnavailable.String())
			pool.Spec.MaxUnavailable = &maxUnavailable
			if err := c.Update(goctx.TODO(), pool); err != nil {
				return fmt.Errorf("error updating MachineConfigPool list MaxUnavailable: %w", err)
			}
		}
	}
	return nil
}

func ensureNamespaceExists(c dynclient.Client, tc *testConfig.TestConfig) error {
	n := path.Join(tc.ContentDir, resourcesPath, namespaceFileName)
	err := createObject(c, n)
	if err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}
	return nil
}

func ensureCatalogSourceExists(c dynclient.Client, tc *testConfig.TestConfig) error {
	cs := path.Join(tc.ContentDir, resourcesPath, catalogSourceFileName)
	err := createObject(c, cs)
	if err != nil {
		return fmt.Errorf("failed to create catalog source: %w", err)
	}
	return nil
}

func ensureOperatorGroupExists(c dynclient.Client, tc *testConfig.TestConfig) error {
	o := path.Join(tc.ContentDir, resourcesPath, operatorGroupFileName)
	err := createObject(c, o)
	if err != nil {
		return fmt.Errorf("failed to create operator group: %w", err)
	}
	return nil
}

// createTailoredProfile creates a TailoredProfile with the given rules.
func createTailoredProfile(tc *testConfig.TestConfig, c dynclient.Client, name string, rules []cmpv1alpha1.Rule) error {
	ruleRefs := make([]cmpv1alpha1.RuleReferenceSpec, len(rules))
	for i := range rules {
		ruleRefs[i] = cmpv1alpha1.RuleReferenceSpec{
			Name: rules[i].Name,
		}
	}

	// Determine product type based on the first rule's check type so we
	// can set the profile's product-type appropriately
	annotations := make(map[string]string)
	if len(rules) > 0 {
		switch rules[0].CheckType {
		case cmpv1alpha1.CheckTypeNode:
			annotations["compliance.openshift.io/product-type"] = "Node"
		case cmpv1alpha1.CheckTypePlatform:
			annotations["compliance.openshift.io/product-type"] = "Platform"
		}
	}

	description := fmt.Sprintf("Tailored profile containing all %s rules", name)
	tailoredProfile := &cmpv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   tc.OperatorNamespace.Namespace,
			Annotations: annotations,
		},
		Spec: cmpv1alpha1.TailoredProfileSpec{
			Description: description,
			EnableRules: ruleRefs,
			Title:       name,
		},
	}

	err := c.Create(goctx.TODO(), tailoredProfile)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	log.Printf("Created %s tailored profile with %d rules", name, len(rules))
	return nil
}

// CreatePlatformTailoredProfile creates a TailoredProfile with all platform rules.
func CreatePlatformTailoredProfile(tc *testConfig.TestConfig, c dynclient.Client) error {
	platformRules, err := findPlatformRules(c, tc)
	if err != nil {
		return fmt.Errorf("failed to find platform rules: %w", err)
	}
	return createTailoredProfile(tc, c, "platform", platformRules)
}

// CreateNodeTailoredProfile creates two TailoredProfiles: one for OpenShift
// node rules and one for RHCOS node rules. We need to create two separate
// tailored profiles because a profile cannot have rules from multiple
// products.
func CreateNodeTailoredProfile(tc *testConfig.TestConfig, c dynclient.Client) error {
	ocpNodeRules, err := findNodeRulesByBundle(c, tc.OpenShiftBundleName)
	if err != nil {
		return fmt.Errorf("failed to find OpenShift node rules: %w", err)
	}

	rhcosNodeRules, err := findNodeRulesByBundle(c, tc.RHCOSBundleName)
	if err != nil {
		return fmt.Errorf("failed to find RHCOS node rules: %w", err)
	}

	if len(ocpNodeRules) > 0 {
		err = createTailoredProfile(tc, c, "ocp-node", ocpNodeRules)
		if err != nil {
			return fmt.Errorf("failed to create OpenShift node tailored profile: %w", err)
		}
	}

	if len(rhcosNodeRules) > 0 {
		err = createTailoredProfile(tc, c, "rhcos-node", rhcosNodeRules)
		if err != nil {
			return fmt.Errorf("failed to create RHCOS node tailored profile: %w", err)
		}
	}

	return nil
}

// findPlatformRules finds all Rule custom resources of type Platform and returns them.
func findPlatformRules(c dynclient.Client, tc *testConfig.TestConfig) ([]cmpv1alpha1.Rule, error) {
	ruleList := &cmpv1alpha1.RuleList{}
	err := c.List(goctx.TODO(), ruleList)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	var platformRules []cmpv1alpha1.Rule

	for i := range ruleList.Items {
		// Only include rules from the e2e profile bundle
		bundleName, exists := ruleList.Items[i].Labels["compliance.openshift.io/profile-bundle"]
		if exists && bundleName == tc.OpenShiftBundleName {
			if ruleList.Items[i].CheckType == cmpv1alpha1.CheckTypePlatform {
				platformRules = append(platformRules, ruleList.Items[i])
			}
		}
	}
	return platformRules, nil
}

// findNodeRulesByBundle finds all Node rules from a specific bundle.
func findNodeRulesByBundle(c dynclient.Client, bundleName string) ([]cmpv1alpha1.Rule, error) {
	ruleList := &cmpv1alpha1.RuleList{}
	err := c.List(goctx.TODO(), ruleList)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	var nodeRules []cmpv1alpha1.Rule

	for i := range ruleList.Items {
		// Only include rules from the specified profile bundle
		ruleBundleName, exists := ruleList.Items[i].Labels["compliance.openshift.io/profile-bundle"]
		if exists && ruleBundleName == bundleName {
			if ruleList.Items[i].CheckType == cmpv1alpha1.CheckTypeNode {
				nodeRules = append(nodeRules, ruleList.Items[i])
			}
		}
	}
	return nodeRules, nil
}

// waitForScanCleanup waits for ComplianceSuite and ComplianceCheckResults to
// be cleaned up after a ScanSettingBinding is deleted.
func waitForScanCleanup(c dynclient.Client, tc *testConfig.TestConfig, bindingName string) error {
	// Expected suite name is typically the same as binding name
	suiteName := bindingName

	log.Printf("Waiting for ComplianceSuite and results cleanup for %s", suiteName)

	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 60) // 5 minutes max
	err := backoff.RetryNotify(func() error {
		// Check if ComplianceSuite still exists
		suite := &cmpv1alpha1.ComplianceSuite{}
		err := c.Get(goctx.TODO(), dynclient.ObjectKey{
			Name:      suiteName,
			Namespace: tc.OperatorNamespace.Namespace,
		}, suite)

		if err == nil {
			return fmt.Errorf("ComplianceSuite %s still exists", suiteName)
		}

		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("error checking ComplianceSuite %s: %w", suiteName, err)
		}

		// Check if any ComplianceCheckResults still exist for this suite
		resultList := &cmpv1alpha1.ComplianceCheckResultList{}
		labelSelector, err := labels.Parse(cmpv1alpha1.SuiteLabel + "=" + suiteName)
		if err != nil {
			return fmt.Errorf("failed to parse label selector: %w", err)
		}
		opts := &dynclient.ListOptions{
			LabelSelector: labelSelector,
		}
		err = c.List(goctx.TODO(), resultList, opts)
		if err != nil {
			return fmt.Errorf("error listing ComplianceCheckResults for suite %s: %w", suiteName, err)
		}

		if len(resultList.Items) > 0 {
			return fmt.Errorf("%d ComplianceCheckResults still exist for suite %s", len(resultList.Items), suiteName)
		}

		return nil
	}, bo, func(err error, d time.Duration) {
		log.Printf("Still waiting for cleanup after %s: %s", d.String(), err)
	})
	if err != nil {
		return fmt.Errorf("timeout waiting for scan cleanup: %w", err)
	}

	log.Printf("Scan cleanup completed for %s", suiteName)
	return nil
}

// CreateScanBinding creates a ScanSettingBinding for the given profile.
// If a binding already exists, it will be deleted first to trigger a new scan.
func CreateScanBinding(
	c dynclient.Client,
	tc *testConfig.TestConfig,
	bindingName, profileName,
	profileKind,
	scanSettingName string,
) error {
	binding := &cmpv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: tc.OperatorNamespace.Namespace,
		},
		SettingsRef: &cmpv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     scanSettingName,
		},
		Profiles: []cmpv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     profileKind,
				Name:     profileName,
			},
		},
	}

	// Check if the binding already exists and delete it if it does
	existingBinding := &cmpv1alpha1.ScanSettingBinding{}
	err := c.Get(goctx.TODO(), dynclient.ObjectKey{
		Name:      bindingName,
		Namespace: tc.OperatorNamespace.Namespace,
	}, existingBinding)

	if err == nil {
		// Binding exists, delete it first
		log.Printf("Deleting existing ScanSettingBinding %s to trigger new scan\n", bindingName)
		err = c.Delete(goctx.TODO(), existingBinding)
		if err != nil {
			return fmt.Errorf("failed to delete existing %s scan binding: %w", bindingName, err)
		}

		// Wait for ComplianceSuite and ComplianceCheckResults to be cleaned up
		err = waitForScanCleanup(c, tc, bindingName)
		if err != nil {
			return fmt.Errorf("failed to wait for scan cleanup after deleting %s: %w", bindingName, err)
		}
	} else if !apierrors.IsNotFound(err) {
		// If error is not "not found", return the error
		return fmt.Errorf("failed to check if %s scan binding exists: %w", bindingName, err)
	}

	// Create the new binding
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 180)
	err = backoff.RetryNotify(func() error {
		return c.Create(goctx.TODO(), binding)
	}, bo, func(err error, d time.Duration) {
		fmt.Printf("Couldn't create %s binding after %s: %s\n", bindingName, d.String(), err)
	})
	if err != nil {
		return fmt.Errorf("failed to create %s scan binding: %w", bindingName, err)
	}
	log.Printf("Created new ScanSettingBinding %s\n", bindingName)
	return nil
}

// CreatePlatformScanBinding creates a ScanSettingBinding for the platform rules.
func CreatePlatformScanBinding(tc *testConfig.TestConfig, c dynclient.Client) error {
	return CreateScanBinding(c, tc, "platform-scan-binding", "platform", "TailoredProfile", tc.E2eSettings)
}

// CreateNodeScanBinding creates a ScanSettingBinding for the node rules using
// both tailored profiles.
func CreateNodeScanBinding(tc *testConfig.TestConfig, c dynclient.Client) error {
	binding := &cmpv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "node-scan-binding",
			Namespace: tc.OperatorNamespace.Namespace,
		},
		SettingsRef: &cmpv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     tc.E2eSettings,
		},
		Profiles: []cmpv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     "ocp-node",
			},
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     "rhcos-node",
			},
		},
	}

	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 180)
	err := backoff.RetryNotify(func() error {
		return c.Create(goctx.TODO(), binding)
	}, bo, func(err error, d time.Duration) {
		fmt.Printf("Couldn't create node-scan-binding after %s: %s\n", d.String(), err)
	})
	if err != nil {
		return fmt.Errorf("failed to create node-scan-binding: %w", err)
	}
	return nil
}

func WaitForComplianceSuite(tc *testConfig.TestConfig, c dynclient.Client, suiteName string) error {
	key := types.NamespacedName{Name: suiteName, Namespace: tc.OperatorNamespace.Namespace}

	// First, check if this might be a rescan scenario by seeing if suite is already DONE
	initialSuite := &cmpv1alpha1.ComplianceSuite{}
	err := c.Get(goctx.TODO(), key, initialSuite)

	// If suite doesn't exist yet, this is a first run - skip rescan detection
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get initial suite status: %w", err)
		}
		log.Printf("ComplianceSuite %s doesn't exist yet, waiting for it to be created", suiteName)
	} else {
		// Suite exists, check if this is a rescan scenario
		err = handleRescanIfNeeded(tc, c, key, suiteName, initialSuite)
		if err != nil {
			return err
		}
	}

	// Now wait for the suite to complete (whether initial scan or rescan)
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 360) // 30 minutes
	err = backoff.RetryNotify(func() error {
		suite := &cmpv1alpha1.ComplianceSuite{}
		err := c.Get(goctx.TODO(), key, suite)
		if err != nil {
			return err
		}
		if len(suite.Status.ScanStatuses) == 0 {
			return fmt.Errorf("no statuses available yet")
		}
		for idx := range suite.Status.ScanStatuses {
			scanstatus := &suite.Status.ScanStatuses[idx]
			if scanstatus.Phase != cmpv1alpha1.PhaseDone {
				return fmt.Errorf("suite %s scan %s is %s", suiteName, scanstatus.Name, scanstatus.Phase)
			}
			if scanstatus.Result == cmpv1alpha1.ResultError {
				return fmt.Errorf("there was an unexpected error in the scan '%s': %s",
					scanstatus.Name, scanstatus.ErrorMessage)
			}
		}
		return nil
	}, bo, func(e error, _ time.Duration) {
		log.Printf("ComplianceSuite %s is not DONE: %s", suiteName, e)
	})
	if err != nil {
		return fmt.Errorf("the Compliance Suite '%s' didn't get to DONE phase: %w", key.Name, err)
	}
	log.Printf("ComplianceSuite %s is DONE", suiteName)
	return nil
}

// VerifyScanResults verifies the results of a scan against expected assertions.
func VerifyScanResults(
	tc *testConfig.TestConfig,
	_ dynclient.Client,
	assertionFile string,
	results map[string]string,
	afterRemediation bool,
) ([]AssertionMismatch, error) {
	mismatchedAssertions, err := assertScanResults(tc, results, assertionFile, afterRemediation)
	if err != nil {
		return nil, err
	}
	return mismatchedAssertions, nil
}

// VerifyPlatformScanResults verifies the results of the platform scan against expected assertions.
func VerifyPlatformScanResults(
	tc *testConfig.TestConfig,
	c dynclient.Client,
	assertionFile string,
	results map[string]string,
	afterRemediation bool,
) ([]AssertionMismatch, error) {
	mismatchedAssertions, err := VerifyScanResults(tc, c, assertionFile, results, afterRemediation)
	if err != nil {
		return nil, err
	}
	return mismatchedAssertions, nil
}

// VerifyNodeScanResults verifies the results of the node scan against expected assertions.
func VerifyNodeScanResults(
	tc *testConfig.TestConfig,
	c dynclient.Client,
	assertionFile string,
	results map[string]string,
	afterRemediation bool,
) ([]AssertionMismatch, error) {
	mismatchedAssertions, err := VerifyScanResults(tc, c, assertionFile, results, afterRemediation)
	if err != nil {
		return nil, err
	}
	return mismatchedAssertions, nil
}

// assertScanResults verifies scan results against expected assertions from YAML files.
func assertScanResults(
	tc *testConfig.TestConfig,
	results map[string]string,
	assertionFile string,
	afterRemediation bool,
) ([]AssertionMismatch, error) {
	mismatchedAssertions, err := assertResultsAgainstAssertionFile(tc, results, assertionFile, afterRemediation)
	if err != nil {
		return nil, err
	}
	return mismatchedAssertions, nil
}

// assertResultsAgainstAssertionFile a consolidated function that handles both
// profile and scan assertions It can load existing assertion files, verify
// results against them, and generate assertion files when they don't exist.
func assertResultsAgainstAssertionFile(
	tc *testConfig.TestConfig,
	results map[string]string,
	assertionFile string,
	afterRemediations bool,
) ([]AssertionMismatch, error) {
	// Try to load existing assertions
	assertions, err := loadAssertionsFromPath(assertionFile)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist so we don't have anything to compare against
			log.Printf("No assertion file found: %s", assertionFile)
			return []AssertionMismatch{}, nil
		}
		log.Printf("Error loading assertion file %s: %s", assertionFile, err)
		return nil, err
	}

	// File exists, verify results against assertions
	mismatchedAssertions, err := verifyResultsAgainstAssertions(tc, results, assertions, afterRemediations)
	if err != nil {
		return nil, err
	}
	return mismatchedAssertions, nil
}

// loadAssertionsFromPath loads rule assertions from a specific file path.
func loadAssertionsFromPath(p string) (*RuleTestResults, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}

	log.Printf("Using %s as assertion file", p)

	var assertions RuleTestResults
	err = yaml.Unmarshal(data, &assertions)
	if err != nil {
		return nil, fmt.Errorf("could not parse assertion file %s: %w", p, err)
	}

	return &assertions, nil
}

// verifyResultsAgainstAssertions verifies scan results against expected assertions.
func verifyResultsAgainstAssertions(
	_ *testConfig.TestConfig,
	results map[string]string,
	assertions *RuleTestResults,
	afterRemediations bool,
) ([]AssertionMismatch, error) {
	// Collect assertion mismatches
	var mismatches []AssertionMismatch

	// Verify each expected assertion
	for ruleName, expected := range assertions.RuleResults {
		expectedResult, ok := expected.DefaultResult.(string)
		if !ok {
			return nil, fmt.Errorf("expected string, got %T", expected.DefaultResult)
		}
		if afterRemediations && expected.ResultAfterRemediation != nil {
			expectedResult, ok = expected.ResultAfterRemediation.(string)
			if !ok {
				return nil, fmt.Errorf("expected string, got %T", expected.ResultAfterRemediation)
			}
		}

		actual, exists := results[ruleName]
		if !exists {
			log.Printf("Expected rule %s to be found in scan results", ruleName)
			e := fmt.Sprintf("E2E-FAILURE: Expected to find rule %s in scan results with %s state",
				ruleName, expectedResult)
			mismatches = append(mismatches, AssertionMismatch{
				CheckResultName: ruleName,
				ExpectedResult:  expectedResult,
				ActualResult:    actual,
				ErrorMessage:    e,
			})
			continue
		}

		err := verifyRuleResult(ruleName, expectedResult, actual)
		if err != nil {
			log.Printf("Rule %s failed result verification: %s", ruleName, err)
			mismatches = append(mismatches, AssertionMismatch{
				CheckResultName: ruleName,
				ExpectedResult:  expectedResult,
				ActualResult:    actual,
				ErrorMessage:    err.Error(),
			})
		}
	}

	log.Printf(
		"Verified %d rule results against assertions (total rules in results: %d)",
		len(assertions.RuleResults), len(results),
	)
	return mismatches, nil
}

func verifyRuleResult(ruleName, expected, actual string) error {
	m, err := resultparser.NewResultMatcher(expected)
	if err != nil {
		return fmt.Errorf("error parsing result evaluator: %w", err)
	}

	match := m.Eval(actual)
	if !match {
		return fmt.Errorf("E2E-FAILURE: The expected result for %s rule didn't match. Expected '%s', Got '%s'",
			ruleName, expected, actual)
	}
	return nil
}

func GenerateAssertionFileFromResults(
	tc *testConfig.TestConfig,
	_ dynclient.Client,
	assertionFile string,
	initialResults, finalResults map[string]string,
) error {
	assertions := &RuleTestResults{
		RuleResults: make(map[string]RuleTest),
	}
	ruleTest := RuleTest{}
	afterRemediation := finalResults != nil
	for ruleName, initialResult := range initialResults {
		ruleTest.DefaultResult = initialResult

		if afterRemediation {
			finalResult := finalResults[ruleName]
			if finalResult != initialResult {
				ruleTest.ResultAfterRemediation = finalResult
			}
		}
		assertions.RuleResults[ruleName] = ruleTest
	}

	// Marshal to YAML
	data, err := yaml.Marshal(assertions)
	if err != nil {
		return fmt.Errorf("failed to marshal assertion content: %w", err)
	}

	fullPath := path.Join(tc.LogDir, assertionFile)
	err = os.WriteFile(fullPath, data, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write assertion file: %w", err)
	}

	log.Printf("Generated assertion file: %s", fullPath)
	log.Printf(
		"Generated assertions for %d rules",
		len(assertions.RuleResults),
	)
	return nil
}

func ApplyManualRemediations(tc *testConfig.TestConfig, c dynclient.Client, results map[string]string) error {
	var wg sync.WaitGroup
	errorChannel := make(chan error, len(results))

	log.Printf("Applying manual remediations")
	for resultName, resultValue := range results {
		// We should only try applying a manual remediation if the rule
		// failed. Ignore all other states.
		if resultValue != "FAIL" {
			continue
		}
		ruleName, err := getRuleNameFromResultName(tc, c, resultName)
		if err != nil {
			return err
		}

		// Convert rule name to regex pattern that matches both - and _
		// characters. We need to do this because - and _ are not used
		// consistently in the CaC/content project for rule names.
		rulePattern := convertRuleNameToRegex(ruleName)

		// Determine if rule contains a manual remediation in
		// ComplianceAsCode/content -- if we don't find one,
		// just move on to the next result since not all rules
		// are guaranteed to have a remediation
		remediationPath, found := findManualRemediation(tc, rulePattern)
		if !found {
			continue
		}
		log.Printf("Applying manual remediation %s", remediationPath)

		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			if err := applyRemediation(tc, path, tc.ManualRemediationTimeout); err != nil {
				errorChannel <- err
			}
		}(remediationPath)
	}

	wg.Wait()
	close(errorChannel)

	for err := range errorChannel {
		if err != nil {
			return err
		}
	}
	return nil
}

func applyRemediation(tc *testConfig.TestConfig, remediationPath string, timeout time.Duration) error {
	ctx, cancel := goctx.WithTimeout(goctx.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", remediationPath)
	// We do this because some remediations need to access the root of the
	// content directory
	cmd.Env = append(os.Environ(), fmt.Sprintf("ROOT_DIR=%s", tc.ContentDir))

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == goctx.DeadlineExceeded {
			return fmt.Errorf("timed out waiting for manual remediation %s to apply: \nOutput: %s",
				remediationPath, string(output))
		}
		return fmt.Errorf("failed to apply manual remediation %s: %w\nOutput: %s",
			remediationPath, err, string(output))
	}
	log.Printf("Applied remediation %s", remediationPath)
	return nil
}

func getRuleNameFromResultName(
	tc *testConfig.TestConfig,
	c dynclient.Client,
	resultName string,
) (ruleName string, err error) {
	key := types.NamespacedName{
		Name:      resultName,
		Namespace: tc.OperatorNamespace.Namespace,
	}
	resultCR := &cmpv1alpha1.ComplianceCheckResult{}
	err = c.Get(goctx.TODO(), key, resultCR)
	if err != nil {
		return "", fmt.Errorf("failed to get ComplianceCheckResult %s: %w", resultName, err)
	}
	ruleName, exists := resultCR.Annotations[cmpv1alpha1.ComplianceCheckResultRuleAnnotation]
	if !exists {
		return "", fmt.Errorf("failed to derive rule name from result %s", ruleName)
	}

	return ruleName, nil
}

func convertRuleNameToRegex(ruleName string) string {
	// Escape any special regex characters in the rule name
	escaped := regexp.QuoteMeta(ruleName)
	// Replace literal \- and \_ with a character class that matches both - and _
	pattern := strings.ReplaceAll(escaped, `\-`, `[-_]`)
	pattern = strings.ReplaceAll(pattern, `\_`, `[-_]`)
	return pattern
}

func findRulePath(tc *testConfig.TestConfig, rulePattern string) (rulePath string, found bool) {
	found = false
	ruleRegex, err := regexp.Compile("^" + rulePattern + "$")
	if err != nil {
		log.Printf("Error compiling regex pattern %s: %s", rulePattern, err)
		return "", false
	}

	err = filepath.WalkDir(tc.ContentDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && ruleRegex.MatchString(d.Name()) {
			rulePath = path
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil && errors.Is(err, filepath.SkipAll) || !found {
		return "", false
	}
	return rulePath, found
}

func findManualRemediation(tc *testConfig.TestConfig, rulePattern string) (remediationPath string, found bool) {
	rulePath, found := findRulePath(tc, rulePattern)
	if !found {
		return "", found
	}

	// If we found a rulePath, let's string together a remediation path and
	// see if it exists. If not, then we'll just return an empty string and
	// move on to the next result since there isn't a manual remediation to
	// apply.
	remediationPath = path.Join(rulePath, "tests", "ocp4", "e2e-remediation.sh")
	if _, err := os.Stat(remediationPath); err != nil {
		return "", false
	}
	return remediationPath, found
}

// ApplyRemediationsWithDependencies handles remediation application with
// dependency resolution. It iteratively applies remediations and rescans until
// no more progress can be made.
func ApplyRemediationsWithDependencies(tc *testConfig.TestConfig, c dynclient.Client, suiteName string) error {
	// Limit the amount of iterations to 5. If we need to bounce the
	// cluster more than 5 times because remediations are that nested, we
	// need to drastically simplify that.
	maxIterations := 5
	iteration := 0

	for iteration < maxIterations {
		iteration++
		log.Printf("Starting remediation iteration %d for suite %s", iteration, suiteName)

		// Wait for remediations to be applied
		err := WaitForRemediationsToBeApplied(tc, c, suiteName)
		if err != nil {
			return fmt.Errorf("failed during remediation iteration %d: %w", iteration, err)
		}

		// Check if we have remediations with missing dependencies
		hasMissingDeps, missingDepCount, err := checkRemediationsWithMissingDependencies(tc, c, suiteName)
		if err != nil {
			return fmt.Errorf("failed to check missing dependencies in iteration %d: %w", iteration, err)
		}

		if !hasMissingDeps {
			log.Printf("No remediations with missing dependencies found after %d iterations", iteration)

			// Perform final rescan to get accurate results after all remediations
			log.Printf("Performing final rescan to get accurate results after all remediations")

			// Wait for MachineConfigPools to be updated after final remediations
			err = WaitForMachineConfigPoolsUpdated(tc, c)
			if err != nil {
				return fmt.Errorf("failed to wait for MachineConfigPools after final remediations: %w", err)
			}

			// Trigger final rescan
			err = RescanComplianceSuite(tc, c, suiteName)
			if err != nil {
				return fmt.Errorf("failed to trigger final rescan: %w", err)
			}

			// Wait for final rescan to complete
			err = WaitForComplianceSuite(tc, c, suiteName)
			if err != nil {
				return fmt.Errorf("failed to wait for final rescan: %w", err)
			}

			log.Printf("Final rescan completed successfully")
			break
		}

		log.Printf("Found %d remediations with missing dependencies, triggering rescan", missingDepCount)

		// Wait for MachineConfigPools to be updated after remediations
		err = WaitForMachineConfigPoolsUpdated(tc, c)
		if err != nil {
			return fmt.Errorf("failed to wait for MachineConfigPools in iteration %d: %w", iteration, err)
		}

		// Trigger rescan to re-evaluate dependencies
		err = RescanComplianceSuite(tc, c, suiteName)
		if err != nil {
			return fmt.Errorf("failed to trigger rescan in iteration %d: %w", iteration, err)
		}

		// Wait for rescan to complete
		err = WaitForComplianceSuite(tc, c, suiteName)
		if err != nil {
			return fmt.Errorf("failed to wait for rescan in iteration %d: %w", iteration, err)
		}

		// Check if we made progress (fewer missing dependencies)
		newHasMissingDeps, newMissingDepCount, err := checkRemediationsWithMissingDependencies(tc, c, suiteName)
		if err != nil {
			return fmt.Errorf("failed to check progress in iteration %d: %w", iteration, err)
		}

		if newHasMissingDeps && newMissingDepCount >= missingDepCount {
			log.Printf("No progress made in iteration %d (missing deps: %d -> %d), stopping",
				iteration,
				missingDepCount,
				newMissingDepCount)
			break
		}
	}

	if iteration >= maxIterations {
		return fmt.Errorf("reached maximum iterations (%d) without resolving all dependencies", maxIterations)
	}

	log.Printf("Successfully resolved all remediation dependencies after %d iterations", iteration)
	return nil
}

// checkRemediationsWithMissingDependencies checks if there are remediations
// with missing dependencies.
func checkRemediationsWithMissingDependencies(
	_ *testConfig.TestConfig,
	c dynclient.Client,
	suiteName string,
) (missingDeps bool, missingDepCount int, err error) {
	remList := &cmpv1alpha1.ComplianceRemediationList{}
	labelSelector, err := labels.Parse(cmpv1alpha1.SuiteLabel + "=" + suiteName)
	if err != nil {
		return false, 0, fmt.Errorf("failed to parse label selector: %w", err)
	}
	opts := &dynclient.ListOptions{
		LabelSelector: labelSelector,
	}
	err = c.List(goctx.TODO(), remList, opts)
	if err != nil {
		return false, 0, fmt.Errorf("failed to get remediation list: %w", err)
	}

	missingDepCount = 0
	for i := range remList.Items {
		if remList.Items[i].Status.ApplicationState == cmpv1alpha1.RemediationMissingDependencies {
			missingDepCount++
		}
	}

	log.Printf("Found %d remediations with missing dependencies", missingDepCount)
	return missingDepCount > 0, missingDepCount, nil
}

// WaitForRemediationsToBeApplied waits for all remediations from a compliance suite to be applied.
func WaitForRemediationsToBeApplied(tc *testConfig.TestConfig, c dynclient.Client, suiteName string) error {
	// Get all remediations for the suite
	remList := &cmpv1alpha1.ComplianceRemediationList{}
	labelSelector, err := labels.Parse(cmpv1alpha1.SuiteLabel + "=" + suiteName)
	if err != nil {
		return fmt.Errorf("failed to parse label selector: %w", err)
	}
	opts := &dynclient.ListOptions{
		LabelSelector: labelSelector,
	}
	err = c.List(goctx.TODO(), remList, opts)
	if err != nil {
		return fmt.Errorf("failed to get remediation list: %w", err)
	}

	if len(remList.Items) == 0 {
		log.Printf("No remediations found for suite %s", suiteName)
		return nil
	}

	log.Printf("Waiting for %d remediations to be applied for suite %s", len(remList.Items), suiteName)

	var errorRemediations []string
	var appliedCount, errorCount, needsReviewCount, outdatedCount, missingDepCount int

	// Wait for each remediation to be applied
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 360) // 30 minutes max
	err = backoff.RetryNotify(func() error {
		pendingCount := 0
		missingDepCount = 0
		appliedCount = 0
		errorCount = 0
		needsReviewCount = 0
		outdatedCount = 0
		errorRemediations = []string{} // Reset error list on each retry

		for i := range remList.Items {
			key := types.NamespacedName{Name: remList.Items[i].Name, Namespace: remList.Items[i].Namespace}
			currentRem := &cmpv1alpha1.ComplianceRemediation{}
			err := c.Get(goctx.TODO(), key, currentRem)
			if err != nil {
				return fmt.Errorf("failed to get remediation %s: %w", remList.Items[i].Name, err)
			}

			switch currentRem.Status.ApplicationState {
			case cmpv1alpha1.RemediationApplied:
				appliedCount++
			case cmpv1alpha1.RemediationError:
				errorCount++
				errorRemediations = append(
					errorRemediations,
					fmt.Sprintf("%s (Error: %s)", remList.Items[i].Name, currentRem.Status.ErrorMessage))
			case cmpv1alpha1.RemediationNeedsReview:
				needsReviewCount++
				errorRemediations = append(errorRemediations, fmt.Sprintf("%s (NeedsReview)", remList.Items[i].Name))
			case cmpv1alpha1.RemediationOutdated:
				outdatedCount++
				errorRemediations = append(errorRemediations, fmt.Sprintf("%s (Outdated)", remList.Items[i].Name))
			case cmpv1alpha1.RemediationMissingDependencies:
				missingDepCount++
			case cmpv1alpha1.RemediationNotApplied:
				pendingCount++
			case cmpv1alpha1.RemediationPending:
				pendingCount++
			default:
				pendingCount++
			}
		}

		// Only wait for NotApplied remediations - others are terminal states
		if pendingCount > 0 {
			return fmt.Errorf(
				"%d remediations still pending (Applied: %d, Error: %d, NeedsReview: %d, Outdated: %d, "+
					"MissingDependencies: %d, Pending: %d)",
				pendingCount,
				appliedCount,
				errorCount,
				needsReviewCount,
				outdatedCount,
				missingDepCount,
				pendingCount)
		}
		return nil
	}, bo, func(err error, d time.Duration) {
		log.Printf("Still waiting for remediations to be applied after %s: %s", d.String(), err)
	})
	if err != nil {
		return handleRemediationTimeout(
			c, remList, appliedCount, errorCount, needsReviewCount, outdatedCount, missingDepCount, err)
	}

	// Report final status
	log.Printf("Remediation status for suite %s: Applied=%d, Error=%d, NeedsReview=%d, Outdated=%d, Total=%d",
		suiteName, appliedCount, errorCount, needsReviewCount, outdatedCount, len(remList.Items))

	if len(errorRemediations) > 0 {
		log.Printf("%d remediations require attention:", len(errorRemediations))
		for _, errRem := range errorRemediations {
			log.Printf("   WARNING: %s", errRem)
		}
	}

	if appliedCount > 0 {
		log.Printf("Successfully applied %d remediations for suite %s", appliedCount, suiteName)
	}

	return nil
}

// RescanComplianceSuite triggers a rescan of all scans in a compliance suite.
func RescanComplianceSuite(tc *testConfig.TestConfig, c dynclient.Client, suiteName string) error {
	// Get all scans for the suite
	scanList := &cmpv1alpha1.ComplianceScanList{}
	labelSelector, err := labels.Parse(cmpv1alpha1.SuiteLabel + "=" + suiteName)
	if err != nil {
		return fmt.Errorf("failed to parse label selector: %w", err)
	}
	opts := &dynclient.ListOptions{
		LabelSelector: labelSelector,
	}
	err = c.List(goctx.TODO(), scanList, opts)
	if err != nil {
		return fmt.Errorf("failed to get scan list: %w", err)
	}

	if len(scanList.Items) == 0 {
		return fmt.Errorf("no scans found for suite %s", suiteName)
	}

	log.Printf("Triggering rescan for %d scans in suite %s", len(scanList.Items), suiteName)

	// Add rescan annotation to each scan
	for i := range scanList.Items {
		scan := &scanList.Items[i]
		key := types.NamespacedName{Name: scan.Name, Namespace: scan.Namespace}

		bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 30)
		err := backoff.RetryNotify(func() error {
			currentScan := &cmpv1alpha1.ComplianceScan{}
			err := c.Get(goctx.TODO(), key, currentScan)
			if err != nil {
				return fmt.Errorf("failed to get scan %s: %w", scan.Name, err)
			}

			// Add rescan annotation
			if currentScan.Annotations == nil {
				currentScan.Annotations = make(map[string]string)
			}
			currentScan.Annotations[cmpv1alpha1.ComplianceScanRescanAnnotation] = ""

			return c.Update(goctx.TODO(), currentScan)
		}, bo, func(err error, d time.Duration) {
			log.Printf("Failed to add rescan annotation to scan %s after %s: %s", scan.Name, d.String(), err)
		})
		if err != nil {
			return fmt.Errorf("failed to trigger rescan for scan %s: %w", scan.Name, err)
		}
		log.Printf("Triggered rescan for scan %s", scan.Name)
	}

	log.Printf("Successfully triggered rescan for all scans in suite %s", suiteName)
	return nil
}

// WaitForMachineConfigPoolsUpdated waits for all MachineConfigPools to be fully updated.
func WaitForMachineConfigPoolsUpdated(tc *testConfig.TestConfig, c dynclient.Client) error {
	// Get all MachineConfigPools
	mcpList := &mcfgv1.MachineConfigPoolList{}
	err := c.List(goctx.TODO(), mcpList)
	if err != nil {
		return fmt.Errorf("failed to list MachineConfigPools: %w", err)
	}

	if len(mcpList.Items) == 0 {
		log.Printf("No MachineConfigPools found")
		return nil
	}

	log.Printf("Waiting for %d MachineConfigPools to be fully updated", len(mcpList.Items))

	// Wait for all MCPs to be updated
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 720) // 60 minutes max
	err = backoff.RetryNotify(func() error {
		pendingPools := []string{}

		for i := range mcpList.Items {
			key := types.NamespacedName{Name: mcpList.Items[i].Name}
			currentMCP := &mcfgv1.MachineConfigPool{}
			err := c.Get(goctx.TODO(), key, currentMCP)
			if err != nil {
				return fmt.Errorf("failed to get MachineConfigPool %s: %w", mcpList.Items[i].Name, err)
			}

			// Check if the pool is fully updated
			if !isMachineConfigPoolUpdated(currentMCP) {
				pendingPools = append(pendingPools, fmt.Sprintf("%s (Updated: %d/%d, Unavailable: %d)",
					currentMCP.Name,
					currentMCP.Status.UpdatedMachineCount,
					currentMCP.Status.MachineCount,
					currentMCP.Status.UnavailableMachineCount))
			}
		}

		if len(pendingPools) > 0 {
			return fmt.Errorf("%d MachineConfigPools still updating: %v", len(pendingPools), pendingPools)
		}
		return nil
	}, bo, func(err error, d time.Duration) {
		log.Printf("Still waiting for MachineConfigPools to update after %s: %s", d.String(), err)
	})
	if err != nil {
		// On timeout, provide detailed information about pending pools
		log.Printf("Timeout reached after 60 minutes waiting for MachineConfigPools")

		pendingPools := []string{}
		for i := range mcpList.Items {
			key := types.NamespacedName{Name: mcpList.Items[i].Name}
			currentMCP := &mcfgv1.MachineConfigPool{}
			getErr := c.Get(goctx.TODO(), key, currentMCP)
			if getErr == nil && !isMachineConfigPoolUpdated(currentMCP) {
				pendingPools = append(pendingPools, fmt.Sprintf("%s (Updated: %d/%d, Unavailable: %d, Ready: %d, Degraded: %s)",
					currentMCP.Name,
					currentMCP.Status.UpdatedMachineCount,
					currentMCP.Status.MachineCount,
					currentMCP.Status.UnavailableMachineCount,
					currentMCP.Status.ReadyMachineCount,
					getBoolString(currentMCP.Status.DegradedMachineCount > 0)))
			}
		}

		if len(pendingPools) > 0 {
			log.Printf("MachineConfigPools still updating:")
			for _, poolInfo := range pendingPools {
				log.Printf("   UPDATING: %s", poolInfo)
			}
		}

		return fmt.Errorf("timed out waiting for MachineConfigPools to update: %w", err)
	}

	log.Printf("All MachineConfigPools are fully updated")
	return nil
}

// isMachineConfigPoolUpdated checks if a MachineConfigPool is fully updated.
func isMachineConfigPoolUpdated(mcp *mcfgv1.MachineConfigPool) bool {
	// Pool is updated when:
	// 1. All machines are updated (UpdatedMachineCount == MachineCount)
	// 2. No machines are unavailable (UnavailableMachineCount == 0)
	// 3. No machines are degraded (DegradedMachineCount == 0)
	return mcp.Status.UpdatedMachineCount == mcp.Status.MachineCount &&
		mcp.Status.UnavailableMachineCount == 0 &&
		mcp.Status.DegradedMachineCount == 0
}

// getBoolString converts a boolean to a string for logging.
func getBoolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// handleRemediationTimeout handles the timeout scenario when waiting for remediations to be applied.
func handleRemediationTimeout(
	c dynclient.Client,
	remList *cmpv1alpha1.ComplianceRemediationList,
	appliedCount, errorCount, needsReviewCount, outdatedCount, missingDepCount int,
	originalErr error,
) error {
	// On timeout, provide detailed information about what's still pending
	log.Printf("Timeout reached after 30 minutes waiting for remediations")
	log.Printf(
		"Final remediation status: Applied=%d, Error=%d, NeedsReview=%d, Outdated=%d, MissingDependencies=%d, Pending=%d",
		appliedCount,
		errorCount,
		needsReviewCount,
		outdatedCount,
		missingDepCount,
		len(remList.Items)-(appliedCount+errorCount+needsReviewCount+outdatedCount))

	// List all non-applied remediations for investigation
	nonAppliedRems := getNonAppliedRemediations(c, remList)

	if len(nonAppliedRems) > 0 {
		log.Printf("Remediations requiring attention:")
		for _, remInfo := range nonAppliedRems {
			log.Printf("   ATTENTION: %s", remInfo)
		}
	}

	return fmt.Errorf("timed out waiting for remediations to be applied: %w", originalErr)
}

// getNonAppliedRemediations retrieves information about remediations that are not applied.
func getNonAppliedRemediations(c dynclient.Client, remList *cmpv1alpha1.ComplianceRemediationList) []string {
	var nonAppliedRems []string
	for i := range remList.Items {
		key := types.NamespacedName{Name: remList.Items[i].Name, Namespace: remList.Items[i].Namespace}
		currentRem := &cmpv1alpha1.ComplianceRemediation{}
		getErr := c.Get(goctx.TODO(), key, currentRem)
		if getErr == nil && currentRem.Status.ApplicationState != cmpv1alpha1.RemediationApplied {
			state := string(currentRem.Status.ApplicationState)
			if currentRem.Status.ApplicationState == cmpv1alpha1.RemediationError && currentRem.Status.ErrorMessage != "" {
				nonAppliedRems = append(
					nonAppliedRems,
					fmt.Sprintf("%s (%s: %s)", remList.Items[i].Name, state, currentRem.Status.ErrorMessage))
			} else {
				nonAppliedRems = append(nonAppliedRems, fmt.Sprintf("%s (%s)", remList.Items[i].Name, state))
			}
		}
	}
	return nonAppliedRems
}

// handleRescanIfNeeded checks if a rescan is needed and handles the waiting.
func handleRescanIfNeeded(
	tc *testConfig.TestConfig,
	c dynclient.Client,
	key types.NamespacedName,
	suiteName string,
	initialSuite *cmpv1alpha1.ComplianceSuite,
) error {
	isRescan := len(initialSuite.Status.ScanStatuses) > 0
	if !isRescan {
		return nil
	}
	return handleRescanWait(tc, c, key, suiteName, initialSuite)
}

// handleRescanWait handles waiting for a rescan to start when the suite is already DONE.
func handleRescanWait(
	tc *testConfig.TestConfig,
	c dynclient.Client,
	key types.NamespacedName,
	suiteName string,
	initialSuite *cmpv1alpha1.ComplianceSuite,
) error {
	if !areAllScansComplete(initialSuite) {
		return nil // Not all scans are done, no need to wait for rescan
	}

	log.Printf("Suite %s is already DONE, waiting for rescan to start", suiteName)
	// Wait for rescan to start (suite transitions away from all DONE)
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 60) // 5 minutes
	err := backoff.RetryNotify(func() error {
		suite := &cmpv1alpha1.ComplianceSuite{}
		err := c.Get(goctx.TODO(), key, suite)
		if err != nil {
			return err
		}

		if areAllScansComplete(suite) {
			return fmt.Errorf("rescan has not started yet")
		}
		return nil
	}, bo, func(e error, ti time.Duration) {
		log.Printf("Still waiting for rescan to start after %s: %s", ti.String(), e)
	})
	if err != nil {
		return fmt.Errorf("timed out waiting for rescan to start: %w", err)
	}
	log.Printf("Rescan has started for suite %s", suiteName)
	return nil
}

// areAllScansComplete checks if all scans in a compliance suite are complete.
func areAllScansComplete(suite *cmpv1alpha1.ComplianceSuite) bool {
	for idx := range suite.Status.ScanStatuses {
		if suite.Status.ScanStatuses[idx].Phase != cmpv1alpha1.PhaseDone {
			return false
		}
	}
	return true
}

// FindPlatformProfiles finds all Profile CRDs with platform type annotation.
func FindPlatformProfiles(tc *testConfig.TestConfig, c dynclient.Client) ([]cmpv1alpha1.Profile, error) {
	profileList := &cmpv1alpha1.ProfileList{}
	err := c.List(goctx.TODO(), profileList, &dynclient.ListOptions{
		Namespace: tc.OperatorNamespace.Namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list profiles: %w", err)
	}

	var platformProfiles []cmpv1alpha1.Profile
	for i := range profileList.Items {
		profile := profileList.Items[i]
		// Check if profile has platform type annotation
		productType, exists := profile.Annotations[cmpv1alpha1.ProductTypeAnnotation]
		if exists && productType == "Platform" {
			platformProfiles = append(platformProfiles, profile)
		}
	}
	return platformProfiles, nil
}

// CreateProfileScanBinding creates a ScanSettingBinding for a given Profile.
func CreateProfileScanBinding(tc *testConfig.TestConfig, c dynclient.Client, bindingName, profileName string) error {
	return CreateScanBinding(c, tc, bindingName, profileName, "Profile", tc.E2eSettings)
}

// DeleteScanBinding deletes a ScanSettingBinding.
func DeleteScanBinding(tc *testConfig.TestConfig, c dynclient.Client, bindingName string) error {
	binding := &cmpv1alpha1.ScanSettingBinding{}
	err := c.Get(goctx.TODO(), dynclient.ObjectKey{Name: bindingName, Namespace: tc.OperatorNamespace.Namespace}, binding)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Printf("ScanSettingBinding %s not found, assuming already deleted", bindingName)
			return nil
		}
		return fmt.Errorf("failed to get ScanSettingBinding %s: %w", bindingName, err)
	}

	err = c.Delete(goctx.TODO(), binding)
	if err != nil {
		return fmt.Errorf("failed to delete ScanSettingBinding %s: %w", bindingName, err)
	}
	log.Printf("Deleted ScanSettingBinding %s", bindingName)
	return nil
}

// WaitForScanCleanup wraps the private waitForScanCleanup function.
func WaitForScanCleanup(tc *testConfig.TestConfig, c dynclient.Client, bindingName string) error {
	return waitForScanCleanup(c, tc, bindingName)
}

// ValidateProfile verifies that the specified profile exists.
func ValidateProfile(tc *testConfig.TestConfig, c dynclient.Client, profileFQN string) error {
	profile := &cmpv1alpha1.Profile{}
	err := c.Get(goctx.TODO(), dynclient.ObjectKey{Name: profileFQN, Namespace: tc.OperatorNamespace.Namespace}, profile)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("profile %s not found in namespace %s", profileFQN, tc.OperatorNamespace.Namespace)
		}
		return fmt.Errorf("failed to get profile %s: %w", profileFQN, err)
	}
	log.Printf("Found profile %s", profileFQN)
	return nil
}

// CreateResultMap creates a map of rule names to RuleTest structs from compliance check results.
func CreateResultMap(_ *testConfig.TestConfig, c dynclient.Client, suiteName string) (map[string]string, error) {
	// Get all ComplianceCheckResults for the suite
	resultList := &cmpv1alpha1.ComplianceCheckResultList{}
	labelSelector, err := labels.Parse(cmpv1alpha1.SuiteLabel + "=" + suiteName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse label selector: %w", err)
	}
	opts := &dynclient.ListOptions{
		LabelSelector: labelSelector,
	}
	err = c.List(goctx.TODO(), resultList, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance check results for suite %s: %w", suiteName, err)
	}

	// Create result map
	resultMap := make(map[string]string)
	for i := range resultList.Items {
		result := &resultList.Items[i]
		resultMap[result.Name] = string(result.Status)
	}

	log.Printf("Created result map with %d rules for suite %s", len(resultMap), suiteName)
	return resultMap, nil
}

// SaveResultAsYAML saves YAML data about the scan results to a file in the configured log directory.
func SaveResultAsYAML(tc *testConfig.TestConfig, results map[string]string, filename string) error {
	p := path.Join(tc.LogDir, filename)
	yamlData, err := yaml.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to marshal results to YAML: %w", err)
	}
	err = os.WriteFile(p, yamlData, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write YAML file: %w", err)
	}
	log.Printf("Saved YAML data to %s", p)
	return nil
}

// SaveMismatchesAsYAML saves YAML data about mismatched assertions to a file in the configured log directory.
func SaveMismatchesAsYAML(tc *testConfig.TestConfig, mismatchedAssertions []AssertionMismatch, filename string) error {
	p := path.Join(tc.LogDir, filename)
	yamlData, err := yaml.Marshal(mismatchedAssertions)
	if err != nil {
		return fmt.Errorf("failed to marshal results to YAML: %w", err)
	}
	err = os.WriteFile(p, yamlData, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write YAML file: %w", err)
	}
	log.Printf("Saved YAML data to %s", p)
	return nil
}

// GenerateMismatchReport creates a markdown report from assertion mismatches.
func GenerateMismatchReport(
	tc *testConfig.TestConfig,
	c dynclient.Client,
	mismatchedAssertions []AssertionMismatch,
	bindingName string,
) error {
	var report strings.Builder

	// Write header
	report.WriteString(fmt.Sprintf("# %s Compliance Test Results\n\n", bindingName))
	report.WriteString(fmt.Sprintf("**Test Run Date:** %s\n", time.Now().Format("2006-01-02 15:04:05 UTC")))
	report.WriteString(fmt.Sprintf("**Platform:** %s\n", tc.Platform))
	report.WriteString(fmt.Sprintf("**Version:** %s\n", tc.Version))
	report.WriteString(fmt.Sprintf("**Content Image:** %s\n\n", tc.ContentImage))

	// Summary section
	report.WriteString("## Summary\n\n")
	report.WriteString(fmt.Sprintf("**Total Assertion Failures:** %d\n\n", len(mismatchedAssertions)))

	// Detailed failures section
	report.WriteString("## Detailed Failures\n\n")

	for i, mismatch := range mismatchedAssertions {
		report.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, mismatch.CheckResultName))

		ruleName, err := getRuleNameFromResultName(tc, c, mismatch.CheckResultName)
		if err == nil {
			// Convert rule name to regex pattern that matches both - and _ characters
			rulePattern := convertRuleNameToRegex(ruleName)
			rulePath, found := findRulePath(tc, rulePattern)
			if found {
				relativePath := path.Join(strings.TrimPrefix(rulePath, tc.ContentDir+"/"), "rule.yml")
				link := fmt.Sprintf(upstreamRepo, relativePath)
				report.WriteString(fmt.Sprintf("- **Rule Source:** [%s](%s)\n", ruleName, link))
			}
		}

		report.WriteString(fmt.Sprintf("- **Expected Result:** `%v`\n", mismatch.ExpectedResult))
		report.WriteString(fmt.Sprintf("- **Actual Result:** `%s`\n", mismatch.ActualResult))

		if mismatch.ErrorMessage != "" {
			report.WriteString(fmt.Sprintf("- **Error Details:** %s\n", mismatch.ErrorMessage))
		}
		report.WriteString("\n")
	}

	f := fmt.Sprintf("%s-report.md", bindingName)
	p := path.Join(tc.LogDir, f)

	err := os.WriteFile(p, []byte(report.String()), 0o600)
	if err != nil {
		return fmt.Errorf("failed to write markdown report: %w", err)
	}

	log.Printf("Generated compliance report: %s", p)

	// Convert markdown to HTML and save
	htmlContent := convertMarkdownToHTML(report.String())
	htmlFilename := fmt.Sprintf("%s-report.html", bindingName)
	htmlFilePath := path.Join(tc.LogDir, htmlFilename)

	err = os.WriteFile(htmlFilePath, []byte(htmlContent), 0o600)
	if err != nil {
		return fmt.Errorf("failed to write HTML report: %w", err)
	}

	log.Printf("Generated HTML compliance report: %s", htmlFilePath)
	return nil
}

func convertMarkdownToHTML(markdown string) string {
	html := markdown

	// Convert headers BEFORE converting newlines
	html = regexp.MustCompile(`(?m)^# (.+)$`).ReplaceAllString(html, "<h1>$1</h1>")
	html = regexp.MustCompile(`(?m)^## (.+)$`).ReplaceAllString(html, "<h2>$1</h2>")
	html = regexp.MustCompile(`(?m)^### (.+)$`).ReplaceAllString(html, "<h3>$1</h3>")

	// Convert bullet points BEFORE converting newlines
	html = regexp.MustCompile(`(?m)^- (.+)$`).ReplaceAllString(html, "<li>$1</li>")

	// Convert bold text
	html = regexp.MustCompile(`\*\*(.+?)\*\*`).ReplaceAllString(html, "<strong>$1</strong>")

	// Convert code blocks
	html = regexp.MustCompile("`(.+?)`").ReplaceAllString(html, "<code>$1</code>")

	// Convert links
	html = regexp.MustCompile(`\[(.+?)\]\((.+?)\)`).ReplaceAllString(html, `<a href="$2">$1</a>`)

	// Convert newlines to <br> AFTER other conversions
	// html = strings.ReplaceAll(html, "\n", "<br>\n")

	// Wrap in basic HTML structure
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #333; }
        code { background-color: #f4f4f4; padding: 2px 4px; }
        li { margin: 5px 0; }
    </style>
</head>
<body>
%s
</body>
</html>`, html)
}
