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
	"path"
	"strings"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	cmpapis "github.com/openshift/compliance-operator/pkg/apis"
	cmpv1alpha1 "github.com/openshift/compliance-operator/pkg/apis/compliance/v1alpha1"
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

// createScanBinding creates a ScanSettingBinding for the given tailored profile.
func createScanBinding(c dynclient.Client, tc *testConfig.TestConfig, bindingName, profileName string) error {
	binding := &cmpv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
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
				Name:     profileName,
			},
		},
	}

	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 180)
	err := backoff.RetryNotify(func() error {
		return c.Create(goctx.TODO(), binding)
	}, bo, func(err error, d time.Duration) {
		fmt.Printf("Couldn't create %s binding after %s: %s\n", bindingName, d.String(), err)
	})
	if err != nil {
		return fmt.Errorf("failed to create %s scan binding: %w", bindingName, err)
	}
	return nil
}

// CreatePlatformScanBinding creates a ScanSettingBinding for the platform rules.
func CreatePlatformScanBinding(tc *testConfig.TestConfig, c dynclient.Client) error {
	return createScanBinding(c, tc, "platform-scan-binding", "platform")
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
	// If a scan takes longer than 30 minutes to spin up and finish,
	// something else is likely interfering or causing issues.
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 360)

	err := backoff.RetryNotify(func() error {
		suite := &cmpv1alpha1.ComplianceSuite{}
		err := c.Get(goctx.TODO(), key, suite)
		if err != nil {
			// Returning an error merely makes this retry after the interval
			return err
		}
		if len(suite.Status.ScanStatuses) == 0 {
			return fmt.Errorf("no statuses available yet")
		}
		for idx := range suite.Status.ScanStatuses {
			scanstatus := &suite.Status.ScanStatuses[idx]
			if scanstatus.Phase != cmpv1alpha1.PhaseDone {
				// Returning an error merely makes this retry after the interval
				return fmt.Errorf("suite %s is %s", suiteName, suite.Status.Phase)
			}
			if scanstatus.Result == cmpv1alpha1.ResultError {
				// If there was an error, we can stop already.
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

// verifyScanResults verifies the results of a scan against expected assertions.
func verifyScanResults(tc *testConfig.TestConfig, c dynclient.Client, suiteName, scanType string) error {
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
		return fmt.Errorf("failed to get compliance check results for suite %s: %w", suiteName, err)
	}

	assertScanResults(tc, resultList, scanType)
	return nil
}

// verifyPlatformScanResults verifies the results of the platform scan against expected assertions.
func VerifyPlatformScanResults(tc *testConfig.TestConfig, c dynclient.Client, suiteName string) error {
	return verifyScanResults(tc, c, suiteName, "platform")
}

// verifyNodeScanResults verifies the results of the node scan against expected assertions.
func VerifyNodeScanResults(tc *testConfig.TestConfig, c dynclient.Client, suiteName string) error {
	return verifyScanResults(tc, c, suiteName, "node")
}

// assertScanResults verifies scan results against expected assertions from YAML files.
func assertScanResults(tc *testConfig.TestConfig, resultList *cmpv1alpha1.ComplianceCheckResultList, scanType string) {
	// For scan assertions, we use the simple file naming convention
	assertionFile := fmt.Sprintf("%s-%s-%s-rule-assertions.yaml", tc.Platform, tc.Version, scanType)
	assertResultsWithFileGeneration(tc, resultList, assertionFile, false)
}

// assertResultsWithFileGeneration is a consolidated function that handles both
// profile and scan assertions It can load existing assertion files, verify
// results against them, and print assertion content to stdout when files don't
// exist.
func assertResultsWithFileGeneration(
	_ *testConfig.TestConfig,
	resultList *cmpv1alpha1.ComplianceCheckResultList,
	assertionFile string,
	afterRemediations bool,
) {
	// Try to load existing assertions
	assertions, err := loadAssertionsFromPath(assertionFile)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, print assertion content to stdout
			log.Printf("No assertion file found, printing assertion content to stdout: %s", assertionFile)
			err = generateAssertionFile(resultList, assertionFile, afterRemediations)
			if err != nil {
				log.Printf("Failed to generate assertion file: %s", err)
			}
			return
		}
		log.Printf("Error loading assertion file %s: %s", assertionFile, err)
		return
	}

	// File exists, verify results against assertions
	verifyResultsAgainstAssertions(resultList, assertions, afterRemediations)
}

// loadAssertionsFromPath loads rule assertions from a specific file path.
func loadAssertionsFromPath(filePath string) (*RuleTestResults, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var assertions RuleTestResults
	err = yaml.Unmarshal(data, &assertions)
	if err != nil {
		return nil, fmt.Errorf("could not parse assertion file %s: %w", filePath, err)
	}

	return &assertions, nil
}

// verifyResultsAgainstAssertions verifies scan results against expected assertions.
func verifyResultsAgainstAssertions(
	resultList *cmpv1alpha1.ComplianceCheckResultList,
	assertions *RuleTestResults,
	_ bool,
) {
	// Create a map of results by rule name for easy lookup
	resultMap := make(map[string]*cmpv1alpha1.ComplianceCheckResult)
	for i := range resultList.Items {
		result := &resultList.Items[i]
		ruleName := getRuleNameFromResult(result)
		resultMap[ruleName] = result
	}

	// Verify each expected assertion
	for ruleName, expectedTest := range assertions.RuleResults {
		result, exists := resultMap[ruleName]
		if !exists {
			log.Printf("Expected rule result for %s not found in scan results", ruleName)
			continue
		}

		// Verify default result
		if expectedTest.DefaultResult != nil {
			err := verifyRuleResult(result, expectedTest.DefaultResult, expectedTest, ruleName, "default")
			if err != nil {
				log.Printf("Rule %s failed default result verification: %s", ruleName, err)
			}
		}

		// Verify result after remediation if specified
		if expectedTest.ResultAfterRemediation != nil {
			err := verifyRuleResult(result, expectedTest.ResultAfterRemediation, expectedTest, ruleName, "after remediation")
			if err != nil {
				log.Printf("Rule %s failed after remediation result verification: %s", ruleName, err)
			}
		}
	}

	log.Printf(
		"Verified %d rule results against assertions (total rules in results: %d)",
		len(assertions.RuleResults),
		len(resultList.Items),
	)
}

// getRuleNameFromResult extracts the rule name from a compliance check result.
func getRuleNameFromResult(result *cmpv1alpha1.ComplianceCheckResult) string {
	// Try to get rule name from annotation first
	if ruleName, exists := result.Annotations[cmpv1alpha1.ComplianceCheckResultRuleAnnotation]; exists {
		return ruleName
	}

	// Fallback to extracting from result name
	// Remove scan prefix and convert to rule name format
	resultName := result.Name
	resultLabels := result.GetLabels()
	if prefix, exists := resultLabels[cmpv1alpha1.ComplianceScanLabel]; exists {
		if strings.HasPrefix(resultName, prefix) {
			// Remove prefix and convert dashes to underscores
			ruleName := resultName[len(prefix)+1:] // +1 for the dash
			return strings.ReplaceAll(ruleName, "-", "_")
		}
	}

	return resultName
}

func verifyRuleResult(
	foundResult *cmpv1alpha1.ComplianceCheckResult,
	expectedResult interface{},
	testDef RuleTest,
	ruleName string,
	phase string,
) error {
	if matches, err := matchFoundResultToExpectation(foundResult, expectedResult); !matches || err != nil {
		if err != nil {
			return fmt.Errorf("E2E-ERROR: The e2e YAML for rule '%s' is malformed: %v . Got error: %w", ruleName, testDef, err)
		}
		return fmt.Errorf("E2E-FAILURE: The expected %s result for the %s rule didn't match. Expected '%s', Got '%s'",
			phase, ruleName, expectedResult, foundResult.Status)
	}
	return nil
}

func matchFoundResultToExpectation(
	foundResult *cmpv1alpha1.ComplianceCheckResult, expectedResult interface{},
) (bool, error) {
	// Handle expected result for all roles
	if resultStr, ok := expectedResult.(string); ok {
		p, perr := resultparser.ParseRoleResultEval(resultStr)
		if perr != nil {
			return false, fmt.Errorf("error parsing result evaluator: %w", perr)
		}
		return p.Eval(string(foundResult.Status)), nil
	}
	// Handle role-specific result
	if resultMap, ok := expectedResult.(map[interface{}]interface{}); ok {
		for rawRole, rawRoleResult := range resultMap {
			role, ok := rawRole.(string)
			if !ok {
				return false, fmt.Errorf("couldn't parse the result as string or map of strings")
			}
			roleResult, ok := rawRoleResult.(string)
			if !ok {
				return false, fmt.Errorf("couldn't parse the result as string or map of strings")
			}
			p, perr := resultparser.ParseRoleResultEval(roleResult)
			if perr != nil {
				return false, fmt.Errorf("error parsing result evaluator: %w", perr)
			}
			// NOTE(jaosorior): Normally, the results will have a reference
			// to the role they apply to in the name. This is hacky...
			if strings.Contains(foundResult.GetLabels()[cmpv1alpha1.ComplianceScanLabel], role) {
				return p.Eval(string(foundResult.Status)), nil
			}
		}
		return false, fmt.Errorf("the role specified in the test doesn't match an existing role")
	}
	return false, fmt.Errorf("couldn't parse the result as string or map")
}

// generateAssertionFile prints assertion content to stdout for the current test results.
func generateAssertionFile(
	resultList *cmpv1alpha1.ComplianceCheckResultList,
	filePath string,
	afterRemediations bool,
) error {
	// Generate assertions from current results
	assertions := &RuleTestResults{
		RuleResults: make(map[string]RuleTest),
	}

	for i := range resultList.Items {
		result := &resultList.Items[i]
		ruleName := getRuleNameFromResult(result)

		ruleTest := assertions.RuleResults[ruleName]
		if !afterRemediations {
			ruleTest.DefaultResult = string(result.Status)
		} else {
			ruleTest.ResultAfterRemediation = string(result.Status)
		}
		assertions.RuleResults[ruleName] = ruleTest
	}

	// Marshal to YAML
	data, err := yaml.Marshal(assertions)
	if err != nil {
		return fmt.Errorf("failed to marshal assertion content: %w", err)
	}

	// Print to stdout instead of writing to file
	log.Printf("=== ASSERTION FILE CONTENT FOR: %s ===", filePath)
	fmt.Printf("%s", string(data))
	log.Printf("=== END ASSERTION FILE CONTENT ===")
	log.Printf("Copy the above content to create: %s", filePath)
	log.Printf(
		"Generated assertions for %d rules (total rules in results: %d)",
		len(assertions.RuleResults),
		len(resultList.Items),
	)
	return nil
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
	var appliedCount, errorCount, needsReviewCount, outdatedCount int

	// Wait for each remediation to be applied
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(tc.APIPollInterval), 360) // 30 minutes max
	err = backoff.RetryNotify(func() error {
		pendingCount := 0
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
			case cmpv1alpha1.RemediationNotApplied, cmpv1alpha1.RemediationPending, cmpv1alpha1.RemediationMissingDependencies:
				pendingCount++
			default:
				pendingCount++
			}
		}

		// Only wait for NotApplied remediations - others are terminal states
		if pendingCount > 0 {
			return fmt.Errorf(
				"%d remediations still pending (Applied: %d, Error: %d, NeedsReview: %d, Outdated: %d, Pending: %d)",
				pendingCount, appliedCount, errorCount, needsReviewCount, outdatedCount, pendingCount)
		}
		return nil
	}, bo, func(err error, d time.Duration) {
		log.Printf("Still waiting for remediations to be applied after %s: %s", d.String(), err)
	})
	if err != nil {
		return fmt.Errorf("timed out waiting for remediations to be applied: %w", err)
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
