package ocp4e2e

import (
	"bufio"
	goctx "context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"testing"
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
	"k8s.io/client-go/rest"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/ComplianceAsCode/ocp4e2e/resultparser"
)

const (
	namespacePath             = "compliance-operator-ns.yaml"
	catalogSourcePath         = "compliance-operator-catalog-source.yaml"
	operatorGroupPath         = "compliance-operator-operator-group.yaml"
	subscriptionPath          = "compliance-operator-alpha-subscription.yaml"
	rosaSubscriptionPath      = "compliance-operator-rosa-subscription.yaml"
	apiPollInterval           = 5 * time.Second
	testProfilebundleName     = "e2e"
	e2eSettingsName           = "e2e-debug"
	manualRemediationsTimeout = 60 * time.Minute
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

var (
	product            string
	profile            string
	platform           string
	contentImage       string
	installOperator    bool
	bypassRemediations bool
	testType           string
)

type e2econtext struct {
	// These are public because they're needed in the template
	Profile                string
	ContentImage           string
	OperatorNamespacedName types.NamespacedName
	// These are only needed for the test and will only be used in this package
	rootdir            string
	profilepath        string
	product            string
	platform           string
	resourcespath      string
	benchmarkRoot      string
	version            string
	installOperator    bool
	bypassRemediations bool
	testType           string
	dynclient          dynclient.Client
	kubecfg            *rest.Config
	// New fields for refactored test suite
	platformRules []cmpv1alpha1.Rule
	nodeRules     []cmpv1alpha1.Rule
}

func init() {
	flag.StringVar(&profile, "profile", "", "The profile to check")
	flag.StringVar(&product, "product", "", "The product this profile is for - e.g. 'rhcos4', 'ocp4'")
	flag.StringVar(&platform, "platform", "ocp4", "The platform that the tests are running on - e.g. 'ocp4', 'rosa'")
	flag.StringVar(&contentImage, "content-image", "", "The path to the image with the content to test")
	flag.BoolVar(&installOperator, "install-operator", true, "Should the test-code install the operator or not? "+
		"This is useful if you need to test with your own deployment of the operator")
	flag.BoolVar(&bypassRemediations, "bypass-remediations", false,
		"Do not apply remedations and summarize results after the first scan")
	flag.StringVar(&testType, "test-type", "all", "Type of rules to test: 'platform', 'node', or 'all' (default)")
}

func newE2EContext(t *testing.T) *e2econtext {
	rootdir := os.Getenv("ROOT_DIR")
	if rootdir == "" {
		var cloneErr error
		rootdir, cloneErr = cloneContentDir()
		if cloneErr != nil {
			t.Fatalf("Unable to clone content dir: %s", cloneErr)
		}
		os.Setenv("ROOT_DIR", rootdir)
	}

	profilefile := fmt.Sprintf("%s.profile", profile)
	productpath, benchmarkRoot, err := getBenchmarkRootFromProductSpec(rootdir, product)
	if err != nil {
		t.Fatal(err)
	}
	profilepath := path.Join(productpath, "profiles", profilefile)
	resourcespath := path.Join(rootdir, "ocp-resources")

	return &e2econtext{
		Profile:                profile,
		ContentImage:           contentImage,
		OperatorNamespacedName: types.NamespacedName{Name: "compliance-operator"},
		rootdir:                rootdir,
		profilepath:            profilepath,
		resourcespath:          resourcespath,
		benchmarkRoot:          benchmarkRoot,
		product:                product,
		platform:               platform,
		installOperator:        installOperator,
		bypassRemediations:     bypassRemediations,
		testType:               testType,
	}
}

func cloneContentDir() (string, error) {
	dir, tmperr := ioutil.TempDir("", "content-*")
	if tmperr != nil {
		return "", fmt.Errorf("couldn't create tmpdir: %w", tmperr)
	}
	ctx := goctx.Background()
	_, cmderr := exec.CommandContext(ctx, "/usr/bin/git", "clone",
		"https://github.com/ComplianceAsCode/content.git", dir).CombinedOutput()
	if cmderr != nil {
		return "", fmt.Errorf("couldn't clone content: %w", cmderr)
	}
	return dir, nil
}

func getBenchmarkRootFromProductSpec(rootdir, product string) (baseProductPath, benchmarkPath string, benchErr error) {
	productpath := path.Join(rootdir, product)
	benchmarkRelative := struct {
		Path string `yaml:"benchmark_root"`
	}{}

	prodyamlpath := path.Join(productpath, "product.yml")
	buf, err := ioutil.ReadFile(prodyamlpath)
	if err != nil && os.IsNotExist(err) {
		productpath = path.Join(rootdir, "products", product)
		prodyamlpath = path.Join(productpath, "product.yml")
		buf, err = ioutil.ReadFile(prodyamlpath)
	}

	// Catches either error
	if err != nil {
		return "", "", err
	}

	err = yaml.Unmarshal(buf, &benchmarkRelative)
	if err != nil {
		return "", "", fmt.Errorf("couldn't parse file %q: %w", prodyamlpath, err)
	}
	return productpath, path.Join(productpath, benchmarkRelative.Path), nil
}

func (ctx *e2econtext) assertRootdir(t *testing.T) {
	t.Helper()
	dirinfo, err := os.Stat(ctx.rootdir)
	if os.IsNotExist(err) {
		t.Fatal("$ROOT_DIR points to an unexistent directory")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !dirinfo.IsDir() {
		t.Fatal("$ROOT_DIR must be a directory")
	}
}

func (ctx *e2econtext) assertProfile(t *testing.T) {
	t.Helper()
	if ctx.Profile == "" {
		t.Fatal("a profile must be given with the `-profile` flag")
	}
	_, err := os.Stat(ctx.profilepath)
	if os.IsNotExist(err) {
		t.Fatalf("The profile path %s points to an unexistent file", ctx.profilepath)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func (ctx *e2econtext) assertContentImage(t *testing.T) {
	t.Helper()
	if ctx.ContentImage == "" {
		t.Fatal("A content image must be provided with the `-content-image` flag")
	}
}

func (ctx *e2econtext) assertKubeClient(t *testing.T) {
	t.Helper()
	// Get a config to talk to the apiserver
	cfg, err := config.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	ctx.kubecfg = cfg

	// create dynamic client
	scheme := runtime.NewScheme()
	if err := cgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add cgo scheme to runtime scheme: %s", err)
	}
	if err := extscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add api extensions scheme to runtime scheme: %s", err)
	}
	if err := cmpapis.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add cmpliance scheme to runtime scheme: %s", err)
	}
	if err := mcfg.Install(scheme); err != nil {
		t.Fatalf("failed to add MachineConfig scheme to runtime scheme: %s", err)
	}

	ctx.dynclient, err = dynclient.New(ctx.kubecfg, dynclient.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("failed to build the dynamic client: %s", err)
	}
}

func (ctx *e2econtext) assertVersion(t *testing.T) {
	t.Helper()
	// TODO(jaosorior): Make this pluggable (we might want to use
	//                  kubectl instead in the future)
	rawversion, err := exec.CommandContext(goctx.Background(), "oc", "version").Output()
	if err != nil {
		t.Fatalf("E2E-FAILURE: failed get cluster version: %s", err)
	}

	r := regexp.MustCompile(`Server Version: ([1-9]\.[0-9]+)\..*`)
	matches := r.FindSubmatch(rawversion)

	if len(matches) < 2 {
		t.Fatalf("E2E-FAILURE: Couldn't get server version from output: %s", rawversion)
	}
	ctx.version = string(matches[1])
}

// Makes sure that the namespace where the test will run exists. Doesn't fail
// if it already does.
func (ctx *e2econtext) ensureNamespaceExistsAndSet(t *testing.T) {
	manifestpath := path.Join(ctx.resourcespath, namespacePath)
	obj := ctx.ensureObjectExists(t, manifestpath)
	// Ensures that we don't depend on a specific namespace in the code,
	// but we can instead change the namespace depending on the resource
	// file
	ctx.OperatorNamespacedName.Namespace = obj.GetName()
}

func (ctx *e2econtext) ensureCatalogSourceExists(t *testing.T) {
	manifestpath := path.Join(ctx.resourcespath, catalogSourcePath)
	ctx.ensureObjectExists(t, manifestpath)
}

func (ctx *e2econtext) ensureOperatorGroupExists(t *testing.T) {
	manifestpath := path.Join(ctx.resourcespath, operatorGroupPath)
	ctx.ensureObjectExists(t, manifestpath)
}

func (ctx *e2econtext) ensureSubscriptionExists(t *testing.T) {
	var manifestpath string
	// We need to modify the default deployment through the subscription if
	// we're dealing with a ROSA cluster because we only have worker nodes
	// available to run the operator. If we don't do this, the deployment
	// will spin waiting for master nodes to schedule the operator on.
	if ctx.platform == "rosa" {
		manifestpath = path.Join(ctx.resourcespath, rosaSubscriptionPath)
	} else {
		manifestpath = path.Join(ctx.resourcespath, subscriptionPath)
	}
	ctx.ensureObjectExists(t, manifestpath)
}

// Makes sure that an object from the given file path exists in the cluster.
// If this already exists, this is not an issue.
// Note that this assumes that the object's manifest already contains
// the Namespace reference.
// If all went well, this will return the reference to the object that was created.
func (ctx *e2econtext) ensureObjectExists(t *testing.T, mpath string) *unstructured.Unstructured {
	obj, err := readObjFromYAMLFilePath(mpath)
	if err != nil {
		t.Fatalf("failed to decode object from '%s' spec: %s", mpath, err)
	}

	err = ctx.dynclient.Create(goctx.TODO(), obj)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("failed to create object from '%s': %s", mpath, err)
	}

	return obj
}

func (ctx *e2econtext) waitForOperatorToBeReady(t *testing.T) {
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(apiPollInterval), 30)

	retryFunc := func() error {
		od := &appsv1.Deployment{}
		err := ctx.dynclient.Get(goctx.TODO(), ctx.OperatorNamespacedName, od)
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
		// TODO(jaosorior): Change this for a log call
		fmt.Printf("Operator deployment not ready after %s: %s\n", d.String(), err)
	}

	err := backoff.RetryNotify(retryFunc, bo, notifyFunc)
	if err != nil {
		t.Fatalf("Operator deployment was never created: %s", err)
	}
}

func (ctx *e2econtext) ensureTestProfileBundle(t *testing.T) {
	key := types.NamespacedName{
		Name:      testProfilebundleName,
		Namespace: ctx.OperatorNamespacedName.Namespace,
	}
	pb := &cmpv1alpha1.ProfileBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testProfilebundleName,
			Namespace: ctx.OperatorNamespacedName.Namespace,
		},
		Spec: cmpv1alpha1.ProfileBundleSpec{
			ContentImage: ctx.ContentImage,
			ContentFile:  fmt.Sprintf("ssg-%s-ds.xml", ctx.product),
		},
	}

	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(apiPollInterval), 180)
	err := backoff.RetryNotify(func() error {
		found := &cmpv1alpha1.ProfileBundle{}
		if err := ctx.dynclient.Get(goctx.TODO(), key, found); err != nil {
			if apierrors.IsNotFound(err) {
				return ctx.dynclient.Create(goctx.TODO(), pb)
			}
			return err
		}
		// Update the spec in case it differs
		found.Spec = pb.Spec
		return ctx.dynclient.Update(goctx.TODO(), found)
	}, bo, func(err error, d time.Duration) {
		fmt.Printf("Couldn't ensure test PB exists after %s: %s\n", d.String(), err)
	})
	if err != nil {
		t.Fatalf("failed to ensure test PB: %s", err)
	}
}

func (ctx *e2econtext) waitForValidTestProfileBundle(t *testing.T) {
	key := types.NamespacedName{
		Name:      testProfilebundleName,
		Namespace: ctx.OperatorNamespacedName.Namespace,
	}

	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(apiPollInterval), 180)
	err := backoff.RetryNotify(func() error {
		found := &cmpv1alpha1.ProfileBundle{}
		if err := ctx.dynclient.Get(goctx.TODO(), key, found); err != nil {
			return err
		}
		if found.Status.DataStreamStatus != cmpv1alpha1.DataStreamValid {
			return fmt.Errorf("%s ProfileBundle is in %s state", found.Name, found.Status.DataStreamStatus)
		}
		return nil
	}, bo, func(err error, _ time.Duration) {
		fmt.Printf("waiting for ProfileBundle to parse: %s\n", err)
	})
	if err != nil {
		t.Fatalf("failed to ensure test PB: %s", err)
	}
}

func (ctx *e2econtext) ensureTestSettings(t *testing.T) {
	defaultkey := types.NamespacedName{
		Name:      "default",
		Namespace: ctx.OperatorNamespacedName.Namespace,
	}
	defaultSettings := &cmpv1alpha1.ScanSetting{}

	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(apiPollInterval), 180)

	err := backoff.RetryNotify(func() error {
		return ctx.dynclient.Get(goctx.TODO(), defaultkey, defaultSettings)
	}, bo, func(err error, d time.Duration) {
		fmt.Printf("Couldn't get default scanSettings after %s: %s\n", d.String(), err)
	})
	if err != nil {
		t.Fatalf("failed to get default scanSettings: %s", err)
	}

	// Ensure auto-apply
	key := types.NamespacedName{
		Name:      e2eSettingsName,
		Namespace: ctx.OperatorNamespacedName.Namespace,
	}
	autoApplySettings := defaultSettings.DeepCopy()
	// Delete Object Meta so we reset unwanted references
	autoApplySettings.ObjectMeta = metav1.ObjectMeta{
		Name:      e2eSettingsName,
		Namespace: ctx.OperatorNamespacedName.Namespace,
	}
	if !ctx.bypassRemediations {
		autoApplySettings.AutoApplyRemediations = true
	}
	autoApplySettings.ShowNotApplicable = true // so that we can test if a setting goes from PASS/FAIL to N/A
	err = backoff.RetryNotify(func() error {
		found := &cmpv1alpha1.ScanSetting{}
		if err := ctx.dynclient.Get(goctx.TODO(), key, found); err != nil {
			if apierrors.IsNotFound(err) {
				return ctx.dynclient.Create(goctx.TODO(), autoApplySettings)
			}
			return err
		}
		// Copy references to enable updating object
		found.ObjectMeta.DeepCopyInto(&autoApplySettings.ObjectMeta)
		return ctx.dynclient.Update(goctx.TODO(), autoApplySettings)
	}, bo, func(err error, d time.Duration) {
		fmt.Printf("Couldn't ensure auto-apply scansettings after %s: %s\n", d.String(), err)
	})
	if err != nil {
		t.Fatalf("failed to ensure auto-apply scanSettings: %s", err)
	}
}

func (ctx *e2econtext) setPoolRollingPolicy(t *testing.T) error {
	mcfgpools := &mcfgv1.MachineConfigPoolList{}
	if err := ctx.dynclient.List(goctx.TODO(), mcfgpools); err != nil {
		return fmt.Errorf("error get MCP list: %w", err)
	}

	for i := range mcfgpools.Items {
		pool := &mcfgpools.Items[i]

		if strings.Contains(pool.Name, "master") {
			continue
		}

		if pool.Spec.MaxUnavailable == nil {
			t.Logf("Setting pool %s Rolling Policy", pool.Name)
			maxUnavailable := intstr.FromInt(2)
			pool.Spec.MaxUnavailable = &maxUnavailable
			if err := ctx.dynclient.Update(goctx.TODO(), pool); err != nil {
				return fmt.Errorf("error update MCP list MaxUnavailable: %w", err)
			}
		}
	}
	return nil
}

func (ctx *e2econtext) waitForComplianceSuite(t *testing.T, suiteName string) {
	key := types.NamespacedName{Name: suiteName, Namespace: ctx.OperatorNamespacedName.Namespace}
	// If a scan takes longer than 30 minutes to spin up and finish,
	// something else is likely interfering or causing issues.
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(apiPollInterval), 360)

	err := backoff.RetryNotify(func() error {
		suite := &cmpv1alpha1.ComplianceSuite{}
		err := ctx.dynclient.Get(goctx.TODO(), key, suite)
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
				t.Fatalf("There was an unexpected error in the scan '%s': %s",
					scanstatus.Name, scanstatus.ErrorMessage)
			}
		}
		return nil
	}, bo, func(e error, _ time.Duration) {
		t.Logf("ComplianceSuite %s is not DONE: %s", suiteName, e)
	})
	if err != nil {
		t.Fatalf("The Compliance Suite '%s' didn't get to DONE phase: %s", key.Name, err)
	}
	t.Logf("ComplianceSuite %s is DONE", suiteName)
}

// assertResultsWithFileGeneration is a consolidated function that handles both profile and scan assertions
// It can load existing assertion files, verify results against them, and print assertion content to stdout
// when files don't exist.
func (ctx *e2econtext) assertResultsWithFileGeneration(
	t *testing.T,
	resultList *cmpv1alpha1.ComplianceCheckResultList,
	assertionFile string,
	afterRemediations bool,
) {
	// Try to load existing assertions
	assertions, err := ctx.loadAssertionsFromPath(assertionFile)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, print assertion content to stdout
			t.Logf("No assertion file found, printing assertion content to stdout: %s", assertionFile)
			ctx.generateAssertionFile(t, resultList, assertionFile, afterRemediations)
			return
		}
		t.Logf("Error loading assertion file %s: %s", assertionFile, err)
		return
	}

	// File exists, verify results against assertions
	ctx.verifyResultsAgainstAssertions(t, resultList, assertions, afterRemediations)
}

// loadAssertionsFromPath loads rule assertions from a specific file path.
func (ctx *e2econtext) loadAssertionsFromPath(filePath string) (*RuleTestResults, error) {
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

// generateAssertionFile prints assertion content to stdout for the current test results.
func (ctx *e2econtext) generateAssertionFile(
	t *testing.T,
	resultList *cmpv1alpha1.ComplianceCheckResultList,
	filePath string,
	afterRemediations bool,
) {
	// Generate assertions from current results
	assertions := &RuleTestResults{
		RuleResults: make(map[string]RuleTest),
	}

	for i := range resultList.Items {
		result := &resultList.Items[i]
		ruleName := ctx.getRuleNameFromResult(result)

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
		t.Logf("Failed to marshal assertion content: %s", err)
		return
	}

	// Print to stdout instead of writing to file
	t.Logf("=== ASSERTION FILE CONTENT FOR: %s ===", filePath)
	fmt.Printf("%s", string(data))
	t.Logf("=== END ASSERTION FILE CONTENT ===")
	t.Logf("Copy the above content to create: %s", filePath)
}

// verifyResultsAgainstAssertions verifies scan results against expected assertions.
func (ctx *e2econtext) verifyResultsAgainstAssertions(
	t *testing.T,
	resultList *cmpv1alpha1.ComplianceCheckResultList,
	assertions *RuleTestResults,
	_ bool,
) {
	// Create a map of results by rule name for easy lookup
	resultMap := make(map[string]*cmpv1alpha1.ComplianceCheckResult)
	for i := range resultList.Items {
		result := &resultList.Items[i]
		ruleName := ctx.getRuleNameFromResult(result)
		resultMap[ruleName] = result
	}

	// Verify each expected assertion
	for ruleName, expectedTest := range assertions.RuleResults {
		result, exists := resultMap[ruleName]
		if !exists {
			t.Errorf("Expected rule result for %s not found in scan results", ruleName)
			continue
		}

		// Verify default result
		if expectedTest.DefaultResult != nil {
			err := verifyRuleResult(result, expectedTest.DefaultResult, expectedTest, ruleName, "default")
			if err != nil {
				t.Errorf("Rule %s failed default result verification: %s", ruleName, err)
			}
		}

		// Verify result after remediation if specified
		if expectedTest.ResultAfterRemediation != nil {
			err := verifyRuleResult(result, expectedTest.ResultAfterRemediation, expectedTest, ruleName, "after remediation")
			if err != nil {
				t.Errorf("Rule %s failed after remediation result verification: %s", ruleName, err)
			}
		}
	}

	t.Logf("Verified %d rule results against assertions", len(assertions.RuleResults))
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

// findAndCategorizeRules finds all Rule custom resources and categorizes them into Platform and Node rules.
func (ctx *e2econtext) findAndCategorizeRules(t *testing.T) (platformRules, nodeRules []cmpv1alpha1.Rule) {
	ruleList := &cmpv1alpha1.RuleList{}
	err := ctx.dynclient.List(goctx.TODO(), ruleList)
	if err != nil {
		t.Fatalf("Failed to list rules: %s", err)
	}

	for i := range ruleList.Items {
		rule := &ruleList.Items[i]
		switch rule.CheckType {
		case cmpv1alpha1.CheckTypePlatform:
			platformRules = append(platformRules, *rule)
		case cmpv1alpha1.CheckTypeNode:
			nodeRules = append(nodeRules, *rule)
		default:
			t.Logf("Skipping rule %s with unknown check type: %s", rule.Name, rule.CheckType)
		}
	}

	return platformRules, nodeRules
}

// createTailoredProfile creates a TailoredProfile with the given rules.
func (ctx *e2econtext) createTailoredProfile(t *testing.T, name string, rules []cmpv1alpha1.Rule) {
	ruleRefs := make([]cmpv1alpha1.RuleReferenceSpec, len(rules))
	for i := range rules {
		ruleRefs[i] = cmpv1alpha1.RuleReferenceSpec{
			Name: rules[i].Name,
		}
	}

	description := fmt.Sprintf("Tailored profile containing all %s rules", name)
	tailoredProfile := &cmpv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ctx.OperatorNamespacedName.Namespace,
		},
		Spec: cmpv1alpha1.TailoredProfileSpec{
			Description: description,
			EnableRules: ruleRefs,
			Title:       name,
		},
	}

	err := ctx.dynclient.Create(goctx.TODO(), tailoredProfile)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("Failed to create %s tailored profile: %s", name, err)
	}
	t.Logf("Created %s tailored profile with %d rules", name, len(rules))
}

// createPlatformTailoredProfile creates a TailoredProfile with all platform rules.
func (ctx *e2econtext) createPlatformTailoredProfile(t *testing.T) {
	ctx.createTailoredProfile(t, "platform", ctx.platformRules)
}

// createNodeTailoredProfile creates a TailoredProfile with all node rules.
func (ctx *e2econtext) createNodeTailoredProfile(t *testing.T) {
	ctx.createTailoredProfile(t, "node", ctx.nodeRules)
}

// createScanBinding creates a ScanSettingBinding for the given tailored profile.
func (ctx *e2econtext) createScanBinding(t *testing.T, bindingName, profileName string) string {
	binding := &cmpv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: ctx.OperatorNamespacedName.Namespace,
		},
		SettingsRef: &cmpv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     e2eSettingsName,
		},
		Profiles: []cmpv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     profileName,
			},
		},
	}

	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(apiPollInterval), 180)
	err := backoff.RetryNotify(func() error {
		return ctx.dynclient.Create(goctx.TODO(), binding)
	}, bo, func(err error, d time.Duration) {
		fmt.Printf("Couldn't create %s binding after %s: %s\n", bindingName, d.String(), err)
	})
	if err != nil {
		t.Fatalf("Failed to create %s scan binding: %s", bindingName, err)
	}
	return binding.Name
}

// createPlatformScanBinding creates a ScanSettingBinding for the platform rules.
func (ctx *e2econtext) createPlatformScanBinding(t *testing.T) string {
	return ctx.createScanBinding(t, "platform-scan-binding", "platform")
}

// createNodeScanBinding creates a ScanSettingBinding for the node rules.
func (ctx *e2econtext) createNodeScanBinding(t *testing.T) string {
	return ctx.createScanBinding(t, "node-scan-binding", "node")
}

// verifyScanResults verifies the results of a scan against expected assertions.
func (ctx *e2econtext) verifyScanResults(t *testing.T, suiteName, scanType string) {
	resultList := &cmpv1alpha1.ComplianceCheckResultList{}
	labelSelector, err := labels.Parse(cmpv1alpha1.SuiteLabel + "=" + suiteName)
	if err != nil {
		t.Fatalf("Failed to parse label selector: %s", err)
	}
	opts := &dynclient.ListOptions{
		LabelSelector: labelSelector,
	}
	err = ctx.dynclient.List(goctx.TODO(), resultList, opts)
	if err != nil {
		t.Fatalf("Failed to get compliance check results for suite %s: %s", suiteName, err)
	}

	ctx.assertScanResults(t, resultList, scanType)
}

// verifyPlatformScanResults verifies the results of the platform scan against expected assertions.
func (ctx *e2econtext) verifyPlatformScanResults(t *testing.T, suiteName string) {
	ctx.verifyScanResults(t, suiteName, "platform")
}

// verifyNodeScanResults verifies the results of the node scan against expected assertions.
func (ctx *e2econtext) verifyNodeScanResults(t *testing.T, suiteName string) {
	ctx.verifyScanResults(t, suiteName, "node")
}

// assertScanResults verifies scan results against expected assertions from YAML files.
func (ctx *e2econtext) assertScanResults(
	t *testing.T,
	resultList *cmpv1alpha1.ComplianceCheckResultList,
	scanType string,
) {
	// For scan assertions, we use the simple file naming convention
	assertionFile := fmt.Sprintf("ocp4-4.12-%s-rules.yaml", scanType)
	ctx.assertResultsWithFileGeneration(t, resultList, assertionFile, false)
}

// getRuleNameFromResult extracts the rule name from a compliance check result.
func (ctx *e2econtext) getRuleNameFromResult(result *cmpv1alpha1.ComplianceCheckResult) string {
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
