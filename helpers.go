package ocp4e2e

import (
	"bufio"
	goctx "context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ComplianceAsCode/ocp4e2e/resultparser"
	backoff "github.com/cenkalti/backoff/v4"
	caolib "github.com/openshift/cluster-authentication-operator/test/library"
	cmpapis "github.com/openshift/compliance-operator/pkg/apis"
	cmpv1alpha1 "github.com/openshift/compliance-operator/pkg/apis/compliance/v1alpha1"
	mcfg "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io"
	mcfgv1 "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io/v1"
	"gopkg.in/yaml.v2"
	appsv1 "k8s.io/api/apps/v1"
	netv1 "k8s.io/api/networking/v1"
	extscheme "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/scheme"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	cgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	namespacePath             = "compliance-operator-ns.yaml"
	catalogSourcePath         = "compliance-operator-catalog-source.yaml"
	operatorGroupPath         = "compliance-operator-operator-group.yaml"
	subscriptionPath          = "compliance-operator-alpha-subscription.yaml"
	apiPollInterval           = 5 * time.Second
	testProfilebundleName     = "e2e"
	autoApplySettingsName     = "auto-apply-debug"
	manualRemediationsTimeout = 30 * time.Minute
)

// RuleTest is the definition of the structure rule-specific e2e tests should have.
type RuleTest struct {
	DefaultResult          interface{} `yaml:"default_result"`
	ResultAfterRemediation interface{} `yaml:"result_after_remediation,omitempty"`
	ExcludeFromCount       interface{} `yaml:"exclude_from_count,omitempty"`
}

var (
	product            string
	profile            string
	contentImage       string
	installOperator    bool
	bypassRemediations bool
)

var (
	ruleTestDir                   = path.Join("tests", "ocp4")
	ruleTestFilePath              = path.Join(ruleTestDir, "e2e.yml")
	ruleManualRemediationFilePath = path.Join(ruleTestDir, "e2e-remediation.sh")
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
	resourcespath      string
	benchmarkRoot      string
	version            string
	installOperator    bool
	bypassRemediations bool
	dynclient          dynclient.Client
	kubecfg            *rest.Config
}

func init() {
	flag.StringVar(&profile, "profile", "", "The profile to check")
	flag.StringVar(&product, "product", "", "The product this profile is for - e.g. 'rhcos4', 'ocp4'")
	flag.StringVar(&contentImage, "content-image", "", "The path to the image with the content to test")
	flag.BoolVar(&installOperator, "install-operator", true, "Should the test-code install the operator or not? "+
		"This is useful if you need to test with your own deployment of the operator")
	flag.BoolVar(&bypassRemediations, "bypass-remediations", false, "Do not apply remedations and summarize results after the first scan")
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
		installOperator:        installOperator,
		bypassRemediations:     bypassRemediations,
	}
}

func cloneContentDir() (string, error) {
	dir, tmperr := ioutil.TempDir("", "content-*")
	if tmperr != nil {
		return "", fmt.Errorf("couldn't create tmpdir: %w", tmperr)
	}
	_, cmderr := exec.Command("/usr/bin/git", "clone",
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
	rawversion, err := exec.Command("oc", "version").Output()
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
	manifestpath := path.Join(ctx.resourcespath, subscriptionPath)
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
		Name:      autoApplySettingsName,
		Namespace: ctx.OperatorNamespacedName.Namespace,
	}
	autoApplySettings := defaultSettings.DeepCopy()
	// Delete Object Meta so we reset unwanted references
	autoApplySettings.ObjectMeta = metav1.ObjectMeta{
		Name:      autoApplySettingsName,
		Namespace: ctx.OperatorNamespacedName.Namespace,
	}
	autoApplySettings.AutoApplyRemediations = true
	autoApplySettings.Debug = true
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

func (ctx *e2econtext) ensureIDP(t *testing.T) func() {
	_, _, cleanups := caolib.AddKeycloakIDP(t, ctx.kubecfg)

	if err := ctx.setIDPNetworkPolicy(t); err != nil {
		t.Fatalf("failed to ensure networkpolicy for IDP: %s", err)
	}
	return func() {
		t.Logf("Cleaning up IdP")
		caolib.IDPCleanupWrapper(func() {
			for _, c := range cleanups {
				c()
			}
		})
	}
}

func (ctx *e2econtext) setIDPNetworkPolicy(t *testing.T) error {
	getNSCmd := `oc get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep e2e-test-authentication-operator`
	rawres, nserr := exec.Command("/bin/bash", "-c", getNSCmd).CombinedOutput()
	if nserr != nil {
		return fmt.Errorf("error getting IDP namespace: %w", nserr)
	}
	ns := strings.TrimSpace(string(rawres))
	np := netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-all-ingress",
			Namespace: ns,
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			Ingress:     []netv1.NetworkPolicyIngressRule{},
			PolicyTypes: []netv1.PolicyType{
				netv1.PolicyTypeIngress,
			},
		},
	}
	return ctx.dynclient.Create(goctx.TODO(), &np)
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

func (ctx *e2econtext) getPrefixedProfileName() string {
	return testProfilebundleName + "-" + ctx.Profile
}

func (ctx *e2econtext) createBindingForProfile(t *testing.T) string {
	var useTailoring bool
	tailoringfilename := fmt.Sprintf("%s-%s.yaml", ctx.product, ctx.Profile)
	tailoringpath := path.Join(ctx.resourcespath, "tailorings", tailoringfilename)
	tp, readErr := readObjFromYAMLFilePath(tailoringpath)
	if readErr != nil {
		// We use the profile directly if no tailoring exists
		if errors.Is(readErr, os.ErrNotExist) {
			useTailoring = false
		} else {
			t.Fatalf("failed read tailoring '%s': %s", tailoringpath, readErr)
		}
	} else {
		useTailoring = true
		createErr := ctx.dynclient.Create(goctx.TODO(), tp)
		if createErr != nil && !apierrors.IsAlreadyExists(createErr) {
			t.Fatalf("failed to create tailoring object from '%s': %s", tailoringpath, createErr)
		}
	}

	binding := &cmpv1alpha1.ScanSettingBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ctx.getPrefixedProfileName(),
			Namespace: ctx.OperatorNamespacedName.Namespace,
		},
		SettingsRef: &cmpv1alpha1.NamedObjectReference{
			APIGroup: "compliance.openshift.io/v1alpha1",
			Kind:     "ScanSetting",
			Name:     autoApplySettingsName,
		},
	}

	if !useTailoring {
		binding.Profiles = []cmpv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "Profile",
				Name:     ctx.getPrefixedProfileName(),
			},
		}
	} else {
		binding.Profiles = []cmpv1alpha1.NamedObjectReference{
			{
				APIGroup: "compliance.openshift.io/v1alpha1",
				Kind:     "TailoredProfile",
				Name:     tp.GetName(),
			},
		}
	}

	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(apiPollInterval), 180)
	err := backoff.RetryNotify(func() error {
		return ctx.dynclient.Create(goctx.TODO(), binding)
	}, bo, func(err error, d time.Duration) {
		fmt.Printf("Couldn't create binding after %s: %s\n", d.String(), err)
	})
	if err != nil {
		t.Fatalf("failed to create binding: %s", err)
	}
	return binding.Name
}

func (ctx *e2econtext) waitForComplianceSuite(t *testing.T, suiteName string) {
	key := types.NamespacedName{Name: suiteName, Namespace: ctx.OperatorNamespacedName.Namespace}
	// aprox. 15 min
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(apiPollInterval), 180)

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
				return fmt.Errorf("still waiting for the scans to be done")
			}
			if scanstatus.Result == cmpv1alpha1.ResultError {
				// If there was an error, we can stop already.
				t.Fatalf("There was an unexpected error in the scan '%s': %s",
					scanstatus.Name, scanstatus.ErrorMessage)
			}
		}
		return nil
	}, bo, func(error, time.Duration) {
		t.Logf("ComplianceSuite %s is still not ready", suiteName)
	})
	if err != nil {
		t.Fatalf("The Compliance Suite '%s' didn't get to DONE phase: %s", key.Name, err)
	}
	t.Logf("ComplianceSuite %s is DONE", suiteName)
}

func (ctx *e2econtext) waitForMachinePoolUpdate(t *testing.T, name string) {
	mcKey := types.NamespacedName{Name: name}

	var lastErr error
	err := wait.PollImmediate(10*time.Second, 40*time.Minute, func() (bool, error) {
		pool := &mcfgv1.MachineConfigPool{}
		lastErr = ctx.dynclient.Get(goctx.TODO(), mcKey, pool)
		if lastErr != nil {
			t.Logf("Could not get the pool %s post update. Retrying.", name)
			return false, nil
		}

		// Check if the pool has finished updating yet.
		if (pool.Status.UpdatedMachineCount == pool.Status.MachineCount) &&
			(pool.Status.UnavailableMachineCount == 0) {
			t.Logf("The pool %s has updated", name)
			return true, nil
		}

		t.Logf("The pool %s has not updated yet. updated %d/%d unavailable %d",
			name,
			pool.Status.UpdatedMachineCount, pool.Status.MachineCount,
			pool.Status.UnavailableMachineCount)
		return false, nil
	})
	// timeout error
	if err != nil {
		t.Errorf("E2E-FAILURE: Waiting for pool %s timed out", name)
	}

	// An actual error at the end of the run
	if lastErr != nil {
		t.Errorf("E2E-FAILURE: Waiting for pool %s errored: %s", name, lastErr)
	}
}

func (ctx *e2econtext) doRescan(t *testing.T, s string) {
	scanList := &cmpv1alpha1.ComplianceScanList{}
	// nolint:errcheck
	labelSelector, _ := labels.Parse(cmpv1alpha1.SuiteLabel + "=" + s)
	opts := &dynclient.ListOptions{
		LabelSelector: labelSelector,
	}
	err := ctx.dynclient.List(goctx.TODO(), scanList, opts)
	if err != nil {
		t.Fatalf("Couldn't get scan list")
	}
	if len(scanList.Items) == 0 {
		t.Fatal("This suite didn't contain scans")
	} else {
		t.Logf("Running a re-scan on %d scans", len(scanList.Items))
	}
	for idx := range scanList.Items {
		updatedScan := scanList.Items[idx].DeepCopy()
		annotations := updatedScan.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[cmpv1alpha1.ComplianceScanRescanAnnotation] = ""
		updatedScan.SetAnnotations(annotations)

		bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(apiPollInterval), 180)
		err := backoff.RetryNotify(func() error {
			return ctx.dynclient.Update(goctx.TODO(), updatedScan)
		}, bo, func(err error, d time.Duration) {
			fmt.Printf("Couldn't rescan after %s: %s\n", d.String(), err)
		})
		if err != nil {
			t.Fatalf("failed rescan: %s", err)
		}
		t.Logf("Annotated scan %s to retrigger", updatedScan.GetName())
	}

	t.Logf("Waiting for scans to retrigger")
	var lastErr error
	err = wait.PollImmediate(2*time.Second, 5*time.Minute, func() (bool, error) {
		suite := &cmpv1alpha1.ComplianceSuite{}
		key := types.NamespacedName{Name: s, Namespace: ctx.OperatorNamespacedName.Namespace}
		lastErr = ctx.dynclient.Get(goctx.TODO(), key, suite)
		if lastErr != nil {
			return false, nil
		}
		if suite.Status.Phase == cmpv1alpha1.PhaseDone {
			t.Logf("Scan still on DONE phase... retrying.")
			return false, nil
		}
		// The scan has been reset, we're good to go
		return true, nil
	})

	// timeout error
	if err != nil {
		t.Fatalf("Timed out waiting for scan to be reset: %s", err)
	}

	// An actual error at the end of the run
	if lastErr != nil {
		t.Fatalf("Error occurred while waiting for scan to be reset: %s", lastErr)
	}
	t.Logf("All scans retriggered")
}

func (ctx *e2econtext) getRemediationsForSuite(t *testing.T, s string) int {
	remList := &cmpv1alpha1.ComplianceRemediationList{}
	// nolint:errcheck
	labelSelector, _ := labels.Parse(cmpv1alpha1.SuiteLabel + "=" + s)
	opts := &dynclient.ListOptions{
		LabelSelector: labelSelector,
	}
	err := ctx.dynclient.List(goctx.TODO(), remList, opts)
	if err != nil {
		t.Fatalf("Couldn't get remediation list")
	}
	if len(remList.Items) > 0 {
		t.Logf("Remediations from ComplianceSuite: %s", s)
	} else {
		t.Log("This suite didn't generate remediations")
	}
	for idx := range remList.Items {
		t.Logf("- %s", remList.Items[idx].Name)
	}
	return len(remList.Items)
}

func (ctx *e2econtext) suiteHasRemediationsWithUnmetDependencies(t *testing.T, s string) bool {
	remList := &cmpv1alpha1.ComplianceRemediationList{}
	// nolint:errcheck
	labelSelector, _ := labels.Parse(cmpv1alpha1.SuiteLabel + "=" + s + "," +
		cmpv1alpha1.RemediationHasUnmetDependenciesLabel)
	opts := &dynclient.ListOptions{
		LabelSelector: labelSelector,
	}
	err := ctx.dynclient.List(goctx.TODO(), remList, opts)
	if err != nil {
		t.Fatalf("Couldn't get remediation list")
	}
	if len(remList.Items) > 0 {
		t.Logf("Remediations from ComplianceSuite: %s", s)
	} else {
		t.Log("This suite didn't contain remediations with unmet dependencies")
	}
	for idx := range remList.Items {
		t.Logf("- %s", remList.Items[idx].Name)
	}
	return len(remList.Items) > 0
}

func (ctx *e2econtext) getFailuresForSuite(t *testing.T, s string) int {
	failList := &cmpv1alpha1.ComplianceCheckResultList{}
	matchLabels := dynclient.MatchingLabels{
		cmpv1alpha1.SuiteLabel:                               s,
		string(cmpv1alpha1.ComplianceCheckResultStatusLabel): string(cmpv1alpha1.CheckResultFail),
	}
	err := ctx.dynclient.List(goctx.TODO(), failList, matchLabels)
	if err != nil {
		t.Fatalf("Couldn't get check result list")
	}
	if len(failList.Items) > 0 {
		t.Logf("Failures from ComplianceSuite: %s", s)
	}
	for idx := range failList.Items {
		t.Logf("- %s", failList.Items[idx].Name)
	}
	return len(failList.Items)
}

// This returns the number of results that are either CheckResultError or CheckResultNoResult.
func (ctx *e2econtext) getInvalidResultsFromSuite(t *testing.T, s string) int {
	errList := &cmpv1alpha1.ComplianceCheckResultList{}
	matchLabels := dynclient.MatchingLabels{
		cmpv1alpha1.SuiteLabel:                               s,
		string(cmpv1alpha1.ComplianceCheckResultStatusLabel): string(cmpv1alpha1.CheckResultError),
	}
	err := ctx.dynclient.List(goctx.TODO(), errList, matchLabels)
	if err != nil {
		t.Fatalf("Couldn't get result list")
	}
	if len(errList.Items) > 0 {
		t.Logf("Errors from ComplianceSuite: %s", s)
	}
	for idx := range errList.Items {
		t.Logf("unexpected Error result - %s", errList.Items[idx].Name)
	}
	ret := len(errList.Items)

	noneList := &cmpv1alpha1.ComplianceCheckResultList{}
	matchLabels = dynclient.MatchingLabels{
		cmpv1alpha1.SuiteLabel:                               s,
		string(cmpv1alpha1.ComplianceCheckResultStatusLabel): string(cmpv1alpha1.CheckResultNoResult),
	}
	err = ctx.dynclient.List(goctx.TODO(), noneList, matchLabels)
	if err != nil {
		t.Fatalf("Couldn't get result list")
	}
	if len(noneList.Items) > 0 {
		t.Logf("None result from ComplianceSuite: %s", s)
	}
	for idx := range noneList.Items {
		t.Logf("unexpected None result - %s", noneList.Items[idx].Name)
	}

	return ret + len(noneList.Items)
}

func (ctx *e2econtext) verifyCheckResultsForSuite(
	t *testing.T, s string, afterRemediations bool,
) (nresults int, manualRems []string) {
	excludeList := make(map[string]int)
	manualRemediationSet := map[string]bool{}
	resList := &cmpv1alpha1.ComplianceCheckResultList{}
	matchLabels := dynclient.MatchingLabels{
		cmpv1alpha1.SuiteLabel: s,
	}
	err := ctx.dynclient.List(goctx.TODO(), resList, matchLabels)
	if err != nil {
		t.Fatalf("Couldn't get result list")
	}
	if len(resList.Items) > 0 {
		t.Logf("Results from ComplianceSuite: %s", s)
	} else {
		t.Logf("There were no results for the ComplianceSuite: %s", s)
	}
	for idx := range resList.Items {
		check := &resList.Items[idx]
		t.Logf("Result - Name: %s - Status: %s - Severity: %s", check.Name, check.Status, check.Severity)
		manualRem, exclude, err := ctx.verifyRule(t, check, afterRemediations)
		if exclude {
			excludeList[check.Name] = 1
			t.Logf("Excluded Rule from counting - Name: %s", check.Name)
		}
		if err != nil {
			t.Error(err)
		}
		if manualRem != "" {
			manualRemediationSet[manualRem] = true
		}
	}

	manualRemediations := []string{}
	for key := range manualRemediationSet {
		manualRemediations = append(manualRemediations, key)
	}

	return len(resList.Items) - len(excludeList), manualRemediations
}

func (ctx *e2econtext) summarizeSuiteFindings(t *testing.T, suite string) {
	su := &cmpv1alpha1.ComplianceSuite{}
	key := types.NamespacedName{Name: suite, Namespace: ctx.OperatorNamespacedName.Namespace}
	err := ctx.dynclient.Get(goctx.TODO(), key, su)
	if err != nil {
		t.Fatalf("failed to get ComplianceSuite %s: %s", suite, err)
	}

	for _, scan := range su.Spec.Scans {
		results := make(map[cmpv1alpha1.ComplianceCheckStatus]int)
		resultList := &cmpv1alpha1.ComplianceCheckResultList{}
		label := dynclient.MatchingLabels{cmpv1alpha1.ComplianceScanLabel: scan.Name}
		err := ctx.dynclient.List(goctx.TODO(), resultList, label)
		if err != nil {
			t.Fatalf("failed to get CompliacneCheckResults for ComplianceScan %s: %s", scan.Name, err)
		}
		for _, result := range resultList.Items {
			results[result.Status]++
		}
		t.Logf("Scan %s contained %d total checks", scan.Name, len(resultList.Items))
		for status, number := range results {
			percentage := (float32(number) / float32(len(resultList.Items)) * 100)
			t.Logf("Scan %s contained %d checks with %s status (%.2f%%)", scan.Name, number, status, percentage)
		}

		failedWithRemediationList := &cmpv1alpha1.ComplianceCheckResultList{}
		labels := dynclient.MatchingLabels{
			cmpv1alpha1.ComplianceCheckResultStatusLabel:    string(cmpv1alpha1.CheckResultFail),
			cmpv1alpha1.ComplianceCheckResultHasRemediation: "",
		}
		err = ctx.dynclient.List(goctx.TODO(), failedWithRemediationList, labels)
		if err != nil {
			t.Fatalf("failed to get ComplianceCheckResults with status FAIL and remediations: %s", err)
		}
		t.Logf("Scan %s contained %d checks that failed, but have a remediation available", scan.Name, len(failedWithRemediationList.Items))
	}
}

func (ctx *e2econtext) verifyRule(
	t *testing.T, result *cmpv1alpha1.ComplianceCheckResult, afterRemediations bool,
) (string, bool, error) {
	ruleName, err := ctx.getRuleFolderNameFromResult(result)
	if err != nil {
		return "", false, err
	}
	// nolint:gosec
	rulePathBytes, err := exec.Command("find", ctx.benchmarkRoot, "-name", ruleName).Output()
	if err != nil {
		return "", false, err
	}
	rulePath := strings.Trim(string(rulePathBytes), "\n")

	buf, err := ctx.getTestDefinition(rulePath)
	if err != nil {
		if os.IsNotExist(err) {
			// There's no test file, so no need to verify
			return "", false, nil
		}
		return "", false, err
	}

	test := RuleTest{}
	if err := yaml.Unmarshal(buf, &test); err != nil {
		return "", false, err
	}

	remPath := ctx.getManualRemediationPath(rulePath)

	// Initial run
	// nolint:nestif
	if !afterRemediations {
		if err := verifyRuleResult(result, test.DefaultResult, test, ruleName); err != nil {
			return remPath, isExcluded(test.ExcludeFromCount), err
		}
	} else {
		// after remediations
		// If we expect a change after remediation is applied, let's test for it
		if test.ResultAfterRemediation != nil {
			if err := verifyRuleResult(result, test.ResultAfterRemediation, test, ruleName); err != nil {
				return remPath, isExcluded(test.ExcludeFromCount), err
			}
		} else {
			// Check that the default didn't change
			if err := verifyRuleResult(result, test.DefaultResult, test, ruleName); err != nil {
				return remPath, isExcluded(test.ExcludeFromCount), err
			}
		}
	}

	t.Logf("Rule %s matched expected result", ruleName)
	return remPath, isExcluded(test.ExcludeFromCount), err
}

// getTestDefinition attempts to use a versioned test (<version>.yml)
// definition, if it fails it'll try to use the standard test
// definition (e2e.yml). If that does not exist either, the function checks
// if other files (presumably versioned tests) exist in that file and if
// they do, it would fail. This is better than just silently ignoring the
// files because:
//  1. we catch rules that have versioned results but no result for the
//     current version more easily
//  2. with each version, this forces us to think if we can already retire
//     certain rules
func (ctx *e2econtext) getTestDefinition(rulePath string) ([]byte, error) {
	versionedManifest := fmt.Sprintf("%s.yml", ctx.version)
	versionedRuleTestFilePath := path.Join(rulePath, ruleTestDir, versionedManifest)
	vbuf, verr := ioutil.ReadFile(versionedRuleTestFilePath)

	if verr == nil {
		return vbuf, nil
	}

	if verr != nil && !os.IsNotExist(verr) {
		return nil, verr
	}

	// the error is now os.IsNotExist, let's try the global file
	testFilePath := path.Join(rulePath, ruleTestFilePath)
	gbuf, gerr := ioutil.ReadFile(testFilePath)
	if os.IsNotExist(gerr) {
		// let's check for other files and fail if they don't exist
		files, err := os.ReadDir(ruleTestDir)
		if err != nil {
			return nil, err
		}
		if len(files) > 0 {
			return nil, fmt.Errorf("E2E-FAILURE: the rule directory %s contains versioned files, but none for %s", ruleTestDir, ctx.version)
		}
	} else if gerr != nil {
		return nil, gerr
	}

	return gbuf, nil
}

// getManualRemediationPath attempts to get a versioned remediation
// (<version>-remediation.sh) path, if it fails it'll try to use the
// standard test remediation path (e2e-remediation.sh).
// If both instances are not present, it'll return an empty string.
func (ctx *e2econtext) getManualRemediationPath(rulePath string) string {
	versionedRemediation := fmt.Sprintf("%s-remediation.sh", ctx.version)
	versionedRemediationPath := path.Join(ruleTestDir, versionedRemediation)
	_, err := os.Stat(versionedRemediationPath)
	if err == nil {
		return versionedRemediationPath
	}

	remPath := path.Join(rulePath, ruleManualRemediationFilePath)
	_, err = os.Stat(remPath)
	if err == nil {
		// We reset the path to return in case there isn't a remediation
		return remPath
	}
	return ""
}

func verifyRuleResult(
	foundResult *cmpv1alpha1.ComplianceCheckResult,
	expectedResult interface{},
	testDef RuleTest,
	ruleName string,
) error {
	if matches, err := matchFoundResultToExpectation(foundResult, expectedResult); !matches || err != nil {
		if err != nil {
			return fmt.Errorf("E2E-ERROR: The e2e YAML for rule '%s' is malformed: %v . Got error: %w", ruleName, testDef, err)
		}
		return fmt.Errorf("E2E-FAILURE: The expected result for the %s rule didn't match. Expected '%s', Got '%s'",
			ruleName, expectedResult, foundResult.Status)
	}
	return nil
}

// Will exclude the rule from counting if excludedString has values
func isExcluded(exclude interface{}) bool {
	if excludedString, ok := exclude.(string); ok {
		if excludedString != "FALSE" {
			return true
		}
	}
	return false
}

func matchFoundResultToExpectation(
	foundResult *cmpv1alpha1.ComplianceCheckResult, expectedResult interface{},
) (bool, error) {
	// Handle expected result for all roles
	if resultStr, ok := expectedResult.(string); ok {
		p, perr := resultparser.ParseRoleResultEval(resultStr)
		if perr != nil {
			return false, fmt.Errorf("Error parsing result evaluator: %w", perr)
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
				return false, fmt.Errorf("Error parsing result evaluator: %w", perr)
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

func (ctx *e2econtext) getRuleFolderNameFromResult(result *cmpv1alpha1.ComplianceCheckResult) (string, error) {
	lbls := result.GetLabels()
	resultName := result.Name
	if lbls == nil {
		return "", fmt.Errorf("ERROR: Can't derive name from rule %s since it contains no label", resultName)
	}
	prefix, ok := lbls[cmpv1alpha1.ComplianceScanLabel]
	if !ok {
		return "", fmt.Errorf("ERROR: Result %s doesn't have label with scan name", resultName)
	}
	if !strings.HasPrefix(resultName, prefix) {
		return "", fmt.Errorf("ERROR: Result %s doesn't have expected prefix %s", resultName, prefix)
	}
	// Removes prefix plus the "-" delimiter
	prefixRemoved := resultName[len(prefix)+1:]
	return strings.ReplaceAll(prefixRemoved, "-", "_"), nil
}

func (ctx *e2econtext) applyManualRemediations(t *testing.T, rems []string) {
	var wg sync.WaitGroup
	cmdctx, cancel := goctx.WithTimeout(goctx.Background(), manualRemediationsTimeout)
	defer cancel()

	for _, rem := range rems {
		wg.Add(1)
		go ctx.runManualRemediation(t, cmdctx, &wg, rem)
	}

	wg.Wait()
}

func (ctx *e2econtext) runManualRemediation(t *testing.T, cmdctx goctx.Context, wg *sync.WaitGroup, rem string) {
	defer wg.Done()

	t.Logf("Running manual remediation '%s'", rem)
	cmd := exec.CommandContext(cmdctx, rem)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()

	if errors.Is(cmdctx.Err(), goctx.DeadlineExceeded) {
		t.Errorf("Command '%s' timed out", rem)
		return
	}

	if err != nil {
		t.Errorf("Failed applying remediation '%s': %s\n%s", rem, err, out)
	}
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
