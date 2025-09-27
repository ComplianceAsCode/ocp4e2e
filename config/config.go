package config

import (
	goctx "context"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

const DefaultContentImage = "quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-content-dev:master"

// TestConfig holds all the configuration arguments for the test suite
// that can be passed between helper and test packages.
type TestConfig struct {
	APIPollInterval          time.Duration
	E2eSettings              string
	Profile                  string
	Product                  string
	Platform                 string
	ContentImage             string
	ContentDir               string
	LogDir                   string
	InstallOperator          bool
	BypassRemediations       bool
	TestType                 string
	OperatorNamespace        types.NamespacedName
	Version                  string
	ManualRemediationTimeout time.Duration
}

var (
	contentDir               string
	product                  string
	profile                  string
	platform                 string
	contentImage             string
	logDir                   string
	installOperator          bool
	bypassRemediations       bool
	testType                 string
	manualRemediationTimeout time.Duration
)

// NewTestConfig creates a new TestConfig from the parsed flags and sets the
// default values for the flags that are not provided. It's safe to call this
// multiple times.
func NewTestConfig() *TestConfig {
	version, err := setVersion()
	if err != nil {
		log.Fatalf("failed to set version: %s", err)
	}
	// Set default log directory if not provided
	defaultLogDir := "/logs/artifacts"
	if logDir == "" {
		logDir = defaultLogDir
	}

	return &TestConfig{
		APIPollInterval:          5 * time.Second,
		E2eSettings:              "e2e-debug",
		Profile:                  profile,
		Product:                  product,
		Platform:                 platform,
		ContentImage:             contentImage,
		ContentDir:               contentDir,
		LogDir:                   logDir,
		InstallOperator:          installOperator,
		BypassRemediations:       bypassRemediations,
		TestType:                 testType,
		OperatorNamespace:        types.NamespacedName{Name: "compliance-operator", Namespace: "openshift-compliance"},
		Version:                  version,
		ManualRemediationTimeout: manualRemediationTimeout,
	}
}

// DefineFlags defines the flags for the test suite.
func DefineFlags() {
	flag.StringVar(&profile, "profile", "", "The profile to check")
	flag.StringVar(&product, "product", "", "The product this profile is for - e.g. 'rhcos4', 'ocp4'")
	flag.StringVar(&platform, "platform", "ocp4", "The platform that the tests are running on - e.g. 'ocp4', 'rosa'")
	flag.StringVar(&contentImage, "content-image", DefaultContentImage,
		"The path to the image with the content to test")
	flag.StringVar(&contentDir, "content-directory", "", "The path to the compliance content directory")
	flag.StringVar(&logDir, "log-dir", "/logs/artifacts", "The directory where log files and artifacts will be written")
	flag.BoolVar(&installOperator, "install-operator", true, "Should the test-code install the operator or not? "+
		"This is useful if you need to test with your own deployment of the operator")
	flag.BoolVar(&bypassRemediations, "bypass-remediations", false,
		"Do not apply remediations and summarize results after the first scan")
	flag.StringVar(&testType, "test-type", "all", "Type of rules to test: 'platform', 'node', or 'all' (default)")
	flag.DurationVar(&manualRemediationTimeout,
		"manual-remediation-timeout", 30*time.Minute, "Timeout for manual remediation scripts")
}

// ValidateFlags checks that required flags are provided.
func ValidateFlags() error {
	if contentImage == "" {
		return fmt.Errorf("a content image must be provided with the `-content-image` flag")
	}
	return nil
}

func setVersion() (string, error) {
	// TODO(jaosorior): Make this pluggable (we might want to use
	//                  kubectl instead in the future)
	ctx := goctx.Background()
	rawversion, err := exec.CommandContext(ctx, "oc", "version").Output()
	if err != nil {
		return "", fmt.Errorf("failed get cluster version: %w", err)
	}

	r := regexp.MustCompile(`Server Version: ([1-9]\.[0-9]+)\..*`)
	matches := r.FindSubmatch(rawversion)

	if len(matches) < 2 {
		return "", fmt.Errorf("couldn't get server version from output: %s", rawversion)
	}
	return string(matches[1]), nil
}
