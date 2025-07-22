package ocp4e2e

import (
	"flag"

	"k8s.io/apimachinery/pkg/types"
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
	testType string
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
