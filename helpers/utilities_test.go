package helpers

import (
	"os"
	"path"
	"testing"

	testConfig "github.com/ComplianceAsCode/ocp4e2e/config"
	"gopkg.in/yaml.v2"
)

// TestGenerateAssertionFileFromResultsNoCarryover is a regression test for
// CMP-4630: GenerateAssertionFileFromResults used to reuse a single RuleTest
// struct across loop iterations, so a rule whose result did not change between
// the initial and final scans inherited the previous rule's
// ResultAfterRemediation value. Because Go map iteration order is randomized,
// the corruption was nondeterministic.
//
// The assertion here holds only when a fresh RuleTest is used per rule:
//   - a rule whose result did NOT change must have no result_after_remediation
//   - a rule whose result DID change must record exactly its final result
func TestGenerateAssertionFileFromResultsNoCarryover(t *testing.T) {
	logDir := t.TempDir()
	tc := &testConfig.TestConfig{LogDir: logDir}

	// Interleave changed and unchanged rules. Many rules increase the chance
	// the old (buggy) code carries a stale value into an unchanged rule
	// regardless of the randomized map iteration order.
	initial := map[string]string{}
	final := map[string]string{}
	// Changed rules: FAIL -> PASS
	changed := []string{"rule-changed-01", "rule-changed-02", "rule-changed-03", "rule-changed-04"}
	for _, r := range changed {
		initial[r] = "FAIL"
		final[r] = "PASS"
	}
	// Unchanged rules: PASS -> PASS and FAIL -> FAIL
	unchangedPass := []string{"rule-pass-01", "rule-pass-02", "rule-pass-03", "rule-pass-04", "rule-pass-05"}
	for _, r := range unchangedPass {
		initial[r] = "PASS"
		final[r] = "PASS"
	}
	unchangedFail := []string{"rule-fail-01", "rule-fail-02", "rule-fail-03", "rule-fail-04", "rule-fail-05"}
	for _, r := range unchangedFail {
		initial[r] = "FAIL"
		final[r] = "FAIL"
	}

	const fileName = "assertions.yml"
	if err := GenerateAssertionFileFromResults(tc, nil, fileName, initial, final); err != nil {
		t.Fatalf("GenerateAssertionFileFromResults returned error: %v", err)
	}

	data, err := os.ReadFile(path.Join(logDir, fileName))
	if err != nil {
		t.Fatalf("failed to read generated assertion file: %v", err)
	}
	var got RuleTestResults
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("failed to unmarshal assertion file: %v", err)
	}

	if len(got.RuleResults) != len(initial) {
		t.Fatalf("expected %d rules, got %d", len(initial), len(got.RuleResults))
	}

	for rule, rt := range got.RuleResults {
		wantDefault := initial[rule]
		if rt.DefaultResult != wantDefault {
			t.Errorf("rule %s: default_result = %v, want %v", rule, rt.DefaultResult, wantDefault)
		}
		if final[rule] == initial[rule] {
			// Unchanged rule: must NOT carry a result_after_remediation.
			if rt.ResultAfterRemediation != nil {
				t.Errorf("rule %s: unchanged result but result_after_remediation = %v (carryover bug)",
					rule, rt.ResultAfterRemediation)
			}
		} else {
			// Changed rule: must record its own final result.
			if rt.ResultAfterRemediation != final[rule] {
				t.Errorf("rule %s: result_after_remediation = %v, want %v",
					rule, rt.ResultAfterRemediation, final[rule])
			}
		}
	}
}
