package ocp4e2e

import (
	"context"
	"fmt"
	"log"
	"strings"

	cmpv1alpha1 "github.com/ComplianceAsCode/compliance-operator/pkg/apis/compliance/v1alpha1"
	"github.com/ComplianceAsCode/ocp4e2e/config"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	dynclient "sigs.k8s.io/controller-runtime/pkg/client"
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

func init() {
}

// createTailoredProfileWithExemptions creates a TailoredProfile for namespace exemption testing.
func createTailoredProfileWithExemptions(tc *config.TestConfig, c dynclient.Client, name, exemptionPattern string) error {
	tp := &cmpv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: tc.OperatorNamespace.Namespace,
			Annotations: map[string]string{"compliance.openshift.io/product-type": "Platform"},
		},
		Spec: cmpv1alpha1.TailoredProfileSpec{
			Title: "Namespace Exemption Test Profile",
			Description: "Test profile for validating namespace exemption variables",
			EnableRules: []cmpv1alpha1.RuleReferenceSpec{
				{Name: "ocp4-resource-requests-limits-in-daemonset"},
				{Name: "ocp4-resource-requests-limits-in-deployment"},
				{Name: "ocp4-resource-requests-limits-in-statefulset"},
			},
			SetValues: []cmpv1alpha1.VariableValueSpec{
				{Name: "ocp4-var-daemonset-limit-namespaces-exempt-regex", Value: exemptionPattern},
				{Name: "ocp4-var-deployment-limit-namespaces-exempt-regex", Value: exemptionPattern},
				{Name: "ocp4-var-statefulset-limit-namespaces-exempt-regex", Value: exemptionPattern},
			},
		},
	}
	return c.Create(context.TODO(), tp)
}

// createTestWorkloadsWithoutLimits creates test workloads without resource limits.
func createTestWorkloadsWithoutLimits(c dynclient.Client, namespace string) error {
	ctx := context.TODO()

	workloads := []dynclient.Object{
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "test-deployment-no-limits", Namespace: namespace},
			Spec: appsv1.DeploymentSpec{
				Replicas: int32Ptr(1),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "test"}},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name: "nginx", Image: "registry.access.redhat.com/ubi8/ubi-minimal:latest",
						Command: []string{"/bin/sh", "-c", "sleep infinity"},
					}}},
				},
			},
		},
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "test-daemonset-no-limits", Namespace: namespace},
			Spec: appsv1.DaemonSetSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "test"}},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{
							Name: "nginx", Image: "registry.access.redhat.com/ubi8/ubi-minimal:latest",
							Command: []string{"/bin/sh", "-c", "sleep infinity"},
						}},
						Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					},
				},
			},
		},
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "test-statefulset-no-limits", Namespace: namespace},
			Spec: appsv1.StatefulSetSpec{
				Replicas: int32Ptr(1), ServiceName: "test",
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "test"}},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name: "nginx", Image: "registry.access.redhat.com/ubi8/ubi-minimal:latest",
						Command: []string{"/bin/sh", "-c", "sleep infinity"},
					}}},
				},
			},
		},
	}

	for _, w := range workloads {
		if err := c.Create(ctx, w); err != nil {
			return err
		}
	}
	return nil
}

// createNamespace creates a namespace.
func createNamespace(c dynclient.Client, name string) error {
	return c.Create(context.TODO(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
}

// deleteNamespace deletes a namespace.
func deleteNamespace(c dynclient.Client, name string) error {
	c.Delete(context.TODO(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
	return nil
}

// findRuleResult searches for a rule result by partial name match.
func findRuleResult(results map[string]string, ruleName string) string {
	if result, exists := results[ruleName]; exists {
		return result
	}
	for resultName, resultValue := range results {
		if strings.Contains(resultName, ruleName) {
			return resultValue
		}
	}
	return ""
}

// int32Ptr returns a pointer to an int32 value.
func int32Ptr(i int32) *int32 { return &i }

// createKubeletConfigWithEmptyCiphers creates a KubeletConfig with insecure tlsCipherSuites
func createKubeletConfigWithEmptyCiphers(c dynclient.Client, name, poolName string) error {
	kubeletConfig := map[string]interface{}{
		"apiVersion": "machineconfiguration.openshift.io/v1",
		"kind":       "KubeletConfig",
		"metadata": map[string]interface{}{
			"name": name,
		},
		"spec": map[string]interface{}{
			"machineConfigPoolSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"pools.operator.machineconfiguration.openshift.io/" + poolName: "",
				},
			},
			"kubeletConfig": map[string]interface{}{
				"tlsCipherSuites": []string{
					// Set weak/insecure ciphers that should fail the check
					"TLS_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_RSA_WITH_AES_256_CBC_SHA",
				},
			},
		},
	}

	obj := &unstructured.Unstructured{Object: kubeletConfig}
	return c.Create(context.TODO(), obj)
}

// getKubeletConfigCiphers retrieves the tlsCipherSuites from a KubeletConfig
func getKubeletConfigCiphers(c dynclient.Client, name string) ([]string, error) {
	kubeletConfig := &unstructured.Unstructured{}
	kubeletConfig.SetAPIVersion("machineconfiguration.openshift.io/v1")
	kubeletConfig.SetKind("KubeletConfig")
	kubeletConfig.SetName(name)

	err := c.Get(context.TODO(), dynclient.ObjectKey{Name: name}, kubeletConfig)
	if err != nil {
		return nil, err
	}

	spec, found, err := unstructured.NestedMap(kubeletConfig.Object, "spec", "kubeletConfig")
	if err != nil || !found {
		return []string{}, nil
	}

	ciphersInterface, found := spec["tlsCipherSuites"]
	if !found {
		return []string{}, nil
	}

	ciphersList, ok := ciphersInterface.([]interface{})
	if !ok {
		return []string{}, fmt.Errorf("tlsCipherSuites is not a list")
	}

	ciphers := make([]string, 0, len(ciphersList))
	for _, c := range ciphersList {
		if cipherStr, ok := c.(string); ok {
			ciphers = append(ciphers, cipherStr)
		}
	}

	return ciphers, nil
}

// deleteKubeletConfig deletes a KubeletConfig object
func deleteKubeletConfig(c dynclient.Client, name string) {
	kubeletConfig := &unstructured.Unstructured{}
	kubeletConfig.SetAPIVersion("machineconfiguration.openshift.io/v1")
	kubeletConfig.SetKind("KubeletConfig")
	kubeletConfig.SetName(name)

	err := c.Delete(context.TODO(), kubeletConfig)
	if err != nil {
		log.Printf("Warning: Failed to delete KubeletConfig %s: %s", name, err)
	}
}

// createCISKubeletTailoredProfile creates a tailored profile for testing CIS kubelet rules
func createCISKubeletTailoredProfile(tc *config.TestConfig, c dynclient.Client, name string) error {
	tp := &cmpv1alpha1.TailoredProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: tc.OperatorNamespace.Namespace,
			Annotations: map[string]string{
				"compliance.openshift.io/product-type": "Node",
			},
		},
		Spec: cmpv1alpha1.TailoredProfileSpec{
			Title:       "CIS Kubelet Auto-Remediation Test Profile",
			Description: "Test profile for validating KubeletConfig auto-remediation",
			EnableRules: []cmpv1alpha1.RuleReferenceSpec{
				{Name: "ocp4-kubelet-configure-tls-cipher-suites"},
			},
		},
	}

	return c.Create(context.TODO(), tp)
}
