package v1alpha1

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RemediationApplicationState string

const (
	RemediationPending             RemediationApplicationState = "Pending"
	RemediationNotApplied          RemediationApplicationState = "NotApplied"
	RemediationApplied             RemediationApplicationState = "Applied"
	RemediationOutdated            RemediationApplicationState = "Outdated"
	RemediationError               RemediationApplicationState = "Error"
	RemediationMissingDependencies RemediationApplicationState = "MissingDependencies"
	RemediationNeedsReview         RemediationApplicationState = "NeedsReview"
)

// +kubebuilder:validation:Enum=Configuration;Enforcement
type RemediationType string

const (
	ConfigurationRemediation RemediationType = "Configuration"
	EnforcementRemediation   RemediationType = "Enforcement"
)

const (
	RemediationEnforcementEmpty string = ""
	RemediationEnforcementOff   string = "off"
	RemediationEnforcementAll   string = "all"
)

const (
	// The key of a ComplianceCheckResult that dependency annotations point to
	ComplianceRemediationDependencyField = "id"
)

const (
	// OutdatedRemediationLabel specifies that the remediation has been superseded by a newer version.
	OutdatedRemediationLabel = "complianceoperator.openshift.io/outdated-remediation"
	// RemediationHasUnmetDependenciesLabel specifies that a remediation has unmet dependencies
	// and thus cannot be applied.
	RemediationHasUnmetDependenciesLabel = "compliance.openshift.io/has-unmet-dependencies"
	// RemediationUnsetValueLabel specifies that a remediation requires a value
	// to be set.
	RemediationUnsetValueLabel = "compliance.openshift.io/has-unset-variable"
	// RemediationValueRequiredProcessedLabel specifies that a remediation's needed value
	// has been processed.
	RemediationValueRequiredProcessedLabel = "compliance.openshift.io/value-required-processed"
	// RemediationCreatedByOperatorAnnotation specifies that a remediation was
	// created by the Compliance Operator; this is used for the Compliance Operator to
	// know whether it can delete the object or not when un-applying a remediation.
	RemediationCreatedByOperatorAnnotation = "compliance.openshift.io/remediation"
	// RemediationNodeRoleAnnotation specifies that a remediation applies to a node role.
	RemediationNodeRoleAnnotation = "compliance.openshift.io/node-role"
	// RemediationDependencyAnnotation specifies that a remediation depends on
	// an XCCDF rule passing in order to be applied.
	RemediationDependencyAnnotation = "compliance.openshift.io/depends-on"
	// RemediationObjectDependencyAnnotation specifies that a remediation depends on
	// another Kubernetes object existing in order to be applied.
	RemediationObjectDependencyAnnotation = "compliance.openshift.io/depends-on-obj"
	// RemediationDependenciesMetAnnotation specifies that a remediation's dependencies
	// have been met.
	RemediationDependenciesMetAnnotation = "compliance.openshift.io/dependencies-met"
	// RemediationOptionalAnnotation specifies that a remediation is optional,
	// and thus failures applying it are to be ignored.
	RemediationOptionalAnnotation = "compliance.openshift.io/optional"
	// RemediationEnforcementTypeAnnotation specifies that a remediation is
	// of a certain policy enforcement type. This generally marks the engine
	// that the policy will be evaluated with. e.g. gatekeeper
	RemediationEnforcementTypeAnnotation = "compliance.openshift.io/enforcement-type"
	// RemediationValueRequiredAnnotation specifies that a remediation requires
	// a value to be set before being applied.
	RemediationValueRequiredAnnotation = "compliance.openshift.io/value-required"
	// RemediationUnsetValueAnnotation specifies the unset value that's missing
	// for the remediation
	RemediationUnsetValueAnnotation = "compliance.openshift.io/unset-value"
	// RemediationValueUsedAnnotation specifies the values used for a remediation
	RemediationValueUsedAnnotation = "compliance.openshift.io/xccdf-value-used"
	// OCPVersionDependencyAnnotation specifies that the OCP cluster needs to fall
	// into a range in order to be applied
	OCPVersionDependencyAnnotation = "compliance.openshift.io/ocp-version"
	// K8SVersionDependencyAnnotation specifies that the k8s cluster needs to fall
	// into a range in order to be applied
	K8SVersionDependencyAnnotation = "compliance.openshift.io/k8s-version"
)

var (
	KubeDepsNotFound = errors.New("kubernetes dependency annotation not found")
)

type RemediationObjectDependencyReference struct {
	metav1.TypeMeta `json:",inline"`
	Name            string `json:"name"`
	Namespace       string `json:"namespace,omitempty"`
}

type ComplianceRemediationSpecMeta struct {
	// Whether the remediation should be picked up and applied by the operator
	Apply bool `json:"apply"`
	// The type of remediation that this object applies. The available
	// types are: Configuration and Enforcement. Where the Configuration
	// type fixes a configuration to match a compliance expectation.
	// The Enforcement type, on the other hand, ensures that the cluster
	// stays in compliance via means of authorization.
	// +kubebuilder:default="Configuration"
	Type RemediationType `json:"type,omitempty"`
}

type ComplianceRemediationPayload struct {
	// The remediation payload. This would normally be a full Kubernetes
	// object.
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:EmbeddedResource
	// +kubebuilder:validation:nullable
	Object *unstructured.Unstructured `json:"object,omitempty"`
}

func (p *ComplianceRemediationPayload) normalized() *ComplianceRemediationPayload {
	n := p.DeepCopy()
	if n.Object == nil {
		return n
	}
	if n.Object.GetAnnotations() == nil {
		n.Object.SetAnnotations(map[string]string{})
	}
	return n
}

// ComplianceRemediationSpec defines the desired state of ComplianceRemediation
// +k8s:openapi-gen=true
type ComplianceRemediationSpec struct {
	ComplianceRemediationSpecMeta `json:",inline"`
	// Defines the remediation that is proposed by the scan. If there is no "outdated"
	// remediation in this object, the "current" remediation is what will be applied.
	Current ComplianceRemediationPayload `json:"current,omitempty"`
	// In case there was a previous remediation proposed by a previous scan, and that remediation
	// now differs, the old remediation will be kept in this "outdated" key. This requires admin
	// intervention to remove this outdated object and ensure the current is what's applied.
	Outdated ComplianceRemediationPayload `json:"outdated,omitempty"`
}

// ComplianceRemediationStatus defines the observed state of ComplianceRemediation
// +k8s:openapi-gen=true
type ComplianceRemediationStatus struct {
	// Whether the remediation is already applied or not
	// +kubebuilder:default="NotApplied"
	ApplicationState RemediationApplicationState `json:"applicationState,omitempty"`
	ErrorMessage     string                      `json:"errorMessage,omitempty"`
}

// +kubebuilder:object:root=true

// ComplianceRemediation represents a remediation that can be applied to the
// cluster to fix the found issues.
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=complianceremediations,scope=Namespaced,shortName=cr;remediations;remediation;rems
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=`.status.applicationState`
type ComplianceRemediation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Contains the definition of what the remediation should be
	Spec ComplianceRemediationSpec `json:"spec,omitempty"`
	// Contains information on the remediation (whether it's applied or not)
	Status ComplianceRemediationStatus `json:"status,omitempty"`
}

func (r *ComplianceRemediation) RemediationPayloadDiffers(other *ComplianceRemediation) bool {
	return !reflect.DeepEqual(r.Spec.Current.normalized(), other.Spec.Current.normalized())
}

func (r *ComplianceRemediation) GetSuite() string {
	return r.Labels[SuiteLabel]
}

func (r *ComplianceRemediation) GetScan() string {
	return r.Labels[ComplianceScanLabel]
}

func (r *ComplianceRemediation) GetMcName() string {
	if r.GetScan() == "" {
		return ""
	}

	mcName := fmt.Sprintf("75-%s", r.GetName())

	return mcName
}

// AddOwnershipLabels labels an object to say it was created
// by this operator and is owned by a specific scan and suite
func (r *ComplianceRemediation) AddOwnershipLabels(obj metav1.Object) {
	labels := obj.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	if r.GetScan() != "" {
		labels[ComplianceScanLabel] = r.GetScan()
	}
	if r.GetSuite() != "" {
		labels[SuiteLabel] = r.GetSuite()
	}
	obj.SetLabels(labels)
}

// IsApplied tells whether the ComplianceRemediation has been applied.
// Note that a Remediation is considered applied if the state of it is
// indeed applied, or if it has been requested to be applied but it has
// become outdated
func (r *ComplianceRemediation) IsApplied() bool {
	applied := r.Status.ApplicationState == RemediationApplied
	outDatedButApplied := r.Spec.Apply && r.Status.ApplicationState == RemediationOutdated
	appliedButUnmet := r.Spec.Apply && r.Status.ApplicationState == RemediationMissingDependencies

	return applied || outDatedButApplied || appliedButUnmet
}

func (r *ComplianceRemediation) HasUnmetDependencies() bool {
	a := r.GetAnnotations()
	if len(a) == 0 {
		return false
	}
	_, hasDependencies := a[RemediationDependencyAnnotation]
	_, hasObjDependencies := a[RemediationObjectDependencyAnnotation]
	_, dependenciesMet := a[RemediationDependenciesMetAnnotation]
	return (hasDependencies || hasObjDependencies) && !dependenciesMet
}

func (r *ComplianceRemediation) HasAnnotation(ann string) bool {

	a := r.GetAnnotations()
	if len(a) == 0 {
		return false
	}
	_, hasAnnotation := a[ann]
	return hasAnnotation

}

func (r *ComplianceRemediation) HasLabel(label string) bool {

	a := r.GetLabels()
	if len(a) == 0 {
		return false
	}
	_, hasLabel := a[label]
	return hasLabel

}

func (r *ComplianceRemediation) HasUnmetKubeDependencies() bool {
	a := r.GetAnnotations()
	if len(a) == 0 {
		return false
	}
	_, hasObjDependencies := a[RemediationObjectDependencyAnnotation]
	_, dependenciesMet := a[RemediationDependenciesMetAnnotation]
	return hasObjDependencies && !dependenciesMet
}

func (r *ComplianceRemediation) GetEnforcementType() string {
	a := r.GetAnnotations()
	if len(a) == 0 {
		return "unknown"
	}
	etype, hasAnnotation := a[RemediationEnforcementTypeAnnotation]
	if !hasAnnotation {
		return "unknown"
	}
	return etype
}

func (r *ComplianceRemediation) ParseRemediationDependencyRefs() ([]RemediationObjectDependencyReference, error) {
	annotations := r.GetAnnotations()
	rawdeps, hasDeps := annotations[RemediationObjectDependencyAnnotation]
	if !hasDeps {
		return nil, KubeDepsNotFound
	}

	deps := []RemediationObjectDependencyReference{}

	if rawdeps == "" {
		return deps, nil
	}
	if parseErr := json.Unmarshal([]byte(rawdeps), &deps); parseErr != nil {
		return nil, fmt.Errorf("couldn't parse kube object dependencies: %w", parseErr)
	}
	return deps, nil
}

// +kubebuilder:object:root=true

// ComplianceRemediationList contains a list of ComplianceRemediation
type ComplianceRemediationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceRemediation `json:"items"`
}

// AddRemediationAnnotation annotates an object to say it was created
// by this operator
func AddRemediationAnnotation(obj metav1.Object) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[RemediationCreatedByOperatorAnnotation] = ""
	obj.SetAnnotations(annotations)
}

// AddRemediationAnnotation tells us if an object was created by this
// operator
func RemediationWasCreatedByOperator(obj metav1.Object) bool {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return false
	}
	_, ok := annotations[RemediationCreatedByOperatorAnnotation]
	return ok
}

func init() {
	SchemeBuilder.Register(&ComplianceRemediation{}, &ComplianceRemediationList{})
}
