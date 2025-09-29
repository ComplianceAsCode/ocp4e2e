package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FIXME: move name/rationale to a common struct with an interface?

// DisableOutdatedReferenceValidation a label is used to disable validation of outdated references
const DisableOutdatedReferenceValidation = "compliance.openshift.io/disable-outdated-reference-validation"

// PruneOutdatedReferencesAnnotationKey is the annotation key used to indicate that the outdated references of rules or variables should be pruned
const PruneOutdatedReferencesAnnotationKey = "compliance.openshift.io/prune-outdated-references"

// RuleLastCheckTypeChangedAnnotationKey is the annotation key used to indicate that the rule check type has changed, store its previous check type
const RuleLastCheckTypeChangedAnnotationKey = "compliance.openshift.io/rule-last-check-type"

// ExtendedProfileGuidLabel is a label used to store the unique ID of the profile being extends
const ExtendedProfileGuidLabel = "compliance.openshift.io/extended-profile-unique-id"

// RuleReferenceSpec specifies a rule to be selected/deselected, as well as the reason why
type RuleReferenceSpec struct {
	// Name of the rule that's being referenced
	Name string `json:"name"`
	// Rationale of why this rule is being selected/deselected
	Rationale string `json:"rationale"`
}

// ValueReferenceSpec specifies a value to be set for a variable with a reason why
type VariableValueSpec struct {
	// Name of the variable that's being referenced
	Name string `json:"name"`
	// Rationale of why this value is being tailored
	Rationale string `json:"rationale"`
	// Value of the variable being set
	Value string `json:"value"`
}

// TailoredProfileSpec defines the desired state of TailoredProfile
type TailoredProfileSpec struct {
	// +optional
	// Points to the name of the profile to extend
	Extends string `json:"extends,omitempty"`
	// Title for the tailored profile. It can't be empty.
	// +kubebuilder:validation:Pattern=^.+$
	Title string `json:"title"`
	// Description of tailored profile. It can't be empty.
	// +kubebuilder:validation:Pattern=^.+$
	Description string `json:"description"`
	// Enables the referenced rules
	// +optional
	// +nullable
	EnableRules []RuleReferenceSpec `json:"enableRules,omitempty"`
	// Disables the referenced rules
	// +optional
	// +nullable
	DisableRules []RuleReferenceSpec `json:"disableRules,omitempty"`
	// Disables the automated check on referenced rules for manual check
	// +optional
	// +nullable
	ManualRules []RuleReferenceSpec `json:"manualRules,omitempty"`
	// Sets the referenced variables to selected values
	// +optional
	// +nullable
	SetValues []VariableValueSpec `json:"setValues,omitempty"`
}

// TailoredProfileState defines the state fo the tailored profile
type TailoredProfileState string

const (
	// TailoredProfileStatePending is a state where a tailored profile is still pending to be processed
	TailoredProfileStatePending TailoredProfileState = "PENDING"
	// TailoredProfileStateReady is a state where a tailored profile is ready to be used
	TailoredProfileStateReady TailoredProfileState = "READY"
	// TailoredProfileStateError is a state where a tailored profile had an error while processing
	TailoredProfileStateError TailoredProfileState = "ERROR"
)

// TailoredProfileStatus defines the observed state of TailoredProfile
type TailoredProfileStatus struct {
	// The XCCDF ID of the tailored profile
	ID string `json:"id,omitempty"`
	// Points to the generated resource
	OutputRef OutputRef `json:"outputRef,omitempty"`
	// The current state of the tailored profile
	State        TailoredProfileState `json:"state,omitempty"`
	ErrorMessage string               `json:"errorMessage,omitempty"`
	Warnings     string               `json:"warnings,omitempty"`
}

// OutputRef is a reference to the object created from the tailored profile
type OutputRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// +kubebuilder:object:root=true

// TailoredProfile is the Schema for the tailoredprofiles API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=tailoredprofiles,scope=Namespaced,shortName=tp;tprof
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=`.status.state`,description="State of the tailored profile"
type TailoredProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TailoredProfileSpec   `json:"spec,omitempty"`
	Status TailoredProfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TailoredProfileList contains a list of TailoredProfile
type TailoredProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TailoredProfile `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TailoredProfile{}, &TailoredProfileList{})
}
