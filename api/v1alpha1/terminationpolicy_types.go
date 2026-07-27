// Copyright 2026 The ExitGuard Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// TargetRule selects REST resources and objects monitored by a TerminationPolicy.
type TargetRule struct {
	// APIGroups contains API group names. The empty string means core and "*" means all groups.
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	APIGroups []string `json:"apiGroups"`
	// Resources contains plural REST resource names. "*" means all eligible resources.
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	Resources []string `json:"resources"`
	// NamespaceSelector selects namespaces for namespaced targets.
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// ObjectSelector selects targets by object labels.
	ObjectSelector *metav1.LabelSelector `json:"objectSelector,omitempty"`
	// ExcludedNamespaces is an exact namespace denylist for namespaced targets.
	// +listType=set
	ExcludedNamespaces []string `json:"excludedNamespaces,omitempty"`
}

// DiagnosisPolicy controls bounded diagnostic checks.
type DiagnosisPolicy struct {
	// CheckAPIServices enables aggregated API availability diagnosis.
	// +kubebuilder:default=true
	CheckAPIServices bool `json:"checkAPIServices"`
	// CheckWebhooks enables fail-closed admission webhook diagnosis.
	// +kubebuilder:default=true
	CheckWebhooks bool `json:"checkWebhooks"`
	// MaxNamespaceObjects bounds objects enumerated in one terminating namespace.
	// +kubebuilder:default=5000
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100000
	MaxNamespaceObjects int32 `json:"maxNamespaceObjects"`
	// MaxCRDInstances bounds custom-resource instances enumerated for one terminating CRD.
	// +kubebuilder:default=5000
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100000
	MaxCRDInstances int32 `json:"maxCRDInstances"`
}

// FinalizerOwner maps an exact finalizer to the workload responsible for it.
type FinalizerOwner struct {
	// Finalizer is an exact finalizer key. Wildcards are not supported.
	// +kubebuilder:validation:MinLength=1
	Finalizer string `json:"finalizer"`
	// ControllerRef identifies the workload whose availability should be checked.
	ControllerRef ControllerReference `json:"controllerRef"`
}

// RemediationPolicy constrains approval eligibility. Every mutation still requires an approval.
type RemediationPolicy struct {
	// MaxRisk is the highest action risk eligible for approval.
	// +kubebuilder:default=None
	MaxRisk RiskLevel `json:"maxRisk"`
	// AllowedFinalizers is an exact allowlist. Wildcards are not supported.
	// +listType=set
	AllowedFinalizers []string `json:"allowedFinalizers,omitempty"`
	// AllowNamespaceForce permits Critical namespace force-finalization actions.
	// +kubebuilder:default=false
	AllowNamespaceForce bool `json:"allowNamespaceForce"`
	// ApprovalTTL is measured from RemediationApproval creation time.
	// +kubebuilder:default="1h"
	// +kubebuilder:validation:XValidation:rule="duration(self) > duration('0s')",message="approvalTTL must be positive"
	ApprovalTTL metav1.Duration `json:"approvalTTL"`
}

// RetentionPolicy controls resolved incident retention.
type RetentionPolicy struct {
	// ResolvedIncidentTTL controls how long resolved incidents and owned approvals remain.
	// +kubebuilder:default="720h"
	// +kubebuilder:validation:XValidation:rule="duration(self) > duration('0s')",message="resolvedIncidentTTL must be positive"
	ResolvedIncidentTTL metav1.Duration `json:"resolvedIncidentTTL"`
}

// TerminationPolicySpec selects targets and sets diagnosis and remediation limits.
type TerminationPolicySpec struct {
	// Priority selects the winning policy; higher values win and names break ties.
	// +kubebuilder:default=0
	Priority int32 `json:"priority"`
	// TargetRules are ORed; selectors within a rule are ANDed.
	// +kubebuilder:validation:MinItems=1
	TargetRules []TargetRule `json:"targetRules"`
	// TerminationAge is the minimum deletion age before a new incident is created.
	// +kubebuilder:default="10m"
	// +kubebuilder:validation:XValidation:rule="duration(self) > duration('0s')",message="terminationAge must be positive"
	TerminationAge metav1.Duration `json:"terminationAge"`
	// Diagnosis configures bounded, read-only evidence collection.
	// +kubebuilder:default={checkAPIServices:true,checkWebhooks:true,maxCRDInstances:5000,maxNamespaceObjects:5000}
	Diagnosis DiagnosisPolicy `json:"diagnosis"`
	// FinalizerOwners contains exact, deterministic finalizer ownership mappings.
	// +listType=map
	// +listMapKey=finalizer
	FinalizerOwners []FinalizerOwner `json:"finalizerOwners,omitempty"`
	// Remediation limits action eligibility but never triggers automatic mutation.
	// +kubebuilder:default={allowNamespaceForce:false,approvalTTL:"1h",maxRisk:None}
	Remediation RemediationPolicy `json:"remediation"`
	// Retention controls cleanup of resolved incidents.
	// +kubebuilder:default={resolvedIncidentTTL:"720h"}
	Retention RetentionPolicy `json:"retention"`
}

// TerminationPolicyStatus reports policy compilation and discovery readiness.
type TerminationPolicyStatus struct {
	// ObservedGeneration is the latest policy generation compiled by the scanner.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Conditions report Ready, DiscoveryResolved, and SelectorsValid state.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// LastValidatedTime is the latest completed validation.
	LastValidatedTime *metav1.Time `json:"lastValidatedTime,omitempty"`
	// ResolvedResourceCount is the number of GroupResources selected by discovery.
	// +kubebuilder:validation:Minimum=0
	ResolvedResourceCount int32 `json:"resolvedResourceCount,omitempty"`
}

// TerminationPolicy declares which deleting resources to diagnose and which actions may be approved.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=tpolicy;tp
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Resources",type=integer,JSONPath=`.status.resolvedResourceCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type TerminationPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TerminationPolicySpec   `json:"spec"`
	Status TerminationPolicyStatus `json:"status,omitempty"`
}

// TerminationPolicyList contains TerminationPolicy objects.
// +kubebuilder:object:root=true
type TerminationPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TerminationPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TerminationPolicy{}, &TerminationPolicyList{})
}
