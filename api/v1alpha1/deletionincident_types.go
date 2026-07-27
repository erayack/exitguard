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

// DeletionIncidentSpec pins an incident to one target incarnation.
type DeletionIncidentSpec struct {
	// Target is the deleting Kubernetes object.
	Target TargetReference `json:"target"`
	// FirstObservedTime is when the scanner first observed the target past its threshold.
	FirstObservedTime metav1.Time `json:"firstObservedTime"`
}

// DeletionIncidentStatus contains scanner-owned diagnosis state.
type DeletionIncidentStatus struct {
	// Phase is the current incident lifecycle state.
	Phase IncidentPhase `json:"phase,omitempty"`
	// ActivePolicyRef is the current winning policy and generation.
	ActivePolicyRef *PolicyReference `json:"activePolicyRef,omitempty"`
	// DeletionTimestamp is copied from the current target.
	DeletionTimestamp *metav1.Time `json:"deletionTimestamp,omitempty"`
	// LastObservedTime is periodically refreshed while the target remains visible.
	LastObservedTime *metav1.Time `json:"lastObservedTime,omitempty"`
	// ActionEvidenceTime is when the evidence backing RecommendedActions was last refreshed.
	ActionEvidenceTime *metav1.Time `json:"actionEvidenceTime,omitempty"`
	// ActionEvidenceExpiresTime is the fail-closed deadline for executing RecommendedActions.
	ActionEvidenceExpiresTime *metav1.Time `json:"actionEvidenceExpiresTime,omitempty"`
	// ResolvedTime is set when the target disappears or leaves monitoring scope.
	ResolvedTime *metav1.Time `json:"resolvedTime,omitempty"`
	// ResolutionReason explains why the incident became resolved.
	// +kubebuilder:validation:MaxLength=512
	ResolutionReason string `json:"resolutionReason,omitempty"`
	// TargetSnapshot contains the exact mutation preconditions observed by diagnosis.
	TargetSnapshot TargetSnapshot `json:"targetSnapshot,omitempty"`
	// Findings are deterministic, current diagnostic observations.
	// +kubebuilder:validation:MaxItems=513
	// +listType=map
	// +listMapKey=id
	Findings []Finding `json:"findings,omitempty"`
	// RecommendedActions are policy-classified operations available for approval.
	// +kubebuilder:validation:MaxItems=256
	// +listType=map
	// +listMapKey=id
	RecommendedActions []RemediationAction `json:"recommendedActions,omitempty"`
	// Conditions report target visibility and diagnosis completeness.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// DeletionIncident is a durable diagnosis of one deleting object UID.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=dincident;di
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Kind",type=string,JSONPath=`.spec.target.kind`
// +kubebuilder:printcolumn:name="Namespace",type=string,JSONPath=`.spec.target.namespace`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.target.name`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type DeletionIncident struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
	Spec   DeletionIncidentSpec   `json:"spec"`
	Status DeletionIncidentStatus `json:"status,omitempty"`
}

// DeletionIncidentList contains DeletionIncident objects.
// +kubebuilder:object:root=true
type DeletionIncidentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DeletionIncident `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DeletionIncident{}, &DeletionIncidentList{})
}
