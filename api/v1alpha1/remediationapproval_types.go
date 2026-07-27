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

// RemediationApprovalSpec approves one current incident action.
type RemediationApprovalSpec struct {
	// IncidentRef pins the approval to one DeletionIncident incarnation.
	IncidentRef ObjectIdentityReference `json:"incidentRef"`
	// ActionID identifies one action in the incident's current status.
	// +kubebuilder:validation:MinLength=1
	ActionID string `json:"actionID"`
	// DryRun asks the API server to validate without persisting the mutation.
	DryRun bool `json:"dryRun,omitempty"`
	// Reason is the operator-provided justification for this approval.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Reason string `json:"reason"`
}

// RemediationAttempt is one bounded, sanitized executor audit entry.
type RemediationAttempt struct {
	// Time is when this attempt completed.
	Time metav1.Time `json:"time"`
	// ActionType is the operation attempted.
	ActionType RemediationActionType `json:"actionType"`
	// DryRun records whether persistence was disabled.
	DryRun bool `json:"dryRun"`
	// ResourceVersionBefore is the concurrency token validated before execution.
	ResourceVersionBefore string `json:"resourceVersionBefore,omitempty"`
	// ResourceVersionAfter is populated when the API returns a persisted version.
	ResourceVersionAfter string `json:"resourceVersionAfter,omitempty"`
	// Result is this attempt's outcome.
	Result ApprovalResult `json:"result"`
	// ErrorReason is a stable, non-sensitive API or validation reason.
	// +kubebuilder:validation:MaxLength=128
	ErrorReason string `json:"errorReason,omitempty"`
	// Message is a sanitized bounded explanation without resource contents.
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message,omitempty"`
}

// RemediationApprovalStatus is the executor-owned lifecycle and audit record.
type RemediationApprovalStatus struct {
	// Phase is the current approval lifecycle state.
	Phase ApprovalPhase `json:"phase,omitempty"`
	// Result is the latest or terminal execution result.
	Result ApprovalResult `json:"result,omitempty"`
	// ObservedGeneration is the immutable spec generation processed by the executor.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// StartedTime is when execution first began.
	StartedTime *metav1.Time `json:"startedTime,omitempty"`
	// CompletedTime is set for every terminal phase.
	CompletedTime *metav1.Time `json:"completedTime,omitempty"`
	// Action preserves the exact validated action before any mutation begins.
	Action *RemediationAction `json:"action,omitempty"`
	// Attempts retains at most the latest twenty execution attempts.
	// +kubebuilder:validation:MaxItems=20
	// +listType=atomic
	Attempts []RemediationAttempt `json:"attempts,omitempty"`
	// Conditions report validation, execution, and terminal state.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// RemediationApproval authorizes one policy-eligible action. Creating this object is the approval act.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=rapproval;ra
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Result",type=string,JSONPath=`.status.result`
// +kubebuilder:printcolumn:name="Incident",type=string,JSONPath=`.spec.incidentRef.name`
// +kubebuilder:printcolumn:name="DryRun",type=boolean,JSONPath=`.spec.dryRun`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type RemediationApproval struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
	Spec   RemediationApprovalSpec   `json:"spec"`
	Status RemediationApprovalStatus `json:"status,omitempty"`
}

// RemediationApprovalList contains RemediationApproval objects.
// +kubebuilder:object:root=true
type RemediationApprovalList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RemediationApproval `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RemediationApproval{}, &RemediationApprovalList{})
}
