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

import "k8s.io/apimachinery/pkg/types"

// RiskLevel describes the irreversible impact of a remediation action.
// +kubebuilder:validation:Enum=None;Low;Medium;High;Critical
type RiskLevel string

const (
	// RiskNone permits reporting but no mutation.
	RiskNone RiskLevel = "None"
	// RiskLow identifies actions with low expected impact.
	RiskLow RiskLevel = "Low"
	// RiskMedium identifies removal of an ordinary custom finalizer.
	RiskMedium RiskLevel = "Medium"
	// RiskHigh identifies protective or CRD finalizer removal.
	RiskHigh RiskLevel = "High"
	// RiskCritical identifies namespace force-finalization.
	RiskCritical RiskLevel = "Critical"
)

// IncidentPhase describes the current incident lifecycle state.
// +kubebuilder:validation:Enum=Active;DiagnosisFailed;Resolved
type IncidentPhase string

const (
	// IncidentPhaseActive means the target remains blocked.
	IncidentPhaseActive IncidentPhase = "Active"
	// IncidentPhaseDiagnosisFailed means current diagnosis is incomplete.
	IncidentPhaseDiagnosisFailed IncidentPhase = "DiagnosisFailed"
	// IncidentPhaseResolved means the target is gone or no longer monitored.
	IncidentPhaseResolved IncidentPhase = "Resolved"
)

// FindingType is a closed classification of deletion blockers.
// +kubebuilder:validation:Enum=BlockingFinalizer;RemainingResource;UnavailableAPIService;DiscoveryFailure;BlockingWebhook;MissingFinalizerController;DeletionGracePeriodExceeded;ResourceTypeRemoved;PolicyDisallowsRemediation;Unknown
type FindingType string

const (
	// FindingBlockingFinalizer identifies a finalizer preventing deletion.
	FindingBlockingFinalizer FindingType = "BlockingFinalizer"
	// FindingRemainingResource identifies content blocking namespace or CRD cleanup.
	FindingRemainingResource FindingType = "RemainingResource"
	// FindingUnavailableAPIService identifies failed aggregated API discovery.
	FindingUnavailableAPIService FindingType = "UnavailableAPIService"
	// FindingDiscoveryFailure identifies incomplete API discovery or enumeration.
	FindingDiscoveryFailure FindingType = "DiscoveryFailure"
	// FindingBlockingWebhook identifies a fail-closed webhook with an unavailable backend.
	FindingBlockingWebhook FindingType = "BlockingWebhook"
	// FindingMissingFinalizerController identifies an explicitly mapped unhealthy controller.
	FindingMissingFinalizerController FindingType = "MissingFinalizerController"
	// FindingDeletionGracePeriodExceeded identifies deletion beyond its grace period.
	FindingDeletionGracePeriodExceeded FindingType = "DeletionGracePeriodExceeded"
	// FindingResourceTypeRemoved identifies a target API removed from discovery.
	FindingResourceTypeRemoved FindingType = "ResourceTypeRemoved"
	// FindingPolicyDisallowsRemediation identifies a diagnosed but ineligible action.
	FindingPolicyDisallowsRemediation FindingType = "PolicyDisallowsRemediation"
	// FindingUnknown identifies a blocker that cannot be classified safely.
	FindingUnknown FindingType = "Unknown"
)

// RemediationActionType is an operation the executor can perform.
// +kubebuilder:validation:Enum=RemoveResourceFinalizer;RemoveCRDFinalizer;ForceFinalizeNamespace
type RemediationActionType string

const (
	// ActionRemoveResourceFinalizer removes one exact metadata finalizer.
	ActionRemoveResourceFinalizer RemediationActionType = "RemoveResourceFinalizer"
	// ActionRemoveCRDFinalizer removes the CRD cleanup metadata finalizer.
	ActionRemoveCRDFinalizer RemediationActionType = "RemoveCRDFinalizer"
	// ActionForceFinalizeNamespace clears namespace spec finalizers.
	ActionForceFinalizeNamespace RemediationActionType = "ForceFinalizeNamespace"
)

// ApprovalPhase describes the remediation approval lifecycle.
// +kubebuilder:validation:Enum=Pending;Running;Succeeded;DryRunSucceeded;Failed;Expired;Superseded
type ApprovalPhase string

const (
	// ApprovalPhasePending means execution has not begun.
	ApprovalPhasePending ApprovalPhase = "Pending"
	// ApprovalPhaseRunning means an execution attempt is active or retryable.
	ApprovalPhaseRunning ApprovalPhase = "Running"
	// ApprovalPhaseSucceeded means the approved state was achieved.
	ApprovalPhaseSucceeded ApprovalPhase = "Succeeded"
	// ApprovalPhaseDryRunSucceeded means API-server dry-run validation succeeded.
	ApprovalPhaseDryRunSucceeded ApprovalPhase = "DryRunSucceeded"
	// ApprovalPhaseFailed means execution ended with a permanent or exhausted failure.
	ApprovalPhaseFailed ApprovalPhase = "Failed"
	// ApprovalPhaseExpired means the policy approval TTL elapsed.
	ApprovalPhaseExpired ApprovalPhase = "Expired"
	// ApprovalPhaseSuperseded means the target or action changed before execution.
	ApprovalPhaseSuperseded ApprovalPhase = "Superseded"
)

// ApprovalResult is the terminal or latest result of approval execution.
// +kubebuilder:validation:Enum=Mutated;AlreadySatisfied;DryRunValidated;RejectedByPolicy;TargetReplaced;TargetChanged;APIError
type ApprovalResult string

const (
	// ApprovalResultMutated means the API server persisted the requested mutation.
	ApprovalResultMutated ApprovalResult = "Mutated"
	// ApprovalResultAlreadySatisfied means replay found the intended state already true.
	ApprovalResultAlreadySatisfied ApprovalResult = "AlreadySatisfied"
	// ApprovalResultDryRunValidated means the API server accepted a dry-run mutation.
	ApprovalResultDryRunValidated ApprovalResult = "DryRunValidated"
	// ApprovalResultRejectedByPolicy means current policy forbids the action.
	ApprovalResultRejectedByPolicy ApprovalResult = "RejectedByPolicy"
	// ApprovalResultTargetReplaced means the target name now has another UID.
	ApprovalResultTargetReplaced ApprovalResult = "TargetReplaced"
	// ApprovalResultTargetChanged means the approved action is no longer provable.
	ApprovalResultTargetChanged ApprovalResult = "TargetChanged"
	// ApprovalResultAPIError means Kubernetes rejected or failed the operation.
	ApprovalResultAPIError ApprovalResult = "APIError"
)

// TargetReference identifies one Kubernetes object through its stable UID and REST identity.
// +kubebuilder:validation:XValidation:rule="self.uid.size() > 0",message="uid must not be empty"
type TargetReference struct {
	// APIGroup is empty for the Kubernetes core API group.
	APIGroup string `json:"apiGroup,omitempty"`
	// Version is the served API version used for this observation.
	// +kubebuilder:validation:MinLength=1
	Version string `json:"version"`
	// Resource is the plural REST resource name.
	// +kubebuilder:validation:MinLength=1
	Resource string `json:"resource"`
	// Kind is the Kubernetes Kind reported by discovery.
	// +kubebuilder:validation:MinLength=1
	Kind string `json:"kind"`
	// Namespace is empty for cluster-scoped resources.
	Namespace string `json:"namespace,omitempty"`
	// Name is the object name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// UID prevents a same-name replacement from receiving an old mutation.
	UID types.UID `json:"uid"`
}

// ObjectIdentityReference identifies a cluster-scoped API object by name and UID.
// +kubebuilder:validation:XValidation:rule="self.uid.size() > 0",message="uid must not be empty"
type ObjectIdentityReference struct {
	// Name is the referenced object's name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// UID pins the reference to one object incarnation.
	UID types.UID `json:"uid"`
}

// PolicyReference identifies the active policy revision used by a diagnosis.
type PolicyReference struct {
	// Name is the policy name.
	Name string `json:"name"`
	// UID pins the policy incarnation.
	UID types.UID `json:"uid"`
	// Generation is the policy generation used to classify actions.
	Generation int64 `json:"generation"`
}

// ControllerReference identifies an explicitly configured finalizer owner.
type ControllerReference struct {
	// APIVersion must identify the apps API used by the controller workload.
	// +kubebuilder:validation:Enum=apps/v1
	APIVersion string `json:"apiVersion"`
	// Kind is a supported controller workload.
	// +kubebuilder:validation:Enum=Deployment;StatefulSet;DaemonSet
	Kind string `json:"kind"`
	// Namespace contains the controller workload.
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// Name is the controller workload name.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// Finding is one deterministic diagnostic observation.
type Finding struct {
	// ID is stable while the same evidence remains present.
	// +kubebuilder:validation:MinLength=1
	ID string `json:"id"`
	// Type classifies the observation.
	Type FindingType `json:"type"`
	// Message is a bounded human-readable explanation.
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message"`
	// ResourceRef identifies a related blocking object.
	ResourceRef *TargetReference `json:"resourceRef,omitempty"`
	// Finalizer is the exact blocking finalizer.
	Finalizer string `json:"finalizer,omitempty"`
	// APIService is an unavailable aggregated API service name.
	APIService string `json:"apiService,omitempty"`
	// Webhook is a matching admission webhook configuration/name pair.
	Webhook string `json:"webhook,omitempty"`
	// ControllerRef is the configured owner whose health was evaluated.
	ControllerRef *ControllerReference `json:"controllerRef,omitempty"`
	// Count summarizes repeated evidence when individual entries are omitted.
	// +kubebuilder:validation:Minimum=0
	Count *int32 `json:"count,omitempty"`
	// Truncated states that diagnosis stopped at a configured safety limit.
	Truncated bool `json:"truncated,omitempty"`
}

// TargetSnapshot stores mutation preconditions observed during diagnosis.
type TargetSnapshot struct {
	// ResourceVersion is the API concurrency token observed by the scanner.
	ResourceVersion string `json:"resourceVersion,omitempty"`
	// MetadataFinalizers is the complete metadata finalizer set.
	// +listType=set
	MetadataFinalizers []string `json:"metadataFinalizers,omitempty"`
	// NamespaceFinalizers is populated from Namespace spec.finalizers.
	// +listType=set
	NamespaceFinalizers []string `json:"namespaceFinalizers,omitempty"`
}

// RemediationAction is one policy-classified operation available for approval.
type RemediationAction struct {
	// ID is a deterministic digest of action type, target UID, finalizer, target resource version, policy UID, and policy generation.
	// +kubebuilder:validation:MinLength=1
	ID string `json:"id"`
	// Type selects the executor operation.
	Type RemediationActionType `json:"type"`
	// Risk is fixed by the operator and cannot be lowered by policy.
	Risk RiskLevel `json:"risk"`
	// Target pins the operation to one object UID.
	Target TargetReference `json:"target"`
	// Finalizer is required by finalizer-removal actions.
	Finalizer string `json:"finalizer,omitempty"`
	// Eligible records whether the active policy permits approval.
	Eligible bool `json:"eligible"`
	// IneligibleReason explains a policy or evidence restriction.
	// +kubebuilder:validation:MaxLength=512
	IneligibleReason string `json:"ineligibleReason,omitempty"`
	// PreconditionResourceVersion is the version observed during diagnosis.
	PreconditionResourceVersion string `json:"preconditionResourceVersion,omitempty"`
	// Reason explains why this action addresses the finding.
	// +kubebuilder:validation:MaxLength=1024
	Reason string `json:"reason"`
}
