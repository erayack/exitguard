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

// Package executor implements approval-gated, preconditioned remediation.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
	policyengine "github.com/erayack/exitguard/internal/policy"
)

const (
	maxAuditAttempts  = 20
	retryDelay        = 5 * time.Second
	apiFailureMessage = "Kubernetes API request failed"
)

// Catalog supplies the latest complete discovery snapshot for policy revalidation.
type Catalog interface {
	Snapshot() catalogdiscovery.Snapshot
}

type namespaceFinalizer interface {
	Finalize(context.Context, *corev1.Namespace, metav1.UpdateOptions) (*corev1.Namespace, error)
}

// Reconciler executes only actions named by immutable RemediationApproval objects.
type Reconciler struct {
	reader      client.Reader
	writer      client.Client
	dynamic     dynamic.Interface
	namespaces  namespaceFinalizer
	catalog     Catalog
	recorder    events.EventRecorder
	maxAttempts int
	now         func() time.Time
	locks       *keyedLocks
}

// NewReconciler creates an executor with bounded retries.
func NewReconciler(reader client.Reader, writer client.Client, dynamicClient dynamic.Interface, kubeClient kubernetes.Interface, catalog Catalog, recorder events.EventRecorder, maxAttempts int) (*Reconciler, error) {
	if reader == nil || writer == nil || dynamicClient == nil || kubeClient == nil || catalog == nil || recorder == nil {
		return nil, errors.New("executor reader, writer, dynamic client, kubernetes client, catalog, and recorder are required")
	}
	if maxAttempts <= 0 || maxAttempts > 5 {
		return nil, errors.New("executor max attempts must be between 1 and 5")
	}
	return &Reconciler{reader: reader, writer: writer, dynamic: dynamicClient, namespaces: kubeClient.CoreV1().Namespaces(), catalog: catalog, recorder: recorder, maxAttempts: maxAttempts, now: time.Now, locks: newKeyedLocks()}, nil
}

// SetupWithManager registers the approval controller independently of scanner incident writes.
func (r *Reconciler) SetupWithManager(manager ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(manager).For(&safetyv1alpha1.RemediationApproval{}).Complete(r)
}

// Reconcile validates an approval in fail-closed order and executes at most one recorded attempt.
func (r *Reconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	var approval safetyv1alpha1.RemediationApproval
	if err := r.reader.Get(ctx, request.NamespacedName, &approval); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if terminal(approval.Status.Phase) {
		return ctrl.Result{}, nil
	}

	var incident safetyv1alpha1.DeletionIncident
	if err := r.reader.Get(ctx, client.ObjectKey{Name: approval.Spec.IncidentRef.Name}, &incident); err != nil {
		if apierrors.IsNotFound(err) {
			return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultTargetChanged, "IncidentNotFound", "referenced incident no longer exists")
		}
		return ctrl.Result{}, err
	}
	if incident.UID != approval.Spec.IncidentRef.UID {
		return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultTargetChanged, "IncidentReplaced", "referenced incident UID does not match")
	}
	if err := r.ensureOwnerReference(ctx, approval.Name, &incident); err != nil {
		return ctrl.Result{}, err
	}

	currentAction := findAction(incident.Status.RecommendedActions, approval.Spec.ActionID)
	action := currentAction
	replayVerification := false
	if approval.Status.Action != nil {
		action = approval.Status.Action
		replayVerification = currentAction == nil || !reflect.DeepEqual(*currentAction, *approval.Status.Action)
	}
	if action == nil || action.ID != approval.Spec.ActionID {
		return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultTargetChanged, "ActionChanged", "approved action is not current")
	}
	if !actionBelongsToIncident(action, incident.Spec.Target) {
		return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultTargetChanged, "ActionTargetChanged", "approved action is not bound to the incident target")
	}
	if incident.Status.Phase != safetyv1alpha1.IncidentPhaseActive || incident.Status.ActivePolicyRef == nil {
		if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseRunning || approval.Status.Action == nil {
			return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultTargetChanged, "IncidentInactive", "incident is not active")
		}
		replayVerification = true
	}
	if !replayVerification && !actionEvidenceCurrent(incident.Status, r.now().UTC()) {
		return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultTargetChanged, "EvidenceExpired", "the diagnosis evidence backing the approved action is stale")
	}

	var policy *policyengine.CompiledPolicy
	var policyRef *safetyv1alpha1.PolicyReference
	var expires time.Time
	if !replayVerification {
		var source safetyv1alpha1.TerminationPolicy
		if err := r.reader.Get(ctx, client.ObjectKey{Name: incident.Status.ActivePolicyRef.Name}, &source); err != nil {
			if apierrors.IsNotFound(err) {
				return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseFailed, safetyv1alpha1.ApprovalResultRejectedByPolicy, "PolicyNotFound", "active policy no longer exists")
			}
			return ctrl.Result{}, err
		}
		policyRef = incident.Status.ActivePolicyRef.DeepCopy()
		if source.UID != policyRef.UID || source.Generation != policyRef.Generation {
			return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultRejectedByPolicy, "PolicyChanged", "active policy revision changed")
		}
		policy, _ = policyengine.Compile(&source, r.catalog.Snapshot(), r.now().UTC())
		if !policy.Ready() {
			return ctrl.Result{}, errors.New("current policy cannot be safely compiled")
		}
		expires = approval.CreationTimestamp.Add(policy.Settings().ApprovalTTL)
		if !r.now().UTC().Before(expires) {
			return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseExpired, safetyv1alpha1.ApprovalResultRejectedByPolicy, "ApprovalExpired", "approval TTL elapsed")
		}
		if !action.Eligible {
			return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseFailed, safetyv1alpha1.ApprovalResultRejectedByPolicy, "ActionIneligible", "action is not eligible")
		}
		eligible, reason := policy.ActionEligibility(action.Type, action.Finalizer)
		if !eligible {
			return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseFailed, safetyv1alpha1.ApprovalResultRejectedByPolicy, "RejectedByPolicy", reason)
		}
		if policyengine.RiskFor(action.Type, action.Finalizer) != action.Risk {
			return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultRejectedByPolicy, "RiskChanged", "action risk does not match operator classification")
		}
	}

	unlock := r.locks.lock(targetKey(action.Target))
	defer unlock()
	if err := r.reader.Get(ctx, request.NamespacedName, &approval); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if terminal(approval.Status.Phase) {
		return ctrl.Result{}, nil
	}

	var lockedIncident safetyv1alpha1.DeletionIncident
	lockedIncidentErr := r.reader.Get(ctx, client.ObjectKey{Name: approval.Spec.IncidentRef.Name}, &lockedIncident)
	if lockedIncidentErr != nil && !apierrors.IsNotFound(lockedIncidentErr) {
		return ctrl.Result{}, lockedIncidentErr
	}
	if replayVerification {
		if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseRunning || approval.Status.Action == nil || !reflect.DeepEqual(*approval.Status.Action, *action) {
			return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultTargetChanged, "ReplayStateChanged", "durable action snapshot is unavailable")
		}
		if lockedIncidentErr == nil && lockedIncident.UID != incident.UID {
			return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultTargetChanged, "IncidentReplaced", "referenced incident changed during replay")
		}
		attempt, outcome, satisfied, err := r.verifySatisfied(ctx, action, approval.Spec.DryRun)
		attempt.Time = metav1.NewTime(r.now().UTC())
		attempt.ActionType = action.Type
		attempt.DryRun = approval.Spec.DryRun
		if err != nil {
			return ctrl.Result{}, err
		}
		if !satisfied {
			return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, outcome, "ReplayNotSatisfied", "incident changed and the approved action is not already satisfied")
		}
		attempt.Result = outcome
		if err := r.recordTerminalAttempt(ctx, approval.Name, attempt, safetyv1alpha1.ApprovalPhaseSucceeded, outcome); err != nil {
			return ctrl.Result{}, err
		}
		remediations.WithLabelValues(string(action.Type), string(action.Risk), string(outcome), strconv.FormatBool(approval.Spec.DryRun)).Inc()
		return ctrl.Result{}, nil
	}

	if !r.now().UTC().Before(expires) {
		return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseExpired, safetyv1alpha1.ApprovalResultRejectedByPolicy, "ApprovalExpired", "approval TTL elapsed while waiting for target lock")
	}
	if lockedIncidentErr != nil || lockedIncident.UID != incident.UID || lockedIncident.Status.Phase != safetyv1alpha1.IncidentPhaseActive || !reflect.DeepEqual(lockedIncident.Status.ActivePolicyRef, policyRef) {
		return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultTargetChanged, "IncidentChanged", "incident changed while waiting for target lock")
	}
	if !actionEvidenceCurrent(lockedIncident.Status, r.now().UTC()) {
		return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultTargetChanged, "EvidenceExpired", "diagnosis evidence expired while waiting for the target lock")
	}
	lockedAction := findAction(lockedIncident.Status.RecommendedActions, approval.Spec.ActionID)
	if lockedAction == nil || !reflect.DeepEqual(*lockedAction, *action) {
		return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultTargetChanged, "ActionChanged", "incident action changed while waiting for target lock")
	}

	var lockedSource safetyv1alpha1.TerminationPolicy
	if err := r.reader.Get(ctx, client.ObjectKey{Name: policyRef.Name}, &lockedSource); err != nil {
		if apierrors.IsNotFound(err) {
			return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseFailed, safetyv1alpha1.ApprovalResultRejectedByPolicy, "PolicyNotFound", "active policy no longer exists")
		}
		return ctrl.Result{}, err
	}
	if lockedSource.UID != policyRef.UID || lockedSource.Generation != policyRef.Generation {
		return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseSuperseded, safetyv1alpha1.ApprovalResultRejectedByPolicy, "PolicyChanged", "active policy revision changed while waiting for target lock")
	}
	policy, _ = policyengine.Compile(&lockedSource, r.catalog.Snapshot(), r.now().UTC())
	if !policy.Ready() {
		return ctrl.Result{}, errors.New("current policy cannot be safely compiled after target lock")
	}
	expires = approval.CreationTimestamp.Add(policy.Settings().ApprovalTTL)
	if !r.now().UTC().Before(expires) {
		return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseExpired, safetyv1alpha1.ApprovalResultRejectedByPolicy, "ApprovalExpired", "approval TTL elapsed during final validation")
	}
	action = lockedAction
	if len(approval.Status.Attempts) >= r.maxAttempts {
		return r.finish(ctx, &approval, safetyv1alpha1.ApprovalPhaseFailed, safetyv1alpha1.ApprovalResultAPIError, "AttemptsExhausted", "maximum remediation attempts exhausted")
	}
	if err := r.markRunning(ctx, &approval, action); err != nil {
		return ctrl.Result{}, err
	}

	attempt, outcome, err := r.execute(ctx, action, &lockedIncident.Spec.Target, policy, approval.Spec.DryRun)
	attempt.Time = metav1.NewTime(r.now().UTC())
	attempt.ActionType = action.Type
	attempt.DryRun = approval.Spec.DryRun
	if err == nil {
		attempt.Result = outcome
		phase := safetyv1alpha1.ApprovalPhaseSucceeded
		if approval.Spec.DryRun {
			phase = safetyv1alpha1.ApprovalPhaseDryRunSucceeded
		}
		if statusErr := r.recordTerminalAttempt(ctx, approval.Name, attempt, phase, outcome); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		remediations.WithLabelValues(string(action.Type), string(action.Risk), string(outcome), strconv.FormatBool(approval.Spec.DryRun)).Inc()
		r.recorder.Eventf(&approval, nil, corev1.EventTypeNormal, "RemediationCompleted", "ExecuteRemediation", "%s completed with %s", action.Type, outcome)
		return ctrl.Result{}, nil
	}
	var terminalErr terminalExecutionError
	if errors.As(err, &terminalErr) {
		attempt.Result = terminalErr.result
		attempt.ErrorReason = terminalErr.reason
		attempt.Message = sanitize(terminalErr.message, 1024)
		if statusErr := r.recordTerminalAttempt(ctx, approval.Name, attempt, terminalErr.phase, terminalErr.result); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		remediations.WithLabelValues(string(action.Type), string(action.Risk), string(terminalErr.result), strconv.FormatBool(approval.Spec.DryRun)).Inc()
		r.recorder.Eventf(&approval, nil, corev1.EventTypeWarning, "RemediationRejected", "ExecuteRemediation", "%s ended with %s", action.Type, terminalErr.result)
		return ctrl.Result{}, nil
	}
	attempt.Result = safetyv1alpha1.ApprovalResultAPIError
	attempt.ErrorReason = errorReason(err)
	attempt.Message = apiFailureMessage
	if statusErr := r.recordRetryAttempt(ctx, approval.Name, attempt); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	remediations.WithLabelValues(string(action.Type), string(action.Risk), string(safetyv1alpha1.ApprovalResultAPIError), strconv.FormatBool(approval.Spec.DryRun)).Inc()
	if !transient(err) || len(approval.Status.Attempts)+1 >= r.maxAttempts {
		return ctrl.Result{}, r.finishByName(ctx, approval.Name, safetyv1alpha1.ApprovalPhaseFailed, safetyv1alpha1.ApprovalResultAPIError, errorReason(err), "remediation failed")
	}
	remaining := expires.Sub(r.now().UTC())
	if remaining <= 0 {
		return ctrl.Result{}, r.finishByName(ctx, approval.Name, safetyv1alpha1.ApprovalPhaseExpired, safetyv1alpha1.ApprovalResultAPIError, "ApprovalExpired", "approval expired after a failed attempt")
	}
	delay := retryDelay
	if seconds, suggested := apierrors.SuggestsClientDelay(err); suggested {
		suggestedDelay := time.Duration(seconds) * time.Second
		if suggestedDelay > delay {
			delay = suggestedDelay
		}
	}
	if remaining < delay {
		delay = remaining
	}
	return ctrl.Result{RequeueAfter: delay}, nil
}

func (r *Reconciler) execute(ctx context.Context, action *safetyv1alpha1.RemediationAction, incidentTarget *safetyv1alpha1.TargetReference, policy *policyengine.CompiledPolicy, dryRun bool) (safetyv1alpha1.RemediationAttempt, safetyv1alpha1.ApprovalResult, error) {
	current, gvr, err := r.getCurrent(ctx, action.Target)
	if apierrors.IsNotFound(err) || apierrors.IsGone(err) {
		return safetyv1alpha1.RemediationAttempt{}, safetyv1alpha1.ApprovalResultAlreadySatisfied, nil
	}
	if err != nil {
		return safetyv1alpha1.RemediationAttempt{}, "", err
	}
	attempt := safetyv1alpha1.RemediationAttempt{ResourceVersionBefore: current.GetResourceVersion()}
	if current.GetUID() != action.Target.UID {
		return attempt, safetyv1alpha1.ApprovalResultTargetReplaced, terminalExecutionError{phase: safetyv1alpha1.ApprovalPhaseSuperseded, result: safetyv1alpha1.ApprovalResultTargetReplaced, reason: "TargetReplaced", message: "target UID changed"}
	}
	matches, err := r.currentPolicyMatches(ctx, current, action, incidentTarget, policy)
	if err != nil {
		return attempt, "", err
	}
	if !matches {
		return attempt, safetyv1alpha1.ApprovalResultRejectedByPolicy, terminalExecutionError{phase: safetyv1alpha1.ApprovalPhaseSuperseded, result: safetyv1alpha1.ApprovalResultRejectedByPolicy, reason: "PolicyNoLongerMatches", message: "current policy no longer selects target"}
	}

	switch action.Type {
	case safetyv1alpha1.ActionRemoveResourceFinalizer, safetyv1alpha1.ActionRemoveCRDFinalizer:
		if action.Type == safetyv1alpha1.ActionRemoveCRDFinalizer && (action.Target.APIGroup != "apiextensions.k8s.io" || action.Target.Resource != "customresourcedefinitions") {
			return attempt, "", terminalExecutionError{phase: safetyv1alpha1.ApprovalPhaseFailed, result: safetyv1alpha1.ApprovalResultRejectedByPolicy, reason: "InvalidAction", message: "CRD finalizer action target is invalid"}
		}
		index := slices.Index(current.GetFinalizers(), action.Finalizer)
		if index < 0 {
			return attempt, safetyv1alpha1.ApprovalResultAlreadySatisfied, nil
		}
		if current.GetResourceVersion() != action.PreconditionResourceVersion {
			return attempt, safetyv1alpha1.ApprovalResultTargetChanged, terminalExecutionError{phase: safetyv1alpha1.ApprovalPhaseSuperseded, result: safetyv1alpha1.ApprovalResultTargetChanged, reason: "TargetChanged", message: "target resourceVersion changed"}
		}
		patch, err := finalizerPatch(current, index)
		if err != nil {
			return attempt, "", err
		}
		options := metav1.PatchOptions{}
		if dryRun {
			options.DryRun = []string{metav1.DryRunAll}
		}
		updated, err := r.dynamic.Resource(gvr).Namespace(action.Target.Namespace).Patch(ctx, action.Target.Name, types.JSONPatchType, patch, options)
		if err != nil {
			return attempt, "", err
		}
		attempt.ResourceVersionAfter = updated.GetResourceVersion()
		if dryRun {
			return attempt, safetyv1alpha1.ApprovalResultDryRunValidated, nil
		}
		return attempt, safetyv1alpha1.ApprovalResultMutated, nil
	case safetyv1alpha1.ActionForceFinalizeNamespace:
		if action.Target.APIGroup != "" || action.Target.Resource != "namespaces" || action.Target.Namespace != "" {
			return attempt, "", terminalExecutionError{phase: safetyv1alpha1.ApprovalPhaseFailed, result: safetyv1alpha1.ApprovalResultRejectedByPolicy, reason: "InvalidAction", message: "namespace finalize target is invalid"}
		}
		finalizers, found, nestedErr := unstructured.NestedStringSlice(current.Object, "spec", "finalizers")
		if nestedErr != nil {
			return attempt, "", nestedErr
		}
		if !found || len(finalizers) == 0 {
			return attempt, safetyv1alpha1.ApprovalResultAlreadySatisfied, nil
		}
		if current.GetResourceVersion() != action.PreconditionResourceVersion {
			return attempt, safetyv1alpha1.ApprovalResultTargetChanged, terminalExecutionError{phase: safetyv1alpha1.ApprovalPhaseSuperseded, result: safetyv1alpha1.ApprovalResultTargetChanged, reason: "TargetChanged", message: "target resourceVersion changed"}
		}
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: current.GetName(), UID: current.GetUID(), ResourceVersion: current.GetResourceVersion()}}
		namespace.Spec.Finalizers = nil
		options := metav1.UpdateOptions{}
		if dryRun {
			options.DryRun = []string{metav1.DryRunAll}
		}
		updated, err := r.namespaces.Finalize(ctx, namespace, options)
		if err != nil {
			return attempt, "", err
		}
		attempt.ResourceVersionAfter = updated.ResourceVersion
		if dryRun {
			return attempt, safetyv1alpha1.ApprovalResultDryRunValidated, nil
		}
		return attempt, safetyv1alpha1.ApprovalResultMutated, nil
	default:
		return attempt, "", terminalExecutionError{phase: safetyv1alpha1.ApprovalPhaseFailed, result: safetyv1alpha1.ApprovalResultRejectedByPolicy, reason: "UnsupportedAction", message: "action type is not supported"}
	}
}

func (r *Reconciler) getCurrent(ctx context.Context, target safetyv1alpha1.TargetReference) (*unstructured.Unstructured, schema.GroupVersionResource, error) {
	groupResource := schema.GroupResource{Group: target.APIGroup, Resource: target.Resource}
	resource, found := r.catalog.Snapshot().Resolve(groupResource)
	if !found {
		gvr := groupResource.WithVersion(target.Version)
		current, err := r.dynamic.Resource(gvr).Namespace(target.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
		return current, gvr, err
	}
	var lastUnavailable error
	for _, version := range resource.OrderedVersions(target.Version) {
		gvr := groupResource.WithVersion(version.Version)
		current, err := r.dynamic.Resource(gvr).Namespace(target.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
		if err == nil {
			return current, gvr, nil
		}
		if !apierrors.IsNotFound(err) && !apierrors.IsGone(err) {
			return nil, gvr, err
		}
		lastUnavailable = err
	}
	return nil, groupResource.WithVersion(target.Version), lastUnavailable
}

func (r *Reconciler) verifySatisfied(ctx context.Context, action *safetyv1alpha1.RemediationAction, dryRun bool) (safetyv1alpha1.RemediationAttempt, safetyv1alpha1.ApprovalResult, bool, error) {
	if dryRun {
		return safetyv1alpha1.RemediationAttempt{}, safetyv1alpha1.ApprovalResultTargetChanged, false, nil
	}
	current, _, err := r.getCurrent(ctx, action.Target)
	if apierrors.IsNotFound(err) || apierrors.IsGone(err) {
		return safetyv1alpha1.RemediationAttempt{}, safetyv1alpha1.ApprovalResultAlreadySatisfied, true, nil
	}
	if err != nil {
		return safetyv1alpha1.RemediationAttempt{}, "", false, err
	}
	attempt := safetyv1alpha1.RemediationAttempt{ResourceVersionBefore: current.GetResourceVersion()}
	if current.GetUID() != action.Target.UID {
		return attempt, safetyv1alpha1.ApprovalResultTargetReplaced, false, nil
	}
	switch action.Type {
	case safetyv1alpha1.ActionRemoveResourceFinalizer, safetyv1alpha1.ActionRemoveCRDFinalizer:
		return attempt, safetyv1alpha1.ApprovalResultAlreadySatisfied, !slices.Contains(current.GetFinalizers(), action.Finalizer), nil
	case safetyv1alpha1.ActionForceFinalizeNamespace:
		finalizers, found, err := unstructured.NestedStringSlice(current.Object, "spec", "finalizers")
		if err != nil {
			return attempt, "", false, err
		}
		return attempt, safetyv1alpha1.ApprovalResultAlreadySatisfied, !found || len(finalizers) == 0, nil
	default:
		return attempt, safetyv1alpha1.ApprovalResultRejectedByPolicy, false, nil
	}
}

func (r *Reconciler) currentPolicyMatches(ctx context.Context, current *unstructured.Unstructured, action *safetyv1alpha1.RemediationAction, incidentTarget *safetyv1alpha1.TargetReference, policy *policyengine.CompiledPolicy) (bool, error) {
	if policy == nil || incidentTarget == nil {
		return false, errors.New("compiled policy and incident target are required")
	}
	groupResource := schema.GroupResource{Group: incidentTarget.APIGroup, Resource: incidentTarget.Resource}
	resource, found := r.catalog.Snapshot().Resolve(groupResource)
	if !found {
		return false, nil
	}
	policyObject := current
	if !sameTargetIdentity(action.Target, *incidentTarget) {
		var err error
		policyObject, _, err = r.getCurrent(ctx, *incidentTarget)
		if apierrors.IsNotFound(err) || apierrors.IsGone(err) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("get incident target: %w", err)
		}
		if policyObject.GetUID() != incidentTarget.UID {
			return false, nil
		}
	}
	namespaceLabels := map[string]string(nil)
	if resource.PreferredVersion.Namespaced {
		namespace, err := r.dynamic.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}).Get(ctx, incidentTarget.Namespace, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("get target namespace: %w", err)
		}
		namespaceLabels = namespace.GetLabels()
	}
	return policy.Match(policyengine.Target{GroupResource: groupResource, Namespaced: resource.PreferredVersion.Namespaced, Namespace: incidentTarget.Namespace, Labels: policyObject.GetLabels(), NamespaceLabels: namespaceLabels}), nil
}

func finalizerPatch(object *unstructured.Unstructured, index int) ([]byte, error) {
	operations := []map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": string(object.GetUID())},
		{"op": "test", "path": "/metadata/resourceVersion", "value": object.GetResourceVersion()},
		{"op": "test", "path": "/metadata/finalizers", "value": object.GetFinalizers()},
		{"op": "remove", "path": fmt.Sprintf("/metadata/finalizers/%d", index)},
	}
	return json.Marshal(operations)
}

func (r *Reconciler) ensureOwnerReference(ctx context.Context, name string, incident *safetyv1alpha1.DeletionIncident) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current safetyv1alpha1.RemediationApproval
		if err := r.reader.Get(ctx, client.ObjectKey{Name: name}, &current); err != nil {
			return err
		}
		for _, owner := range current.OwnerReferences {
			if owner.UID == incident.UID {
				return nil
			}
		}
		base := current.DeepCopy()
		current.OwnerReferences = append(current.OwnerReferences, metav1.OwnerReference{APIVersion: safetyv1alpha1.GroupVersion.String(), Kind: "DeletionIncident", Name: incident.Name, UID: incident.UID})
		return r.writer.Patch(ctx, &current, client.MergeFrom(base))
	})
}

func (r *Reconciler) markRunning(ctx context.Context, approval *safetyv1alpha1.RemediationApproval, action *safetyv1alpha1.RemediationAction) error {
	return r.updateStatus(ctx, approval.Name, func(status *safetyv1alpha1.RemediationApprovalStatus, generation int64) {
		status.Phase = safetyv1alpha1.ApprovalPhaseRunning
		status.ObservedGeneration = generation
		if status.Action == nil {
			snapshot := *action
			status.Action = &snapshot
		}
		if status.StartedTime == nil {
			value := metav1.NewTime(r.now().UTC())
			status.StartedTime = &value
		}
		now := metav1.NewTime(r.now().UTC())
		status.Conditions = []metav1.Condition{{Type: "Running", Status: metav1.ConditionTrue, Reason: "ExecutionStarted", Message: "approval execution is in progress", LastTransitionTime: now, ObservedGeneration: generation}}
	})
}

func (r *Reconciler) recordRetryAttempt(ctx context.Context, name string, attempt safetyv1alpha1.RemediationAttempt) error {
	return r.updateStatus(ctx, name, func(status *safetyv1alpha1.RemediationApprovalStatus, _ int64) {
		status.Phase = safetyv1alpha1.ApprovalPhaseRunning
		status.Result = attempt.Result
		status.Attempts = appendBounded(status.Attempts, attempt)
	})
}

func (r *Reconciler) recordTerminalAttempt(ctx context.Context, name string, attempt safetyv1alpha1.RemediationAttempt, phase safetyv1alpha1.ApprovalPhase, result safetyv1alpha1.ApprovalResult) error {
	return r.updateStatus(ctx, name, func(status *safetyv1alpha1.RemediationApprovalStatus, generation int64) {
		status.Phase = phase
		status.Result = result
		status.ObservedGeneration = generation
		status.Attempts = appendBounded(status.Attempts, attempt)
		value := attempt.Time
		status.CompletedTime = &value
		status.Conditions = []metav1.Condition{{Type: "Completed", Status: metav1.ConditionTrue, Reason: string(result), Message: "approval execution completed", LastTransitionTime: value, ObservedGeneration: generation}}
	})
}

func (r *Reconciler) finish(ctx context.Context, approval *safetyv1alpha1.RemediationApproval, phase safetyv1alpha1.ApprovalPhase, result safetyv1alpha1.ApprovalResult, reason, message string) (ctrl.Result, error) {
	err := r.finishByName(ctx, approval.Name, phase, result, reason, message)
	if err == nil {
		r.recorder.Eventf(approval, nil, corev1.EventTypeWarning, "ApprovalRejected", "RejectApproval", "%s: %s", sanitize(reason, 128), sanitize(message, 768))
	}
	return ctrl.Result{}, err
}
func (r *Reconciler) finishByName(ctx context.Context, name string, phase safetyv1alpha1.ApprovalPhase, result safetyv1alpha1.ApprovalResult, reason, message string) error {
	return r.updateStatus(ctx, name, func(status *safetyv1alpha1.RemediationApprovalStatus, generation int64) {
		status.Phase = phase
		status.Result = result
		status.ObservedGeneration = generation
		now := metav1.NewTime(r.now().UTC())
		status.CompletedTime = &now
		status.Conditions = []metav1.Condition{{Type: "Completed", Status: metav1.ConditionTrue, Reason: sanitize(reason, 128), Message: sanitize(message, 1024), LastTransitionTime: now, ObservedGeneration: generation}}
	})
}

func (r *Reconciler) updateStatus(ctx context.Context, name string, mutate func(*safetyv1alpha1.RemediationApprovalStatus, int64)) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		var current safetyv1alpha1.RemediationApproval
		if err := r.reader.Get(ctx, client.ObjectKey{Name: name}, &current); err != nil {
			return err
		}
		before := current.Status.DeepCopy()
		mutate(&current.Status, current.Generation)
		if statusesEqual(before, &current.Status) {
			return nil
		}
		return r.writer.Status().Update(ctx, &current)
	})
}

func findAction(actions []safetyv1alpha1.RemediationAction, id string) *safetyv1alpha1.RemediationAction {
	for i := range actions {
		if actions[i].ID == id {
			return &actions[i]
		}
	}
	return nil
}

func actionEvidenceCurrent(status safetyv1alpha1.DeletionIncidentStatus, now time.Time) bool {
	if status.ActionEvidenceTime == nil || status.ActionEvidenceExpiresTime == nil {
		return false
	}
	return !status.ActionEvidenceExpiresTime.Before(status.ActionEvidenceTime) && now.Before(status.ActionEvidenceExpiresTime.Time)
}

func sameTargetIdentity(left, right safetyv1alpha1.TargetReference) bool {
	return left.UID == right.UID && left.APIGroup == right.APIGroup && left.Resource == right.Resource && left.Namespace == right.Namespace && left.Name == right.Name
}

func actionBelongsToIncident(action *safetyv1alpha1.RemediationAction, incidentTarget safetyv1alpha1.TargetReference) bool {
	if action == nil {
		return false
	}
	if sameTargetIdentity(action.Target, incidentTarget) {
		return true
	}
	return incidentTarget.APIGroup == "" && incidentTarget.Resource == "namespaces" && incidentTarget.Namespace == "" &&
		action.Type == safetyv1alpha1.ActionRemoveResourceFinalizer && action.Target.Namespace == incidentTarget.Name &&
		action.Target.UID != "" && action.Target.Name != "" && action.Target.Resource != ""
}

func targetKey(target safetyv1alpha1.TargetReference) string {
	return strings.Join([]string{target.APIGroup, target.Resource, target.Namespace, target.Name, string(target.UID)}, "\x00")
}
func terminal(phase safetyv1alpha1.ApprovalPhase) bool {
	switch phase {
	case safetyv1alpha1.ApprovalPhaseSucceeded, safetyv1alpha1.ApprovalPhaseDryRunSucceeded, safetyv1alpha1.ApprovalPhaseFailed, safetyv1alpha1.ApprovalPhaseExpired, safetyv1alpha1.ApprovalPhaseSuperseded:
		return true
	case safetyv1alpha1.ApprovalPhasePending, safetyv1alpha1.ApprovalPhaseRunning:
		return false
	default:
		return false
	}
}
func appendBounded(attempts []safetyv1alpha1.RemediationAttempt, attempt safetyv1alpha1.RemediationAttempt) []safetyv1alpha1.RemediationAttempt {
	attempts = append(attempts, attempt)
	if len(attempts) > maxAuditAttempts {
		attempts = attempts[len(attempts)-maxAuditAttempts:]
	}
	return attempts
}
func sanitize(value string, maximum int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 && r != ' ' {
			return -1
		}
		return r
	}, value)
	if len(value) > maximum {
		value = value[:maximum]
	}
	return value
}
func errorReason(err error) string {
	var terminalErr terminalExecutionError
	if errors.As(err, &terminalErr) {
		return terminalErr.reason
	}
	reason := apierrors.ReasonForError(err)
	if reason != metav1.StatusReasonUnknown {
		return sanitize(string(reason), 128)
	}
	return "APIError"
}
func transient(err error) bool {
	var terminalErr terminalExecutionError
	if errors.As(err, &terminalErr) {
		return false
	}
	text := strings.ToLower(err.Error())
	return errors.Is(err, context.DeadlineExceeded) || apierrors.IsConflict(err) || apierrors.IsTooManyRequests(err) || apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsInternalError(err) || apierrors.IsServiceUnavailable(err) || strings.Contains(text, "webhook") || strings.Contains(text, "timeout")
}
func statusesEqual(left, right *safetyv1alpha1.RemediationApprovalStatus) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

// terminalExecutionError records a safe terminal outcome without retrying a mutation.
type terminalExecutionError struct {
	phase           safetyv1alpha1.ApprovalPhase
	result          safetyv1alpha1.ApprovalResult
	reason, message string
}

func (e terminalExecutionError) Error() string { return e.message }

type keyedLocks struct {
	mu      sync.Mutex
	entries map[string]*lockEntry
}
type lockEntry struct {
	mu    sync.Mutex
	users int
}

func newKeyedLocks() *keyedLocks { return &keyedLocks{entries: map[string]*lockEntry{}} }
func (locks *keyedLocks) lock(key string) func() {
	locks.mu.Lock()
	entry := locks.entries[key]
	if entry == nil {
		entry = &lockEntry{}
		locks.entries[key] = entry
	}
	entry.users++
	locks.mu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		locks.mu.Lock()
		entry.users--
		if entry.users == 0 {
			delete(locks.entries, key)
		}
		locks.mu.Unlock()
	}
}
func (locks *keyedLocks) size() int {
	locks.mu.Lock()
	defer locks.mu.Unlock()
	return len(locks.entries)
}
