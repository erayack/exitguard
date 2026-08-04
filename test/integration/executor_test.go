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

//go:build integration

package integration

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
)

func TestExecutorDryRunThenPersistsRealFinalizerMutation(t *testing.T) {
	ctx := boundedContext(t)
	fixture := createScannerIncident(t, true)
	action := findFinalizerAction(fixture.incident.Status.RecommendedActions, blockingFinalizer)
	if action == nil || !action.Eligible {
		t.Fatalf("scanner action = %#v, want eligible finalizer removal", action)
	}
	reconciler := newExecutor(t)

	dryRun := newApproval(fixtureName(t, "dry-run"), fixture.incident, action.ID, true)
	if err := suite.client.Create(ctx, dryRun); err != nil {
		t.Fatalf("create dry-run approval: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: ctrlclient.ObjectKeyFromObject(dryRun)}); err != nil {
		t.Fatalf("reconcile dry-run approval: %v", err)
	}
	var persistedDryRun safetyv1alpha1.RemediationApproval
	if err := suite.client.Get(ctx, ctrlclient.ObjectKeyFromObject(dryRun), &persistedDryRun); err != nil {
		t.Fatalf("read dry-run approval status: %v", err)
	}
	assertApprovalAttempt(t, persistedDryRun, safetyv1alpha1.ApprovalPhaseDryRunSucceeded, safetyv1alpha1.ApprovalResultDryRunValidated, true, fixture.targetResourceVersion, action.ID)

	var afterDryRun corev1.ConfigMap
	if err := suite.client.Get(ctx, ctrlclient.ObjectKey{Namespace: fixture.namespace, Name: fixture.targetName}, &afterDryRun); err != nil {
		t.Fatalf("read target after dry-run: %v", err)
	}
	if !containsString(afterDryRun.Finalizers, blockingFinalizer) {
		t.Fatalf("dry-run mutated target finalizers: %v", afterDryRun.Finalizers)
	}
	if afterDryRun.ResourceVersion != fixture.targetResourceVersion {
		t.Fatalf("dry-run target resourceVersion = %q, want unchanged %q", afterDryRun.ResourceVersion, fixture.targetResourceVersion)
	}

	persisted := newApproval(fixtureName(t, "persisted"), fixture.incident, action.ID, false)
	if err := suite.client.Create(ctx, persisted); err != nil {
		t.Fatalf("create persisted approval: %v", err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: ctrlclient.ObjectKeyFromObject(persisted)}); err != nil {
		t.Fatalf("reconcile persisted approval: %v", err)
	}
	var persistedStatus safetyv1alpha1.RemediationApproval
	if err := suite.client.Get(ctx, ctrlclient.ObjectKeyFromObject(persisted), &persistedStatus); err != nil {
		t.Fatalf("read persisted approval status: %v", err)
	}
	assertApprovalAttempt(t, persistedStatus, safetyv1alpha1.ApprovalPhaseSucceeded, safetyv1alpha1.ApprovalResultMutated, false, fixture.targetResourceVersion, action.ID)

	poll(t, func(ctx context.Context) (bool, error) {
		var target corev1.ConfigMap
		err := suite.client.Get(ctx, ctrlclient.ObjectKey{Namespace: fixture.namespace, Name: fixture.targetName}, &target)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return !containsString(target.Finalizers, blockingFinalizer), nil
	})
}

func newApproval(name string, incident safetyv1alpha1.DeletionIncident, actionID string, dryRun bool) *safetyv1alpha1.RemediationApproval {
	return &safetyv1alpha1.RemediationApproval{
		TypeMeta:   metav1.TypeMeta{APIVersion: safetyv1alpha1.GroupVersion.String(), Kind: "RemediationApproval"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: safetyv1alpha1.RemediationApprovalSpec{
			IncidentRef: safetyv1alpha1.ObjectIdentityReference{Name: incident.Name, UID: incident.UID},
			ActionID:    actionID,
			DryRun:      dryRun,
			Reason:      "integration test approved current scanner action",
		},
	}
}

func assertApprovalAttempt(t *testing.T, approval safetyv1alpha1.RemediationApproval, phase safetyv1alpha1.ApprovalPhase, result safetyv1alpha1.ApprovalResult, dryRun bool, resourceVersion, actionID string) {
	t.Helper()
	if approval.Status.Phase != phase || approval.Status.Result != result {
		t.Fatalf("approval status = %#v, want phase %q result %q", approval.Status, phase, result)
	}
	if approval.Status.Action == nil || approval.Status.Action.ID != actionID {
		t.Fatalf("approval action snapshot = %#v, want action %q", approval.Status.Action, actionID)
	}
	if approval.Status.StartedTime == nil || approval.Status.CompletedTime == nil || approval.Status.ObservedGeneration != approval.Generation {
		t.Fatalf("approval lifecycle audit fields missing: %#v", approval.Status)
	}
	if len(approval.Status.Attempts) != 1 {
		t.Fatalf("approval attempts = %#v, want exactly one", approval.Status.Attempts)
	}
	attempt := approval.Status.Attempts[0]
	if attempt.ActionType != safetyv1alpha1.ActionRemoveResourceFinalizer || attempt.DryRun != dryRun || attempt.Result != result {
		t.Fatalf("approval attempt = %#v, want finalizer action/dryRun=%t/result=%q", attempt, dryRun, result)
	}
	if attempt.ResourceVersionBefore != resourceVersion || attempt.ResourceVersionAfter == "" || attempt.Time.IsZero() {
		t.Fatalf("approval attempt lacks real API resource versions/time: %#v", attempt)
	}
	if len(approval.OwnerReferences) != 1 || approval.OwnerReferences[0].UID == "" {
		t.Fatalf("approval incident owner reference missing: %#v", approval.OwnerReferences)
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
