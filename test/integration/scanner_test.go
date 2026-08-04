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
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	policyengine "github.com/erayack/exitguard/internal/policy"
)

const blockingFinalizer = "example.io/cleanup"

func TestScannerPersistsOversizedPolicyStatus(t *testing.T) {
	const (
		ruleCount                = 1500
		conditionMessageAPILimit = 32_768
		truncationSuffix         = "... (truncated)"
	)
	ctx := boundedContext(t)
	policy := completePolicy(fixtureName(t, "oversized-policy"), false)
	policy.Spec.TargetRules = make([]safetyv1alpha1.TargetRule, ruleCount)
	for index := range policy.Spec.TargetRules {
		policy.Spec.TargetRules[index] = safetyv1alpha1.TargetRule{
			APIGroups: []string{fmt.Sprintf("missing-%04d.example.io", index)},
			Resources: []string{"widgets"},
		}
	}
	if err := suite.client.Create(ctx, policy); err != nil {
		t.Fatalf("create oversized policy: %v", err)
	}

	if err := newScanner(t).RunCycle(ctx); err != nil {
		t.Fatalf("run scanner cycle: %v", err)
	}
	var persisted safetyv1alpha1.TerminationPolicy
	if err := suite.client.Get(ctx, ctrlclient.ObjectKeyFromObject(policy), &persisted); err != nil {
		t.Fatalf("read persisted policy status: %v", err)
	}
	ready := findCondition(persisted.Status.Conditions, policyengine.ConditionReady)
	if ready == nil {
		t.Fatal("persisted policy has no Ready condition")
	}
	if ready.Status != metav1.ConditionFalse || ready.Reason != "InvalidPolicy" {
		t.Fatalf("Ready condition = %#v, want False/InvalidPolicy", *ready)
	}
	if got := len([]rune(ready.Message)); got > conditionMessageAPILimit {
		t.Fatalf("Ready message has %d runes, exceeds %d", got, conditionMessageAPILimit)
	}
	if !strings.HasSuffix(ready.Message, truncationSuffix) {
		t.Fatalf("Ready message does not end in %q", truncationSuffix)
	}
}

func TestScannerCreatesIncidentFromRealDeletingObject(t *testing.T) {
	fixture := createScannerIncident(t, false)
	incident := fixture.incident

	if incident.Status.Phase != safetyv1alpha1.IncidentPhaseActive {
		t.Fatalf("incident phase = %q, want Active", incident.Status.Phase)
	}
	if incident.Spec.Target.UID != fixture.targetUID || incident.Spec.Target.Namespace != fixture.namespace || incident.Spec.Target.Name != fixture.targetName {
		t.Fatalf("incident target = %#v, want real ConfigMap identity", incident.Spec.Target)
	}
	if incident.Status.TargetSnapshot.ResourceVersion != fixture.targetResourceVersion {
		t.Fatalf("snapshot resourceVersion = %q, want %q", incident.Status.TargetSnapshot.ResourceVersion, fixture.targetResourceVersion)
	}
	if incident.Status.DeletionTimestamp == nil {
		t.Fatal("incident did not persist the target deletion timestamp")
	}
	if !hasBlockingFinalizerFinding(incident.Status.Findings, blockingFinalizer) {
		t.Fatalf("incident findings = %#v, want blocking finalizer evidence", incident.Status.Findings)
	}
	action := findFinalizerAction(incident.Status.RecommendedActions, blockingFinalizer)
	if action == nil {
		t.Fatalf("recommended actions = %#v, want finalizer removal", incident.Status.RecommendedActions)
	}
	if action.Target.UID != fixture.targetUID || action.PreconditionResourceVersion != fixture.targetResourceVersion {
		t.Fatalf("recommended action = %#v, want current real target preconditions", *action)
	}
	if action.Eligible {
		t.Fatal("report-only policy unexpectedly made the action eligible")
	}
}

type scannerIncidentFixture struct {
	policy                *safetyv1alpha1.TerminationPolicy
	incident              safetyv1alpha1.DeletionIncident
	namespace             string
	targetName            string
	targetUID             types.UID
	targetResourceVersion string
}

func createScannerIncident(t *testing.T, allowRemediation bool) scannerIncidentFixture {
	t.Helper()
	ctx := boundedContext(t)
	namespace := fixtureName(t, "scanner-ns")
	targetName := fixtureName(t, "blocked")
	policy := completePolicy(fixtureName(t, "configmap-policy"), allowRemediation)
	policy.Spec.TargetRules = []safetyv1alpha1.TargetRule{{
		APIGroups: []string{""}, Resources: []string{"configmaps"},
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"exitguard-test": namespace}},
	}}

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: map[string]string{"exitguard-test": namespace}}}
	if err := suite.client.Create(ctx, ns); err != nil {
		t.Fatalf("create scanner namespace: %v", err)
	}
	if err := suite.client.Create(ctx, policy); err != nil {
		t.Fatalf("create scanner policy: %v", err)
	}
	target := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: namespace, Name: targetName, Finalizers: []string{blockingFinalizer},
	}}
	if err := suite.client.Create(ctx, target); err != nil {
		t.Fatalf("create scanner target: %v", err)
	}
	uid := target.UID
	if err := suite.client.Delete(ctx, target); err != nil {
		t.Fatalf("delete scanner target: %v", err)
	}

	var deleting corev1.ConfigMap
	poll(t, func(ctx context.Context) (bool, error) {
		if err := suite.client.Get(ctx, ctrlclient.ObjectKey{Namespace: namespace, Name: targetName}, &deleting); err != nil {
			return false, err
		}
		return deleting.DeletionTimestamp != nil && deleting.UID == uid && deleting.ResourceVersion != "", nil
	})
	if err := newScanner(t).RunCycle(ctx); err != nil {
		t.Fatalf("run scanner cycle: %v", err)
	}

	var incidents safetyv1alpha1.DeletionIncidentList
	if err := suite.client.List(ctx, &incidents); err != nil {
		t.Fatalf("list scanner incidents: %v", err)
	}
	for i := range incidents.Items {
		if incidents.Items[i].Spec.Target.UID == uid {
			return scannerIncidentFixture{
				policy: policy, incident: incidents.Items[i], namespace: namespace, targetName: targetName,
				targetUID: uid, targetResourceVersion: deleting.ResourceVersion,
			}
		}
	}
	t.Fatalf("scanner did not create incident for ConfigMap UID %q", uid)
	return scannerIncidentFixture{}
}

func completePolicy(name string, allowRemediation bool) *safetyv1alpha1.TerminationPolicy {
	maxRisk := safetyv1alpha1.RiskNone
	var allowed []string
	if allowRemediation {
		maxRisk = safetyv1alpha1.RiskMedium
		allowed = []string{blockingFinalizer}
	}
	return &safetyv1alpha1.TerminationPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: safetyv1alpha1.GroupVersion.String(), Kind: "TerminationPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: safetyv1alpha1.TerminationPolicySpec{
			TargetRules:    []safetyv1alpha1.TargetRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}}},
			TerminationAge: metav1.Duration{Duration: time.Nanosecond},
			Diagnosis: safetyv1alpha1.DiagnosisPolicy{
				MaxNamespaceObjects: 100, MaxCRDInstances: 100,
			},
			Remediation: safetyv1alpha1.RemediationPolicy{
				MaxRisk: maxRisk, AllowedFinalizers: allowed, ApprovalTTL: metav1.Duration{Duration: time.Hour},
			},
			Retention: safetyv1alpha1.RetentionPolicy{ResolvedIncidentTTL: metav1.Duration{Duration: time.Hour}},
		},
	}
}

func findCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

func hasBlockingFinalizerFinding(findings []safetyv1alpha1.Finding, finalizer string) bool {
	for _, finding := range findings {
		if finding.Type == safetyv1alpha1.FindingBlockingFinalizer && finding.Finalizer == finalizer {
			return true
		}
	}
	return false
}

func findFinalizerAction(actions []safetyv1alpha1.RemediationAction, finalizer string) *safetyv1alpha1.RemediationAction {
	for i := range actions {
		if actions[i].Type == safetyv1alpha1.ActionRemoveResourceFinalizer && actions[i].Finalizer == finalizer {
			return &actions[i]
		}
	}
	return nil
}
