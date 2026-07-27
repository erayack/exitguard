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

package executor

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
	policyengine "github.com/erayack/exitguard/internal/policy"
)

func TestReconcileRemovesExactFinalizerAndAudits(t *testing.T) {
	reconciler, store, dynamicClient, _ := testExecutor(t, time.Hour, "target-uid", []string{"keep.io/finalizer", "remove.io/finalizer"})
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "approval"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var approval safetyv1alpha1.RemediationApproval
	if err := store.Get(context.Background(), client.ObjectKey{Name: "approval"}, &approval); err != nil {
		t.Fatal(err)
	}
	if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseSucceeded || approval.Status.Result != safetyv1alpha1.ApprovalResultMutated {
		t.Fatalf("unexpected status: %#v", approval.Status)
	}
	if len(approval.Status.Attempts) != 1 || len(approval.OwnerReferences) != 1 || approval.Status.Action == nil {
		t.Fatalf("audit/action snapshot/owner reference missing: %#v", approval)
	}
	object, err := dynamicClient.Resource(schema.GroupVersionResource{Version: "v1", Resource: "pods"}).Namespace("ns").Get(context.Background(), "blocked", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := object.GetFinalizers(); len(got) != 1 || got[0] != "keep.io/finalizer" {
		t.Fatalf("wrong finalizers after patch: %v", got)
	}
}

func TestReconcileExpiresWithoutMutation(t *testing.T) {
	reconciler, store, dynamicClient, now := testExecutor(t, time.Minute, "target-uid", []string{"remove.io/finalizer"})
	reconciler.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "approval"}}); err != nil {
		t.Fatal(err)
	}
	var approval safetyv1alpha1.RemediationApproval
	if err := store.Get(context.Background(), client.ObjectKey{Name: "approval"}, &approval); err != nil {
		t.Fatal(err)
	}
	if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseExpired {
		t.Fatalf("phase = %q", approval.Status.Phase)
	}
	if actions := dynamicClient.Actions(); len(actions) != 0 {
		t.Fatalf("expired approval touched target: %#v", actions)
	}
}

func TestReconcileRejectsExpiredActionEvidenceWithoutMutation(t *testing.T) {
	reconciler, store, dynamicClient, now := testExecutor(t, time.Hour, "target-uid", []string{"remove.io/finalizer"})
	ctx := context.Background()
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatal(err)
	}
	expired := metav1.NewTime(now.Add(-time.Second))
	incident.Status.ActionEvidenceExpiresTime = &expired
	if err := store.Update(ctx, &incident); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "approval"}}); err != nil {
		t.Fatal(err)
	}
	var approval safetyv1alpha1.RemediationApproval
	if err := store.Get(ctx, client.ObjectKey{Name: "approval"}, &approval); err != nil {
		t.Fatal(err)
	}
	if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseSuperseded || approval.Status.Conditions[0].Reason != "EvidenceExpired" {
		t.Fatalf("stale evidence status = %#v", approval.Status)
	}
	if actions := dynamicClient.Actions(); len(actions) != 0 {
		t.Fatalf("stale evidence touched target: %#v", actions)
	}
}

func TestReconcileRejectsReplacementWithoutMutation(t *testing.T) {
	reconciler, store, dynamicClient, _ := testExecutor(t, time.Hour, "replacement-uid", []string{"remove.io/finalizer"})
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "approval"}}); err != nil {
		t.Fatal(err)
	}
	var approval safetyv1alpha1.RemediationApproval
	if err := store.Get(context.Background(), client.ObjectKey{Name: "approval"}, &approval); err != nil {
		t.Fatal(err)
	}
	if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseSuperseded || approval.Status.Result != safetyv1alpha1.ApprovalResultTargetReplaced {
		t.Fatalf("unexpected replacement status: %#v", approval.Status)
	}
	for _, action := range dynamicClient.Actions() {
		if action.GetVerb() == "patch" {
			t.Fatal("replacement target was patched")
		}
	}
}

func TestPendingApprovalIsSupersededWhenActionIDRotates(t *testing.T) {
	reconciler, store, dynamicClient, _ := testExecutor(t, time.Hour, "target-uid", []string{"remove.io/finalizer"})
	ctx := context.Background()
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatal(err)
	}
	incident.Status.RecommendedActions[0].ID = "action-refreshed-evidence"
	if err := store.Update(ctx, &incident); err != nil {
		t.Fatal(err)
	}

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "approval"}}); err != nil {
		t.Fatal(err)
	}
	var approval safetyv1alpha1.RemediationApproval
	if err := store.Get(ctx, client.ObjectKey{Name: "approval"}, &approval); err != nil {
		t.Fatal(err)
	}
	if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseSuperseded || approval.Status.Result != safetyv1alpha1.ApprovalResultTargetChanged {
		t.Fatalf("stale approval status = %#v", approval.Status)
	}
	if actions := dynamicClient.Actions(); len(actions) != 0 {
		t.Fatalf("stale approval touched target: %#v", actions)
	}
}

func TestReconcileRejectsIneligibleAction(t *testing.T) {
	reconciler, store, dynamicClient, _ := testExecutor(t, time.Hour, "target-uid", []string{"remove.io/finalizer"})
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(context.Background(), client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatal(err)
	}
	incident.Status.RecommendedActions[0].Eligible = false
	if err := store.Update(context.Background(), &incident); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "approval"}}); err != nil {
		t.Fatal(err)
	}
	var approval safetyv1alpha1.RemediationApproval
	if err := store.Get(context.Background(), client.ObjectKey{Name: "approval"}, &approval); err != nil {
		t.Fatal(err)
	}
	if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseFailed || approval.Status.Result != safetyv1alpha1.ApprovalResultRejectedByPolicy {
		t.Fatalf("unexpected denial: %#v", approval.Status)
	}
	if actions := dynamicClient.Actions(); len(actions) != 0 {
		t.Fatalf("denied approval touched target: %#v", actions)
	}
}

func TestReconcileStopsWhenIncidentBecomesDiagnosisFailedAfterLock(t *testing.T) {
	reconciler, store, dynamicClient, _ := testExecutor(t, time.Hour, "target-uid", []string{"remove.io/finalizer"})
	reconciler.reader = &phaseChangingReader{Reader: store}
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "approval"}}); err != nil {
		t.Fatal(err)
	}
	var approval safetyv1alpha1.RemediationApproval
	if err := store.Get(context.Background(), client.ObjectKey{Name: "approval"}, &approval); err != nil {
		t.Fatal(err)
	}
	if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseSuperseded {
		t.Fatalf("phase = %q, want Superseded", approval.Status.Phase)
	}
	for _, action := range dynamicClient.Actions() {
		if action.GetVerb() == "patch" {
			t.Fatal("target was mutated after incident diagnosis failed")
		}
	}
}

type phaseChangingReader struct {
	client.Reader
	incidentGets int
}

func (r *phaseChangingReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, options ...client.GetOption) error {
	if err := r.Reader.Get(ctx, key, object, options...); err != nil {
		return err
	}
	if incident, ok := object.(*safetyv1alpha1.DeletionIncident); ok {
		r.incidentGets++
		if r.incidentGets > 1 {
			incident.Status.Phase = safetyv1alpha1.IncidentPhaseDiagnosisFailed
		}
	}
	return nil
}

func TestTransientClassifiesContextDeadline(t *testing.T) {
	if !transient(context.DeadlineExceeded) {
		t.Fatal("context deadline was classified as permanent")
	}
	if transient(context.Canceled) {
		t.Fatal("context cancellation was classified as retryable")
	}
}

func TestTransientFailureRecordsBoundedRetry(t *testing.T) {
	reconciler, store, dynamicClient, _ := testExecutor(t, time.Hour, "target-uid", []string{"remove.io/finalizer"})
	dynamicClient.PrependReactor("patch", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewTooManyRequests("busy: object contained secret-token", 30)
	})
	result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "approval"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("transient error requeue = %s, want API retry delay", result.RequeueAfter)
	}
	var approval safetyv1alpha1.RemediationApproval
	if err := store.Get(context.Background(), client.ObjectKey{Name: "approval"}, &approval); err != nil {
		t.Fatal(err)
	}
	if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseRunning || len(approval.Status.Attempts) != 1 || approval.Status.Attempts[0].ErrorReason != "TooManyRequests" {
		t.Fatalf("retry audit missing: %#v", approval.Status)
	}
	if message := approval.Status.Attempts[0].Message; message != "Kubernetes API request failed" {
		t.Fatalf("retry message = %q, want non-sensitive summary", message)
	}
}

func TestDuplicateApprovalObservesAlreadySatisfied(t *testing.T) {
	reconciler, store, _, now := testExecutor(t, time.Hour, "target-uid", []string{"remove.io/finalizer"})
	ctx := context.Background()
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "approval"}}); err != nil {
		t.Fatal(err)
	}
	second := &safetyv1alpha1.RemediationApproval{ObjectMeta: metav1.ObjectMeta{Name: "approval-two", UID: "approval-two-uid", CreationTimestamp: metav1.NewTime(now)}, Spec: safetyv1alpha1.RemediationApprovalSpec{IncidentRef: safetyv1alpha1.ObjectIdentityReference{Name: "deletion-target-uid", UID: "incident-uid"}, ActionID: "action", Reason: "duplicate approval test"}}
	if err := store.Create(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: second.Name}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Get(ctx, client.ObjectKey{Name: second.Name}, second); err != nil {
		t.Fatal(err)
	}
	if second.Status.Phase != safetyv1alpha1.ApprovalPhaseSucceeded || second.Status.Result != safetyv1alpha1.ApprovalResultAlreadySatisfied {
		t.Fatalf("duplicate was not idempotent: %#v", second.Status)
	}
}

func TestCrashReplayWithMissingFinalizerSucceeds(t *testing.T) {
	reconciler, store, _, _ := testExecutor(t, time.Hour, "target-uid", []string{"keep.io/finalizer"})
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "approval"}}); err != nil {
		t.Fatal(err)
	}
	var approval safetyv1alpha1.RemediationApproval
	if err := store.Get(context.Background(), client.ObjectKey{Name: "approval"}, &approval); err != nil {
		t.Fatal(err)
	}
	if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseSucceeded || approval.Status.Result != safetyv1alpha1.ApprovalResultAlreadySatisfied {
		t.Fatalf("crash replay failed: %#v", approval.Status)
	}
}

func TestReplayAuditsSatisfiedActionAfterIncidentResolution(t *testing.T) {
	reconciler, store, dynamicClient, _ := testExecutor(t, time.Hour, "target-uid", []string{"remove.io/finalizer"})
	ctx := context.Background()
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatal(err)
	}
	action := incident.Status.RecommendedActions[0]
	var approval safetyv1alpha1.RemediationApproval
	if err := store.Get(ctx, client.ObjectKey{Name: "approval"}, &approval); err != nil {
		t.Fatal(err)
	}
	approval.Status.Phase = safetyv1alpha1.ApprovalPhaseRunning
	approval.Status.Action = &action
	if err := store.Status().Update(ctx, &approval); err != nil {
		t.Fatal(err)
	}
	incident.Status.Phase = safetyv1alpha1.IncidentPhaseResolved
	incident.Status.RecommendedActions = nil
	if err := store.Update(ctx, &incident); err != nil {
		t.Fatal(err)
	}
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	target, err := dynamicClient.Resource(gvr).Namespace("ns").Get(ctx, "blocked", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	target.SetFinalizers(nil)
	if _, err := dynamicClient.Resource(gvr).Namespace("ns").Update(ctx, target, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "approval"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Get(ctx, client.ObjectKey{Name: "approval"}, &approval); err != nil {
		t.Fatal(err)
	}
	if approval.Status.Phase != safetyv1alpha1.ApprovalPhaseSucceeded || approval.Status.Result != safetyv1alpha1.ApprovalResultAlreadySatisfied {
		t.Fatalf("resolved replay lost mutation audit: %#v", approval.Status)
	}
}

func TestReconcileExecutesNamespaceChildAction(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := safetyv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	policy := &safetyv1alpha1.TerminationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "namespace-policy", UID: "policy-uid", Generation: 1},
		Spec: safetyv1alpha1.TerminationPolicySpec{
			TargetRules: []safetyv1alpha1.TargetRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}}}, TerminationAge: metav1.Duration{Duration: time.Minute},
			Diagnosis: safetyv1alpha1.DiagnosisPolicy{MaxNamespaceObjects: 10, MaxCRDInstances: 10}, Remediation: safetyv1alpha1.RemediationPolicy{MaxRisk: safetyv1alpha1.RiskMedium, AllowedFinalizers: []string{"remove.io/finalizer"}, ApprovalTTL: metav1.Duration{Duration: time.Hour}}, Retention: safetyv1alpha1.RetentionPolicy{ResolvedIncidentTTL: metav1.Duration{Duration: time.Hour}},
		},
	}
	incidentTarget := safetyv1alpha1.TargetReference{Version: "v1", Resource: "namespaces", Kind: "Namespace", Name: "stuck", UID: "namespace-uid"}
	action := safetyv1alpha1.RemediationAction{ID: "child-action", Type: safetyv1alpha1.ActionRemoveResourceFinalizer, Risk: safetyv1alpha1.RiskMedium, Eligible: true, Finalizer: "remove.io/finalizer", PreconditionResourceVersion: "7", Reason: "remove child blocker", Target: safetyv1alpha1.TargetReference{Version: "v1", Resource: "configmaps", Kind: "ConfigMap", Namespace: "stuck", Name: "blocked", UID: "child-uid"}}
	evidenceTime := metav1.NewTime(now)
	evidenceExpires := metav1.NewTime(now.Add(time.Hour))
	incident := &safetyv1alpha1.DeletionIncident{ObjectMeta: metav1.ObjectMeta{Name: "deletion-namespace-uid", UID: "incident-uid"}, Spec: safetyv1alpha1.DeletionIncidentSpec{Target: incidentTarget, FirstObservedTime: metav1.NewTime(now)}, Status: safetyv1alpha1.DeletionIncidentStatus{Phase: safetyv1alpha1.IncidentPhaseActive, ActivePolicyRef: &safetyv1alpha1.PolicyReference{Name: policy.Name, UID: policy.UID, Generation: 1}, ActionEvidenceTime: &evidenceTime, ActionEvidenceExpiresTime: &evidenceExpires, RecommendedActions: []safetyv1alpha1.RemediationAction{action}}}
	approval := &safetyv1alpha1.RemediationApproval{ObjectMeta: metav1.ObjectMeta{Name: "child-approval", UID: "approval-uid", CreationTimestamp: metav1.NewTime(now)}, Spec: safetyv1alpha1.RemediationApprovalSpec{IncidentRef: safetyv1alpha1.ObjectIdentityReference{Name: incident.Name, UID: incident.UID}, ActionID: action.ID, Reason: "approved child cleanup"}}
	store := clientfake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(approval).WithObjects(policy, incident, approval).Build()
	discovery := &fake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{{GroupVersion: "v1", APIResources: []metav1.APIResource{{Name: "namespaces", Kind: "Namespace", Verbs: metav1.Verbs{"get", "list"}}, {Name: "configmaps", Kind: "ConfigMap", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}}}}
	catalog := catalogdiscovery.NewCatalog(discovery, time.Hour, logr.Discard())
	if err := catalog.Refresh(); err != nil {
		t.Fatal(err)
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "stuck", UID: "namespace-uid", ResourceVersion: "3"}}
	child := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "blocked", Namespace: "stuck", UID: "child-uid", ResourceVersion: "7", Finalizers: []string{"remove.io/finalizer"}}}
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme, namespace, child)
	reconciler, err := NewReconciler(store, store, dynamicClient, kubernetesfake.NewClientset(), catalog, events.NewFakeRecorder(10), 5)
	if err != nil {
		t.Fatal(err)
	}
	reconciler.now = func() time.Time { return now }
	if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: approval.Name}}); err != nil {
		t.Fatal(err)
	}
	updated, err := dynamicClient.Resource(schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}).Namespace("stuck").Get(context.Background(), "blocked", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.GetFinalizers()) != 0 {
		t.Fatalf("namespace child finalizer was not removed: %v", updated.GetFinalizers())
	}
}

func TestGetCurrentFallsBackToAlternateServedVersion(t *testing.T) {
	discovery := &fake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{
		{GroupVersion: "example.io/v1", APIResources: []metav1.APIResource{{Name: "widgets", Kind: "Widget", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}}},
		{GroupVersion: "example.io/v1beta1", APIResources: []metav1.APIResource{{Name: "widgets", Kind: "Widget", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}}},
	}
	catalog := catalogdiscovery.NewCatalog(discovery, time.Hour, logr.Discard())
	if err := catalog.Refresh(); err != nil {
		t.Fatal(err)
	}
	object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "example.io/v1beta1", "kind": "Widget", "metadata": map[string]any{"name": "one", "namespace": "ns", "uid": "widget-uid", "resourceVersion": "4"}}}
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), object)
	reconciler := &Reconciler{dynamic: dynamicClient, catalog: catalog}
	current, used, err := reconciler.getCurrent(context.Background(), safetyv1alpha1.TargetReference{APIGroup: "example.io", Version: "v1", Resource: "widgets", Kind: "Widget", Namespace: "ns", Name: "one", UID: "widget-uid"})
	if err != nil {
		t.Fatal(err)
	}
	if current.GetUID() != "widget-uid" || used.Version != "v1beta1" {
		t.Fatalf("fallback returned uid=%q version=%q", current.GetUID(), used.Version)
	}
}

func TestFinalizerPatchContainsAllPreconditions(t *testing.T) {
	object := &unstructured.Unstructured{}
	object.SetUID("uid")
	object.SetResourceVersion("9")
	object.SetFinalizers([]string{"first", "second"})
	patch, err := finalizerPatch(object, 1)
	if err != nil {
		t.Fatal(err)
	}
	var operations []map[string]any
	if err := json.Unmarshal(patch, &operations); err != nil {
		t.Fatal(err)
	}
	if len(operations) != 4 || operations[0]["path"] != "/metadata/uid" || operations[1]["path"] != "/metadata/resourceVersion" || operations[2]["path"] != "/metadata/finalizers" || operations[3]["path"] != "/metadata/finalizers/1" {
		t.Fatalf("unsafe patch: %s", patch)
	}
}

func TestNamespaceFinalizeUsesAPIServerDryRun(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := safetyv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	discovery := &fake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{{GroupVersion: "v1", APIResources: []metav1.APIResource{{Name: "namespaces", Kind: "Namespace", Verbs: metav1.Verbs{"get", "list"}}}}}
	catalog := catalogdiscovery.NewCatalog(discovery, time.Hour, logr.Discard())
	if err := catalog.Refresh(); err != nil {
		t.Fatal(err)
	}
	policySource := &safetyv1alpha1.TerminationPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", UID: "policy-uid", Generation: 1}, Spec: safetyv1alpha1.TerminationPolicySpec{TargetRules: []safetyv1alpha1.TargetRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}}}, TerminationAge: metav1.Duration{Duration: time.Minute}, Diagnosis: safetyv1alpha1.DiagnosisPolicy{MaxNamespaceObjects: 1, MaxCRDInstances: 1}, Remediation: safetyv1alpha1.RemediationPolicy{MaxRisk: safetyv1alpha1.RiskCritical, AllowNamespaceForce: true, ApprovalTTL: metav1.Duration{Duration: time.Hour}}, Retention: safetyv1alpha1.RetentionPolicy{ResolvedIncidentTTL: metav1.Duration{Duration: time.Hour}}}}
	policy, _ := policyengine.Compile(policySource, catalog.Snapshot(), time.Now())
	if !policy.Ready() {
		t.Fatal("namespace policy did not compile")
	}
	target := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "stuck", UID: "namespace-uid", ResourceVersion: "7"}, Spec: corev1.NamespaceSpec{Finalizers: []corev1.FinalizerName{"kubernetes"}}}
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme, target)
	kubeClient := kubernetesfake.NewClientset()
	store := clientfake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler, err := NewReconciler(store, store, dynamicClient, kubeClient, catalog, events.NewFakeRecorder(1), 5)
	if err != nil {
		t.Fatal(err)
	}
	finalizer := &recordingNamespaceFinalizer{}
	reconciler.namespaces = finalizer
	action := &safetyv1alpha1.RemediationAction{Type: safetyv1alpha1.ActionForceFinalizeNamespace, Target: safetyv1alpha1.TargetReference{Version: "v1", Resource: "namespaces", Kind: "Namespace", Name: "stuck", UID: "namespace-uid"}, Risk: safetyv1alpha1.RiskCritical, PreconditionResourceVersion: "7"}
	_, result, err := reconciler.execute(context.Background(), action, &action.Target, policy, true)
	if err != nil {
		t.Fatal(err)
	}
	seenDryRun := finalizer.called && len(finalizer.options.DryRun) == 1 && finalizer.options.DryRun[0] == metav1.DryRunAll
	if result != safetyv1alpha1.ApprovalResultDryRunValidated || !seenDryRun {
		t.Fatalf("dry-run was not sent to namespaces/finalize: result=%s seen=%v", result, seenDryRun)
	}
}

type recordingNamespaceFinalizer struct {
	called  bool
	options metav1.UpdateOptions
}

func (finalizer *recordingNamespaceFinalizer) Finalize(_ context.Context, namespace *corev1.Namespace, options metav1.UpdateOptions) (*corev1.Namespace, error) {
	finalizer.called = true
	finalizer.options = options
	result := namespace.DeepCopy()
	result.ResourceVersion = "8"
	return result, nil
}

func TestKeyedLocksCleanUp(t *testing.T) {
	locks := newKeyedLocks()
	unlock := locks.lock("target")
	if locks.size() != 1 {
		t.Fatal("lock entry not retained while used")
	}
	unlock()
	if locks.size() != 0 {
		t.Fatal("lock entry leaked")
	}
}

func testExecutor(t *testing.T, ttl time.Duration, actualUID types.UID, finalizers []string) (*Reconciler, client.Client, *dynamicfake.FakeDynamicClient, time.Time) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := safetyv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	policy := &safetyv1alpha1.TerminationPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", UID: "policy-uid", Generation: 1}, Spec: safetyv1alpha1.TerminationPolicySpec{
		TargetRules: []safetyv1alpha1.TargetRule{{APIGroups: []string{""}, Resources: []string{"pods"}}}, TerminationAge: metav1.Duration{Duration: time.Minute},
		Diagnosis: safetyv1alpha1.DiagnosisPolicy{MaxNamespaceObjects: 10, MaxCRDInstances: 10}, Remediation: safetyv1alpha1.RemediationPolicy{MaxRisk: safetyv1alpha1.RiskHigh, AllowedFinalizers: []string{"remove.io/finalizer"}, ApprovalTTL: metav1.Duration{Duration: ttl}}, Retention: safetyv1alpha1.RetentionPolicy{ResolvedIncidentTTL: metav1.Duration{Duration: time.Hour}},
	}}
	action := safetyv1alpha1.RemediationAction{ID: "action", Type: safetyv1alpha1.ActionRemoveResourceFinalizer, Risk: safetyv1alpha1.RiskMedium, Eligible: true, Finalizer: "remove.io/finalizer", PreconditionResourceVersion: "7", Target: safetyv1alpha1.TargetReference{Version: "v1", Resource: "pods", Kind: "Pod", Namespace: "ns", Name: "blocked", UID: "target-uid"}}
	evidenceTime := metav1.NewTime(now)
	evidenceExpires := metav1.NewTime(now.Add(24 * time.Hour))
	incident := &safetyv1alpha1.DeletionIncident{ObjectMeta: metav1.ObjectMeta{Name: "deletion-target-uid", UID: "incident-uid"}, Spec: safetyv1alpha1.DeletionIncidentSpec{Target: action.Target, FirstObservedTime: metav1.NewTime(now)}, Status: safetyv1alpha1.DeletionIncidentStatus{Phase: safetyv1alpha1.IncidentPhaseActive, ActivePolicyRef: &safetyv1alpha1.PolicyReference{Name: policy.Name, UID: policy.UID, Generation: policy.Generation}, ActionEvidenceTime: &evidenceTime, ActionEvidenceExpiresTime: &evidenceExpires, RecommendedActions: []safetyv1alpha1.RemediationAction{action}}}
	approval := &safetyv1alpha1.RemediationApproval{ObjectMeta: metav1.ObjectMeta{Name: "approval", UID: "approval-uid", CreationTimestamp: metav1.NewTime(now)}, Spec: safetyv1alpha1.RemediationApprovalSpec{IncidentRef: safetyv1alpha1.ObjectIdentityReference{Name: incident.Name, UID: incident.UID}, ActionID: action.ID, Reason: "approved for test"}}
	store := clientfake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(approval).WithObjects(policy, incident, approval).Build()

	discovery := &fake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{{GroupVersion: "v1", APIResources: []metav1.APIResource{{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: metav1.Verbs{"get", "list"}}}}}
	catalog := catalogdiscovery.NewCatalog(discovery, time.Hour, logr.Discard())
	if err := catalog.Refresh(); err != nil {
		t.Fatal(err)
	}
	target := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "blocked", "namespace": "ns", "uid": string(actualUID), "resourceVersion": "7", "finalizers": stringInterfaces(finalizers)}}}
	namespace := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "ns", "uid": "namespace-uid", "resourceVersion": "2"}}}
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme, target, namespace)
	kubeClient := kubernetesfake.NewClientset()
	reconciler, err := NewReconciler(store, store, dynamicClient, kubeClient, catalog, events.NewFakeRecorder(10), 5)
	if err != nil {
		t.Fatal(err)
	}
	reconciler.now = func() time.Time { return now }
	return reconciler, store, dynamicClient, now
}

func stringInterfaces(values []string) []any {
	result := make([]any, len(values))
	for i := range values {
		result[i] = values[i]
	}
	return result
}
