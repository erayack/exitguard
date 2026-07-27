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
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
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
	"github.com/erayack/exitguard/internal/perftest"
)

type executorBenchmarkCase struct {
	name              string
	actionType        safetyv1alpha1.RemediationActionType
	dryRun            bool
	replay            bool
	superseded        bool
	alreadySatisfied  bool
	targetReplaced    bool
	ineligible        bool
	wantPhase         safetyv1alpha1.ApprovalPhase
	wantResult        safetyv1alpha1.ApprovalResult
	wantTargetMutated bool
	operations        map[perftest.Operation]int64
}

// BenchmarkExecutorReconcile measures complete approval reconciliation against
// deterministic fake clients. Every iteration receives isolated API state; all
// fixture construction, counter checks, and durable-state verification are
// outside the timed region.
func BenchmarkExecutorReconcile(b *testing.B) {
	cases := []executorBenchmarkCase{
		{
			name: "ResourceFinalizerMutation", actionType: safetyv1alpha1.ActionRemoveResourceFinalizer,
			wantPhase: safetyv1alpha1.ApprovalPhaseSucceeded, wantResult: safetyv1alpha1.ApprovalResultMutated, wantTargetMutated: true,
			operations: executorMutationOperations(2, 1, 0),
		},
		{
			name: "ResourceFinalizerDryRun", actionType: safetyv1alpha1.ActionRemoveResourceFinalizer, dryRun: true,
			wantPhase: safetyv1alpha1.ApprovalPhaseDryRunSucceeded, wantResult: safetyv1alpha1.ApprovalResultDryRunValidated,
			operations: executorMutationOperations(2, 1, 1),
		},
		{
			name: "ReplayAlreadySatisfied", actionType: safetyv1alpha1.ActionRemoveResourceFinalizer, replay: true, alreadySatisfied: true,
			wantPhase: safetyv1alpha1.ApprovalPhaseSucceeded, wantResult: safetyv1alpha1.ApprovalResultAlreadySatisfied,
			operations: map[perftest.Operation]int64{perftest.TypedGet: 6, perftest.DynamicGet: 1, perftest.StatusWrite: 1, perftest.Write: 1},
		},
		{
			name: "SupersededAction", actionType: safetyv1alpha1.ActionRemoveResourceFinalizer, superseded: true,
			wantPhase: safetyv1alpha1.ApprovalPhaseSuperseded, wantResult: safetyv1alpha1.ApprovalResultTargetChanged,
			operations: map[perftest.Operation]int64{perftest.TypedGet: 4, perftest.Patch: 1, perftest.StatusWrite: 1, perftest.Write: 2},
		},
		{
			name: "AlreadySatisfied", actionType: safetyv1alpha1.ActionRemoveResourceFinalizer, alreadySatisfied: true,
			wantPhase: safetyv1alpha1.ApprovalPhaseSucceeded, wantResult: safetyv1alpha1.ApprovalResultAlreadySatisfied,
			operations: executorMutationOperations(2, 0, 0),
		},
		{
			name: "TargetReplaced", actionType: safetyv1alpha1.ActionRemoveResourceFinalizer, targetReplaced: true,
			wantPhase: safetyv1alpha1.ApprovalPhaseSuperseded, wantResult: safetyv1alpha1.ApprovalResultTargetReplaced,
			operations: executorMutationOperations(1, 0, 0),
		},
		{
			name: "ValidationRejected", actionType: safetyv1alpha1.ActionRemoveResourceFinalizer, ineligible: true,
			wantPhase: safetyv1alpha1.ApprovalPhaseFailed, wantResult: safetyv1alpha1.ApprovalResultRejectedByPolicy,
			operations: map[perftest.Operation]int64{perftest.TypedGet: 5, perftest.Patch: 1, perftest.StatusWrite: 1, perftest.Write: 2},
		},
		{
			name: "CRDFinalizerMutation", actionType: safetyv1alpha1.ActionRemoveCRDFinalizer,
			wantPhase: safetyv1alpha1.ApprovalPhaseSucceeded, wantResult: safetyv1alpha1.ApprovalResultMutated, wantTargetMutated: true,
			operations: executorMutationOperations(1, 1, 0),
		},
		{
			name: "NamespaceFinalize", actionType: safetyv1alpha1.ActionForceFinalizeNamespace,
			wantPhase: safetyv1alpha1.ApprovalPhaseSucceeded, wantResult: safetyv1alpha1.ApprovalResultMutated, wantTargetMutated: true,
			operations: executorFinalizeOperations(),
		},
	}

	for _, benchmarkCase := range cases {
		benchmarkCase := benchmarkCase
		b.Run(benchmarkCase.name, func(b *testing.B) {
			benchmarkExecutorCase(b, benchmarkCase)
		})
	}
}

func benchmarkExecutorCase(b *testing.B, benchmarkCase executorBenchmarkCase) {
	ctx := context.Background()
	var counters perftest.Counters
	b.ReportAllocs()
	b.ResetTimer()
	b.StopTimer()
	for range b.N {
		fixture := newExecutorBenchmarkFixture(b, benchmarkCase, &counters)
		b.StartTimer()
		_, err := fixture.reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: fixture.approvalName}})
		b.StopTimer()
		if err != nil {
			counters.Record(perftest.Mismatch)
			b.Fatalf("reconcile: %v", err)
		}
		fixture.verify(b)
	}

	expected := multiplyOperations(benchmarkCase.operations, int64(b.N))
	if err := counters.Check(expected); err != nil {
		b.Fatal(err)
	}
	reconciliations := float64(b.N)
	snapshot := counters.Snapshot()
	b.ReportMetric(float64(snapshot.Value(perftest.TypedGet)+snapshot.Value(perftest.DynamicGet))/reconciliations, "gets/reconcile")
	b.ReportMetric(float64(snapshot.Value(perftest.Patch))/reconciliations, "patches/reconcile")
	b.ReportMetric(float64(snapshot.Value(perftest.Finalizer))/reconciliations, "finalizer_calls/reconcile")
	b.ReportMetric(float64(snapshot.Value(perftest.StatusWrite))/reconciliations, "status_writes/reconcile")
	b.ReportMetric(float64(snapshot.Value(perftest.Retry))/reconciliations, "retries/reconcile")
	b.ReportMetric(float64(executorAPIOperations(snapshot))/reconciliations, "api_operations/reconcile")
	b.ReportMetric(float64(snapshot.Value(perftest.Write))/reconciliations, "writes/reconcile")
	b.ReportMetric(float64(snapshot.Value(perftest.Mismatch))/reconciliations, "mismatches/reconcile")
}

func executorMutationOperations(dynamicGets, dynamicPatches, dryRuns int64) map[perftest.Operation]int64 {
	operations := map[perftest.Operation]int64{
		perftest.TypedGet: 9, perftest.DynamicGet: dynamicGets, perftest.Patch: 1 + dynamicPatches,
		perftest.StatusWrite: 2, perftest.Write: 3 + dynamicPatches,
	}
	if dryRuns != 0 {
		operations[perftest.DryRun] = dryRuns
	}
	return operations
}

func executorFinalizeOperations() map[perftest.Operation]int64 {
	return map[perftest.Operation]int64{
		perftest.TypedGet: 9, perftest.DynamicGet: 1, perftest.Patch: 1,
		perftest.StatusWrite: 2, perftest.Finalizer: 1, perftest.Write: 4,
	}
}

func multiplyOperations(operations map[perftest.Operation]int64, multiplier int64) map[perftest.Operation]int64 {
	result := make(map[perftest.Operation]int64, len(operations))
	for operation, count := range operations {
		result[operation] = count * multiplier
	}
	return result
}

func executorAPIOperations(snapshot perftest.Snapshot) int64 {
	return snapshot.Value(perftest.TypedGet) + snapshot.Value(perftest.DynamicGet) +
		snapshot.Value(perftest.TypedList) + snapshot.Value(perftest.DynamicList) +
		snapshot.Value(perftest.IncidentList) + snapshot.Value(perftest.PolicyList) +
		snapshot.Value(perftest.Create) + snapshot.Value(perftest.Update) +
		snapshot.Value(perftest.Patch) + snapshot.Value(perftest.StatusWrite) +
		snapshot.Value(perftest.Delete) + snapshot.Value(perftest.Finalizer)
}

type executorBenchmarkFixture struct {
	reconciler    *Reconciler
	store         client.Client
	dynamicClient *dynamicfake.FakeDynamicClient
	counters      *perftest.Counters
	benchmarkCase executorBenchmarkCase
	approvalName  string
	action        safetyv1alpha1.RemediationAction
	gvr           schema.GroupVersionResource
	initialTarget *unstructured.Unstructured
}

func newExecutorBenchmarkFixture(tb testing.TB, benchmarkCase executorBenchmarkCase, counters *perftest.Counters) *executorBenchmarkFixture {
	tb.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, safetyv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			tb.Fatal(err)
		}
	}

	now := perftest.FixedNow()
	action, target, gvr, apiResource := executorBenchmarkTarget(benchmarkCase, now)
	incidentTarget := action.Target
	policy := executorBenchmarkPolicy(action, incidentTarget)
	evidenceTime := metav1.NewTime(now.Add(-time.Minute))
	evidenceExpires := metav1.NewTime(now.Add(time.Hour))
	incident := &safetyv1alpha1.DeletionIncident{
		ObjectMeta: metav1.ObjectMeta{Name: "deletion-benchmark-target", UID: "incident-uid", ResourceVersion: "11"},
		Spec:       safetyv1alpha1.DeletionIncidentSpec{Target: incidentTarget, FirstObservedTime: metav1.NewTime(now.Add(-time.Hour))},
		Status: safetyv1alpha1.DeletionIncidentStatus{
			Phase:              safetyv1alpha1.IncidentPhaseActive,
			ActivePolicyRef:    &safetyv1alpha1.PolicyReference{Name: policy.Name, UID: policy.UID, Generation: policy.Generation},
			ActionEvidenceTime: &evidenceTime, ActionEvidenceExpiresTime: &evidenceExpires,
			RecommendedActions: []safetyv1alpha1.RemediationAction{action},
		},
	}
	approval := &safetyv1alpha1.RemediationApproval{
		ObjectMeta: metav1.ObjectMeta{Name: "benchmark-approval", UID: "approval-uid", ResourceVersion: "13", CreationTimestamp: metav1.NewTime(now.Add(-time.Minute))},
		Spec: safetyv1alpha1.RemediationApprovalSpec{
			IncidentRef: safetyv1alpha1.ObjectIdentityReference{Name: incident.Name, UID: incident.UID},
			ActionID:    action.ID, Reason: "deterministic benchmark approval", DryRun: benchmarkCase.dryRun,
		},
	}
	if benchmarkCase.replay {
		approval.OwnerReferences = []metav1.OwnerReference{{APIVersion: safetyv1alpha1.GroupVersion.String(), Kind: "DeletionIncident", Name: incident.Name, UID: incident.UID}}
		approval.Status = safetyv1alpha1.RemediationApprovalStatus{Phase: safetyv1alpha1.ApprovalPhaseRunning, Action: action.DeepCopy()}
		incident.Status.RecommendedActions = nil
	}
	if benchmarkCase.superseded {
		incident.Status.RecommendedActions = nil
	}

	store := clientfake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(approval).
		WithObjects(policy, incident, approval).Build()
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme, target, executorBenchmarkNamespace(now))
	instrumentDynamicClient(dynamicClient, counters)

	discovery := &fake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = executorBenchmarkDiscovery(apiResource)
	catalog := catalogdiscovery.NewCatalog(discovery, time.Hour, logr.Discard())
	if err := catalog.Refresh(); err != nil {
		tb.Fatalf("refresh catalog: %v", err)
	}
	reader := perftest.NewCountingReader(store, counters)
	writer := perftest.NewCountingClient(store, counters)
	reconciler, err := NewReconciler(reader, writer, dynamicClient, kubernetesfake.NewClientset(), catalog, events.NewFakeRecorder(4), 5)
	if err != nil {
		tb.Fatal(err)
	}
	reconciler.now = func() time.Time { return now }
	reconciler.namespaces = &benchmarkNamespaceFinalizer{client: dynamicClient, counters: counters}
	initialTarget, ok := target.(*unstructured.Unstructured)
	if !ok {
		tb.Fatalf("benchmark target has type %T", target)
	}
	return &executorBenchmarkFixture{
		reconciler: reconciler, store: store, dynamicClient: dynamicClient, counters: counters,
		benchmarkCase: benchmarkCase, approvalName: approval.Name, action: action, gvr: gvr,
		initialTarget: initialTarget.DeepCopy(),
	}
}

func executorBenchmarkTarget(benchmarkCase executorBenchmarkCase, now time.Time) (safetyv1alpha1.RemediationAction, runtime.Object, schema.GroupVersionResource, metav1.APIResource) {
	finalizers := []any{"keep.benchmark.io/finalizer", "remove.benchmark.io/finalizer"}
	if benchmarkCase.alreadySatisfied {
		finalizers = []any{"keep.benchmark.io/finalizer"}
	}
	uid := "target-uid"
	objectUID := uid
	if benchmarkCase.targetReplaced {
		objectUID = "replacement-uid"
	}
	target := safetyv1alpha1.TargetReference{Version: "v1", Resource: "pods", Kind: "Pod", Namespace: "benchmark", Name: "terminating", UID: types.UID(uid)}
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	apiResource := metav1.APIResource{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: metav1.Verbs{"get", "list", "patch"}}
	risk := safetyv1alpha1.RiskMedium

	switch benchmarkCase.actionType {
	case safetyv1alpha1.ActionRemoveResourceFinalizer:
		// The defaults above describe the ordinary namespaced resource path.
	case safetyv1alpha1.ActionRemoveCRDFinalizer:
		target = safetyv1alpha1.TargetReference{APIGroup: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions", Kind: "CustomResourceDefinition", Name: "fixtures.benchmark.io", UID: types.UID(uid)}
		gvr = schema.GroupVersionResource{Group: target.APIGroup, Version: target.Version, Resource: target.Resource}
		apiResource = metav1.APIResource{Name: target.Resource, Kind: target.Kind, Verbs: metav1.Verbs{"get", "list", "patch"}}
		risk = safetyv1alpha1.RiskHigh
	case safetyv1alpha1.ActionForceFinalizeNamespace:
		target = safetyv1alpha1.TargetReference{Version: "v1", Resource: "namespaces", Kind: "Namespace", Name: "terminating", UID: types.UID(uid)}
		gvr = schema.GroupVersionResource{Version: target.Version, Resource: target.Resource}
		apiResource = metav1.APIResource{Name: target.Resource, Kind: target.Kind, Verbs: metav1.Verbs{"get", "list", "update"}}
		risk = safetyv1alpha1.RiskCritical
	}

	metadata := map[string]any{
		"name": target.Name, "uid": objectUID, "resourceVersion": "7",
		"deletionTimestamp": now.Add(-time.Hour).Format(time.RFC3339), "finalizers": finalizers,
	}
	if target.Namespace != "" {
		metadata["namespace"] = target.Namespace
	}
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": gvr.GroupVersion().String(), "kind": target.Kind, "metadata": metadata,
	}}
	if benchmarkCase.actionType == safetyv1alpha1.ActionForceFinalizeNamespace {
		object.Object["spec"] = map[string]any{"finalizers": []any{"kubernetes"}}
	}
	action := safetyv1alpha1.RemediationAction{
		ID: "benchmark-action", Type: benchmarkCase.actionType, Risk: risk,
		Eligible: !benchmarkCase.ineligible, Finalizer: "remove.benchmark.io/finalizer",
		PreconditionResourceVersion: "7", Reason: "deterministic benchmark action", Target: target,
	}
	if benchmarkCase.actionType == safetyv1alpha1.ActionForceFinalizeNamespace {
		action.Finalizer = ""
	}
	return action, object, gvr, apiResource
}

func executorBenchmarkNamespace(now time.Time) runtime.Object {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": "benchmark", "uid": "namespace-uid", "resourceVersion": "5", "creationTimestamp": now.Add(-24 * time.Hour).Format(time.RFC3339)},
	}}
}

func executorBenchmarkPolicy(action safetyv1alpha1.RemediationAction, target safetyv1alpha1.TargetReference) *safetyv1alpha1.TerminationPolicy {
	allowedFinalizers := []string(nil)
	if action.Finalizer != "" {
		allowedFinalizers = []string{action.Finalizer}
	}
	return &safetyv1alpha1.TerminationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "benchmark-policy", UID: "policy-uid", ResourceVersion: "17", Generation: 3},
		Spec: safetyv1alpha1.TerminationPolicySpec{
			TargetRules:    []safetyv1alpha1.TargetRule{{APIGroups: []string{target.APIGroup}, Resources: []string{target.Resource}}},
			TerminationAge: timeDuration(time.Minute),
			Diagnosis:      safetyv1alpha1.DiagnosisPolicy{MaxNamespaceObjects: 100, MaxCRDInstances: 100},
			Remediation: safetyv1alpha1.RemediationPolicy{
				MaxRisk: safetyv1alpha1.RiskCritical, AllowedFinalizers: allowedFinalizers,
				AllowNamespaceForce: true, ApprovalTTL: timeDuration(time.Hour),
			},
			Retention: safetyv1alpha1.RetentionPolicy{ResolvedIncidentTTL: timeDuration(time.Hour)},
		},
	}
}

func timeDuration(duration time.Duration) metav1.Duration { return metav1.Duration{Duration: duration} }

func executorBenchmarkDiscovery(target metav1.APIResource) []*metav1.APIResourceList {
	coreResources := []metav1.APIResource{
		{Name: "namespaces", Kind: "Namespace", Verbs: metav1.Verbs{"get", "list", "update"}},
		{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: metav1.Verbs{"get", "list", "patch"}},
	}
	if target.Name == "customresourcedefinitions" {
		return []*metav1.APIResourceList{
			{GroupVersion: "v1", APIResources: coreResources},
			{GroupVersion: "apiextensions.k8s.io/v1", APIResources: []metav1.APIResource{target}},
		}
	}
	return []*metav1.APIResourceList{{GroupVersion: "v1", APIResources: coreResources}}
}

func instrumentDynamicClient(dynamicClient *dynamicfake.FakeDynamicClient, counters *perftest.Counters) {
	dynamicClient.PrependReactor("*", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		switch action.GetVerb() {
		case "get":
			counters.Record(perftest.DynamicGet)
		case "patch":
			counters.Record(perftest.Patch)
			counters.Record(perftest.Write)
			withOptions, ok := action.(interface{ GetPatchOptions() metav1.PatchOptions })
			if ok && len(withOptions.GetPatchOptions().DryRun) != 0 {
				counters.Record(perftest.DryRun)
				patch := action.(k8stesting.PatchAction)
				object, err := dynamicClient.Tracker().Get(action.GetResource(), action.GetNamespace(), patch.GetName())
				if err != nil {
					return true, nil, err
				}
				return true, object.DeepCopyObject(), nil
			}
		}
		return false, nil, nil
	})
}

type benchmarkNamespaceFinalizer struct {
	client   *dynamicfake.FakeDynamicClient
	counters *perftest.Counters
}

func (f *benchmarkNamespaceFinalizer) Finalize(_ context.Context, namespace *corev1.Namespace, options metav1.UpdateOptions) (*corev1.Namespace, error) {
	f.counters.Record(perftest.Finalizer)
	f.counters.Record(perftest.Write)
	if len(options.DryRun) != 0 {
		f.counters.Record(perftest.DryRun)
		return namespace.DeepCopy(), nil
	}
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	object, err := f.client.Tracker().Get(gvr, "", namespace.Name)
	if err != nil {
		return nil, err
	}
	current, ok := object.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("tracked namespace has type %T", object)
	}
	updated := current.DeepCopy()
	if err := unstructured.SetNestedStringSlice(updated.Object, nil, "spec", "finalizers"); err != nil {
		return nil, err
	}
	if err := f.client.Tracker().Update(gvr, updated, ""); err != nil {
		return nil, err
	}
	return namespace.DeepCopy(), nil
}

func (f *executorBenchmarkFixture) verify(tb testing.TB) {
	tb.Helper()
	ctx := context.Background()
	var approval safetyv1alpha1.RemediationApproval
	if err := f.store.Get(ctx, client.ObjectKey{Name: f.approvalName}, &approval); err != nil {
		f.fail(tb, "get approval: %v", err)
		return
	}
	if approval.Status.Phase != f.benchmarkCase.wantPhase || approval.Status.Result != f.benchmarkCase.wantResult {
		f.fail(tb, "approval outcome = %s/%s, want %s/%s", approval.Status.Phase, approval.Status.Result, f.benchmarkCase.wantPhase, f.benchmarkCase.wantResult)
	}
	if f.benchmarkCase.superseded || f.benchmarkCase.ineligible {
		if approval.Status.Action != nil || len(approval.Status.Attempts) != 0 {
			f.fail(tb, "rejected approval unexpectedly captured or attempted an action")
		}
	} else {
		if approval.Status.Action == nil || !reflect.DeepEqual(*approval.Status.Action, f.action) || len(approval.Status.Attempts) != 1 {
			f.fail(tb, "durable action snapshot or attempt is missing/mutable")
		}
	}

	object, err := f.dynamicClient.Tracker().Get(f.gvr, f.action.Target.Namespace, f.action.Target.Name)
	if err != nil {
		f.fail(tb, "get target: %v", err)
		return
	}
	current, ok := object.(*unstructured.Unstructured)
	if !ok {
		f.fail(tb, "tracked target has type %T", object)
		return
	}
	if !f.benchmarkCase.wantTargetMutated {
		if !reflect.DeepEqual(current.Object, f.initialTarget.Object) {
			f.fail(tb, "target changed in a no-mutation scenario")
		}
		return
	}
	if f.action.Type == safetyv1alpha1.ActionForceFinalizeNamespace {
		finalizers, found, nestedErr := unstructured.NestedStringSlice(current.Object, "spec", "finalizers")
		if nestedErr != nil {
			f.fail(tb, "read namespace finalizers: %v", nestedErr)
			return
		}
		if found && len(finalizers) != 0 {
			f.fail(tb, "namespace finalizers persisted after finalize: %v", finalizers)
		}
		return
	}
	if finalizerIndex(current.GetFinalizers(), f.action.Finalizer) >= 0 {
		f.fail(tb, "target finalizer persisted after patch: %v", current.GetFinalizers())
	}
}

func (f *executorBenchmarkFixture) fail(tb testing.TB, format string, arguments ...any) {
	f.counters.Record(perftest.Mismatch)
	tb.Errorf(format, arguments...)
}
