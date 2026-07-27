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

package scanner

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	metadatafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	"github.com/erayack/exitguard/internal/diagnosis"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
	policyengine "github.com/erayack/exitguard/internal/policy"
)

func TestRunCycleCreatesResolvesAndRetainsIncident(t *testing.T) {
	coordinator, metadataClient, store, now := testCoordinator(t)
	ctx := context.Background()
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("initial cycle: %v", err)
	}

	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatalf("get incident: %v", err)
	}
	if incident.Status.Phase != safetyv1alpha1.IncidentPhaseActive {
		t.Fatalf("phase = %q", incident.Status.Phase)
	}
	if incident.Status.ActionEvidenceTime == nil || incident.Status.ActionEvidenceExpiresTime == nil || !incident.Status.ActionEvidenceExpiresTime.After(incident.Status.ActionEvidenceTime.Time) {
		t.Fatalf("action evidence freshness was not persisted: %#v", incident.Status)
	}
	firstObserved := incident.Status.LastObservedTime.DeepCopy()

	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("no-op cycle: %v", err)
	}
	if err := store.Get(ctx, client.ObjectKey{Name: incident.Name}, &incident); err != nil {
		t.Fatal(err)
	}
	if !incident.Status.LastObservedTime.Equal(firstObserved) {
		t.Fatalf("lastObservedTime churned before five minutes")
	}

	gvr := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	if err := metadataClient.Resource(gvr).Namespace("ns").Delete(ctx, "blocked", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete metadata fixture: %v", err)
	}
	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("resolution cycle: %v", err)
	}
	if err := store.Get(ctx, client.ObjectKey{Name: incident.Name}, &incident); err != nil {
		t.Fatal(err)
	}
	if incident.Status.Phase != safetyv1alpha1.IncidentPhaseResolved || incident.Status.ResolutionReason != "TargetAbsent" {
		t.Fatalf("unexpected resolution: %#v", incident.Status)
	}

	*now = now.Add(2 * time.Hour)
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("retention cycle: %v", err)
	}
	if err := store.Get(ctx, client.ObjectKey{Name: incident.Name}, &incident); !apierrors.IsNotFound(err) {
		t.Fatalf("incident was not deleted after TTL: %v", err)
	}
}

func TestRunCyclePinsCurrentPolicyRetentionOnIncident(t *testing.T) {
	coordinator, _, store, now := testCoordinator(t)
	ctx := context.Background()
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("initial cycle: %v", err)
	}
	var policy safetyv1alpha1.TerminationPolicy
	if err := store.Get(ctx, client.ObjectKey{Name: "policy"}, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Generation++
	policy.Spec.Retention.ResolvedIncidentTTL.Duration = 2 * time.Hour
	if err := store.Update(ctx, &policy); err != nil {
		t.Fatalf("update policy retention: %v", err)
	}

	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("cycle after policy update: %v", err)
	}
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatal(err)
	}
	if got := incident.Annotations[retentionAnnotation]; got != "2h0m0s" {
		t.Fatalf("retention annotation = %q, want current policy TTL", got)
	}
}

func TestRunCyclePreservesPolicyConditionTransitionTimes(t *testing.T) {
	coordinator, _, store, now := testCoordinator(t)
	ctx := context.Background()
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("initial cycle: %v", err)
	}
	var policy safetyv1alpha1.TerminationPolicy
	if err := store.Get(ctx, client.ObjectKey{Name: "policy"}, &policy); err != nil {
		t.Fatal(err)
	}
	firstTransition := policy.Status.Conditions[0].LastTransitionTime
	firstValidation := policy.Status.LastValidatedTime.DeepCopy()

	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("second cycle: %v", err)
	}
	if err := store.Get(ctx, client.ObjectKey{Name: "policy"}, &policy); err != nil {
		t.Fatal(err)
	}
	if !policy.Status.Conditions[0].LastTransitionTime.Equal(&firstTransition) {
		t.Fatalf("unchanged policy condition transition time changed from %s to %s", firstTransition, policy.Status.Conditions[0].LastTransitionTime)
	}
	if policy.Status.LastValidatedTime == nil || !policy.Status.LastValidatedTime.After(firstValidation.Time) {
		t.Fatalf("lastValidatedTime = %v, want after %s", policy.Status.LastValidatedTime, firstValidation)
	}
}

func TestUpdatePolicyStatusHandlesStaleListedObjects(t *testing.T) {
	t.Run("conflict fetches current policy before retry", func(t *testing.T) {
		coordinator, _, store, now := testCoordinator(t)
		ctx := context.Background()
		if err := coordinator.RunCycle(ctx); err != nil {
			t.Fatalf("initial cycle: %v", err)
		}
		var stale safetyv1alpha1.TerminationPolicy
		if err := store.Get(ctx, client.ObjectKey{Name: "policy"}, &stale); err != nil {
			t.Fatal(err)
		}
		desired := *stale.Status.DeepCopy()
		desired.ResolvedResourceCount = 1
		validated := metav1.NewTime(now.Add(time.Minute))
		desired.LastValidatedTime = &validated

		hookClient := &statusUpdateHookClient{Client: store}
		hookClient.beforeFirstUpdate = func(client.Object) error {
			var concurrent safetyv1alpha1.TerminationPolicy
			if err := store.Get(ctx, client.ObjectKey{Name: stale.Name}, &concurrent); err != nil {
				return err
			}
			concurrent.Status.ResolvedResourceCount = 99
			if err := store.Status().Update(ctx, &concurrent); err != nil {
				return err
			}
			return apierrors.NewConflict(schema.GroupResource{Group: safetyv1alpha1.GroupVersion.Group, Resource: "terminationpolicies"}, stale.Name, errors.New("stale listed policy"))
		}
		coordinator.writer = hookClient

		if err := coordinator.updatePolicyStatus(ctx, &stale, desired); err != nil {
			t.Fatalf("update policy status after conflict: %v", err)
		}
		var updated safetyv1alpha1.TerminationPolicy
		if err := store.Get(ctx, client.ObjectKey{Name: stale.Name}, &updated); err != nil {
			t.Fatal(err)
		}
		if updated.Status.ResolvedResourceCount != desired.ResolvedResourceCount {
			t.Fatalf("status after retry = %#v, want resolved resource count %d", updated.Status, desired.ResolvedResourceCount)
		}
		if attempts := hookClient.statusUpdateAttempts.Load(); attempts != 2 {
			t.Fatalf("status update attempts = %d, want 2", attempts)
		}
	})

	t.Run("deletion during conflict retry is returned without recreation", func(t *testing.T) {
		coordinator, _, store, _ := testCoordinator(t)
		ctx := context.Background()
		var stale safetyv1alpha1.TerminationPolicy
		if err := store.Get(ctx, client.ObjectKey{Name: "policy"}, &stale); err != nil {
			t.Fatal(err)
		}
		desired := safetyv1alpha1.TerminationPolicyStatus{ObservedGeneration: stale.Generation}
		hookClient := &statusUpdateHookClient{Client: store}
		hookClient.beforeFirstUpdate = func(client.Object) error {
			if err := store.Delete(ctx, &stale); err != nil {
				return err
			}
			return apierrors.NewConflict(schema.GroupResource{Group: safetyv1alpha1.GroupVersion.Group, Resource: "terminationpolicies"}, stale.Name, errors.New("policy deleted"))
		}
		coordinator.writer = hookClient

		err := coordinator.updatePolicyStatus(ctx, &stale, desired)
		if !apierrors.IsNotFound(err) {
			t.Fatalf("update after deletion error = %v, want NotFound", err)
		}
		var current safetyv1alpha1.TerminationPolicy
		if err := store.Get(ctx, client.ObjectKey{Name: stale.Name}, &current); !apierrors.IsNotFound(err) {
			t.Fatalf("deleted policy was recreated: %v", err)
		}
	})
}

func TestPersistDiagnosisHandlesStaleIncidentSnapshots(t *testing.T) {
	setup := func(t *testing.T) (*Coordinator, client.Client, observation, diagnosis.Result, safetyv1alpha1.DeletionIncident, *atomic.Bool) {
		t.Helper()
		coordinator, _, store, now := testCoordinator(t)
		ctx := context.Background()
		if err := coordinator.RunCycle(ctx); err != nil {
			t.Fatalf("initial cycle: %v", err)
		}
		var incident safetyv1alpha1.DeletionIncident
		if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
			t.Fatal(err)
		}
		compiled, err := coordinator.compilePolicies(ctx, coordinator.catalog.Snapshot(), *now)
		if err != nil {
			t.Fatalf("compile policy: %v", err)
		}
		target := incident.Spec.Target
		observed := observation{
			target: target,
			policy: compiled.byUID["policy-uid"],
			meta: metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
				Name:              target.Name,
				Namespace:         target.Namespace,
				UID:               target.UID,
				ResourceVersion:   "8",
				DeletionTimestamp: incident.Status.DeletionTimestamp.DeepCopy(),
				Finalizers:        []string{"example.io/finalizer"},
			}},
		}
		result := diagnosis.Result{
			TargetFound:       true,
			UIDMatches:        true,
			ThresholdElapsed:  true,
			DiagnosisComplete: true,
			TargetSnapshot: safetyv1alpha1.TargetSnapshot{
				ResourceVersion:    "8",
				MetadataFinalizers: []string{"example.io/finalizer"},
			},
		}
		return coordinator, store, observed, result, incident, &atomic.Bool{}
	}

	t.Run("conflict fetches current incident before retry", func(t *testing.T) {
		coordinator, store, observed, result, stale, mutated := setup(t)
		ctx := context.Background()
		hookClient := &statusUpdateHookClient{Client: store}
		hookClient.beforeFirstUpdate = func(client.Object) error {
			var concurrent safetyv1alpha1.DeletionIncident
			if err := store.Get(ctx, client.ObjectKey{Name: stale.Name}, &concurrent); err != nil {
				return err
			}
			concurrent.Status.ResolutionReason = "concurrent-change"
			if err := store.Status().Update(ctx, &concurrent); err != nil {
				return err
			}
			return apierrors.NewConflict(schema.GroupResource{Group: safetyv1alpha1.GroupVersion.Group, Resource: "deletionincidents"}, stale.Name, errors.New("stale incident snapshot"))
		}
		coordinator.writer = hookClient

		if err := coordinator.persistDiagnosis(ctx, observed, result, &stale, mutated, time.Now().UTC()); err != nil {
			t.Fatalf("persist diagnosis after conflict: %v", err)
		}
		var updated safetyv1alpha1.DeletionIncident
		if err := store.Get(ctx, client.ObjectKey{Name: stale.Name}, &updated); err != nil {
			t.Fatal(err)
		}
		if updated.Status.ActivePolicyRef == nil || updated.Status.ActivePolicyRef.UID != "policy-uid" || updated.Status.ResolutionReason != "" || updated.Status.TargetSnapshot.ResourceVersion != "8" {
			t.Fatalf("unexpected status after retry: %#v", updated.Status)
		}
		if !mutated.Load() {
			t.Fatal("persisted status was not reported as mutated")
		}
		if attempts := hookClient.statusUpdateAttempts.Load(); attempts != 2 {
			t.Fatalf("status update attempts = %d, want 2", attempts)
		}
	})

	t.Run("deletion during conflict retry is returned without recreation", func(t *testing.T) {
		coordinator, store, observed, result, stale, mutated := setup(t)
		ctx := context.Background()
		hookClient := &statusUpdateHookClient{Client: store}
		hookClient.beforeFirstUpdate = func(client.Object) error {
			if err := store.Delete(ctx, &stale); err != nil {
				return err
			}
			return apierrors.NewConflict(schema.GroupResource{Group: safetyv1alpha1.GroupVersion.Group, Resource: "deletionincidents"}, stale.Name, errors.New("incident deleted"))
		}
		coordinator.writer = hookClient

		err := coordinator.persistDiagnosis(ctx, observed, result, &stale, mutated, time.Now().UTC())
		if !apierrors.IsNotFound(err) {
			t.Fatalf("persist after deletion error = %v, want NotFound", err)
		}
		var current safetyv1alpha1.DeletionIncident
		if err := store.Get(ctx, client.ObjectKey{Name: stale.Name}, &current); !apierrors.IsNotFound(err) {
			t.Fatalf("deleted incident was recreated: %v", err)
		}
	})
}

func TestCompilePoliciesCacheMatchesFreshCompilationAndInvalidatesOnCatalogChange(t *testing.T) {
	coordinator, _, store, now := testCoordinator(t)
	ctx := context.Background()
	catalog := coordinator.catalog.Snapshot()
	first, err := coordinator.compilePolicies(ctx, catalog, *now)
	if err != nil {
		t.Fatalf("first compile: %v", err)
	}
	*now = now.Add(time.Minute)
	cached, err := coordinator.compilePolicies(ctx, catalog, *now)
	if err != nil {
		t.Fatalf("cached compile: %v", err)
	}
	firstPolicy, cachedPolicy := first.byUID["policy-uid"], cached.byUID["policy-uid"]
	if firstPolicy != cachedPolicy {
		t.Fatal("unchanged policy and catalog did not reuse the compiled policy")
	}
	var source safetyv1alpha1.TerminationPolicy
	if err := store.Get(ctx, client.ObjectKey{Name: "policy"}, &source); err != nil {
		t.Fatal(err)
	}
	fresh, _ := policyengine.Compile(&source, catalog, *now)
	samePolicyIdentity := cachedPolicy.Name() == fresh.Name() &&
		cachedPolicy.UID() == fresh.UID() &&
		cachedPolicy.Generation() == fresh.Generation()
	samePolicyBehavior := cachedPolicy.Priority() == fresh.Priority() &&
		cachedPolicy.Ready() == fresh.Ready() &&
		reflect.DeepEqual(cachedPolicy.Settings(), fresh.Settings()) &&
		reflect.DeepEqual(cachedPolicy.ResolvedGroupResources(), fresh.ResolvedGroupResources())
	if !samePolicyIdentity || !samePolicyBehavior {
		t.Fatalf("cached policy behavior differs from fresh compilation: cached=%#v fresh=%#v", cachedPolicy, fresh)
	}
	for _, target := range []policyengine.Target{
		{GroupResource: schema.GroupResource{Resource: "pods"}, Namespaced: true, Namespace: "ns"},
		{GroupResource: schema.GroupResource{Resource: "configmaps"}, Namespaced: true, Namespace: "ns"},
	} {
		if cachedPolicy.Match(target) != fresh.Match(target) {
			t.Fatalf("cached match result differs from fresh compilation for %s", target.GroupResource)
		}
	}

	changedCatalog := scannerTestCatalogSnapshot(t, metav1.APIResource{Name: "configmaps", SingularName: "configmap", Namespaced: true, Kind: "ConfigMap", Verbs: metav1.Verbs{"get", "list"}})
	invalidated, err := coordinator.compilePolicies(ctx, changedCatalog, *now)
	if err != nil {
		t.Fatalf("compile after catalog change: %v", err)
	}
	invalidatedPolicy := invalidated.byUID["policy-uid"]
	if invalidatedPolicy == cachedPolicy {
		t.Fatal("catalog change reused the cached compiled policy")
	}
	if invalidatedPolicy.Ready() {
		t.Fatalf("policy remained ready after its resource disappeared from discovery: %#v", invalidatedPolicy)
	}
	if err := store.Get(ctx, client.ObjectKey{Name: "policy"}, &source); err != nil {
		t.Fatal(err)
	}
	if source.Status.ResolvedResourceCount != 0 || len(source.Status.Conditions) == 0 || source.Status.Conditions[0].Status != metav1.ConditionFalse {
		t.Fatalf("status did not reflect changed discovery catalog: %#v", source.Status)
	}
}

func TestRunCycleSkipsDiagnosisSnapshotWithoutDeletingTargets(t *testing.T) {
	coordinator, metadataClient, _, _ := testCoordinator(t)
	ctx := context.Background()
	if err := metadataClient.Resource(schema.GroupVersionResource{Version: "v1", Resource: "pods"}).Namespace("ns").Delete(ctx, "blocked", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	coordinator.reader = snapshotFailingReader{Reader: coordinator.reader}
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("empty cycle built an unnecessary diagnosis snapshot: %v", err)
	}
}

func TestSnapshotErrorClearsStaleRemediationActions(t *testing.T) {
	coordinator, _, store, now := testCoordinator(t)
	ctx := context.Background()
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("initial cycle: %v", err)
	}
	coordinator.reader = snapshotFailingReader{Reader: store}
	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); err == nil {
		t.Fatal("cycle with diagnosis snapshot failure returned nil error")
	}
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatal(err)
	}
	if incident.Status.Phase != safetyv1alpha1.IncidentPhaseDiagnosisFailed || len(incident.Status.RecommendedActions) != 0 {
		t.Fatalf("snapshot failure left stale remediation actionable: %#v", incident.Status)
	}
}

func TestOversizedDiagnosisFallsBackToCompactFailureStatus(t *testing.T) {
	coordinator, _, store, now := testCoordinator(t)
	ctx := context.Background()
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("initial cycle: %v", err)
	}
	coordinator.writer = oversizedDiagnosisClient{Client: store}
	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); !apierrors.IsRequestEntityTooLargeError(err) {
		t.Fatalf("oversized cycle error = %v, want request entity too large", err)
	}
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatal(err)
	}
	if incident.Status.Phase != safetyv1alpha1.IncidentPhaseDiagnosisFailed || len(incident.Status.Findings) != 0 || len(incident.Status.RecommendedActions) != 0 || incident.Status.ActionEvidenceExpiresTime != nil {
		t.Fatalf("oversized diagnosis did not persist compact fail-closed status: %#v", incident.Status)
	}
}

func TestCancelledScanClearsStaleRemediationActions(t *testing.T) {
	coordinator, metadataClient, store, now := testCoordinator(t)
	ctx := context.Background()
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("initial cycle: %v", err)
	}
	cancelledCtx, cancel := context.WithCancel(context.Background())
	metadataClient.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		cancel()
		return true, nil, context.Canceled
	})
	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(cancelledCtx); err == nil {
		t.Fatal("cancelled cycle returned nil error")
	}
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(context.Background(), client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatal(err)
	}
	if incident.Status.Phase != safetyv1alpha1.IncidentPhaseDiagnosisFailed || len(incident.Status.RecommendedActions) != 0 || incident.Status.ActionEvidenceExpiresTime != nil {
		t.Fatalf("cancelled scan left stale remediation actionable: %#v", incident.Status)
	}
}

func TestDiagnosisErrorClearsStaleRemediationActions(t *testing.T) {
	coordinator, _, store, now := testCoordinator(t)
	ctx := context.Background()
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("initial cycle: %v", err)
	}
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatal(err)
	}
	if len(incident.Status.RecommendedActions) == 0 {
		t.Fatal("initial diagnosis did not publish a remediation action")
	}

	coordinator.engine = diagnosis.NewEngine(failingDiagnosisReader{})
	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); err == nil {
		t.Fatal("cycle with diagnosis GET failure returned nil error")
	}
	if err := store.Get(ctx, client.ObjectKey{Name: incident.Name}, &incident); err != nil {
		t.Fatal(err)
	}
	if incident.Status.Phase != safetyv1alpha1.IncidentPhaseDiagnosisFailed || len(incident.Status.RecommendedActions) != 0 {
		t.Fatalf("stale remediation remained actionable after diagnosis failure: %#v", incident.Status)
	}
}

func TestFailedCoverageBlocksStaleRemediation(t *testing.T) {
	coordinator, metadataClient, store, now := testCoordinator(t)
	ctx := context.Background()
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatal(err)
	}
	metadataClient.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("denied"))
	})
	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); err == nil {
		t.Fatal("expected degraded cycle error")
	}
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatal(err)
	}
	if incident.Status.Phase != safetyv1alpha1.IncidentPhaseDiagnosisFailed || len(incident.Status.RecommendedActions) != 0 {
		t.Fatalf("failed coverage left stale remediation actionable: %#v", incident.Status)
	}
}

func TestRunCycleListsOnlyPolicySelectedResources(t *testing.T) {
	coordinator, metadataClient, _, _ := testCoordinator(t)
	if err := coordinator.RunCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, action := range metadataClient.Actions() {
		if action.GetVerb() == "list" && action.GetResource().Resource == "configmaps" {
			t.Fatalf("scanner listed unrelated policy resource: %#v", action)
		}
	}
}

func TestRawInventoryDoesNotConsumeTargetBound(t *testing.T) {
	coordinator, metadataClient, store, now := testCoordinator(t)
	coordinator.config.MaxTargets = 1
	deleting := metav1.NewTime(now.Add(-10 * time.Minute))
	calls := 0
	metadataClient.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls == 1 {
			ordinary := metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "ordinary", Namespace: "ns", UID: "ordinary-uid", ResourceVersion: "1"}}
			return true, fakeMetadataList("next", ordinary), nil
		}
		blocked := metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "blocked", Namespace: "ns", UID: "target-uid", ResourceVersion: "7", DeletionTimestamp: &deleting, Finalizers: []string{"example.io/finalizer"}}}
		return true, fakeMetadataList("", blocked), nil
	})
	if err := coordinator.RunCycle(context.Background()); err != nil {
		t.Fatalf("raw inventory incorrectly exhausted target bound: %v", err)
	}
	if calls != 2 {
		t.Fatalf("metadata pages = %d, want 2", calls)
	}
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(context.Background(), client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatalf("deleting target after ordinary page was not diagnosed: %v", err)
	}
}

func TestListResourceFallsBackToAlternateServedVersion(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	metadataClient := metadatafake.NewSimpleMetadataClient(scheme)
	metadataClient.PrependReactor("list", "widgets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetResource().Version == "v1" {
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "example.io", Resource: "widgets"}, "")
		}
		return true, fakeMetadataList(""), nil
	})
	coordinator := &Coordinator{metadata: metadataClient, config: Config{PageSize: 10, MaxTargets: 1}}
	resource := catalogdiscovery.Resource{
		GroupResource:     schema.GroupResource{Group: "example.io", Resource: "widgets"},
		PreferredVersion:  catalogdiscovery.Version{Version: "v1", Kind: "Widget", Namespaced: true},
		AlternateVersions: []catalogdiscovery.Version{{Version: "v1beta1", Kind: "Widget", Namespaced: true}},
	}
	_, used, err := coordinator.listResource(context.Background(), resource, compiledPolicies{}, nil, trackedTargets{}, &targetBudget{maximum: 1, reserved: map[types.UID]struct{}{}})
	if err != nil {
		t.Fatal(err)
	}
	if used.Version != "v1beta1" {
		t.Fatalf("used version = %q, want v1beta1", used.Version)
	}
}

func TestIncidentActionIDsTrackRefreshedEvidence(t *testing.T) {
	coordinator, metadataClient, dynamicClient, store, now := testCoordinatorWithDynamic(t)
	ctx := context.Background()
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("initial cycle: %v", err)
	}

	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
		t.Fatal(err)
	}
	if len(incident.Status.RecommendedActions) != 1 {
		t.Fatalf("recommended actions = %#v, want one", incident.Status.RecommendedActions)
	}
	initialID := incident.Status.RecommendedActions[0].ID

	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("unchanged cycle: %v", err)
	}
	if err := store.Get(ctx, client.ObjectKey{Name: incident.Name}, &incident); err != nil {
		t.Fatal(err)
	}
	if got := incident.Status.RecommendedActions[0].ID; got != initialID {
		t.Fatalf("unchanged evidence rotated action ID from %q to %q", initialID, got)
	}

	gvr := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	if _, err := metadataClient.Resource(gvr).Namespace("ns").Patch(ctx, "blocked", types.MergePatchType, []byte(`{"metadata":{"resourceVersion":"8"}}`), metav1.PatchOptions{}); err != nil {
		t.Fatal(err)
	}
	dynamicTarget, err := dynamicClient.Resource(gvr).Namespace("ns").Get(ctx, "blocked", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dynamicTarget.SetResourceVersion("8")
	if _, err := dynamicClient.Resource(gvr).Namespace("ns").Update(ctx, dynamicTarget, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("resource-version cycle: %v", err)
	}
	if err := store.Get(ctx, client.ObjectKey{Name: incident.Name}, &incident); err != nil {
		t.Fatal(err)
	}
	resourceVersionID := incident.Status.RecommendedActions[0].ID
	if resourceVersionID == initialID {
		t.Fatalf("resource-version change preserved stale action ID %q", initialID)
	}

	var policy safetyv1alpha1.TerminationPolicy
	if err := store.Get(ctx, client.ObjectKey{Name: "policy"}, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Generation++
	if err := store.Update(ctx, &policy); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("policy-revision cycle: %v", err)
	}
	if err := store.Get(ctx, client.ObjectKey{Name: incident.Name}, &incident); err != nil {
		t.Fatal(err)
	}
	policyRevisionID := incident.Status.RecommendedActions[0].ID
	if policyRevisionID == resourceVersionID {
		t.Fatalf("policy revision preserved stale action ID %q", resourceVersionID)
	}

	*now = now.Add(time.Minute)
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatalf("second unchanged cycle: %v", err)
	}
	if err := store.Get(ctx, client.ObjectKey{Name: incident.Name}, &incident); err != nil {
		t.Fatal(err)
	}
	if got := incident.Status.RecommendedActions[0].ID; got != policyRevisionID {
		t.Fatalf("unchanged refreshed evidence rotated action ID from %q to %q", policyRevisionID, got)
	}
}

func TestRunCycleRejectsOverlap(t *testing.T) {
	coordinator, _, _, _ := testCoordinator(t)
	coordinator.cycleMu.Lock()
	defer coordinator.cycleMu.Unlock()
	if err := coordinator.RunCycle(context.Background()); err == nil {
		t.Fatal("expected overlapping cycle rejection")
	}
}

func testCoordinator(t *testing.T) (*Coordinator, *metadatafake.FakeMetadataClient, client.Client, *time.Time) {
	t.Helper()
	coordinator, metadataClient, _, store, now := testCoordinatorWithDynamic(t)
	return coordinator, metadataClient, store, now
}

func testCoordinatorWithDynamic(t *testing.T) (*Coordinator, *metadatafake.FakeMetadataClient, *dynamicfake.FakeDynamicClient, client.Client, *time.Time) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := apiregistrationv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := safetyv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	started := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	deleting := metav1.NewTime(started.Add(-10 * time.Minute))
	policy := &safetyv1alpha1.TerminationPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", UID: "policy-uid", Generation: 1}, Spec: safetyv1alpha1.TerminationPolicySpec{
		TargetRules:    []safetyv1alpha1.TargetRule{{APIGroups: []string{""}, Resources: []string{"pods"}}},
		TerminationAge: metav1.Duration{Duration: time.Minute}, Diagnosis: safetyv1alpha1.DiagnosisPolicy{MaxNamespaceObjects: 10, MaxCRDInstances: 10},
		Remediation: safetyv1alpha1.RemediationPolicy{MaxRisk: safetyv1alpha1.RiskHigh, ApprovalTTL: metav1.Duration{Duration: time.Hour}},
		Retention:   safetyv1alpha1.RetentionPolicy{ResolvedIncidentTTL: metav1.Duration{Duration: time.Hour}},
	}}
	store := clientfake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(policy, &safetyv1alpha1.DeletionIncident{}).WithObjects(policy).Build()

	discovery := &fake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{{GroupVersion: "v1", APIResources: []metav1.APIResource{
		{Name: "pods", SingularName: "pod", Namespaced: true, Kind: "Pod", Verbs: metav1.Verbs{"get", "list"}},
		{Name: "configmaps", SingularName: "configmap", Namespaced: true, Kind: "ConfigMap", Verbs: metav1.Verbs{"get", "list"}},
	}}}
	catalog := catalogdiscovery.NewCatalog(discovery, time.Hour, discardLogger())
	if err := catalog.Refresh(); err != nil {
		t.Fatalf("refresh catalog: %v", err)
	}

	metadataObject := &metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{Name: "blocked", Namespace: "ns", UID: "target-uid", ResourceVersion: "7", DeletionTimestamp: &deleting, Finalizers: []string{"example.io/finalizer"}}}
	metadataClient := metadatafake.NewSimpleMetadataClient(scheme, metadataObject)
	target := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "blocked", "namespace": "ns", "uid": "target-uid", "resourceVersion": "7", "deletionTimestamp": deleting.Format(time.RFC3339), "finalizers": []any{"example.io/finalizer"}}}}
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme, target)
	reader := NewTargetReader(dynamicClient, metadataClient)
	coordinator, err := NewCoordinator(store, store, metadataClient, catalog, diagnosis.NewEngine(reader), Config{Interval: time.Second, Timeout: time.Minute, ResourceWorkers: 2, DiagnosisWorkers: 2, PageSize: 1, MaxTargets: 100})
	if err != nil {
		t.Fatal(err)
	}
	coordinator.now = func() time.Time { return started }
	now := &started
	coordinator.now = func() time.Time { return *now }
	return coordinator, metadataClient, dynamicClient, store, now
}

func scannerTestCatalogSnapshot(t *testing.T, resources ...metav1.APIResource) catalogdiscovery.Snapshot {
	t.Helper()
	discovery := &fake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{{GroupVersion: "v1", APIResources: resources}}
	catalog := catalogdiscovery.NewCatalog(discovery, time.Hour, discardLogger())
	if err := catalog.Refresh(); err != nil {
		t.Fatalf("refresh test catalog: %v", err)
	}
	return catalog.Snapshot()
}

func fakeMetadataList(continueToken string, items ...metav1.PartialObjectMetadata) *metav1.List {
	list := &metav1.List{ListMeta: metav1.ListMeta{Continue: continueToken}, Items: make([]runtime.RawExtension, len(items))}
	for i := range items {
		item := items[i]
		list.Items[i] = runtime.RawExtension{Object: &item}
	}
	return list
}

type snapshotFailingReader struct {
	client.Reader
}

func (r snapshotFailingReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	if _, ok := list.(*apiregistrationv1.APIServiceList); ok {
		return errors.New("snapshot list failed")
	}
	return r.Reader.List(ctx, list, options...)
}

type statusUpdateHookClient struct {
	client.Client
	beforeFirstUpdate    func(client.Object) error
	statusUpdateAttempts atomic.Int64
}

func (c *statusUpdateHookClient) Status() client.SubResourceWriter {
	return &statusUpdateHookWriter{SubResourceWriter: c.Client.Status(), client: c}
}

type statusUpdateHookWriter struct {
	client.SubResourceWriter
	client *statusUpdateHookClient
}

func (w *statusUpdateHookWriter) Update(ctx context.Context, object client.Object, options ...client.SubResourceUpdateOption) error {
	w.client.statusUpdateAttempts.Add(1)
	if hook := w.client.beforeFirstUpdate; hook != nil {
		w.client.beforeFirstUpdate = nil
		if err := hook(object); err != nil {
			return err
		}
	}
	return w.SubResourceWriter.Update(ctx, object, options...)
}

type oversizedDiagnosisClient struct {
	client.Client
}

func (c oversizedDiagnosisClient) Status() client.SubResourceWriter {
	return oversizedDiagnosisStatusWriter{delegate: c.Client.Status()}
}

type oversizedDiagnosisStatusWriter struct {
	delegate client.SubResourceWriter
}

func (w oversizedDiagnosisStatusWriter) Create(ctx context.Context, object client.Object, subResource client.Object, options ...client.SubResourceCreateOption) error {
	return w.delegate.Create(ctx, object, subResource, options...)
}

func (w oversizedDiagnosisStatusWriter) Update(ctx context.Context, object client.Object, options ...client.SubResourceUpdateOption) error {
	if incident, ok := object.(*safetyv1alpha1.DeletionIncident); ok && (len(incident.Status.Findings) > 0 || len(incident.Status.RecommendedActions) > 0) {
		return apierrors.NewRequestEntityTooLargeError("test diagnosis status is oversized")
	}
	return w.delegate.Update(ctx, object, options...)
}

func (w oversizedDiagnosisStatusWriter) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
	return w.delegate.Patch(ctx, object, patch, options...)
}

func (w oversizedDiagnosisStatusWriter) Apply(ctx context.Context, object runtime.ApplyConfiguration, options ...client.SubResourceApplyOption) error {
	return w.delegate.Apply(ctx, object, options...)
}

type failingDiagnosisReader struct{}

func (failingDiagnosisReader) Get(context.Context, schema.GroupVersionResource, string, string) (*unstructured.Unstructured, error) {
	return nil, apierrors.NewInternalError(errors.New("target read failed"))
}

func (failingDiagnosisReader) ListMetadata(context.Context, schema.GroupVersionResource, string, metav1.ListOptions) (*metav1.PartialObjectMetadataList, error) {
	return nil, errors.New("unexpected metadata list")
}

func discardLogger() logr.Logger { return logr.Discard() }
