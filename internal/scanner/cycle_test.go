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
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	"github.com/erayack/exitguard/internal/diagnosis"
)

func TestRunCycleDegradedCheckpoints(t *testing.T) {
	tests := []struct {
		name      string
		reason    string
		configure func(*testing.T, *Coordinator, client.Client, context.CancelFunc) error
	}{
		{
			name:   "catalog unavailable",
			reason: "DiscoveryUnavailable",
			configure: func(t *testing.T, coordinator *Coordinator, _ client.Client, _ context.CancelFunc) error {
				runner := liveCycleRunnerForTest(t, coordinator)
				runner.catalog = unavailableCycleCatalog{Catalog: runner.catalog}
				return nil
			},
		},
		{
			name:   "policy list",
			reason: "PolicyCompilationFailed",
			configure: func(t *testing.T, coordinator *Coordinator, _ client.Client, _ context.CancelFunc) error {
				liveCycleRunnerForTest(t, coordinator).reader = cycleFailingReader{Reader: liveCycleRunnerForTest(t, coordinator).reader, policyErr: errors.New("policy list failed")}
				return nil
			},
		},
		{
			name:   "policy status",
			reason: "PolicyCompilationFailed",
			configure: func(t *testing.T, coordinator *Coordinator, _ client.Client, _ context.CancelFunc) error {
				runner := liveCycleRunnerForTest(t, coordinator)
				runner.writer = cycleFailingClient{Client: runner.writer, policyStatusErr: errors.New("policy status failed")}
				return nil
			},
		},
		{
			name:   "namespace inventory",
			reason: "NamespaceInventoryFailed",
			configure: func(t *testing.T, coordinator *Coordinator, _ client.Client, _ context.CancelFunc) error {
				metadataClient := liveCycleRunnerForTest(t, coordinator).metadata
				fakeClient, ok := metadataClient.(interface {
					PrependReactor(string, string, k8stesting.ReactionFunc)
				})
				if !ok {
					t.Fatalf("metadata client = %T, want reactor support", metadataClient)
				}
				fakeClient.PrependReactor("list", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("namespace list failed")
				})
				return nil
			},
		},
		{
			name:   "diagnosis snapshot",
			reason: "SnapshotFailed",
			configure: func(t *testing.T, coordinator *Coordinator, _ client.Client, _ context.CancelFunc) error {
				runner := liveCycleRunnerForTest(t, coordinator)
				runner.reader = snapshotFailingReader{Reader: runner.reader}
				return nil
			},
		},
		{
			name:   "target list cancellation",
			reason: "ScanTimedOut",
			configure: func(t *testing.T, coordinator *Coordinator, _ client.Client, cancel context.CancelFunc) error {
				metadataClient := liveCycleRunnerForTest(t, coordinator).metadata
				fakeClient := metadataClient.(interface {
					PrependReactor(string, string, k8stesting.ReactionFunc)
				})
				fakeClient.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
					cancel()
					return true, nil, context.Canceled
				})
				return nil
			},
		},
		{
			name:   "diagnosis cancellation",
			reason: "ScanTimedOut",
			configure: func(t *testing.T, coordinator *Coordinator, _ client.Client, cancel context.CancelFunc) error {
				liveCycleRunnerForTest(t, coordinator).engine = diagnosis.NewEngine(cancelingDiagnosisReader{cancel: cancel})
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator, _, store, now := testCoordinator(t)
			if err := coordinator.RunCycle(context.Background()); err != nil {
				t.Fatalf("prime active incident: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := test.configure(t, coordinator, store, cancel); err != nil {
				t.Fatal(err)
			}
			*now = now.Add(time.Minute)
			err := coordinator.RunCycle(ctx)
			if err == nil {
				t.Fatal("degraded cycle returned nil error")
			}
			assertFailedIncident(t, store, "deletion-target-uid", test.reason)
		})
	}
}

func TestRunCycleJoinsPrimaryAndDegradedWriteErrors(t *testing.T) {
	coordinator, _, _, _ := testCoordinator(t)
	runner := liveCycleRunnerForTest(t, coordinator)
	primaryErr := errors.New("policy primary failure")
	degradedErr := errors.New("degraded incident list failure")
	runner.reader = cycleFailingReader{Reader: runner.reader, policyErr: primaryErr, incidentErr: degradedErr}

	err := coordinator.RunCycle(context.Background())
	if !errors.Is(err, primaryErr) || !errors.Is(err, degradedErr) {
		t.Fatalf("cycle error = %v, want joined primary and degraded errors", err)
	}
}

func TestRunCycleContinuesAfterRecoverableFailures(t *testing.T) {
	t.Run("target inventory error continues lifecycle", func(t *testing.T) {
		coordinator, metadataClient, store, now := testCoordinator(t)
		ctx := context.Background()
		if err := coordinator.RunCycle(ctx); err != nil {
			t.Fatal(err)
		}
		addConfigMapPolicyRuleAndStaleIncident(t, store, *now)
		targetErr := errors.New("pods inventory failed")
		metadataClient.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, targetErr
		})
		*now = now.Add(time.Minute)

		err := coordinator.RunCycle(ctx)
		if !errors.Is(err, targetErr) {
			t.Fatalf("cycle error = %v, want target inventory error", err)
		}
		assertIncidentPhase(t, store, "stale-configmap", safetyv1alpha1.IncidentPhaseResolved)
	})

	t.Run("diagnosis error continues lifecycle", func(t *testing.T) {
		coordinator, _, store, now := testCoordinator(t)
		ctx := context.Background()
		if err := coordinator.RunCycle(ctx); err != nil {
			t.Fatal(err)
		}
		createStalePodIncident(t, store, *now, "stale-pod")
		runner := liveCycleRunnerForTest(t, coordinator)
		runner.engine = diagnosis.NewEngine(failingDiagnosisReader{})
		*now = now.Add(time.Minute)

		if err := coordinator.RunCycle(ctx); err == nil || !strings.Contains(err.Error(), "target read failed") {
			t.Fatalf("cycle error = %v, want diagnosis error", err)
		}
		assertIncidentPhase(t, store, "stale-pod", safetyv1alpha1.IncidentPhaseResolved)
	})

	t.Run("diagnosis and lifecycle errors are joined", func(t *testing.T) {
		coordinator, _, store, now := testCoordinator(t)
		ctx := context.Background()
		if err := coordinator.RunCycle(ctx); err != nil {
			t.Fatal(err)
		}
		createStalePodIncident(t, store, *now, "stale-pod")
		runner := liveCycleRunnerForTest(t, coordinator)
		runner.engine = diagnosis.NewEngine(failingDiagnosisReader{})
		lifecycleErr := errors.New("stale lifecycle update failed")
		runner.writer = namedIncidentStatusFailingClient{Client: runner.writer, name: "stale-pod", err: lifecycleErr}
		*now = now.Add(time.Minute)

		err := coordinator.RunCycle(ctx)
		if err == nil || !strings.Contains(err.Error(), "target read failed") || !errors.Is(err, lifecycleErr) {
			t.Fatalf("cycle error = %v, want joined diagnosis and lifecycle errors", err)
		}
	})
}

func TestRunCycleIncidentViewRelistRules(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		coordinator, _, _, _ := testCoordinator(t)
		counter := installIncidentListCounter(t, coordinator)
		if err := coordinator.RunCycle(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertIncidentLists(t, counter, 2)
	})

	t.Run("same phase refresh", func(t *testing.T) {
		coordinator, _, _, now := testCoordinator(t)
		if err := coordinator.RunCycle(context.Background()); err != nil {
			t.Fatal(err)
		}
		counter := installIncidentListCounter(t, coordinator)
		*now = now.Add(observationRefresh)
		if err := coordinator.RunCycle(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertIncidentLists(t, counter, 1)
	})

	t.Run("phase transition", func(t *testing.T) {
		coordinator, _, _, now := testCoordinator(t)
		if err := coordinator.RunCycle(context.Background()); err != nil {
			t.Fatal(err)
		}
		runner := liveCycleRunnerForTest(t, coordinator)
		runner.engine = diagnosis.NewEngine(failingDiagnosisReader{})
		counter := installIncidentListCounter(t, coordinator)
		*now = now.Add(time.Minute)
		if err := coordinator.RunCycle(context.Background()); err == nil {
			t.Fatal("phase transition cycle returned nil error")
		}
		assertIncidentLists(t, counter, 2)
	})

	t.Run("resolution and retention deletion", func(t *testing.T) {
		coordinator, metadataClient, _, now := testCoordinator(t)
		ctx := context.Background()
		if err := coordinator.RunCycle(ctx); err != nil {
			t.Fatal(err)
		}
		if err := metadataClient.Resource(schema.GroupVersionResource{Version: "v1", Resource: "pods"}).Namespace("ns").Delete(ctx, "blocked", metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		resolutionCounter := installIncidentListCounter(t, coordinator)
		*now = now.Add(time.Minute)
		if err := coordinator.RunCycle(ctx); err != nil {
			t.Fatal(err)
		}
		assertIncidentLists(t, resolutionCounter, 2)

		deletionCounter := installIncidentListCounter(t, coordinator)
		*now = now.Add(2 * time.Hour)
		if err := coordinator.RunCycle(ctx); err != nil {
			t.Fatal(err)
		}
		assertIncidentLists(t, deletionCounter, 2)
	})

	t.Run("concurrent create detection", func(t *testing.T) {
		coordinator, _, store, now := testCoordinator(t)
		ctx := context.Background()
		if err := coordinator.RunCycle(ctx); err != nil {
			t.Fatal(err)
		}
		var incident safetyv1alpha1.DeletionIncident
		if err := store.Get(ctx, client.ObjectKey{Name: "deletion-target-uid"}, &incident); err != nil {
			t.Fatal(err)
		}
		if err := store.Delete(ctx, &incident); err != nil {
			t.Fatal(err)
		}
		incident.ResourceVersion = ""
		runner := liveCycleRunnerForTest(t, coordinator)
		hook := &incidentListHookReader{Reader: runner.reader, afterFirst: func() error { return store.Create(ctx, &incident) }}
		runner.reader = hook
		*now = now.Add(time.Minute)
		if err := coordinator.RunCycle(ctx); err != nil {
			t.Fatal(err)
		}
		if hook.incidentLists != 2 {
			t.Fatalf("incident list calls = %d, want scan-scope and concurrent-create relist", hook.incidentLists)
		}
	})

	t.Run("degraded transition", func(t *testing.T) {
		coordinator, _, _, _ := testCoordinator(t)
		if err := coordinator.RunCycle(context.Background()); err != nil {
			t.Fatal(err)
		}
		runner := liveCycleRunnerForTest(t, coordinator)
		counter := installIncidentListCounter(t, coordinator)
		runner.reader = cycleFailingReader{Reader: runner.reader, policyErr: errors.New("policy list failed")}
		if err := coordinator.RunCycle(context.Background()); err == nil {
			t.Fatal("degraded cycle returned nil error")
		}
		assertIncidentLists(t, counter, 2)
	})
}

func TestRunCycleFinalizesMetricsAfterLifecycleError(t *testing.T) {
	coordinator, metadataClient, store, now := testCoordinator(t)
	ctx := context.Background()
	if err := coordinator.RunCycle(ctx); err != nil {
		t.Fatal(err)
	}
	if err := metadataClient.Resource(schema.GroupVersionResource{Version: "v1", Resource: "pods"}).Namespace("ns").Delete(ctx, "blocked", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	runner := liveCycleRunnerForTest(t, coordinator)
	lifecycleErr := errors.New("lifecycle status failed")
	runner.writer = cycleFailingClient{Client: store, incidentStatusErr: lifecycleErr}
	counter := installIncidentListCounter(t, coordinator)
	*now = now.Add(time.Minute)

	err := coordinator.RunCycle(ctx)
	if !errors.Is(err, lifecycleErr) {
		t.Fatalf("cycle error = %v, want lifecycle error", err)
	}
	assertIncidentLists(t, counter, 2)
}

func assertFailedIncident(t *testing.T, store client.Client, name, reason string) {
	t.Helper()
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(context.Background(), client.ObjectKey{Name: name}, &incident); err != nil {
		t.Fatal(err)
	}
	if incident.Status.Phase != safetyv1alpha1.IncidentPhaseDiagnosisFailed || len(incident.Status.RecommendedActions) != 0 || incident.Status.ActionEvidenceExpiresTime != nil {
		t.Fatalf("degraded incident status = %#v", incident.Status)
	}
	for _, condition := range incident.Status.Conditions {
		if condition.Type == "DiagnosisComplete" && condition.Reason == reason {
			return
		}
	}
	t.Fatalf("DiagnosisComplete reason %q not found in %#v", reason, incident.Status.Conditions)
}

func assertIncidentPhase(t *testing.T, store client.Client, name string, phase safetyv1alpha1.IncidentPhase) {
	t.Helper()
	var incident safetyv1alpha1.DeletionIncident
	if err := store.Get(context.Background(), client.ObjectKey{Name: name}, &incident); err != nil {
		t.Fatal(err)
	}
	if incident.Status.Phase != phase {
		t.Fatalf("incident %s phase = %q, want %q", name, incident.Status.Phase, phase)
	}
}

func installIncidentListCounter(t *testing.T, coordinator *Coordinator) *incidentListCountingReader {
	t.Helper()
	runner := liveCycleRunnerForTest(t, coordinator)
	counter := &incidentListCountingReader{Reader: runner.reader}
	runner.reader = counter
	return counter
}

func assertIncidentLists(t *testing.T, counter *incidentListCountingReader, want int64) {
	t.Helper()
	if got := counter.incidentLists.Load(); got != want {
		t.Fatalf("incident list calls = %d, want %d", got, want)
	}
}

func addConfigMapPolicyRuleAndStaleIncident(t *testing.T, store client.Client, now time.Time) {
	t.Helper()
	ctx := context.Background()
	var policy safetyv1alpha1.TerminationPolicy
	if err := store.Get(ctx, client.ObjectKey{Name: "policy"}, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Generation++
	policy.Spec.TargetRules[0].Resources = []string{"pods", "configmaps"}
	if err := store.Update(ctx, &policy); err != nil {
		t.Fatal(err)
	}
	incident := staleIncident(now, "stale-configmap", "configmaps", "ConfigMap", "missing-configmap", "stale-configmap-uid")
	if err := store.Create(ctx, incident); err != nil {
		t.Fatal(err)
	}
}

func createStalePodIncident(t *testing.T, store client.Client, now time.Time, name string) {
	t.Helper()
	if err := store.Create(context.Background(), staleIncident(now, name, "pods", "Pod", "missing-pod", "stale-pod-uid")); err != nil {
		t.Fatal(err)
	}
}

func staleIncident(now time.Time, name, resource, kind, targetName string, uid types.UID) *safetyv1alpha1.DeletionIncident {
	return &safetyv1alpha1.DeletionIncident{
		ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: map[string]string{retentionAnnotation: time.Hour.String()}},
		Spec: safetyv1alpha1.DeletionIncidentSpec{
			Target:            safetyv1alpha1.TargetReference{Version: "v1", Resource: resource, Kind: kind, Namespace: "ns", Name: targetName, UID: uid},
			FirstObservedTime: metav1.NewTime(now.Add(-time.Hour)),
		},
		Status: safetyv1alpha1.DeletionIncidentStatus{
			Phase:           safetyv1alpha1.IncidentPhaseActive,
			ActivePolicyRef: &safetyv1alpha1.PolicyReference{Name: "policy", UID: "policy-uid", Generation: 1},
		},
	}
}

type unavailableCycleCatalog struct{ Catalog }

func (unavailableCycleCatalog) LastResult() (time.Time, error) {
	return time.Time{}, errors.New("catalog refresh failed")
}

type cycleFailingReader struct {
	client.Reader
	policyErr   error
	incidentErr error
}

func (r cycleFailingReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	switch list.(type) {
	case *safetyv1alpha1.TerminationPolicyList:
		if r.policyErr != nil {
			return r.policyErr
		}
	case *safetyv1alpha1.DeletionIncidentList:
		if r.incidentErr != nil {
			return r.incidentErr
		}
	}
	return r.Reader.List(ctx, list, options...)
}

type cycleFailingClient struct {
	client.Client
	policyStatusErr   error
	incidentStatusErr error
}

func (c cycleFailingClient) Status() client.SubResourceWriter {
	return cycleFailingStatusWriter{SubResourceWriter: c.Client.Status(), policyErr: c.policyStatusErr, incidentErr: c.incidentStatusErr}
}

type cycleFailingStatusWriter struct {
	client.SubResourceWriter
	policyErr   error
	incidentErr error
}

func (w cycleFailingStatusWriter) Update(ctx context.Context, object client.Object, options ...client.SubResourceUpdateOption) error {
	switch object.(type) {
	case *safetyv1alpha1.TerminationPolicy:
		if w.policyErr != nil {
			return w.policyErr
		}
	case *safetyv1alpha1.DeletionIncident:
		if w.incidentErr != nil {
			return w.incidentErr
		}
	}
	return w.SubResourceWriter.Update(ctx, object, options...)
}

type namedIncidentStatusFailingClient struct {
	client.Client
	name string
	err  error
}

func (c namedIncidentStatusFailingClient) Status() client.SubResourceWriter {
	return namedIncidentStatusFailingWriter{SubResourceWriter: c.Client.Status(), name: c.name, err: c.err}
}

type namedIncidentStatusFailingWriter struct {
	client.SubResourceWriter
	name string
	err  error
}

func (w namedIncidentStatusFailingWriter) Update(ctx context.Context, object client.Object, options ...client.SubResourceUpdateOption) error {
	if incident, ok := object.(*safetyv1alpha1.DeletionIncident); ok && incident.Name == w.name {
		return w.err
	}
	return w.SubResourceWriter.Update(ctx, object, options...)
}

type cancelingDiagnosisReader struct{ cancel context.CancelFunc }

func (r cancelingDiagnosisReader) Get(context.Context, schema.GroupVersionResource, string, string) (*unstructured.Unstructured, error) {
	r.cancel()
	return nil, context.Canceled
}

func (cancelingDiagnosisReader) ListMetadata(context.Context, schema.GroupVersionResource, string, metav1.ListOptions) (*metav1.PartialObjectMetadataList, error) {
	return nil, errors.New("unexpected metadata list")
}

type incidentListHookReader struct {
	client.Reader
	mu            sync.Mutex
	incidentLists int
	afterFirst    func() error
}

func (r *incidentListHookReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	if _, ok := list.(*safetyv1alpha1.DeletionIncidentList); !ok {
		return r.Reader.List(ctx, list, options...)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.incidentLists++
	if err := r.Reader.List(ctx, list, options...); err != nil {
		return err
	}
	if r.incidentLists == 1 && r.afterFirst != nil {
		return r.afterFirst()
	}
	return nil
}
