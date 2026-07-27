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
	"fmt"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/metadata"
	k8stesting "k8s.io/client-go/testing"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	"github.com/erayack/exitguard/internal/diagnosis"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
)

const (
	benchmarkResourceCount   = 20
	benchmarkObjectsPerType  = 500
	benchmarkDeletingTargets = 100
	benchmarkPolicyCount     = 20
	benchmarkPageSize        = 100
)

// BenchmarkScannerCycleFixedScale exercises a complete scanner cycle at a stable
// 10k-object cluster scale. Fixture construction and one priming cycle are kept
// outside the timed region so results represent steady-state cycle cost.
func BenchmarkScannerCycleFixedScale(b *testing.B) {
	fixture := newScannerCycleBenchmarkFixture(b)
	ctx := context.Background()
	fixture.advance()
	if err := fixture.coordinator.RunCycle(ctx); err != nil {
		b.Fatalf("prime scanner cycle: %v", err)
	}

	fixture.resetCounters()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		fixture.advance()
		if err := fixture.coordinator.RunCycle(ctx); err != nil {
			fixture.mismatches.Add(1)
			b.Fatalf("scanner cycle: %v", err)
		}
	}
	b.StopTimer()

	fixture.verify(b)
	cycles := float64(b.N)
	b.ReportMetric(float64(benchmarkResourceCount*benchmarkObjectsPerType), "objects/cycle")
	b.ReportMetric(float64(fixture.metadata.listCalls.Load())/cycles, "metadata_list_calls/cycle")
	b.ReportMetric(float64(fixture.statusWrites.Load())/cycles, "status_writes/cycle")
	b.ReportMetric(float64(benchmarkDeletingTargets), "fixture_deleting_targets/cycle")
	b.ReportMetric(float64(fixture.mismatches.Load())/cycles, "result_mismatches/cycle")
}

type scannerCycleBenchmarkFixture struct {
	coordinator  *Coordinator
	store        client.Client
	metadata     *benchmarkMetadataClient
	statusWrites atomic.Int64
	mismatches   atomic.Int64
	now          time.Time
}

func newScannerCycleBenchmarkFixture(tb testing.TB) *scannerCycleBenchmarkFixture {
	tb.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme,
		metav1.AddMetaToScheme,
		apiregistrationv1.AddToScheme,
		safetyv1alpha1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			tb.Fatal(err)
		}
	}

	started := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	deletingAt := metav1.NewTime(started.Add(-30 * time.Minute))
	resourceNames := make([]string, benchmarkResourceCount)
	apiResources := make([]metav1.APIResource, benchmarkResourceCount)
	metadataObjects := make(map[schema.GroupVersionResource][]metav1.PartialObjectMetadata, benchmarkResourceCount+1)
	targets := make(map[string]*unstructured.Unstructured, benchmarkDeletingTargets)
	objects := make([]client.Object, 0, benchmarkPolicyCount+benchmarkDeletingTargets*2)
	namespaces := make([]metav1.PartialObjectMetadata, 10)
	for i := range namespaces {
		namespaces[i] = metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("ns-%02d", i), Labels: map[string]string{"team": "scanner"}}}
	}
	metadataObjects[schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}] = namespaces
	for resourceIndex := range benchmarkResourceCount {
		resourceName := fmt.Sprintf("resources-%02d", resourceIndex)
		kind := fmt.Sprintf("Resource%02d", resourceIndex)
		resourceNames[resourceIndex] = resourceName
		apiResources[resourceIndex] = metav1.APIResource{Name: resourceName, SingularName: fmt.Sprintf("resource-%02d", resourceIndex), Namespaced: true, Kind: kind, Verbs: metav1.Verbs{"get", "list"}}
		gvr := schema.GroupVersionResource{Group: "benchmark.io", Version: "v1", Resource: resourceName}
		items := make([]metav1.PartialObjectMetadata, benchmarkObjectsPerType)
		for objectIndex := range benchmarkObjectsPerType {
			uid := types.UID(fmt.Sprintf("r%02d-object-%04d", resourceIndex, objectIndex))
			name := fmt.Sprintf("object-%04d", objectIndex)
			namespace := fmt.Sprintf("ns-%02d", objectIndex%10)
			item := metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "benchmark.io/v1", Kind: kind}, ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: namespace, UID: uid, ResourceVersion: "7",
				Labels: map[string]string{"environment": "production", "role": "ordinary"},
			}}
			if objectIndex%100 == 0 {
				item.DeletionTimestamp = deletingAt.DeepCopy()
				item.Finalizers = []string{"benchmark.io/finalizer"}
				target := &unstructured.Unstructured{Object: map[string]any{
					"apiVersion": "benchmark.io/v1", "kind": kind,
					"metadata": map[string]any{"name": name, "namespace": namespace, "uid": string(uid), "resourceVersion": "7", "deletionTimestamp": deletingAt.Format(time.RFC3339), "finalizers": []any{"benchmark.io/finalizer"}, "labels": map[string]any{"environment": "production", "role": "ordinary"}},
				}}
				targets[benchmarkTargetKey(gvr, namespace, name)] = target
				objects = append(objects, benchmarkActiveIncident(started, resourceName, kind, namespace, name, uid, deletingAt))
			}
			items[objectIndex] = item
		}
		metadataObjects[gvr] = items
	}

	for i := range benchmarkPolicyCount {
		objects = append(objects, benchmarkPolicy(i, resourceNames))
	}
	for i := range benchmarkDeletingTargets {
		objects = append(objects, benchmarkResolvedIncident(started, i))
	}

	store := clientfake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&safetyv1alpha1.TerminationPolicy{}, &safetyv1alpha1.DeletionIncident{}).
		WithObjects(objects...).Build()
	metadataClient := &benchmarkMetadataClient{objects: metadataObjects, pageSize: benchmarkPageSize}

	discovery := &fake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{{GroupVersion: "benchmark.io/v1", APIResources: apiResources}}
	catalog := catalogdiscovery.NewCatalog(discovery, time.Hour, discardLogger())
	if err := catalog.Refresh(); err != nil {
		tb.Fatalf("refresh benchmark catalog: %v", err)
	}

	fixture := &scannerCycleBenchmarkFixture{store: store, metadata: metadataClient, now: started}
	writer := &countingStatusClient{Client: store, writes: &fixture.statusWrites}
	coordinator, err := NewCoordinator(store, writer, metadataClient, catalog, diagnosis.NewEngine(&benchmarkTargetReader{objects: targets}), Config{
		Interval: time.Minute, Timeout: time.Minute, ResourceWorkers: 4, DiagnosisWorkers: 4,
		PageSize: benchmarkPageSize, MaxTargets: benchmarkDeletingTargets * 2,
	})
	if err != nil {
		tb.Fatal(err)
	}
	coordinator.now = func() time.Time { return fixture.now }
	fixture.coordinator = coordinator
	return fixture
}

func benchmarkPolicy(index int, resources []string) *safetyv1alpha1.TerminationPolicy {
	selector := func(key, value string) *metav1.LabelSelector {
		return &metav1.LabelSelector{MatchLabels: map[string]string{key: value}}
	}
	return &safetyv1alpha1.TerminationPolicy{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("policy-%02d", index), UID: types.UID(fmt.Sprintf("policy-uid-%02d", index)), Generation: 1}, Spec: safetyv1alpha1.TerminationPolicySpec{
		Priority: int32(index),
		TargetRules: []safetyv1alpha1.TargetRule{
			{APIGroups: []string{"benchmark.io"}, Resources: resources, ObjectSelector: selector("role", "database"), NamespaceSelector: selector("team", "scanner")},
			{APIGroups: []string{"benchmark.io"}, Resources: resources, ObjectSelector: selector("environment", "production"), NamespaceSelector: selector("team", "scanner"), ExcludedNamespaces: []string{"kube-system"}},
			{APIGroups: []string{"benchmark.io"}, Resources: resources, ObjectSelector: selector("role", "ordinary"), NamespaceSelector: selector("team", "other")},
		},
		TerminationAge: metav1.Duration{Duration: time.Minute},
		Diagnosis:      safetyv1alpha1.DiagnosisPolicy{CheckAPIServices: true, CheckWebhooks: true, MaxNamespaceObjects: 1000, MaxCRDInstances: 1000},
		Remediation:    safetyv1alpha1.RemediationPolicy{MaxRisk: safetyv1alpha1.RiskHigh, AllowedFinalizers: []string{"benchmark.io/finalizer"}, ApprovalTTL: metav1.Duration{Duration: time.Hour}},
		Retention:      safetyv1alpha1.RetentionPolicy{ResolvedIncidentTTL: metav1.Duration{Duration: 365 * 24 * time.Hour}},
	}}
}

func benchmarkActiveIncident(started time.Time, resource, kind, namespace, name string, uid types.UID, deletingAt metav1.Time) *safetyv1alpha1.DeletionIncident {
	lastObserved := metav1.NewTime(started)
	return &safetyv1alpha1.DeletionIncident{ObjectMeta: metav1.ObjectMeta{Name: incidentName(uid), Annotations: map[string]string{retentionAnnotation: (365 * 24 * time.Hour).String()}}, Spec: safetyv1alpha1.DeletionIncidentSpec{
		Target: safetyv1alpha1.TargetReference{APIGroup: "benchmark.io", Version: "v1", Resource: resource, Kind: kind, Namespace: namespace, Name: name, UID: uid}, FirstObservedTime: metav1.NewTime(started.Add(-time.Hour)),
	}, Status: safetyv1alpha1.DeletionIncidentStatus{Phase: safetyv1alpha1.IncidentPhaseActive, DeletionTimestamp: deletingAt.DeepCopy(), LastObservedTime: &lastObserved}}
}

func benchmarkResolvedIncident(started time.Time, index int) *safetyv1alpha1.DeletionIncident {
	resolved := metav1.NewTime(started)
	uid := types.UID(fmt.Sprintf("resolved-%03d", index))
	return &safetyv1alpha1.DeletionIncident{ObjectMeta: metav1.ObjectMeta{Name: incidentName(uid), Annotations: map[string]string{retentionAnnotation: (365 * 24 * time.Hour).String()}}, Spec: safetyv1alpha1.DeletionIncidentSpec{
		Target: safetyv1alpha1.TargetReference{APIGroup: "benchmark.io", Version: "v1", Resource: "resources-00", Kind: "Resource00", Namespace: "ns-00", Name: fmt.Sprintf("resolved-%03d", index), UID: uid}, FirstObservedTime: metav1.NewTime(started.Add(-2 * time.Hour)),
	}, Status: safetyv1alpha1.DeletionIncidentStatus{Phase: safetyv1alpha1.IncidentPhaseResolved, ResolvedTime: &resolved, ActivePolicyRef: &safetyv1alpha1.PolicyReference{Name: "policy-19", UID: "policy-uid-19", Generation: 1}}}
}

func (f *scannerCycleBenchmarkFixture) advance() { f.now = f.now.Add(time.Minute) }

func (f *scannerCycleBenchmarkFixture) resetCounters() {
	f.metadata.listCalls.Store(0)
	f.statusWrites.Store(0)
	f.mismatches.Store(0)
}

func (f *scannerCycleBenchmarkFixture) verify(tb testing.TB) {
	tb.Helper()
	var incidents safetyv1alpha1.DeletionIncidentList
	if err := f.store.List(context.Background(), &incidents); err != nil {
		f.mismatches.Add(1)
		tb.Errorf("list benchmark incidents: %v", err)
		return
	}
	active, resolved := 0, 0
	policyReferenceMismatches := 0
	statusPayloadMismatches := 0
	for i := range incidents.Items {
		incident := &incidents.Items[i]
		policyRef := incident.Status.ActivePolicyRef
		if policyRef == nil || policyRef.Name != "policy-19" || policyRef.UID != "policy-uid-19" || policyRef.Generation != 1 {
			policyReferenceMismatches++
		}
		switch incident.Status.Phase {
		case safetyv1alpha1.IncidentPhaseActive:
			active++
			finalizers := incident.Status.TargetSnapshot.MetadataFinalizers
			if incident.Status.DeletionTimestamp == nil || incident.Status.LastObservedTime == nil ||
				incident.Status.TargetSnapshot.ResourceVersion != "7" ||
				len(finalizers) != 1 || finalizers[0] != "benchmark.io/finalizer" ||
				len(incident.Status.Conditions) == 0 {
				statusPayloadMismatches++
			}
		case safetyv1alpha1.IncidentPhaseResolved:
			resolved++
			if incident.Status.ResolvedTime == nil {
				statusPayloadMismatches++
			}
		default:
			statusPayloadMismatches++
		}
	}
	if policyReferenceMismatches != 0 {
		f.mismatches.Add(int64(policyReferenceMismatches))
		tb.Errorf("incidents with unexpected active policy reference = %d", policyReferenceMismatches)
	}
	if statusPayloadMismatches != 0 {
		f.mismatches.Add(int64(statusPayloadMismatches))
		tb.Errorf("incidents with unexpected status payload = %d", statusPayloadMismatches)
	}
	if active != benchmarkDeletingTargets {
		f.mismatches.Add(int64(abs(active - benchmarkDeletingTargets)))
		tb.Errorf("active incidents = %d, want %d", active, benchmarkDeletingTargets)
	}
	if resolved != benchmarkDeletingTargets {
		f.mismatches.Add(int64(abs(resolved - benchmarkDeletingTargets)))
		tb.Errorf("resolved incidents = %d, want %d", resolved, benchmarkDeletingTargets)
	}
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

type benchmarkMetadataClient struct {
	objects   map[schema.GroupVersionResource][]metav1.PartialObjectMetadata
	pageSize  int64
	listCalls atomic.Int64
}

func (c *benchmarkMetadataClient) Resource(resource schema.GroupVersionResource) metadata.Getter {
	return &benchmarkMetadataResource{client: c, resource: resource}
}

type benchmarkMetadataResource struct {
	client    *benchmarkMetadataClient
	resource  schema.GroupVersionResource
	namespace string
}

func (r *benchmarkMetadataResource) Namespace(namespace string) metadata.ResourceInterface {
	copy := *r
	copy.namespace = namespace
	return &copy
}

func (r *benchmarkMetadataResource) List(_ context.Context, options metav1.ListOptions) (*metav1.PartialObjectMetadataList, error) {
	r.client.listCalls.Add(1)
	items, found := r.client.objects[r.resource]
	if !found {
		return nil, fmt.Errorf("benchmark resource %s not found", r.resource)
	}
	start := 0
	if options.Continue != "" {
		parsed, err := strconv.Atoi(options.Continue)
		if err != nil {
			return nil, fmt.Errorf("invalid continue token %q: %w", options.Continue, err)
		}
		start = parsed
	}
	limit := options.Limit
	if limit <= 0 {
		limit = r.client.pageSize
	}
	end := min(start+int(limit), len(items))
	result := &metav1.PartialObjectMetadataList{Items: make([]metav1.PartialObjectMetadata, end-start)}
	for i := start; i < end; i++ {
		result.Items[i-start] = *items[i].DeepCopy()
	}
	if end < len(items) {
		result.Continue = strconv.Itoa(end)
	}
	return result, nil
}

func (*benchmarkMetadataResource) Delete(context.Context, string, metav1.DeleteOptions, ...string) error {
	return errors.New("benchmark metadata delete is unsupported")
}
func (*benchmarkMetadataResource) DeleteCollection(context.Context, metav1.DeleteOptions, metav1.ListOptions) error {
	return errors.New("benchmark metadata delete collection is unsupported")
}
func (*benchmarkMetadataResource) Get(context.Context, string, metav1.GetOptions, ...string) (*metav1.PartialObjectMetadata, error) {
	return nil, errors.New("benchmark metadata get is unsupported")
}
func (*benchmarkMetadataResource) Watch(context.Context, metav1.ListOptions) (watch.Interface, error) {
	return nil, errors.New("benchmark metadata watch is unsupported")
}
func (*benchmarkMetadataResource) Patch(context.Context, string, types.PatchType, []byte, metav1.PatchOptions, ...string) (*metav1.PartialObjectMetadata, error) {
	return nil, errors.New("benchmark metadata patch is unsupported")
}

type benchmarkTargetReader struct {
	objects map[string]*unstructured.Unstructured
}

func (r *benchmarkTargetReader) Get(_ context.Context, resource schema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error) {
	object, found := r.objects[benchmarkTargetKey(resource, namespace, name)]
	if !found {
		return nil, fmt.Errorf("benchmark target %s/%s not found", namespace, name)
	}
	return object.DeepCopy(), nil
}

func (*benchmarkTargetReader) ListMetadata(context.Context, schema.GroupVersionResource, string, metav1.ListOptions) (*metav1.PartialObjectMetadataList, error) {
	return nil, errors.New("unexpected benchmark target metadata list")
}

func benchmarkTargetKey(resource schema.GroupVersionResource, namespace, name string) string {
	return resource.String() + "/" + namespace + "/" + name
}

type countingStatusClient struct {
	client.Client
	writes *atomic.Int64
}

func (c *countingStatusClient) Status() client.SubResourceWriter {
	return &countingStatusWriter{SubResourceWriter: c.Client.Status(), writes: c.writes}
}

type countingStatusWriter struct {
	client.SubResourceWriter
	writes *atomic.Int64
}

func (w *countingStatusWriter) Create(ctx context.Context, object client.Object, subResource client.Object, options ...client.SubResourceCreateOption) error {
	w.writes.Add(1)
	return w.SubResourceWriter.Create(ctx, object, subResource, options...)
}
func (w *countingStatusWriter) Update(ctx context.Context, object client.Object, options ...client.SubResourceUpdateOption) error {
	w.writes.Add(1)
	return w.SubResourceWriter.Update(ctx, object, options...)
}
func (w *countingStatusWriter) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.SubResourcePatchOption) error {
	w.writes.Add(1)
	return w.SubResourceWriter.Patch(ctx, object, patch, options...)
}
func (w *countingStatusWriter) Apply(ctx context.Context, object runtime.ApplyConfiguration, options ...client.SubResourceApplyOption) error {
	w.writes.Add(1)
	return w.SubResourceWriter.Apply(ctx, object, options...)
}
