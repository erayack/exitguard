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
	"github.com/erayack/exitguard/internal/perftest"
)

var scannerBenchmarkScales = []perftest.Scale{
	{Name: "StubSmall", Policies: 3, Resources: 3, Objects: 40, PageSize: 20},
	{Name: "StubMedium", Policies: 8, Resources: 8, Objects: 200, PageSize: 50},
	{Name: "StubFullLarge", Policies: 20, Resources: 20, Objects: 500, PageSize: 100},
}

// BenchmarkScannerCycle measures complete steady-state RunCycle work. Start is
// intentionally excluded: it adds ticker scheduling rather than scanner work
// and cannot be benchmarked deterministically without sleeping. StubFullLarge
// is reserved for the explicit full suite.
func BenchmarkScannerCycle(b *testing.B) {
	for _, scale := range scannerBenchmarkScales {
		scale := scale
		b.Run(scale.Name, func(b *testing.B) {
			fixture := newScannerBenchmarkFixture(b, scale, true)
			fixture.counters.Reset()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := fixture.coordinator.RunCycle(context.Background()); err != nil {
					fixture.counters.Record(perftest.Mismatch)
					b.Fatalf("scanner cycle: %v", err)
				}
			}
			b.StopTimer()
			fixture.verify(b)
			fixture.checkOperations(b, steadyScannerOperations(scale, int64(b.N)))
			fixture.report(b, b.N)
		})
	}
}

// BenchmarkScannerLifecycle measures a cold complete cycle with deterministic
// create, active/failed status refresh, resolution, retention deletion, policy
// status, and metrics-list paths. Per-iteration state is built and verified
// outside timing. The small scale keeps this routine benchmark practical.
func BenchmarkScannerLifecycle(b *testing.B) {
	scale := scannerBenchmarkScales[0]
	var aggregate perftest.Counters
	b.ReportAllocs()
	b.ResetTimer()
	b.StopTimer()
	for range b.N {
		fixture := newScannerBenchmarkFixtureWithCounters(b, scale, false, &aggregate)
		b.StartTimer()
		err := fixture.coordinator.RunCycle(context.Background())
		b.StopTimer()
		if err != nil {
			aggregate.Record(perftest.Mismatch)
			b.Fatalf("scanner lifecycle cycle: %v", err)
		}
		fixture.verify(b)
	}
	fixture := &scannerBenchmarkFixture{scale: scale, counters: &aggregate, deletingTargets: deletingTargets(scale)}
	fixture.checkOperations(b, lifecycleScannerOperations(scale, int64(b.N)))
	fixture.report(b, b.N)
}

type scannerBenchmarkFixture struct {
	coordinator     *Coordinator
	store           client.Client
	counters        *perftest.Counters
	scale           perftest.Scale
	deletingTargets int
	now             time.Time
}

func newScannerBenchmarkFixture(tb testing.TB, scale perftest.Scale, prime bool) *scannerBenchmarkFixture {
	return newScannerBenchmarkFixtureWithCounters(tb, scale, prime, &perftest.Counters{})
}

func newScannerBenchmarkFixtureWithCounters(tb testing.TB, scale perftest.Scale, prime bool, counters *perftest.Counters) *scannerBenchmarkFixture {
	tb.Helper()
	if err := scale.Validate(); err != nil {
		tb.Fatal(err)
	}
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

	now := perftest.FixedNow()
	deletingAt := metav1.NewTime(now.Add(-30 * time.Minute))
	resourceNames := make([]string, scale.Resources)
	apiResources := make([]metav1.APIResource, scale.Resources)
	metadataObjects := make(map[schema.GroupVersionResource][]metav1.PartialObjectMetadata, scale.Resources+1)
	targets := make(map[string]*unstructured.Unstructured, deletingTargets(scale))
	objects := make([]client.Object, 0, scale.Policies+deletingTargets(scale)+3)
	namespaces := make([]metav1.PartialObjectMetadata, min(scale.Objects, 10))
	for i := range namespaces {
		namespaces[i] = metav1.PartialObjectMetadata{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("ns-%02d", i), Labels: map[string]string{"team": "scanner"}},
		}
	}
	metadataObjects[schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}] = namespaces

	deletingIndex := 0
	for resourceIndex := range scale.Resources {
		resourceName := fmt.Sprintf("resources-%02d", resourceIndex)
		kind := fmt.Sprintf("Resource%02d", resourceIndex)
		namespaced := resourceIndex != scale.Resources-1
		resourceNames[resourceIndex] = resourceName
		apiResources[resourceIndex] = metav1.APIResource{Name: resourceName, SingularName: fmt.Sprintf("resource-%02d", resourceIndex), Namespaced: namespaced, Kind: kind, Verbs: metav1.Verbs{"get", "list"}}
		gvr := schema.GroupVersionResource{Group: "benchmark.io", Version: "v1", Resource: resourceName}
		items := make([]metav1.PartialObjectMetadata, scale.Objects)
		for objectIndex := range scale.Objects {
			uid := types.UID(fmt.Sprintf("r%02d-object-%04d", resourceIndex, objectIndex))
			name := fmt.Sprintf("object-%04d", objectIndex)
			namespace := ""
			if namespaced {
				namespace = fmt.Sprintf("ns-%02d", objectIndex%len(namespaces))
			}
			item := metav1.PartialObjectMetadata{
				TypeMeta:   metav1.TypeMeta{APIVersion: "benchmark.io/v1", Kind: kind},
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: uid, ResourceVersion: "7", Labels: map[string]string{"environment": "production", "role": "ordinary"}},
			}
			if objectIndex%100 == 0 {
				item.DeletionTimestamp = deletingAt.DeepCopy()
				item.Finalizers = []string{"benchmark.io/finalizer"}
				targets[benchmarkTargetKey(gvr, namespace, name)] = benchmarkTarget(gvr, kind, item)
				switch deletingIndex % 3 {
				case 1:
					objects = append(objects, benchmarkLifecycleIncident(now, safetyv1alpha1.IncidentPhaseActive, resourceName, kind, namespace, name, uid, deletingAt))
				case 2:
					objects = append(objects, benchmarkLifecycleIncident(now, safetyv1alpha1.IncidentPhaseDiagnosisFailed, resourceName, kind, namespace, name, uid, deletingAt))
				}
				deletingIndex++
			}
			items[objectIndex] = item
		}
		metadataObjects[gvr] = items
	}

	for i := range scale.Policies {
		objects = append(objects, benchmarkPolicy(i, resourceNames))
	}
	objects = append(objects,
		benchmarkStaleActiveIncident(now, resourceNames[0]),
		benchmarkResolvedIncident(now, "expired", -2*time.Hour),
		benchmarkResolvedIncident(now, "retained", -30*time.Minute),
	)

	store := clientfake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&safetyv1alpha1.TerminationPolicy{}, &safetyv1alpha1.DeletionIncident{}).
		WithObjects(objects...).Build()
	metadataClient := &benchmarkMetadataClient{objects: metadataObjects, pageSize: int64(scale.PageSize), counters: counters}
	discovery := &fake.FakeDiscovery{Fake: &k8stesting.Fake{}}
	discovery.Resources = []*metav1.APIResourceList{
		{GroupVersion: "v1", APIResources: []metav1.APIResource{{Name: "namespaces", Kind: "Namespace", Verbs: metav1.Verbs{"get", "list"}}}},
		{GroupVersion: "benchmark.io/v1", APIResources: apiResources},
	}
	catalog := catalogdiscovery.NewCatalog(discovery, time.Hour, discardLogger())
	if err := catalog.Refresh(); err != nil {
		tb.Fatalf("refresh benchmark catalog: %v", err)
	}

	reader := perftest.NewCountingReader(store, counters)
	writer := perftest.NewCountingClient(store, counters)
	coordinator, err := NewCoordinator(reader, writer, metadataClient, catalog, diagnosis.NewEngine(&benchmarkTargetReader{objects: targets, counters: counters}), Config{
		Interval: time.Minute, Timeout: time.Minute, ResourceWorkers: 4, DiagnosisWorkers: 4,
		PageSize: int64(scale.PageSize), MaxTargets: deletingTargets(scale) * 2,
	})
	if err != nil {
		tb.Fatal(err)
	}
	fixture := &scannerBenchmarkFixture{coordinator: coordinator, store: store, counters: counters, scale: scale, deletingTargets: deletingTargets(scale), now: now}
	coordinator.now = func() time.Time { return fixture.now }
	if prime {
		if err := coordinator.RunCycle(context.Background()); err != nil {
			tb.Fatalf("prime scanner cycle: %v", err)
		}
		fixture.verify(tb)
	}
	return fixture
}

func deletingTargets(scale perftest.Scale) int {
	return scale.Resources * ((scale.Objects + 99) / 100)
}

func benchmarkTarget(gvr schema.GroupVersionResource, kind string, item metav1.PartialObjectMetadata) *unstructured.Unstructured {
	metadata := map[string]any{
		"name": item.Name, "uid": string(item.UID), "resourceVersion": item.ResourceVersion,
		"deletionTimestamp": item.DeletionTimestamp.Format(time.RFC3339), "finalizers": []any{"benchmark.io/finalizer"},
		"labels": map[string]any{"environment": "production", "role": "ordinary"},
	}
	if item.Namespace != "" {
		metadata["namespace"] = item.Namespace
	}
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": gvr.GroupVersion().String(), "kind": kind, "metadata": metadata}}
}

func benchmarkPolicy(index int, resources []string) *safetyv1alpha1.TerminationPolicy {
	selector := func(key, value string) *metav1.LabelSelector {
		return &metav1.LabelSelector{MatchLabels: map[string]string{key: value}}
	}
	return &safetyv1alpha1.TerminationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("policy-%02d", index), UID: types.UID(fmt.Sprintf("policy-uid-%02d", index)), ResourceVersion: perftest.ResourceVersion(index), Generation: 1},
		Spec: safetyv1alpha1.TerminationPolicySpec{
			Priority: int32(index),
			TargetRules: []safetyv1alpha1.TargetRule{
				{APIGroups: []string{"benchmark.io"}, Resources: resources, ObjectSelector: selector("role", "database"), NamespaceSelector: selector("team", "scanner")},
				{APIGroups: []string{"benchmark.io"}, Resources: resources, ObjectSelector: selector("environment", "production"), NamespaceSelector: selector("team", "scanner"), ExcludedNamespaces: []string{"kube-system"}},
				{APIGroups: []string{"benchmark.io"}, Resources: resources, ObjectSelector: selector("role", "ordinary"), NamespaceSelector: selector("team", "other")},
			},
			TerminationAge: metav1.Duration{Duration: time.Minute},
			Diagnosis:      safetyv1alpha1.DiagnosisPolicy{MaxNamespaceObjects: 1000, MaxCRDInstances: 1000},
			Remediation:    safetyv1alpha1.RemediationPolicy{MaxRisk: safetyv1alpha1.RiskHigh, AllowedFinalizers: []string{"benchmark.io/finalizer"}, ApprovalTTL: metav1.Duration{Duration: time.Hour}},
			Retention:      safetyv1alpha1.RetentionPolicy{ResolvedIncidentTTL: metav1.Duration{Duration: time.Hour}},
		},
	}
}

func benchmarkLifecycleIncident(now time.Time, phase safetyv1alpha1.IncidentPhase, resource, kind, namespace, name string, uid types.UID, deletingAt metav1.Time) *safetyv1alpha1.DeletionIncident {
	return &safetyv1alpha1.DeletionIncident{
		ObjectMeta: metav1.ObjectMeta{Name: incidentName(uid), UID: types.UID("incident-" + string(uid)), ResourceVersion: "21", Annotations: map[string]string{retentionAnnotation: time.Hour.String()}},
		Spec:       safetyv1alpha1.DeletionIncidentSpec{Target: safetyv1alpha1.TargetReference{APIGroup: "benchmark.io", Version: "v1", Resource: resource, Kind: kind, Namespace: namespace, Name: name, UID: uid}, FirstObservedTime: metav1.NewTime(now.Add(-time.Hour))},
		Status:     safetyv1alpha1.DeletionIncidentStatus{Phase: phase, DeletionTimestamp: deletingAt.DeepCopy()},
	}
}

func benchmarkStaleActiveIncident(now time.Time, resource string) *safetyv1alpha1.DeletionIncident {
	deletingAt := metav1.NewTime(now.Add(-time.Hour))
	return benchmarkLifecycleIncident(now, safetyv1alpha1.IncidentPhaseActive, resource, "Resource00", "ns-00", "absent", "stale-uid", deletingAt)
}

func benchmarkResolvedIncident(now time.Time, suffix string, age time.Duration) *safetyv1alpha1.DeletionIncident {
	resolved := metav1.NewTime(now.Add(age))
	uid := types.UID("resolved-" + suffix)
	return &safetyv1alpha1.DeletionIncident{
		ObjectMeta: metav1.ObjectMeta{Name: incidentName(uid), UID: types.UID("incident-" + suffix), ResourceVersion: "22", Annotations: map[string]string{retentionAnnotation: time.Hour.String()}},
		Spec:       safetyv1alpha1.DeletionIncidentSpec{Target: safetyv1alpha1.TargetReference{APIGroup: "benchmark.io", Version: "v1", Resource: "resources-00", Kind: "Resource00", Namespace: "ns-00", Name: suffix, UID: uid}, FirstObservedTime: metav1.NewTime(now.Add(-3 * time.Hour))},
		Status:     safetyv1alpha1.DeletionIncidentStatus{Phase: safetyv1alpha1.IncidentPhaseResolved, ResolvedTime: &resolved},
	}
}

func (f *scannerBenchmarkFixture) verify(tb testing.TB) {
	tb.Helper()
	var incidents safetyv1alpha1.DeletionIncidentList
	if err := f.store.List(context.Background(), &incidents); err != nil {
		f.fail(tb, "list benchmark incidents: %v", err)
		return
	}
	active, failed, resolved := 0, 0, 0
	for i := range incidents.Items {
		incident := &incidents.Items[i]
		switch incident.Status.Phase {
		case safetyv1alpha1.IncidentPhaseActive:
			active++
			policyRef := incident.Status.ActivePolicyRef
			if policyRef == nil || policyRef.Name != fmt.Sprintf("policy-%02d", f.scale.Policies-1) || incident.Status.TargetSnapshot.ResourceVersion != "7" || len(incident.Status.Conditions) == 0 {
				f.fail(tb, "active incident %s has incomplete policy/status evidence", incident.Name)
			}
		case safetyv1alpha1.IncidentPhaseDiagnosisFailed:
			failed++
		case safetyv1alpha1.IncidentPhaseResolved:
			resolved++
			if incident.Status.ResolvedTime == nil {
				f.fail(tb, "resolved incident %s has no resolution time", incident.Name)
			}
		default:
			f.fail(tb, "incident %s has unexpected phase %q", incident.Name, incident.Status.Phase)
		}
	}
	if active != f.deletingTargets || failed != 0 || resolved != 2 {
		f.fail(tb, "incident phases active/failed/resolved = %d/%d/%d, want %d/0/2", active, failed, resolved, f.deletingTargets)
	}
	var policies safetyv1alpha1.TerminationPolicyList
	if err := f.store.List(context.Background(), &policies); err != nil {
		f.fail(tb, "list benchmark policies: %v", err)
		return
	}
	for i := range policies.Items {
		if policies.Items[i].Status.ObservedGeneration != policies.Items[i].Generation || len(policies.Items[i].Status.Conditions) == 0 {
			f.fail(tb, "policy %s status was not reconciled", policies.Items[i].Name)
		}
	}
}

func (f *scannerBenchmarkFixture) checkOperations(tb testing.TB, expected map[perftest.Operation]int64) {
	tb.Helper()
	if err := f.counters.Check(expected); err != nil {
		tb.Fatal(err)
	}
}

func (f *scannerBenchmarkFixture) fail(tb testing.TB, format string, arguments ...any) {
	f.counters.Record(perftest.Mismatch)
	tb.Errorf(format, arguments...)
}

func (f *scannerBenchmarkFixture) report(b *testing.B, cycles int) {
	perCycle := float64(cycles)
	snapshot := f.counters.Snapshot()
	b.ReportMetric(float64(f.scale.Resources*f.scale.Objects), "objects/cycle")
	b.ReportMetric(float64(snapshot.Value(perftest.MetadataPage))/perCycle, "pages/cycle")
	b.ReportMetric(float64(scannerAPIOperations(snapshot))/perCycle, "api_operations/cycle")
	b.ReportMetric(float64(snapshot.Value(perftest.Write))/perCycle, "writes/cycle")
	b.ReportMetric(float64(snapshot.Value(perftest.Retry))/perCycle, "retries/cycle")
	b.ReportMetric(float64(snapshot.Value(perftest.StatusWrite))/perCycle, "status_writes/cycle")
	b.ReportMetric(float64(snapshot.Value(perftest.Delete))/perCycle, "deletes/cycle")
	b.ReportMetric(float64(snapshot.Value(perftest.Mismatch))/perCycle, "mismatches/cycle")
}

func steadyScannerOperations(scale perftest.Scale, cycles int64) map[perftest.Operation]int64 {
	pages := int64(scale.Resources*((scale.Objects+scale.PageSize-1)/scale.PageSize) + (min(scale.Objects, 10)+scale.PageSize-1)/scale.PageSize)
	return map[perftest.Operation]int64{
		perftest.MetadataList: pages * cycles, perftest.MetadataPage: pages * cycles,
		perftest.PolicyList: cycles, perftest.IncidentList: cycles, perftest.TypedList: 3 * cycles,
		perftest.DynamicGet: int64(deletingTargets(scale)) * cycles,
	}
}

func lifecycleScannerOperations(scale perftest.Scale, cycles int64) map[perftest.Operation]int64 {
	operations := steadyScannerOperations(scale, cycles)
	missing := int64((deletingTargets(scale) + 2) / 3)
	statusWrites := int64(scale.Policies+deletingTargets(scale)+1) * cycles
	operations[perftest.IncidentList] = 2 * cycles
	operations[perftest.TypedGet] = (2*missing + 1) * cycles
	operations[perftest.Create] = missing * cycles
	operations[perftest.StatusWrite] = statusWrites
	operations[perftest.Delete] = cycles
	operations[perftest.Write] = statusWrites + missing*cycles + cycles
	return operations
}

func scannerAPIOperations(snapshot perftest.Snapshot) int64 {
	return snapshot.Value(perftest.MetadataList) + snapshot.Value(perftest.TypedGet) + snapshot.Value(perftest.DynamicGet) +
		snapshot.Value(perftest.TypedList) + snapshot.Value(perftest.DynamicList) + snapshot.Value(perftest.IncidentList) +
		snapshot.Value(perftest.PolicyList) + snapshot.Value(perftest.Create) + snapshot.Value(perftest.Update) +
		snapshot.Value(perftest.Patch) + snapshot.Value(perftest.StatusWrite) + snapshot.Value(perftest.Delete)
}

type benchmarkMetadataClient struct {
	objects  map[schema.GroupVersionResource][]metav1.PartialObjectMetadata
	pageSize int64
	counters *perftest.Counters
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
	resourceCopy := *r
	resourceCopy.namespace = namespace
	return &resourceCopy
}

func (r *benchmarkMetadataResource) List(_ context.Context, options metav1.ListOptions) (*metav1.PartialObjectMetadataList, error) {
	r.client.counters.Record(perftest.MetadataList)
	r.client.counters.Record(perftest.MetadataPage)
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
	objects  map[string]*unstructured.Unstructured
	counters *perftest.Counters
}

func (r *benchmarkTargetReader) Get(_ context.Context, resource schema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error) {
	r.counters.Record(perftest.DynamicGet)
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
