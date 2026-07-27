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

package diagnosis

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	"github.com/erayack/exitguard/internal/perftest"
)

type evidenceAlgorithmScale struct {
	name     string
	findings int
	actions  int
}

var evidenceAlgorithmScales = []evidenceAlgorithmScale{
	{name: "small_below_bound", findings: 64, actions: 32},
	{name: "medium_at_bound", findings: maxPersistedFindings, actions: maxPersistedActions},
	{name: "large_above_bound", findings: maxPersistedFindings + 128, actions: maxPersistedActions + 64},
}

var (
	diagnosisFindingSink  []safetyv1alpha1.Finding
	diagnosisActionSink   []safetyv1alpha1.RemediationAction
	diagnosisOverflowSink bool
	diagnosisHashSink     string
	diagnosisCloneSink    []string
)

func BenchmarkEvidenceCollectionSortAndBounds(b *testing.B) {
	for _, scale := range evidenceAlgorithmScales {
		b.Run(scale.name, func(b *testing.B) {
			findingFixtures, actionFixtures := evidenceBenchmarkFixtures(scale)
			var findings []safetyv1alpha1.Finding
			var actions []safetyv1alpha1.RemediationAction
			var overflow bool

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				collector := newCollector(nil)
				for _, finding := range findingFixtures {
					collector.addFinding(finding)
				}
				for _, action := range actionFixtures {
					collector.addAction(action)
				}
				findings, actions, overflow = collector.sorted()
			}
			b.StopTimer()
			diagnosisFindingSink = findings
			diagnosisActionSink = actions
			diagnosisOverflowSink = overflow
			b.ReportMetric(float64(scale.findings), "findings/op")
			b.ReportMetric(float64(scale.actions), "actions/op")

			wantOverflow := scale.findings > maxPersistedFindings || scale.actions > maxPersistedActions
			wantFindings := min(scale.findings, maxPersistedFindings)
			if wantOverflow {
				wantFindings++
			}
			wantActions := min(scale.actions, maxPersistedActions)
			if overflow != wantOverflow || len(findings) != wantFindings || len(actions) != wantActions {
				b.Fatalf("evidence result = findings:%d actions:%d overflow:%t, want %d/%d/%t", len(findings), len(actions), overflow, wantFindings, wantActions, wantOverflow)
			}
			if !findingIDsSorted(findings) || !actionIDsSorted(actions) {
				b.Fatal("evidence IDs are not sorted")
			}
			if len(findings) == 0 || perftest.Checksum(findings[0].ID, findings[len(findings)-1].ID) == 0 {
				b.Fatal("evidence result was not observable")
			}
			b.ReportMetric(float64(len(findings)), "retained_findings/op")
			b.ReportMetric(float64(len(actions)), "retained_actions/op")
			b.ReportMetric(0, "mismatches/op")
		})
	}
}

func BenchmarkEvidenceIDHashing(b *testing.B) {
	for _, scale := range []struct {
		name  string
		count int
	}{{name: "small", count: 64}, {name: "medium", count: 1_000}, {name: "large", count: 10_000}} {
		b.Run(scale.name, func(b *testing.B) {
			findings, actions := evidenceBenchmarkFixtures(evidenceAlgorithmScale{findings: scale.count})
			if len(actions) != 0 {
				b.Fatalf("hash fixture actions = %d, want 0", len(actions))
			}
			var findingHash string
			var actionHash string

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for index, finding := range findings {
					findingHash = findingID(finding)
					actionHash = actionID(
						safetyv1alpha1.ActionRemoveResourceFinalizer,
						types.UID(perftest.Name("target", index)), perftest.Name("finalizer", index),
						perftest.ResourceVersion(index), "policy-uid", 7,
					)
				}
			}
			b.StopTimer()
			diagnosisHashSink = findingHash + actionHash
			b.ReportMetric(float64(scale.count*2), "hashes/op")

			if !strings.HasPrefix(findingHash, "finding-") || !strings.HasPrefix(actionHash, "action-") || findingHash == actionHash {
				b.Fatal("hash results were not observable or correctly typed")
			}
			b.ReportMetric(0, "mismatches/op")
		})
	}
}

func BenchmarkEvidenceSortedClone(b *testing.B) {
	for _, scale := range []struct {
		name  string
		count int
	}{{name: "small", count: 64}, {name: "medium", count: 1_000}, {name: "large", count: 10_000}} {
		b.Run(scale.name, func(b *testing.B) {
			fixture := make([]string, scale.count)
			for index := range fixture {
				fixture[index] = perftest.Name("value", scale.count-index)
			}
			var cloned []string

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				cloned = sortedCopy(fixture)
			}
			b.StopTimer()
			diagnosisCloneSink = cloned
			b.ReportMetric(float64(scale.count), "values/op")

			if len(cloned) != len(fixture) || !slices.IsSorted(cloned) || slices.Equal(cloned, fixture) {
				b.Fatal("sorted clone did not produce a detached ordered result")
			}
			cloned[0] = "mutated"
			if fixture[0] == "mutated" {
				b.Fatal("sorted clone aliases fixture storage")
			}
			b.ReportMetric(0, "mismatches/op")
		})
	}
}

func evidenceBenchmarkFixtures(scale evidenceAlgorithmScale) ([]safetyv1alpha1.Finding, []safetyv1alpha1.RemediationAction) {
	findings := make([]safetyv1alpha1.Finding, scale.findings)
	for index := range findings {
		findings[index] = safetyv1alpha1.Finding{
			Type: safetyv1alpha1.FindingBlockingFinalizer, Message: fmt.Sprintf("blocking finalizer evidence %06d", index),
			Finalizer: perftest.Name("benchmark.io/finalizer", index),
		}
	}
	actions := make([]safetyv1alpha1.RemediationAction, scale.actions)
	for index := range actions {
		uid := perftest.UID("target", index)
		finalizer := perftest.Name("benchmark.io/finalizer", index)
		resourceVersion := perftest.ResourceVersion(index)
		actions[index] = safetyv1alpha1.RemediationAction{
			ID:   actionID(safetyv1alpha1.ActionRemoveResourceFinalizer, uid, finalizer, resourceVersion, "policy-uid", 7),
			Type: safetyv1alpha1.ActionRemoveResourceFinalizer,
			Target: safetyv1alpha1.TargetReference{
				APIGroup: "benchmark.io", Version: "v1", Resource: "widgets", Kind: "Widget",
				Namespace: "default", Name: perftest.Name("target", index), UID: uid,
			},
			Finalizer: finalizer, PreconditionResourceVersion: resourceVersion,
			Risk: safetyv1alpha1.RiskMedium, Eligible: true, Reason: "fixed benchmark action",
		}
	}
	return findings, actions
}

func findingIDsSorted(findings []safetyv1alpha1.Finding) bool {
	return slices.IsSortedFunc(findings, func(left, right safetyv1alpha1.Finding) int {
		return strings.Compare(left.ID, right.ID)
	})
}

func actionIDsSorted(actions []safetyv1alpha1.RemediationAction) bool {
	return slices.IsSortedFunc(actions, func(left, right safetyv1alpha1.RemediationAction) int {
		return strings.Compare(left.ID, right.ID)
	})
}

type diagnosisComponentScale struct {
	name     string
	objects  int
	maximum  int
	pageSize int
}

type diagnosisComponentFixture struct {
	request  Request
	reader   *diagnosisComponentReader
	counters *perftest.Counters
	objects  int
	verify   func(testing.TB, Result)
}

type diagnosisComponentReader struct {
	target         *unstructured.Unstructured
	targetResource schema.GroupVersionResource
	pages          map[string]perftest.Pager[metav1.PartialObjectMetadata]
	counters       *perftest.Counters
}

var diagnosisComponentSink Result

func BenchmarkDiagnosisGenericComponentStub(b *testing.B) {
	fixture := genericDiagnosisComponentFixture(b)
	runDiagnosisComponentBenchmark(b, fixture)
}

func BenchmarkDiagnosisNamespaceComponentStub(b *testing.B) {
	for _, scale := range []diagnosisComponentScale{
		{name: "small", objects: 24, maximum: 30, pageSize: 7},
		{name: "medium", objects: 480, maximum: 500, pageSize: 100},
		{name: "large_bound", objects: 520, maximum: 500, pageSize: 100},
	} {
		b.Run(scale.name, func(b *testing.B) {
			runDiagnosisComponentBenchmark(b, namespaceDiagnosisComponentFixture(b, scale))
		})
	}
}

func BenchmarkDiagnosisCRDComponentStub(b *testing.B) {
	for _, scale := range []diagnosisComponentScale{
		{name: "small", objects: 24, maximum: 30, pageSize: 7},
		{name: "medium", objects: 480, maximum: 500, pageSize: 100},
		{name: "large_bound", objects: 520, maximum: 500, pageSize: 100},
	} {
		b.Run(scale.name, func(b *testing.B) {
			runDiagnosisComponentBenchmark(b, crdDiagnosisComponentFixture(b, scale))
		})
	}
}

func runDiagnosisComponentBenchmark(b *testing.B, fixture diagnosisComponentFixture) {
	b.Helper()
	engine := NewEngine(fixture.reader)
	prime, err := engine.Diagnose(context.Background(), fixture.request)
	if err != nil {
		b.Fatalf("prime diagnosis: %v", err)
	}
	fixture.verify(b, prime)
	primeCounts := fixture.counters.Snapshot()
	if primeCounts.Value(perftest.DynamicGet) != 1 {
		b.Fatalf("prime dynamic GETs = %d, want 1", primeCounts.Value(perftest.DynamicGet))
	}
	fixture.counters.Reset()

	var result Result
	var runErr error
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		result, runErr = engine.Diagnose(context.Background(), fixture.request)
	}
	b.StopTimer()
	diagnosisComponentSink = result

	if runErr != nil {
		b.Fatalf("diagnosis: %v", runErr)
	}
	fixture.verify(b, result)
	if !reflect.DeepEqual(result, prime) {
		b.Fatal("diagnosis result changed from deterministic prime")
	}
	expected := diagnosisExpectedCounts(primeCounts, int64(b.N))
	if err := fixture.counters.Check(expected); err != nil {
		b.Fatal(err)
	}
	cycles := float64(b.N)
	apiOperations := fixture.counters.Value(perftest.DynamicGet) + fixture.counters.Value(perftest.MetadataList)
	b.ReportMetric(float64(fixture.objects), "objects/op")
	b.ReportMetric(float64(fixture.counters.Value(perftest.MetadataPage))/cycles, "pages/op")
	b.ReportMetric(float64(apiOperations)/cycles, "api_operations/op")
	b.ReportMetric(float64(fixture.counters.Value(perftest.Retry))/cycles, "retries/op")
	b.ReportMetric(float64(fixture.counters.Value(perftest.Mismatch))/cycles, "mismatches/op")
}

func diagnosisExpectedCounts(prime perftest.Snapshot, iterations int64) map[perftest.Operation]int64 {
	expected := make(map[perftest.Operation]int64)
	for _, operation := range []perftest.Operation{
		perftest.DynamicGet,
		perftest.MetadataList,
		perftest.MetadataPage,
		perftest.Retry,
	} {
		if count := prime.Value(operation); count > 0 {
			expected[operation] = count * iterations
		}
	}
	return expected
}

func genericDiagnosisComponentFixture(tb testing.TB) diagnosisComponentFixture {
	tb.Helper()
	catalog := diagnosisCatalog(tb)
	policy := diagnosisPolicy(tb, catalog, policyOptions{
		allowedFinalizers: []string{"example.io/cleanup"},
		maxRisk:           safetyv1alpha1.RiskMedium,
		owners: []safetyv1alpha1.FinalizerOwner{{
			Finalizer: "example.io/cleanup",
			ControllerRef: safetyv1alpha1.ControllerReference{
				APIVersion: "apps/v1", Kind: "Deployment", Namespace: "operators", Name: "widget-controller",
			},
		}},
	})
	targetReference := widgetReference()
	target := deletingObject(targetReference, testNow.Add(-time.Hour), []string{"example.io/cleanup"})
	fail := admissionv1.Fail
	update := admissionv1.Update
	ready := false
	snapshot := Snapshot{
		Catalog: catalog,
		APIServices: []apiregistrationv1.APIService{{
			ObjectMeta: metav1.ObjectMeta{Name: "v1.apps.example.io"},
			Spec:       apiregistrationv1.APIServiceSpec{Group: "apps.example.io", Version: "v1"},
			Status: apiregistrationv1.APIServiceStatus{Conditions: []apiregistrationv1.APIServiceCondition{{
				Type: apiregistrationv1.Available, Status: apiregistrationv1.ConditionFalse,
			}}},
		}},
		ValidatingWebhooks: []admissionv1.ValidatingWebhookConfiguration{{
			ObjectMeta: metav1.ObjectMeta{Name: "guard"},
			Webhooks: []admissionv1.ValidatingWebhook{{
				Name: "update.guard.benchmark.io", FailurePolicy: &fail,
				Rules: []admissionv1.RuleWithOperations{{
					Operations: []admissionv1.OperationType{update},
					Rule:       admissionv1.Rule{APIGroups: []string{"apps.example.io"}, APIVersions: []string{"v1"}, Resources: []string{"widgets"}},
				}},
				ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: "webhooks", Name: "guard"}},
			}},
		}},
		Services: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Namespace: "webhooks", Name: "guard"}}},
		EndpointSlices: []discoveryv1.EndpointSlice{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "webhooks", Labels: map[string]string{discoveryv1.LabelServiceName: "guard"}},
			Endpoints:  []discoveryv1.Endpoint{{Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		}},
		Deployments:     []appsv1.Deployment{},
		NamespaceLabels: map[string]map[string]string{"workloads": {"environment": "production"}},
	}
	counters := &perftest.Counters{}
	reader := &diagnosisComponentReader{
		target: target, targetResource: schema.GroupVersionResource{Group: "apps.example.io", Version: "v1", Resource: "widgets"},
		pages: make(map[string]perftest.Pager[metav1.PartialObjectMetadata]), counters: counters,
	}
	return diagnosisComponentFixture{
		request: Request{Target: targetReference, Policy: policy, Snapshot: snapshot, Now: testNow},
		reader:  reader, counters: counters, objects: 1,
		verify: func(tb testing.TB, result Result) {
			tb.Helper()
			if !result.TargetFound || !result.UIDMatches || !result.ThresholdElapsed || !result.DiagnosisComplete {
				tb.Fatalf("generic diagnosis state = %#v", result)
			}
			for _, findingType := range []safetyv1alpha1.FindingType{
				safetyv1alpha1.FindingBlockingFinalizer,
				safetyv1alpha1.FindingMissingFinalizerController,
				safetyv1alpha1.FindingUnavailableAPIService,
				safetyv1alpha1.FindingBlockingWebhook,
			} {
				if diagnosisFindingCount(result.Findings, findingType) == 0 {
					tb.Fatalf("generic diagnosis has no %s finding", findingType)
				}
			}
			if len(result.Actions) != 1 || !result.Actions[0].Eligible || !findingIDsSorted(result.Findings) || !actionIDsSorted(result.Actions) {
				tb.Fatalf("generic diagnosis output is not actionable and sorted: %#v", result)
			}
		},
	}
}

func namespaceDiagnosisComponentFixture(tb testing.TB, scale diagnosisComponentScale) diagnosisComponentFixture {
	tb.Helper()
	catalog := diagnosisCatalog(tb)
	policy := diagnosisPolicy(tb, catalog, policyOptions{
		allowedFinalizers: []string{"example.io/cleanup"}, maxRisk: safetyv1alpha1.RiskCritical,
		allowNamespaceForce: true, maxNamespaceObjects: int32(scale.maximum),
	})
	reference := safetyv1alpha1.TargetReference{Version: "v1", Resource: "namespaces", Kind: "Namespace", Name: "benchmark-namespace", UID: "namespace-uid"}
	target := diagnosisMustUnstructured(tb, &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{
			Name: reference.Name, UID: reference.UID, ResourceVersion: "11",
			DeletionTimestamp: &metav1.Time{Time: testNow.Add(-time.Hour)},
		},
		Spec: corev1.NamespaceSpec{Finalizers: []corev1.FinalizerName{corev1.FinalizerKubernetes}},
	})
	counters := &perftest.Counters{}
	itemsByResource := make(map[schema.GroupVersionResource][]metav1.PartialObjectMetadata)
	namespacedResources := make([]schema.GroupVersionResource, 0)
	for _, resource := range catalog.Resources() {
		if resource.PreferredVersion.Namespaced {
			namespacedResources = append(namespacedResources, resource.GroupResource.WithVersion(resource.PreferredVersion.Version))
		}
	}
	for index := range scale.objects {
		gvr := namespacedResources[index%len(namespacedResources)]
		item := metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
			Namespace: reference.Name, Name: perftest.Name("object", index), UID: perftest.UID("namespace-object", index),
			ResourceVersion: perftest.ResourceVersion(index), Labels: map[string]string{"environment": "production"},
		}}
		if index%10 == 0 {
			item.DeletionTimestamp = &metav1.Time{Time: testNow.Add(-30 * time.Minute)}
		}
		if index%100 == 0 {
			item.Finalizers = []string{"example.io/cleanup"}
		}
		itemsByResource[gvr] = append(itemsByResource[gvr], item)
	}
	pages := make(map[string]perftest.Pager[metav1.PartialObjectMetadata], len(namespacedResources))
	for _, gvr := range namespacedResources {
		pages[diagnosisComponentListKey(gvr, reference.Name)] = perftest.Pager[metav1.PartialObjectMetadata]{
			Items: itemsByResource[gvr], PageSize: scale.pageSize, Counters: counters, ListOperation: perftest.MetadataList,
		}
	}
	reader := &diagnosisComponentReader{
		target: target, targetResource: namespaceResource, pages: pages, counters: counters,
	}
	wantComplete := scale.objects <= scale.maximum
	return diagnosisComponentFixture{
		request: Request{Target: reference, Policy: policy, Snapshot: Snapshot{Catalog: catalog}, Now: testNow},
		reader:  reader, counters: counters, objects: min(scale.objects, scale.maximum),
		verify: func(tb testing.TB, result Result) {
			tb.Helper()
			if !result.TargetFound || !result.UIDMatches || !result.ThresholdElapsed || result.DiagnosisComplete != wantComplete {
				tb.Fatalf("namespace diagnosis completeness = %t, want %t", result.DiagnosisComplete, wantComplete)
			}
			wantRemaining := min(scale.objects, scale.maximum)
			if got := diagnosisDetailedFindingCount(result.Findings, safetyv1alpha1.FindingRemainingResource); got != wantRemaining {
				tb.Fatalf("namespace detailed remaining findings = %d, want %d", got, wantRemaining)
			}
			if !wantComplete && !hasTruncatedFinding(result.Findings) {
				tb.Fatal("bounded namespace diagnosis has no truncation finding")
			}
			if wantComplete && len(result.Actions) == 0 {
				tb.Fatal("complete namespace diagnosis has no actions")
			}
			if !wantComplete && len(result.Actions) != 0 {
				tb.Fatalf("incomplete namespace diagnosis has %d actions", len(result.Actions))
			}
			if !findingIDsSorted(result.Findings) || !actionIDsSorted(result.Actions) {
				tb.Fatal("namespace evidence is not sorted")
			}
		},
	}
}

func crdDiagnosisComponentFixture(tb testing.TB, scale diagnosisComponentScale) diagnosisComponentFixture {
	tb.Helper()
	catalog := diagnosisCatalog(tb)
	policy := diagnosisPolicy(tb, catalog, policyOptions{
		allowedFinalizers: []string{apiextensionsv1.CustomResourceCleanupFinalizer}, maxRisk: safetyv1alpha1.RiskHigh,
		maxCRDInstances: int32(scale.maximum),
	})
	crd := &apiextensionsv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{APIVersion: "apiextensions.k8s.io/v1", Kind: "CustomResourceDefinition"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "widgets.benchmark.io", UID: "crd-uid", ResourceVersion: "17",
			Finalizers: []string{apiextensionsv1.CustomResourceCleanupFinalizer}, DeletionTimestamp: &metav1.Time{Time: testNow.Add(-time.Hour)},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "benchmark.io", Names: apiextensionsv1.CustomResourceDefinitionNames{Plural: "widgets", Kind: "Widget"}, Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{Name: "v1", Served: true, Storage: true}, {Name: "v1beta1", Served: true}},
			Conversion: &apiextensionsv1.CustomResourceConversion{
				Strategy: apiextensionsv1.WebhookConverter,
				Webhook: &apiextensionsv1.WebhookConversion{ClientConfig: &apiextensionsv1.WebhookClientConfig{
					Service: &apiextensionsv1.ServiceReference{Namespace: "webhooks", Name: "converter"},
				}},
			},
		},
	}
	target := diagnosisMustUnstructured(tb, crd)
	counters := &perftest.Counters{}
	versionItems := crdVersionedItems(scale.objects)
	pages := make(map[string]perftest.Pager[metav1.PartialObjectMetadata], len(versionItems))
	for version, items := range versionItems {
		gvr := schema.GroupVersionResource{Group: crd.Spec.Group, Version: version, Resource: crd.Spec.Names.Plural}
		pages[diagnosisComponentListKey(gvr, "")] = perftest.Pager[metav1.PartialObjectMetadata]{
			Items: items, PageSize: scale.pageSize, Counters: counters, ListOperation: perftest.MetadataList,
		}
	}
	ready := true
	snapshot := Snapshot{
		Catalog:  catalog,
		Services: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Namespace: "webhooks", Name: "converter"}}},
		EndpointSlices: []discoveryv1.EndpointSlice{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "webhooks", Labels: map[string]string{discoveryv1.LabelServiceName: "converter"}},
			Endpoints:  []discoveryv1.Endpoint{{Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		}},
	}
	reference := safetyv1alpha1.TargetReference{
		APIGroup: apiextensionsv1.GroupName, Version: "v1", Resource: "customresourcedefinitions", Kind: "CustomResourceDefinition",
		Name: crd.Name, UID: crd.UID,
	}
	reader := &diagnosisComponentReader{target: target, targetResource: crdResource, pages: pages, counters: counters}
	wantComplete := scale.objects <= scale.maximum
	return diagnosisComponentFixture{
		request: Request{Target: reference, Policy: policy, Snapshot: snapshot, Now: testNow},
		reader:  reader, counters: counters, objects: min(scale.objects, scale.maximum),
		verify: func(tb testing.TB, result Result) {
			tb.Helper()
			if !result.TargetFound || !result.UIDMatches || !result.ThresholdElapsed || result.DiagnosisComplete != wantComplete {
				tb.Fatalf("CRD diagnosis completeness = %t, want %t", result.DiagnosisComplete, wantComplete)
			}
			wantRemaining := min(scale.objects, scale.maximum)
			if got := diagnosisDetailedFindingCount(result.Findings, safetyv1alpha1.FindingRemainingResource); got != wantRemaining {
				tb.Fatalf("CRD detailed remaining findings = %d, want deduplicated %d", got, wantRemaining)
			}
			if !wantComplete && !hasTruncatedFinding(result.Findings) {
				tb.Fatal("bounded CRD diagnosis has no truncation finding")
			}
			if wantComplete && len(result.Actions) != 1 {
				tb.Fatalf("complete CRD diagnosis actions = %d, want 1", len(result.Actions))
			}
			if !wantComplete && len(result.Actions) != 0 {
				tb.Fatalf("incomplete CRD diagnosis actions = %d, want 0", len(result.Actions))
			}
			if !findingIDsSorted(result.Findings) || !actionIDsSorted(result.Actions) {
				tb.Fatal("CRD evidence is not sorted")
			}
		},
	}
}

func (r *diagnosisComponentReader) Get(_ context.Context, resource schema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error) {
	r.counters.Record(perftest.DynamicGet)
	if resource != r.targetResource || namespace != r.target.GetNamespace() || name != r.target.GetName() {
		return nil, fmt.Errorf("unexpected target GET %s %s/%s", resource, namespace, name)
	}
	return r.target.DeepCopy(), nil
}

func (r *diagnosisComponentReader) ListMetadata(_ context.Context, resource schema.GroupVersionResource, namespace string, options metav1.ListOptions) (*metav1.PartialObjectMetadataList, error) {
	pager, found := r.pages[diagnosisComponentListKey(resource, namespace)]
	if !found {
		return nil, fmt.Errorf("unexpected metadata LIST %s namespace %q", resource, namespace)
	}
	items, next, err := pager.Page(options.Continue, options.Limit)
	if err != nil {
		return nil, err
	}
	return &metav1.PartialObjectMetadataList{ListMeta: metav1.ListMeta{Continue: next}, Items: items}, nil
}

func diagnosisMustUnstructured(tb testing.TB, object any) *unstructured.Unstructured {
	tb.Helper()
	converted, err := k8sruntime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		tb.Fatalf("convert benchmark object: %v", err)
	}
	return &unstructured.Unstructured{Object: converted}
}

func diagnosisComponentListKey(resource schema.GroupVersionResource, namespace string) string {
	return resource.String() + "|" + namespace
}

func crdVersionedItems(unique int) map[string][]metav1.PartialObjectMetadata {
	firstVersionCount := unique * 3 / 5
	duplicateCount := min(unique/5, firstVersionCount)
	items := map[string][]metav1.PartialObjectMetadata{
		"v1":      make([]metav1.PartialObjectMetadata, 0, firstVersionCount),
		"v1beta1": make([]metav1.PartialObjectMetadata, 0, unique-firstVersionCount+duplicateCount),
	}
	instance := func(index int) metav1.PartialObjectMetadata {
		return metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
			Namespace: perftest.Name("namespace", index%16), Name: perftest.Name("widget", index), UID: perftest.UID("widget", index),
			ResourceVersion: perftest.ResourceVersion(index),
		}}
	}
	for index := range firstVersionCount {
		items["v1"] = append(items["v1"], instance(index))
	}
	for index := range duplicateCount {
		items["v1beta1"] = append(items["v1beta1"], instance(index))
	}
	for index := firstVersionCount; index < unique; index++ {
		items["v1beta1"] = append(items["v1beta1"], instance(index))
	}
	return items
}

func diagnosisFindingCount(findings []safetyv1alpha1.Finding, findingType safetyv1alpha1.FindingType) int {
	count := 0
	for _, finding := range findings {
		if finding.Type == findingType {
			count++
		}
	}
	return count
}

func diagnosisDetailedFindingCount(findings []safetyv1alpha1.Finding, findingType safetyv1alpha1.FindingType) int {
	count := 0
	for _, finding := range findings {
		if finding.Type == findingType && finding.ResourceRef != nil {
			count++
		}
	}
	return count
}
