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
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
	policyengine "github.com/erayack/exitguard/internal/policy"
)

var testNow = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

func TestDiagnoseConfirmsExistenceUIDAndAge(t *testing.T) {
	catalog := diagnosisCatalog(t)
	policy := diagnosisPolicy(t, catalog, policyOptions{})
	targetRef := widgetReference()

	t.Run("not found", func(t *testing.T) {
		reader := &fakeReader{getErr: apierrors.NewNotFound(schema.GroupResource{Group: targetRef.APIGroup, Resource: targetRef.Resource}, targetRef.Name)}
		result, err := NewEngine(reader).Diagnose(context.Background(), Request{Target: targetRef, Policy: policy, Snapshot: Snapshot{Catalog: catalog}, Now: testNow})
		if err != nil {
			t.Fatalf("Diagnose() error: %v", err)
		}
		if result.TargetFound || !result.DiagnosisComplete || reader.listCallCount() != 0 {
			t.Fatalf("result = %#v, list calls = %d", result, reader.listCallCount())
		}
	})

	t.Run("UID mismatch", func(t *testing.T) {
		object := deletingObject(targetRef, testNow.Add(-time.Hour), []string{"example.io/cleanup"})
		object.SetUID("replacement")
		reader := &fakeReader{target: object}
		result, err := NewEngine(reader).Diagnose(context.Background(), Request{Target: targetRef, Policy: policy, Snapshot: Snapshot{Catalog: catalog}, Now: testNow})
		if err != nil {
			t.Fatalf("Diagnose() error: %v", err)
		}
		if !result.TargetFound || result.UIDMatches || len(result.Findings) != 0 || reader.listCallCount() != 0 {
			t.Fatalf("result = %#v, want identity rejection", result)
		}
	})

	t.Run("threshold not elapsed", func(t *testing.T) {
		reader := &fakeReader{target: deletingObject(targetRef, testNow.Add(-time.Minute), []string{"example.io/cleanup"})}
		result, err := NewEngine(reader).Diagnose(context.Background(), Request{Target: targetRef, Policy: policy, Snapshot: Snapshot{Catalog: catalog}, Now: testNow})
		if err != nil {
			t.Fatalf("Diagnose() error: %v", err)
		}
		if !result.UIDMatches || result.ThresholdElapsed || len(result.Findings) != 0 {
			t.Fatalf("result = %#v, want no diagnosis before policy age", result)
		}
	})
}

func TestGenericDiagnosisProducesDeterministicEvidence(t *testing.T) {
	catalog := diagnosisCatalog(t)
	policy := diagnosisPolicy(t, catalog, policyOptions{
		allowedFinalizers: []string{"example.io/cleanup"},
		maxRisk:           safetyv1alpha1.RiskMedium,
		owners: []safetyv1alpha1.FinalizerOwner{{
			Finalizer: "example.io/cleanup",
			ControllerRef: safetyv1alpha1.ControllerReference{
				APIVersion: "apps/v1", Kind: "Deployment", Namespace: "operators", Name: "widget-controller",
			},
		}},
	})
	targetRef := widgetReference()
	target := deletingObject(targetRef, testNow.Add(-time.Hour), []string{"example.io/cleanup"})
	grace := int64(30)
	target.SetDeletionGracePeriodSeconds(&grace)
	original := target.DeepCopy()
	fail := admissionv1.Fail
	updateOperation := admissionv1.Update
	snapshot := Snapshot{
		Catalog: catalog,
		APIServices: []apiregistrationv1.APIService{
			unavailableAPIService("v1.apps.example.io", "apps.example.io", "v1"),
			unavailableAPIService("v1.other.example.io", "other.example.io", "v1"),
		},
		ValidatingWebhooks: []admissionv1.ValidatingWebhookConfiguration{{
			ObjectMeta: metav1.ObjectMeta{Name: "guard"},
			Webhooks: []admissionv1.ValidatingWebhook{{
				Name: "update.guard.example.io", FailurePolicy: &fail,
				Rules: []admissionv1.RuleWithOperations{{
					Operations: []admissionv1.OperationType{updateOperation},
					Rule:       admissionv1.Rule{APIGroups: []string{"apps.example.io"}, APIVersions: []string{"v1"}, Resources: []string{"widgets"}},
				}},
				ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: "webhooks", Name: "guard"}},
			}},
		}},
		NamespaceLabels: map[string]map[string]string{"workloads": {"environment": "prod"}},
	}
	reader := &fakeReader{target: target}
	request := Request{Target: targetRef, Policy: policy, Snapshot: snapshot, Now: testNow}
	result, err := NewEngine(reader).Diagnose(context.Background(), request)
	if err != nil {
		t.Fatalf("Diagnose() error: %v", err)
	}
	assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingBlockingFinalizer, 1)
	assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingDeletionGracePeriodExceeded, 1)
	assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingMissingFinalizerController, 1)
	assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingUnavailableAPIService, 1)
	assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingBlockingWebhook, 1)
	if len(result.Actions) != 1 || result.Actions[0].Risk != safetyv1alpha1.RiskMedium || !result.Actions[0].Eligible {
		t.Fatalf("actions = %#v, want one eligible Medium action", result.Actions)
	}
	assertSortedIDs(t, result)
	if !reflect.DeepEqual(target, original) {
		t.Error("diagnosis mutated the direct target")
	}

	again, err := NewEngine(&fakeReader{target: target}).Diagnose(context.Background(), request)
	if err != nil {
		t.Fatalf("second Diagnose() error: %v", err)
	}
	if !reflect.DeepEqual(result.Findings, again.Findings) || !reflect.DeepEqual(result.Actions, again.Actions) {
		t.Error("diagnosis IDs or ordering changed for identical evidence")
	}
}

func TestActionIDBindsTargetAndPolicyEvidence(t *testing.T) {
	base := actionID(safetyv1alpha1.ActionRemoveResourceFinalizer, types.UID("target-uid"), "example.io/cleanup", "7", types.UID("policy-uid"), 3)
	identical := actionID(safetyv1alpha1.ActionRemoveResourceFinalizer, types.UID("target-uid"), "example.io/cleanup", "7", types.UID("policy-uid"), 3)
	if identical != base {
		t.Fatalf("identical evidence produced IDs %q and %q", base, identical)
	}

	rotated := map[string]string{
		"resource version":  actionID(safetyv1alpha1.ActionRemoveResourceFinalizer, types.UID("target-uid"), "example.io/cleanup", "8", types.UID("policy-uid"), 3),
		"policy UID":        actionID(safetyv1alpha1.ActionRemoveResourceFinalizer, types.UID("target-uid"), "example.io/cleanup", "7", types.UID("replacement-policy"), 3),
		"policy generation": actionID(safetyv1alpha1.ActionRemoveResourceFinalizer, types.UID("target-uid"), "example.io/cleanup", "7", types.UID("policy-uid"), 4),
	}
	for evidence, id := range rotated {
		if id == base {
			t.Errorf("%s change did not rotate action ID %q", evidence, base)
		}
	}
}

func TestFindingMessagesRespectAPIMaxLength(t *testing.T) {
	catalog := diagnosisCatalog(t)
	policy := diagnosisPolicy(t, catalog, policyOptions{})
	targetRef := widgetReference()
	apiService := unavailableAPIService("v1.apps.example.io", "apps.example.io", "v1")
	apiService.Status.Conditions[0].Message = strings.Repeat("evidence", 200)

	result, err := NewEngine(&fakeReader{target: deletingObject(targetRef, testNow.Add(-time.Hour), nil)}).Diagnose(context.Background(), Request{
		Target: targetRef,
		Policy: policy,
		Snapshot: Snapshot{
			Catalog:     catalog,
			APIServices: []apiregistrationv1.APIService{apiService},
		},
		Now: testNow,
	})
	if err != nil {
		t.Fatalf("Diagnose() error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one APIService finding", result.Findings)
	}
	if length := len([]rune(result.Findings[0].Message)); length != 1024 {
		t.Fatalf("finding message length = %d, want 1024", length)
	}
}

func TestNamespaceDiagnosisEnumeratesMetadataAndReportsTruncation(t *testing.T) {
	catalog := diagnosisCatalog(t)
	policy := diagnosisPolicy(t, catalog, policyOptions{
		allowedFinalizers: []string{"example.io/cleanup"}, maxRisk: safetyv1alpha1.RiskCritical,
		allowNamespaceForce: true, maxNamespaceObjects: 1,
	})
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "stuck", UID: "namespace-uid", ResourceVersion: "10",
			DeletionTimestamp: &metav1.Time{Time: testNow.Add(-time.Hour)},
		},
		Spec: corev1.NamespaceSpec{Finalizers: []corev1.FinalizerName{"kubernetes"}},
		Status: corev1.NamespaceStatus{Conditions: []corev1.NamespaceCondition{
			{Type: corev1.NamespaceContentRemaining, Status: corev1.ConditionTrue, Message: "resources remain"},
			{Type: corev1.NamespaceFinalizersRemaining, Status: corev1.ConditionTrue, Message: "finalizers remain"},
			{Type: corev1.NamespaceConditionType("ExampleUnknown"), Status: corev1.ConditionTrue, Message: "unknown deletion state"},
			{Type: corev1.NamespaceDeletionDiscoveryFailure, Status: corev1.ConditionFalse, Message: "resolved"},
		}},
	}
	target := toUnstructured(t, namespace)
	targetRef := safetyv1alpha1.TargetReference{Version: "v1", Resource: "namespaces", Kind: "Namespace", Name: "stuck", UID: "namespace-uid"}
	pod := metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Namespace: "stuck", Name: "blocked-pod", UID: "pod-uid", ResourceVersion: "7", Finalizers: []string{"example.io/cleanup"},
	}}
	reader := &fakeReader{
		target: target,
		lists: map[string][]listResponse{
			listKey(schema.GroupVersionResource{Version: "v1", Resource: "pods"}, "stuck"): {{
				list: &metav1.PartialObjectMetadataList{ListMeta: metav1.ListMeta{Continue: "more"}, Items: []metav1.PartialObjectMetadata{pod}},
			}},
		},
	}
	snapshot := Snapshot{
		Catalog:     catalog,
		APIServices: []apiregistrationv1.APIService{unavailableAPIService("v1.unrelated.example.io", "unrelated.example.io", "v1")},
	}
	result, err := NewEngine(reader).Diagnose(context.Background(), Request{Target: targetRef, Policy: policy, Snapshot: snapshot, Now: testNow})
	if err != nil {
		t.Fatalf("Diagnose() error: %v", err)
	}
	if result.DiagnosisComplete {
		t.Error("truncated diagnosis reported complete")
	}
	if !reflect.DeepEqual(result.TargetSnapshot.NamespaceFinalizers, []string{"kubernetes"}) {
		t.Errorf("namespace finalizers = %v", result.TargetSnapshot.NamespaceFinalizers)
	}
	assertFindingTypeAtLeast(t, result.Findings, safetyv1alpha1.FindingRemainingResource, 2)
	assertFindingTypeAtLeast(t, result.Findings, safetyv1alpha1.FindingBlockingFinalizer, 2)
	assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingUnknown, 1)
	assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingUnavailableAPIService, 1)
	if !hasTruncatedFinding(result.Findings) {
		t.Error("truncation finding is missing")
	}
	if len(result.Actions) != 0 {
		t.Fatalf("incomplete diagnosis published actions: %#v", result.Actions)
	}
	if calls := reader.callsFor(schema.GroupVersionResource{Version: "v1", Resource: "pods"}, "stuck"); len(calls) != 1 || calls[0].Limit != 1 {
		t.Errorf("pod list calls = %#v, want one partial-metadata page limited to 1", calls)
	}
}

func TestNamespaceDiagnosisChecksChildUpdateWebhooks(t *testing.T) {
	catalog := diagnosisCatalog(t)
	policy := diagnosisPolicy(t, catalog, policyOptions{maxRisk: safetyv1alpha1.RiskCritical, allowNamespaceForce: true})
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "stuck", UID: "namespace-uid", ResourceVersion: "10", DeletionTimestamp: &metav1.Time{Time: testNow.Add(-time.Hour)}},
		Spec:       corev1.NamespaceSpec{Finalizers: []corev1.FinalizerName{"kubernetes"}},
	}
	pod := metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: "stuck", Name: "blocked-pod", UID: "pod-uid", ResourceVersion: "7", Labels: map[string]string{"app": "api"}}}
	fail := admissionv1.Fail
	namespaced := admissionv1.NamespacedScope
	webhook := admissionv1.ValidatingWebhook{
		Name: "pods.guard.example.io", FailurePolicy: &fail,
		Rules:        []admissionv1.RuleWithOperations{{Operations: []admissionv1.OperationType{admissionv1.Update}, Rule: admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"}, Scope: &namespaced}}},
		ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: "webhooks", Name: "missing"}},
	}
	reader := &fakeReader{target: toUnstructured(t, namespace), lists: map[string][]listResponse{
		listKey(schema.GroupVersionResource{Version: "v1", Resource: "pods"}, "stuck"): {{list: &metav1.PartialObjectMetadataList{Items: []metav1.PartialObjectMetadata{pod}}}},
	}}
	result, err := NewEngine(reader).Diagnose(context.Background(), Request{
		Target:   safetyv1alpha1.TargetReference{Version: "v1", Resource: "namespaces", Kind: "Namespace", Name: "stuck", UID: "namespace-uid"},
		Policy:   policy,
		Snapshot: Snapshot{Catalog: catalog, ValidatingWebhooks: []admissionv1.ValidatingWebhookConfiguration{{ObjectMeta: metav1.ObjectMeta{Name: "guard"}, Webhooks: []admissionv1.ValidatingWebhook{webhook}}}, NamespaceLabels: map[string]map[string]string{"stuck": {}}},
		Now:      testNow,
	})
	if err != nil {
		t.Fatalf("Diagnose() error: %v", err)
	}
	if !result.DiagnosisComplete {
		t.Fatalf("child webhook diagnosis was incomplete: %#v", result.Findings)
	}
	assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingBlockingWebhook, 1)
	for i := range result.Findings {
		finding := &result.Findings[i]
		if finding.Type == safetyv1alpha1.FindingBlockingWebhook && (finding.ResourceRef == nil || finding.ResourceRef.UID != "pod-uid") {
			t.Fatalf("blocking webhook was not attributed to child: %#v", finding)
		}
	}
}

func TestNamespaceDiagnosisFallsBackToAlternateServedVersion(t *testing.T) {
	catalog := diagnosisCatalog(t)
	policy := diagnosisPolicy(t, catalog, policyOptions{})
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "stuck", UID: "namespace-uid", ResourceVersion: "10", DeletionTimestamp: &metav1.Time{Time: testNow.Add(-time.Hour)}}}
	widget := metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: "stuck", Name: "remaining", UID: "widget-uid", ResourceVersion: "4"}}
	preferred := schema.GroupVersionResource{Group: "apps.example.io", Version: "v1", Resource: "widgets"}
	alternate := schema.GroupVersionResource{Group: "apps.example.io", Version: "v1beta1", Resource: "widgets"}
	reader := &fakeReader{target: toUnstructured(t, namespace), lists: map[string][]listResponse{
		listKey(preferred, "stuck"): {{err: apierrors.NewNotFound(preferred.GroupResource(), "")}},
		listKey(alternate, "stuck"): {{list: &metav1.PartialObjectMetadataList{Items: []metav1.PartialObjectMetadata{widget}}}},
	}}
	result, err := NewEngine(reader).Diagnose(context.Background(), Request{
		Target: safetyv1alpha1.TargetReference{Version: "v1", Resource: "namespaces", Kind: "Namespace", Name: "stuck", UID: "namespace-uid"},
		Policy: policy, Snapshot: Snapshot{Catalog: catalog}, Now: testNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.DiagnosisComplete {
		t.Fatalf("alternate-version evidence was incomplete: %#v", result.Findings)
	}
	found := false
	for i := range result.Findings {
		ref := result.Findings[i].ResourceRef
		if ref != nil && ref.UID == "widget-uid" {
			found = ref.Version == "v1beta1"
		}
	}
	if !found {
		t.Fatalf("alternate-version child was not diagnosed: %#v", result.Findings)
	}
}

func TestCRDDiagnosisDeduplicatesVersionsAndGatesCleanupAction(t *testing.T) {
	catalog := diagnosisCatalog(t)
	policy := diagnosisPolicy(t, catalog, policyOptions{
		allowedFinalizers: []string{apiextensionsv1.CustomResourceCleanupFinalizer}, maxRisk: safetyv1alpha1.RiskHigh,
	})
	crd := testCRD()
	target := toUnstructured(t, crd)
	targetRef := safetyv1alpha1.TargetReference{
		APIGroup: apiextensionsv1.GroupName, Version: "v1", Resource: "customresourcedefinitions",
		Kind: "CustomResourceDefinition", Name: crd.Name, UID: crd.UID,
	}
	instance := metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: "workloads", Name: "one", UID: "instance-uid", ResourceVersion: "4"}}
	lists := map[string][]listResponse{
		listKey(schema.GroupVersionResource{Group: "example.io", Version: "v1", Resource: "widgets"}, ""):      {{list: &metav1.PartialObjectMetadataList{Items: []metav1.PartialObjectMetadata{instance}}}},
		listKey(schema.GroupVersionResource{Group: "example.io", Version: "v1beta1", Resource: "widgets"}, ""): {{list: &metav1.PartialObjectMetadataList{Items: []metav1.PartialObjectMetadata{instance}}}},
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
	result, err := NewEngine(&fakeReader{target: target, lists: lists}).Diagnose(context.Background(), Request{Target: targetRef, Policy: policy, Snapshot: snapshot, Now: testNow})
	if err != nil {
		t.Fatalf("Diagnose() error: %v", err)
	}
	if !result.DiagnosisComplete {
		t.Fatalf("complete CRD evidence reported incomplete: %#v", result.Findings)
	}
	assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingRemainingResource, 1)
	assertAction(t, result.Actions, safetyv1alpha1.ActionRemoveCRDFinalizer, string(crd.UID), safetyv1alpha1.RiskHigh, true)

	failedLists := map[string][]listResponse{
		listKey(schema.GroupVersionResource{Group: "example.io", Version: "v1", Resource: "widgets"}, ""): {{err: errors.New("conversion failed")}},
	}
	failed, err := NewEngine(&fakeReader{target: target, lists: failedLists}).Diagnose(context.Background(), Request{Target: targetRef, Policy: policy, Snapshot: snapshot, Now: testNow})
	if err != nil {
		t.Fatalf("failed-evidence Diagnose() error: %v", err)
	}
	if failed.DiagnosisComplete || hasActionType(failed.Actions, safetyv1alpha1.ActionRemoveCRDFinalizer) {
		t.Fatalf("incomplete evidence produced cleanup action: %#v", failed)
	}
	assertFindingTypeAtLeast(t, failed.Findings, safetyv1alpha1.FindingDiscoveryFailure, 1)

	unavailableConversion, err := NewEngine(&fakeReader{target: target, lists: lists}).Diagnose(context.Background(), Request{
		Target: targetRef, Policy: policy, Snapshot: Snapshot{Catalog: catalog}, Now: testNow,
	})
	if err != nil {
		t.Fatalf("unavailable-conversion Diagnose() error: %v", err)
	}
	if unavailableConversion.DiagnosisComplete || hasActionType(unavailableConversion.Actions, safetyv1alpha1.ActionRemoveCRDFinalizer) {
		t.Fatalf("unavailable conversion backend produced cleanup action: %#v", unavailableConversion)
	}
	assertFindingTypeCount(t, unavailableConversion.Findings, safetyv1alpha1.FindingBlockingWebhook, 1)
}

func TestCRDDiagnosisBoundsInstanceEvidence(t *testing.T) {
	catalog := diagnosisCatalog(t)
	crd := testCRD()
	crd.Spec.Conversion = nil
	target := toUnstructured(t, crd)
	targetRef := safetyv1alpha1.TargetReference{
		APIGroup: apiextensionsv1.GroupName, Version: "v1", Resource: "customresourcedefinitions",
		Kind: "CustomResourceDefinition", Name: crd.Name, UID: crd.UID,
	}
	v1 := schema.GroupVersionResource{Group: "example.io", Version: "v1", Resource: "widgets"}
	v1beta1 := schema.GroupVersionResource{Group: "example.io", Version: "v1beta1", Resource: "widgets"}
	instance := func(name, uid string) metav1.PartialObjectMetadata {
		return metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: "workloads", Name: name, UID: types.UID(uid)}}
	}
	diagnose := func(t *testing.T, maxInstances int32, lists map[string][]listResponse) Result {
		t.Helper()
		policy := diagnosisPolicy(t, catalog, policyOptions{
			allowedFinalizers: []string{apiextensionsv1.CustomResourceCleanupFinalizer},
			maxRisk:           safetyv1alpha1.RiskHigh,
			maxCRDInstances:   maxInstances,
		})
		result, err := NewEngine(&fakeReader{target: target, lists: lists}).Diagnose(context.Background(), Request{
			Target: targetRef, Policy: policy, Snapshot: Snapshot{Catalog: catalog}, Now: testNow,
		})
		if err != nil {
			t.Fatalf("Diagnose() error: %v", err)
		}
		return result
	}
	assertEvidenceCounts := func(t *testing.T, result Result, wantInstances, wantMissingUIDs int) {
		t.Helper()
		instances := 0
		for _, finding := range result.Findings {
			if finding.Type == safetyv1alpha1.FindingRemainingResource && finding.ResourceRef != nil && finding.ResourceRef.APIGroup == crd.Spec.Group {
				instances++
			}
		}
		if instances != wantInstances {
			t.Errorf("retained CRD instance findings = %d, want %d; findings: %#v", instances, wantInstances, result.Findings)
		}
		assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingUnknown, wantMissingUIDs)
	}

	t.Run("exact limit with cross-version duplicates remains complete", func(t *testing.T) {
		one := instance("one", "uid-one")
		two := instance("two", "uid-two")
		lists := map[string][]listResponse{
			listKey(v1, ""):      {{list: &metav1.PartialObjectMetadataList{Items: []metav1.PartialObjectMetadata{one, two}}}},
			listKey(v1beta1, ""): {{list: &metav1.PartialObjectMetadataList{Items: []metav1.PartialObjectMetadata{one, two}}}},
		}
		result := diagnose(t, 2, lists)
		if !result.DiagnosisComplete || hasTruncatedFinding(result.Findings) {
			t.Fatalf("exact-limit duplicate evidence was truncated: %#v", result.Findings)
		}
		assertEvidenceCounts(t, result, 2, 0)
		assertAction(t, result.Actions, safetyv1alpha1.ActionRemoveCRDFinalizer, string(crd.UID), safetyv1alpha1.RiskHigh, true)
	})

	t.Run("additional unique instance across versions truncates", func(t *testing.T) {
		one := instance("one", "uid-one")
		two := instance("two", "uid-two")
		three := instance("three", "uid-three")
		lists := map[string][]listResponse{
			listKey(v1, ""):      {{list: &metav1.PartialObjectMetadataList{Items: []metav1.PartialObjectMetadata{one}}}},
			listKey(v1beta1, ""): {{list: &metav1.PartialObjectMetadataList{Items: []metav1.PartialObjectMetadata{one, two, three}}}},
		}
		result := diagnose(t, 2, lists)
		if result.DiagnosisComplete || !hasTruncatedFinding(result.Findings) {
			t.Fatalf("over-limit evidence was not marked incomplete and truncated: %#v", result.Findings)
		}
		assertEvidenceCounts(t, result, 2, 0)
		if hasActionType(result.Actions, safetyv1alpha1.ActionRemoveCRDFinalizer) {
			t.Fatalf("truncated evidence published CRD cleanup action: %#v", result.Actions)
		}

		again := diagnose(t, 2, lists)
		if !reflect.DeepEqual(result.Findings, again.Findings) || !reflect.DeepEqual(result.Actions, again.Actions) {
			t.Error("bounded CRD evidence changed for identical input")
		}
	})

	t.Run("missing UID evidence consumes the limit", func(t *testing.T) {
		lists := map[string][]listResponse{
			listKey(v1, ""): {{list: &metav1.PartialObjectMetadataList{Items: []metav1.PartialObjectMetadata{
				instance("one", ""), instance("two", ""), instance("three", ""),
			}}}},
		}
		result := diagnose(t, 2, lists)
		if result.DiagnosisComplete || !hasTruncatedFinding(result.Findings) {
			t.Fatalf("missing-UID overflow was not marked incomplete and truncated: %#v", result.Findings)
		}
		assertEvidenceCounts(t, result, 0, 2)
		if hasActionType(result.Actions, safetyv1alpha1.ActionRemoveCRDFinalizer) {
			t.Fatalf("missing-UID overflow published CRD cleanup action: %#v", result.Actions)
		}
	})
}

func TestWebhookNamespaceSelectorUsesNamespaceObjectLabels(t *testing.T) {
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"environment": "prod"}}
	request := Request{Target: safetyv1alpha1.TargetReference{Version: "v1", Resource: "namespaces", Kind: "Namespace", Name: "workloads", UID: "namespace-uid"}}
	target := &unstructured.Unstructured{}
	target.SetLabels(map[string]string{"environment": "dev"})
	webhook := webhookView{
		namespaceSelector: selector,
		rules: []admissionv1.RuleWithOperations{{
			Operations: []admissionv1.OperationType{admissionv1.Update},
			Rule:       admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"namespaces/finalize"}},
		}},
	}

	matches, uncertain := webhookMatches(request, target, webhook)
	if matches || uncertain != "" {
		t.Fatalf("webhookMatches() = (%t, %q), want selector exclusion", matches, uncertain)
	}
	target.SetLabels(map[string]string{"environment": "prod"})
	matches, uncertain = webhookMatches(request, target, webhook)
	if !matches || uncertain != "" {
		t.Fatalf("webhookMatches() = (%t, %q), want namespace object match", matches, uncertain)
	}
}

func TestNamespaceFinalizeWebhookResourceRules(t *testing.T) {
	request := Request{Target: safetyv1alpha1.TargetReference{Version: "v1", Resource: "namespaces", Kind: "Namespace", Name: "stuck", UID: "namespace-uid"}}
	tests := []struct {
		resource  string
		operation admissionv1.OperationType
		want      bool
	}{
		{resource: "namespaces", operation: admissionv1.Update},
		{resource: "*", operation: admissionv1.Update},
		{resource: "namespaces/finalize", operation: admissionv1.Update, want: true},
		{resource: "namespaces/*", operation: admissionv1.Update, want: true},
		{resource: "*/finalize", operation: admissionv1.Update, want: true},
		{resource: "*/*", operation: admissionv1.Update, want: true},
		{resource: "namespaces/finalize", operation: admissionv1.Delete},
	}
	for _, test := range tests {
		rule := admissionv1.RuleWithOperations{
			Operations: []admissionv1.OperationType{test.operation},
			Rule:       admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{test.resource}},
		}
		if got := ruleMatches(request, rule, nil); got != test.want {
			t.Errorf("resource %q operation %q match = %t, want %t", test.resource, test.operation, got, test.want)
		}
	}
}

func TestWebhookMatchingRulesSelectorsBackendsAndUncertainty(t *testing.T) {
	catalog := diagnosisCatalog(t)
	policy := diagnosisPolicy(t, catalog, policyOptions{})
	targetRef := widgetReference()
	target := deletingObject(targetRef, testNow.Add(-time.Hour), nil)
	target.SetLabels(map[string]string{"app": "api"})
	fail := admissionv1.Fail
	ignore := admissionv1.Ignore
	exact := admissionv1.Exact
	equivalent := admissionv1.Equivalent
	deleteOperation := admissionv1.Delete
	updateOperation := admissionv1.Update
	createOperation := admissionv1.Create
	namespaced := admissionv1.NamespacedScope
	cluster := admissionv1.ClusterScope
	service := admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: "webhooks", Name: "guard"}}
	baseRule := admissionv1.RuleWithOperations{
		Operations: []admissionv1.OperationType{updateOperation},
		Rule:       admissionv1.Rule{APIGroups: []string{"apps.example.io"}, APIVersions: []string{"v1"}, Resources: []string{"widgets"}, Scope: &namespaced},
	}

	tests := []struct {
		name              string
		failurePolicy     *admissionv1.FailurePolicyType
		matchPolicy       *admissionv1.MatchPolicyType
		rule              admissionv1.RuleWithOperations
		namespaceSelector *metav1.LabelSelector
		objectSelector    *metav1.LabelSelector
		clientConfig      admissionv1.WebhookClientConfig
		matchConditions   []admissionv1.MatchCondition
		services          []corev1.Service
		endpointSlices    []discoveryv1.EndpointSlice
		wantBlocking      int
		wantAdvisory      int
	}{
		{name: "missing service blocks", failurePolicy: &fail, matchPolicy: &exact, rule: baseRule, clientConfig: service, wantBlocking: 1},
		{name: "ignore does not block", failurePolicy: &ignore, rule: baseRule, clientConfig: service},
		{name: "create does not match", failurePolicy: &fail, rule: withOperations(baseRule, createOperation), clientConfig: service},
		{name: "delete does not match remediation", failurePolicy: &fail, rule: withOperations(baseRule, deleteOperation), clientConfig: service},
		{name: "group does not match", failurePolicy: &fail, rule: withGroups(baseRule, "other.example.io"), clientConfig: service},
		{name: "resource does not match", failurePolicy: &fail, rule: withResources(baseRule, "gadgets"), clientConfig: service},
		{name: "scope does not match", failurePolicy: &fail, rule: withScope(baseRule, cluster), clientConfig: service},
		{name: "exact version does not match", failurePolicy: &fail, matchPolicy: &exact, rule: withVersions(baseRule, "v1beta1"), clientConfig: service},
		{name: "equivalent version matches", failurePolicy: &fail, matchPolicy: &equivalent, rule: withVersions(baseRule, "v1beta1"), clientConfig: service, wantBlocking: 1},
		{name: "namespace selector excludes", failurePolicy: &fail, rule: baseRule, namespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"environment": "dev"}}, clientConfig: service},
		{name: "object selector excludes", failurePolicy: &fail, rule: baseRule, objectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}, clientConfig: service},
		{name: "match conditions advisory", failurePolicy: &fail, rule: baseRule, clientConfig: service, matchConditions: []admissionv1.MatchCondition{{Name: "maybe", Expression: "true"}}, wantAdvisory: 1},
		{name: "URL advisory", failurePolicy: &fail, rule: baseRule, clientConfig: admissionv1.WebhookClientConfig{URL: stringPointer("https://example.invalid")}, wantAdvisory: 1},
		{name: "ready service leaves TLS advisory", failurePolicy: &fail, rule: baseRule, clientConfig: service,
			services:       []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Namespace: "webhooks", Name: "guard"}}},
			endpointSlices: readyEndpointSlices("webhooks", "guard"), wantAdvisory: 1},
		{name: "nil ready condition is ready", failurePolicy: &fail, rule: baseRule, clientConfig: service,
			services: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Namespace: "webhooks", Name: "guard"}}},
			endpointSlices: []discoveryv1.EndpointSlice{{
				ObjectMeta: metav1.ObjectMeta{Namespace: "webhooks", Labels: map[string]string{discoveryv1.LabelServiceName: "guard"}},
				Endpoints:  []discoveryv1.Endpoint{{}},
			}}, wantAdvisory: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			webhook := admissionv1.ValidatingWebhook{
				Name: "guard.example.io", FailurePolicy: test.failurePolicy, MatchPolicy: test.matchPolicy,
				Rules: []admissionv1.RuleWithOperations{test.rule}, NamespaceSelector: test.namespaceSelector,
				ObjectSelector: test.objectSelector, ClientConfig: test.clientConfig, MatchConditions: test.matchConditions,
			}
			snapshot := Snapshot{
				Catalog:            catalog,
				ValidatingWebhooks: []admissionv1.ValidatingWebhookConfiguration{{ObjectMeta: metav1.ObjectMeta{Name: "guard"}, Webhooks: []admissionv1.ValidatingWebhook{webhook}}},
				Services:           test.services, EndpointSlices: test.endpointSlices,
				NamespaceLabels: map[string]map[string]string{"workloads": {"environment": "prod"}},
			}
			result, err := NewEngine(&fakeReader{target: target}).Diagnose(context.Background(), Request{Target: targetRef, Policy: policy, Snapshot: snapshot, Now: testNow})
			if err != nil {
				t.Fatalf("Diagnose() error: %v", err)
			}
			assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingBlockingWebhook, test.wantBlocking)
			assertFindingTypeCount(t, result.Findings, safetyv1alpha1.FindingUnknown, test.wantAdvisory)
		})
	}
}

func TestOwnerHealthSupportsOnlyConfiguredWorkloadKinds(t *testing.T) {
	replicas := int32(1)
	zeroReplicas := int32(0)
	tests := []struct {
		name     string
		owner    safetyv1alpha1.ControllerReference
		snapshot Snapshot
		want     bool
	}{
		{name: "Deployment", owner: ownerRef("Deployment"), snapshot: Snapshot{Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "operators", Name: "controller", Generation: 2},
			Spec:       appsv1.DeploymentSpec{Replicas: &replicas}, Status: appsv1.DeploymentStatus{ObservedGeneration: 2, AvailableReplicas: 1},
		}}}, want: true},
		{name: "StatefulSet", owner: ownerRef("StatefulSet"), snapshot: Snapshot{StatefulSets: []appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "operators", Name: "controller", Generation: 2},
			Spec:       appsv1.StatefulSetSpec{Replicas: &replicas}, Status: appsv1.StatefulSetStatus{ObservedGeneration: 2, ReadyReplicas: 1},
		}}}, want: true},
		{name: "DaemonSet", owner: ownerRef("DaemonSet"), snapshot: Snapshot{DaemonSets: []appsv1.DaemonSet{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "operators", Name: "controller", Generation: 2},
			Status:     appsv1.DaemonSetStatus{ObservedGeneration: 2, DesiredNumberScheduled: 1, NumberReady: 1},
		}}}, want: true},
		{name: "scaled-to-zero Deployment", owner: ownerRef("Deployment"), snapshot: Snapshot{Deployments: []appsv1.Deployment{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "operators", Name: "controller", Generation: 2},
			Spec:       appsv1.DeploymentSpec{Replicas: &zeroReplicas}, Status: appsv1.DeploymentStatus{ObservedGeneration: 2},
		}}}},
		{name: "scaled-to-zero StatefulSet", owner: ownerRef("StatefulSet"), snapshot: Snapshot{StatefulSets: []appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "operators", Name: "controller", Generation: 2},
			Spec:       appsv1.StatefulSetSpec{Replicas: &zeroReplicas}, Status: appsv1.StatefulSetStatus{ObservedGeneration: 2},
		}}}},
		{name: "unsupported", owner: ownerRef("ReplicaSet"), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _ := ownerHealthy(test.snapshot, test.owner)
			if got != test.want {
				t.Errorf("ownerHealthy() = %v, want %v", got, test.want)
			}
		})
	}
}

type policyOptions struct {
	allowedFinalizers   []string
	maxRisk             safetyv1alpha1.RiskLevel
	allowNamespaceForce bool
	maxNamespaceObjects int32
	maxCRDInstances     int32
	owners              []safetyv1alpha1.FinalizerOwner
}

func diagnosisPolicy(t *testing.T, catalog catalogdiscovery.Snapshot, options policyOptions) *policyengine.CompiledPolicy {
	t.Helper()
	maxRisk := options.maxRisk
	if maxRisk == "" {
		maxRisk = safetyv1alpha1.RiskNone
	}
	maxObjects := options.maxNamespaceObjects
	if maxObjects == 0 {
		maxObjects = 5000
	}
	maxCRDInstances := options.maxCRDInstances
	if maxCRDInstances == 0 {
		maxCRDInstances = 5000
	}
	source := &safetyv1alpha1.TerminationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "diagnosis", UID: "policy-uid", Generation: 1},
		Spec: safetyv1alpha1.TerminationPolicySpec{
			TargetRules:    []safetyv1alpha1.TargetRule{{APIGroups: []string{"*"}, Resources: []string{"*"}}},
			TerminationAge: metav1.Duration{Duration: 10 * time.Minute},
			Diagnosis: safetyv1alpha1.DiagnosisPolicy{
				CheckAPIServices: true, CheckWebhooks: true,
				MaxNamespaceObjects: maxObjects, MaxCRDInstances: maxCRDInstances,
			},
			FinalizerOwners: options.owners,
			Remediation: safetyv1alpha1.RemediationPolicy{
				MaxRisk: maxRisk, AllowedFinalizers: options.allowedFinalizers,
				AllowNamespaceForce: options.allowNamespaceForce, ApprovalTTL: metav1.Duration{Duration: time.Hour},
			},
			Retention: safetyv1alpha1.RetentionPolicy{ResolvedIncidentTTL: metav1.Duration{Duration: 30 * 24 * time.Hour}},
		},
	}
	compiled, status := policyengine.Compile(source, catalog, testNow)
	if !compiled.Ready() {
		t.Fatalf("compile diagnosis policy: %#v", status.Conditions)
	}
	return compiled
}

func diagnosisCatalog(t *testing.T) catalogdiscovery.Snapshot {
	t.Helper()
	client := staticDiscovery{
		resources: []*metav1.APIResourceList{
			{GroupVersion: "v1", APIResources: []metav1.APIResource{
				{Name: "namespaces", Kind: "Namespace", Namespaced: false, Verbs: []string{"get", "list"}},
				{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get", "list"}},
			}},
			{GroupVersion: "apps.example.io/v1", APIResources: []metav1.APIResource{{Name: "widgets", Kind: "Widget", Namespaced: true, Verbs: []string{"get", "list"}}}},
			{GroupVersion: "apps.example.io/v1beta1", APIResources: []metav1.APIResource{{Name: "widgets", Kind: "Widget", Namespaced: true, Verbs: []string{"get", "list"}}}},
			{GroupVersion: "apiextensions.k8s.io/v1", APIResources: []metav1.APIResource{{Name: "customresourcedefinitions", Kind: "CustomResourceDefinition", Namespaced: false, Verbs: []string{"get", "list"}}}},
		},
	}
	groups := []*metav1.APIGroup{{
		Name:             "apps.example.io",
		PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: "apps.example.io/v1", Version: "v1"},
		Versions: []metav1.GroupVersionForDiscovery{
			{GroupVersion: "apps.example.io/v1", Version: "v1"},
			{GroupVersion: "apps.example.io/v1beta1", Version: "v1beta1"},
		},
	}}
	catalog := catalogdiscovery.NewCatalog(staticDiscovery{groups: groups, resources: client.resources}, time.Minute, logr.Discard())
	if err := catalog.Refresh(); err != nil {
		t.Fatalf("refresh catalog: %v", err)
	}
	return catalog.Snapshot()
}

type staticDiscovery struct {
	groups    []*metav1.APIGroup
	resources []*metav1.APIResourceList
}

func (s staticDiscovery) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	return s.groups, s.resources, nil
}

type listResponse struct {
	list *metav1.PartialObjectMetadataList
	err  error
}

type listCall struct {
	resource  schema.GroupVersionResource
	namespace string
	options   metav1.ListOptions
}

type fakeReader struct {
	mu        sync.Mutex
	target    *unstructured.Unstructured
	getErr    error
	lists     map[string][]listResponse
	indexes   map[string]int
	listCalls []listCall
}

func (f *fakeReader) Get(_ context.Context, _ schema.GroupVersionResource, _, _ string) (*unstructured.Unstructured, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.target, nil
}

func (f *fakeReader) ListMetadata(_ context.Context, resource schema.GroupVersionResource, namespace string, options metav1.ListOptions) (*metav1.PartialObjectMetadataList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls = append(f.listCalls, listCall{resource: resource, namespace: namespace, options: options})
	key := listKey(resource, namespace)
	responses := f.lists[key]
	if len(responses) == 0 {
		return &metav1.PartialObjectMetadataList{}, nil
	}
	if f.indexes == nil {
		f.indexes = make(map[string]int)
	}
	index := f.indexes[key]
	if index >= len(responses) {
		index = len(responses) - 1
	} else {
		f.indexes[key]++
	}
	response := responses[index]
	return response.list, response.err
}

func (f *fakeReader) listCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.listCalls)
}

func (f *fakeReader) callsFor(resource schema.GroupVersionResource, namespace string) []metav1.ListOptions {
	f.mu.Lock()
	defer f.mu.Unlock()
	var result []metav1.ListOptions
	for _, call := range f.listCalls {
		if call.resource == resource && call.namespace == namespace {
			result = append(result, call.options)
		}
	}
	return result
}

func listKey(resource schema.GroupVersionResource, namespace string) string {
	return resource.String() + "|" + namespace
}

func widgetReference() safetyv1alpha1.TargetReference {
	return safetyv1alpha1.TargetReference{
		APIGroup: "apps.example.io", Version: "v1", Resource: "widgets", Kind: "Widget",
		Namespace: "workloads", Name: "stuck", UID: types.UID("widget-uid"),
	}
}

func deletingObject(reference safetyv1alpha1.TargetReference, deletionTime time.Time, finalizers []string) *unstructured.Unstructured {
	object := &unstructured.Unstructured{}
	object.SetAPIVersion(schema.GroupVersion{Group: reference.APIGroup, Version: reference.Version}.String())
	object.SetKind(reference.Kind)
	object.SetNamespace(reference.Namespace)
	object.SetName(reference.Name)
	object.SetUID(reference.UID)
	object.SetResourceVersion("12")
	object.SetFinalizers(append([]string(nil), finalizers...))
	object.SetDeletionTimestamp(&metav1.Time{Time: deletionTime})
	return object
}

func unavailableAPIService(name, group, version string) apiregistrationv1.APIService {
	return apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       apiregistrationv1.APIServiceSpec{Group: group, Version: version},
		Status: apiregistrationv1.APIServiceStatus{Conditions: []apiregistrationv1.APIServiceCondition{{
			Type: apiregistrationv1.Available, Status: apiregistrationv1.ConditionFalse, Message: "backend unavailable",
		}}},
	}
}

func testCRD() *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "widgets.example.io", UID: "crd-uid", ResourceVersion: "8",
			Finalizers:        []string{apiextensionsv1.CustomResourceCleanupFinalizer},
			DeletionTimestamp: &metav1.Time{Time: testNow.Add(-time.Hour)},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "example.io", Names: apiextensionsv1.CustomResourceDefinitionNames{Plural: "widgets", Kind: "Widget"},
			Scope:    apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{Name: "v1", Served: true, Storage: true}, {Name: "v1beta1", Served: true}, {Name: "v1alpha1", Served: false}},
			Conversion: &apiextensionsv1.CustomResourceConversion{
				Strategy: apiextensionsv1.WebhookConverter,
				Webhook: &apiextensionsv1.WebhookConversion{ClientConfig: &apiextensionsv1.WebhookClientConfig{
					Service: &apiextensionsv1.ServiceReference{Namespace: "webhooks", Name: "converter"},
				}},
			},
		},
	}
}

func toUnstructured(t *testing.T, object any) *unstructured.Unstructured {
	t.Helper()
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		t.Fatalf("convert %T to unstructured: %v", object, err)
	}
	return &unstructured.Unstructured{Object: content}
}

func readyEndpointSlices(namespace, service string) []discoveryv1.EndpointSlice {
	ready := true
	return []discoveryv1.EndpointSlice{{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Labels: map[string]string{discoveryv1.LabelServiceName: service}},
		Endpoints:  []discoveryv1.Endpoint{{Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
	}}
}

func withOperations(rule admissionv1.RuleWithOperations, operations ...admissionv1.OperationType) admissionv1.RuleWithOperations {
	rule.Operations = operations
	return rule
}

func withGroups(rule admissionv1.RuleWithOperations, groups ...string) admissionv1.RuleWithOperations {
	rule.APIGroups = groups
	return rule
}

func withVersions(rule admissionv1.RuleWithOperations, versions ...string) admissionv1.RuleWithOperations {
	rule.APIVersions = versions
	return rule
}

func withResources(rule admissionv1.RuleWithOperations, resources ...string) admissionv1.RuleWithOperations {
	rule.Resources = resources
	return rule
}

func withScope(rule admissionv1.RuleWithOperations, scope admissionv1.ScopeType) admissionv1.RuleWithOperations {
	rule.Scope = &scope
	return rule
}

func stringPointer(value string) *string { return &value }

func ownerRef(kind string) safetyv1alpha1.ControllerReference {
	return safetyv1alpha1.ControllerReference{APIVersion: "apps/v1", Kind: kind, Namespace: "operators", Name: "controller"}
}

func assertFindingTypeCount(t *testing.T, findings []safetyv1alpha1.Finding, findingType safetyv1alpha1.FindingType, want int) {
	t.Helper()
	got := 0
	for _, finding := range findings {
		if finding.Type == findingType {
			got++
		}
	}
	if got != want {
		t.Errorf("finding type %s count = %d, want %d; findings: %#v", findingType, got, want, findings)
	}
}

func assertFindingTypeAtLeast(t *testing.T, findings []safetyv1alpha1.Finding, findingType safetyv1alpha1.FindingType, want int) {
	t.Helper()
	got := 0
	for _, finding := range findings {
		if finding.Type == findingType {
			got++
		}
	}
	if got < want {
		t.Errorf("finding type %s count = %d, want at least %d; findings: %#v", findingType, got, want, findings)
	}
}

func hasTruncatedFinding(findings []safetyv1alpha1.Finding) bool {
	for _, finding := range findings {
		if finding.Truncated {
			return true
		}
	}
	return false
}

func assertAction(t *testing.T, actions []safetyv1alpha1.RemediationAction, actionType safetyv1alpha1.RemediationActionType, uid string, risk safetyv1alpha1.RiskLevel, eligible bool) {
	t.Helper()
	for _, action := range actions {
		if action.Type == actionType && string(action.Target.UID) == uid {
			if action.Risk != risk || action.Eligible != eligible {
				t.Errorf("action = %#v, want risk %s eligible %v", action, risk, eligible)
			}
			return
		}
	}
	t.Errorf("action %s for UID %s not found in %#v", actionType, uid, actions)
}

func hasActionType(actions []safetyv1alpha1.RemediationAction, actionType safetyv1alpha1.RemediationActionType) bool {
	for _, action := range actions {
		if action.Type == actionType {
			return true
		}
	}
	return false
}

func TestCollectorCompactsPersistedEvidenceOverflow(t *testing.T) {
	collector := newCollector(nil)
	for i := 0; i < maxPersistedFindings+100; i++ {
		collector.addFinding(safetyv1alpha1.Finding{Type: safetyv1alpha1.FindingUnknown, Message: fmt.Sprintf("evidence-%04d", i)})
	}
	findings, actions, overflow := collector.sorted()
	if !overflow {
		t.Fatal("collector did not report persisted evidence overflow")
	}
	if len(findings) > maxPersistedFindings+1 || len(actions) != 0 {
		t.Fatalf("bounded output sizes = findings %d actions %d", len(findings), len(actions))
	}
	if !slices.ContainsFunc(findings, func(finding safetyv1alpha1.Finding) bool {
		return finding.Truncated && finding.Count != nil && *finding.Count == 100
	}) {
		t.Fatalf("overflow summary missing from findings: %#v", findings)
	}
}

func assertSortedIDs(t *testing.T, result Result) {
	t.Helper()
	findingIDs := make([]string, len(result.Findings))
	for i := range result.Findings {
		findingIDs[i] = result.Findings[i].ID
	}
	actionIDs := make([]string, len(result.Actions))
	for i := range result.Actions {
		actionIDs[i] = result.Actions[i].ID
	}
	if !sort.StringsAreSorted(findingIDs) || !sort.StringsAreSorted(actionIDs) {
		t.Errorf("IDs are not sorted: findings=%v actions=%v", findingIDs, actionIDs)
	}
}
