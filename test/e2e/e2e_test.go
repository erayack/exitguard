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

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	operatorNamespace = "exitguard-system"
	testNamespace     = "exitguard-e2e"
	policyName        = "e2e"
	ordinaryFinalizer = "e2e.safety.exitguard.io/cleanup"
	blockedFinalizer  = "e2e.safety.exitguard.io/not-allowlisted"
)

var (
	policyGVR   = schema.GroupVersionResource{Group: "safety.exitguard.io", Version: "v1alpha1", Resource: "terminationpolicies"}
	incidentGVR = schema.GroupVersionResource{Group: "safety.exitguard.io", Version: "v1alpha1", Resource: "deletionincidents"}
	approvalGVR = schema.GroupVersionResource{Group: "safety.exitguard.io", Version: "v1alpha1", Resource: "remediationapprovals"}
)

//revive:disable:context-as-argument E2E helpers keep testing.T first for conventional test failure reporting.
type environment struct {
	kube    kubernetes.Interface
	dynamic dynamic.Interface
	ext     apiextensionsclient.Interface
}

func TestKind(t *testing.T) {
	phase := os.Getenv("E2E_PHASE")
	if phase == "" {
		t.Skip("set E2E_PHASE through hack/kind-e2e.sh")
	}
	env := newEnvironment(t)
	t.Run("RBACSeparation", func(t *testing.T) { testRBACSeparation(t, env, phase) })
	if phase != "remediation" {
		return
	}

	ctx := context.Background()
	preparePolicy(t, ctx, env)
	t.Run("HealthyDeletion", func(t *testing.T) { testHealthyDeletion(t, ctx, env) })
	t.Run("IncidentDryRunRealAndReplay", func(t *testing.T) { testApprovalLifecycle(t, ctx, env) })
	t.Run("UnavailableWebhookAudit", func(t *testing.T) { testUnavailableWebhook(t, ctx, env) })
	t.Run("NamespaceRemainingResourceAPIServiceAndFinalize", func(t *testing.T) { testNamespaceFinalize(t, ctx, env) })
	t.Run("TerminatingCRD", func(t *testing.T) { testTerminatingCRD(t, ctx, env) })
	t.Run("RiskAndAllowlist", func(t *testing.T) { testRiskAllowlist(t, ctx, env) })
	t.Run("RecreatedUID", func(t *testing.T) { testRecreatedUID(t, ctx, env) })
}

func newEnvironment(t *testing.T) *environment {
	t.Helper()
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		t.Fatalf("load kubeconfig: %v", err)
	}
	config.QPS, config.Burst = 50, 100
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("create Kubernetes client: %v", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatalf("create dynamic client: %v", err)
	}
	ext, err := apiextensionsclient.NewForConfig(config)
	if err != nil {
		t.Fatalf("create API extensions client: %v", err)
	}
	return &environment{kube: kube, dynamic: dynamicClient, ext: ext}
}

func testRBACSeparation(t *testing.T, env *environment, phase string) {
	ctx := context.Background()
	scanner := "system:serviceaccount:" + operatorNamespace + ":exitguard-scanner"
	executor := "system:serviceaccount:" + operatorNamespace + ":exitguard-executor"
	assertAccess(t, ctx, env, scanner, authorizationv1.ResourceAttributes{Verb: "list", Resource: "configmaps"}, true)
	assertAccess(t, ctx, env, scanner, authorizationv1.ResourceAttributes{Verb: "patch", Resource: "configmaps"}, false)
	assertAccess(t, ctx, env, scanner, authorizationv1.ResourceAttributes{Verb: "update", Resource: "namespaces", Subresource: "finalize"}, false)
	assertAccess(t, ctx, env, scanner, authorizationv1.ResourceAttributes{Verb: "patch", Group: "safety.exitguard.io", Resource: "remediationapprovals", Subresource: "status"}, false)

	wantExecutor := phase == "remediation"
	assertAccess(t, ctx, env, executor, authorizationv1.ResourceAttributes{Verb: "patch", Resource: "configmaps"}, wantExecutor)
	assertAccess(t, ctx, env, executor, authorizationv1.ResourceAttributes{Verb: "list", Resource: "configmaps"}, false)
	assertAccess(t, ctx, env, executor, authorizationv1.ResourceAttributes{Verb: "delete", Resource: "configmaps"}, false)
	assertAccess(t, ctx, env, executor, authorizationv1.ResourceAttributes{Verb: "patch", Group: "apiregistration.k8s.io", Resource: "apiservices"}, false)
	assertAccess(t, ctx, env, executor, authorizationv1.ResourceAttributes{Verb: "patch", Group: "admissionregistration.k8s.io", Resource: "validatingwebhookconfigurations"}, false)
	assertAccess(t, ctx, env, executor, authorizationv1.ResourceAttributes{Verb: "patch", Group: "safety.exitguard.io", Resource: "terminationpolicies", Subresource: "status"}, false)
	assertAccess(t, ctx, env, executor, authorizationv1.ResourceAttributes{Verb: "patch", Group: "safety.exitguard.io", Resource: "deletionincidents", Subresource: "status"}, false)
	assertAccess(t, ctx, env, executor, authorizationv1.ResourceAttributes{Verb: "update", Resource: "namespaces", Subresource: "finalize"}, wantExecutor)
}

func assertAccess(t *testing.T, ctx context.Context, env *environment, user string, attributes authorizationv1.ResourceAttributes, want bool) {
	t.Helper()
	review, err := env.kube.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: user, ResourceAttributes: &attributes}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("subject access review %s %s: %v", attributes.Verb, attributes.Resource, err)
	}
	if review.Status.Allowed != want {
		t.Fatalf("%s %s %s/%s allowed=%t, want %t: %s", user, attributes.Verb, attributes.Resource, attributes.Subresource, review.Status.Allowed, want, review.Status.Reason)
	}
}

func preparePolicy(t *testing.T, ctx context.Context, env *environment) {
	t.Helper()
	_, _ = env.kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace, Labels: map[string]string{"safety.exitguard.io/e2e": "true"}}}, metav1.CreateOptions{})
	policy := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "safety.exitguard.io/v1alpha1", "kind": "TerminationPolicy",
		"metadata": map[string]interface{}{"name": policyName},
		"spec": map[string]interface{}{
			"priority": int64(100), "terminationAge": "1s",
			"targetRules": []interface{}{map[string]interface{}{"apiGroups": []interface{}{"*"}, "resources": []interface{}{"*"}, "excludedNamespaces": []interface{}{"kube-system", "kube-public", "kube-node-lease", operatorNamespace}}},
			"diagnosis":   map[string]interface{}{"checkAPIServices": true, "checkWebhooks": true, "maxNamespaceObjects": int64(5000), "maxCRDInstances": int64(1)},
			"remediation": map[string]interface{}{"maxRisk": "Critical", "allowedFinalizers": []interface{}{ordinaryFinalizer, apiextensionsv1.CustomResourceCleanupFinalizer}, "allowNamespaceForce": true, "approvalTTL": "10m"},
			"retention":   map[string]interface{}{"resolvedIncidentTTL": "1h"},
		},
	}}
	if _, err := env.dynamic.Resource(policyGVR).Create(ctx, policy, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create e2e policy: %v", err)
	}
	waitFor(t, "policy ready", 90*time.Second, func() (bool, error) {
		current, err := env.dynamic.Resource(policyGVR).Get(ctx, policyName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		conditions, _, _ := unstructured.NestedSlice(current.Object, "status", "conditions")
		for _, item := range conditions {
			condition := item.(map[string]interface{})
			if condition["type"] == "Ready" && condition["status"] == "True" {
				return true, nil
			}
		}
		return false, nil
	})
}

func testHealthyDeletion(t *testing.T, ctx context.Context, env *environment) {
	cm, err := env.kube.CoreV1().ConfigMaps(testNamespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "healthy"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.kube.CoreV1().ConfigMaps(testNamespace).Delete(ctx, cm.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitGone(t, "healthy configmap", func() error {
		_, err := env.kube.CoreV1().ConfigMaps(testNamespace).Get(ctx, cm.Name, metav1.GetOptions{})
		return err
	})
	incidents, err := env.dynamic.Resource(incidentGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, incident := range incidents.Items {
		uid, _, _ := unstructured.NestedString(incident.Object, "spec", "target", "uid")
		if uid == string(cm.UID) {
			t.Fatal("healthy deletion unexpectedly produced an incident")
		}
	}
}

func testApprovalLifecycle(t *testing.T, ctx context.Context, env *environment) {
	target := deletingConfigMap(t, ctx, env, "approval-lifecycle", ordinaryFinalizer)
	incident := waitIncident(t, ctx, env, target.UID, "BlockingFinalizer")
	actionID := actionID(t, incident, "RemoveResourceFinalizer")

	dry := createApproval(t, ctx, env, incident, actionID, true, "dry-run validation")
	dry = waitApproval(t, ctx, env, dry.GetName(), "DryRunSucceeded")
	if result, _, _ := unstructured.NestedString(dry.Object, "status", "result"); result != "DryRunValidated" {
		t.Fatalf("dry-run result=%q", result)
	}
	current, err := env.kube.CoreV1().ConfigMaps(testNamespace).Get(ctx, target.Name, metav1.GetOptions{})
	if err != nil || !contains(current.Finalizers, ordinaryFinalizer) {
		t.Fatalf("dry-run mutated target: %v", err)
	}

	persisted := createApproval(t, ctx, env, incident, actionID, false, "approved finalizer removal")
	waitApproval(t, ctx, env, persisted.GetName(), "Succeeded")
	replay := createApproval(t, ctx, env, incident, actionID, false, "idempotency replay")
	replay = waitApproval(t, ctx, env, replay.GetName(), "Succeeded")
	if result, _, _ := unstructured.NestedString(replay.Object, "status", "result"); result != "AlreadySatisfied" {
		t.Fatalf("replay result=%q, want AlreadySatisfied", result)
	}
}

func testUnavailableWebhook(t *testing.T, ctx context.Context, env *environment) {
	target := deletingConfigMap(t, ctx, env, "webhook-blocked", ordinaryFinalizer)
	failure := admissionv1.Fail
	sideEffects := admissionv1.SideEffectClassNone
	timeout := int32(2)
	webhook := &admissionv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "exitguard-e2e-unavailable"}, Webhooks: []admissionv1.ValidatingWebhook{{
		Name:          "unavailable.e2e.safety.exitguard.io",
		ClientConfig:  admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: testNamespace, Name: "missing-webhook", Path: stringPtr("/validate")}, CABundle: []byte("invalid")},
		Rules:         []admissionv1.RuleWithOperations{{Operations: []admissionv1.OperationType{admissionv1.Update}, Rule: admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"configmaps"}}}},
		FailurePolicy: &failure, SideEffects: &sideEffects, AdmissionReviewVersions: []string{"v1"}, TimeoutSeconds: &timeout,
	}}}
	if _, err := env.kube.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, webhook, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = env.kube.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(ctx, webhook.Name, metav1.DeleteOptions{})
	}()

	incident := waitIncident(t, ctx, env, target.UID, "BlockingWebhook")
	approval := createApproval(t, ctx, env, incident, actionID(t, incident, "RemoveResourceFinalizer"), false, "expected fail-closed webhook audit")
	approval = waitApproval(t, ctx, env, approval.GetName(), "Failed")
	if result, _, _ := unstructured.NestedString(approval.Object, "status", "result"); result != "APIError" {
		t.Fatalf("webhook-blocked result=%q", result)
	}
	attempts, _, _ := unstructured.NestedSlice(approval.Object, "status", "attempts")
	if len(attempts) == 0 {
		t.Fatal("failed webhook mutation has no audit attempt")
	}
}

func testNamespaceFinalize(t *testing.T, ctx context.Context, env *environment) {
	const namespace = "exitguard-e2e-stuck"
	_, err := env.kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: map[string]string{"safety.exitguard.io/e2e": "true"}}}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	cm, err := env.kube.CoreV1().ConfigMaps(namespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "remaining", Finalizers: []string{ordinaryFinalizer}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	apiService := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "apiregistration.k8s.io/v1", "kind": "APIService", "metadata": map[string]interface{}{"name": "v1alpha1.unavailable.e2e.safety.exitguard.io"},
		"spec": map[string]interface{}{"group": "unavailable.e2e.safety.exitguard.io", "version": "v1alpha1", "groupPriorityMinimum": int64(1000), "versionPriority": int64(15), "service": map[string]interface{}{"namespace": namespace, "name": "missing-api"}, "insecureSkipTLSVerify": true},
	}}
	apiServiceGVR := schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"}
	if _, err := env.dynamic.Resource(apiServiceGVR).Create(ctx, apiService, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = env.dynamic.Resource(apiServiceGVR).Delete(ctx, apiService.GetName(), metav1.DeleteOptions{})
	}()
	if err := env.kube.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	ns, err := env.kube.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	incident := waitIncident(t, ctx, env, ns.UID, "RemainingResource")
	assertFinding(t, incident, "UnavailableAPIService")
	action := actionID(t, incident, "ForceFinalizeNamespace")

	dryCandidate := ns.DeepCopy()
	dryCandidate.Spec.Finalizers = nil
	if _, err := env.kube.CoreV1().Namespaces().Finalize(ctx, dryCandidate, metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
		t.Fatalf("namespace finalize dry-run capability is required on this supported version: %v", err)
	}
	if current, err := env.kube.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{}); err != nil || len(current.Spec.Finalizers) == 0 {
		t.Fatalf("namespace finalize dry-run persisted a mutation: %v", err)
	}

	approval := createApproval(t, ctx, env, incident, action, false, "critical namespace force-finalization")
	waitApproval(t, ctx, env, approval.GetName(), "Succeeded")
	waitGone(t, "force-finalized namespace", func() error {
		_, err := env.kube.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
		return err
	})
	_ = cm // Never log arbitrary object bodies; identity is enough for the remaining-resource assertion.
}

func testTerminatingCRD(t *testing.T, ctx context.Context, env *environment) {
	const (
		crdName   = "gadgets.e2e.safety.exitguard.io"
		namespace = "exitguard-e2e-crd"
	)
	_, _ = env.kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: map[string]string{"safety.exitguard.io/e2e": "true"}}}, metav1.CreateOptions{})
	crd := fixtureCRD(crdName, "e2e.safety.exitguard.io", "gadgets", "Gadget")
	created, err := env.ext.ApiextensionsV1().CustomResourceDefinitions().Create(ctx, crd, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	waitCRDEstablished(t, ctx, env, crdName)
	gvr := schema.GroupVersionResource{Group: crd.Spec.Group, Version: "v1alpha1", Resource: crd.Spec.Names.Plural}
	for _, name := range []string{"remaining-one", "remaining-two"} {
		instance := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": crd.Spec.Group + "/v1alpha1", "kind": crd.Spec.Names.Kind, "metadata": map[string]interface{}{"name": name, "namespace": namespace, "finalizers": []interface{}{ordinaryFinalizer}}, "spec": map[string]interface{}{}}}
		if _, err := env.dynamic.Resource(gvr).Namespace(namespace).Create(ctx, instance, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := env.ext.ApiextensionsV1().CustomResourceDefinitions().Delete(ctx, crdName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	incident := waitIncident(t, ctx, env, created.UID, "RemainingResource")
	if got := incidentConditionStatus(incident, "DiagnosisComplete"); got != "False" {
		t.Fatalf("over-limit CRD diagnosis condition = %q, want False", got)
	}
	if !hasTruncatedFinding(incident, "RemainingResource") {
		t.Fatalf("over-limit CRD incident has no truncated finding: %#v", incident.Object)
	}
	if hasRecommendedAction(incident, "RemoveCRDFinalizer") {
		t.Fatalf("over-limit CRD diagnosis published a cleanup action: %#v", incident.Object)
	}

	policy, err := env.dynamic.Resource(policyGVR).Get(ctx, policyName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedField(policy.Object, int64(10), "spec", "diagnosis", "maxCRDInstances"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.dynamic.Resource(policyGVR).Update(ctx, policy, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "complete CRD diagnosis after raising maxCRDInstances", 120*time.Second, func() (bool, error) {
		current, err := env.dynamic.Resource(incidentGVR).Get(ctx, incident.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if incidentConditionStatus(current, "DiagnosisComplete") != "True" || !hasRecommendedAction(current, "RemoveCRDFinalizer") {
			return false, nil
		}
		incident = current
		return true, nil
	})
	_ = actionID(t, incident, "RemoveCRDFinalizer")
}

func testRiskAllowlist(t *testing.T, ctx context.Context, env *environment) {
	target := deletingConfigMap(t, ctx, env, "not-allowlisted", blockedFinalizer)
	incident := waitIncident(t, ctx, env, target.UID, "BlockingFinalizer")
	approval := createApproval(t, ctx, env, incident, actionID(t, incident, "RemoveResourceFinalizer"), false, "verify exact allowlist rejection")
	approval = waitApproval(t, ctx, env, approval.GetName(), "Failed")
	if result, _, _ := unstructured.NestedString(approval.Object, "status", "result"); result != "RejectedByPolicy" {
		t.Fatalf("allowlist rejection result=%q", result)
	}
}

func testRecreatedUID(t *testing.T, ctx context.Context, env *environment) {
	target := deletingConfigMap(t, ctx, env, "recreated-uid", ordinaryFinalizer)
	incident := waitIncident(t, ctx, env, target.UID, "BlockingFinalizer")
	action := actionID(t, incident, "RemoveResourceFinalizer")
	current, err := env.kube.CoreV1().ConfigMaps(testNamespace).Get(ctx, target.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	current.Finalizers = nil
	if _, err := env.kube.CoreV1().ConfigMaps(testNamespace).Update(ctx, current, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitGone(t, "old target UID", func() error {
		_, err := env.kube.CoreV1().ConfigMaps(testNamespace).Get(ctx, target.Name, metav1.GetOptions{})
		return err
	})
	recreated, err := env.kube.CoreV1().ConfigMaps(testNamespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: target.Name, Finalizers: []string{ordinaryFinalizer}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if recreated.UID == target.UID {
		t.Fatal("recreated target unexpectedly retained UID")
	}
	approval := createApproval(t, ctx, env, incident, action, false, "verify stale UID protection")
	approval = waitApproval(t, ctx, env, approval.GetName(), "Superseded")
	if result, _, _ := unstructured.NestedString(approval.Object, "status", "result"); result != "TargetReplaced" {
		t.Fatalf("recreated UID result=%q", result)
	}
}

func deletingConfigMap(t *testing.T, ctx context.Context, env *environment, name, finalizer string) *corev1.ConfigMap {
	t.Helper()
	created, err := env.kube.CoreV1().ConfigMaps(testNamespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Finalizers: []string{finalizer}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.kube.CoreV1().ConfigMaps(testNamespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	return created
}

func waitIncident(t *testing.T, ctx context.Context, env *environment, uid types.UID, finding string) *unstructured.Unstructured {
	t.Helper()
	var matched *unstructured.Unstructured
	waitFor(t, "incident for target UID", 120*time.Second, func() (bool, error) {
		list, err := env.dynamic.Resource(incidentGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		for i := range list.Items {
			candidate := &list.Items[i]
			targetUID, _, _ := unstructured.NestedString(candidate.Object, "spec", "target", "uid")
			if targetUID == string(uid) && hasFinding(candidate, finding) {
				matched = candidate.DeepCopy()
				return true, nil
			}
		}
		return false, nil
	})
	return matched
}

func actionID(t *testing.T, incident *unstructured.Unstructured, actionType string) string {
	t.Helper()
	actions, _, _ := unstructured.NestedSlice(incident.Object, "status", "recommendedActions")
	for _, item := range actions {
		action := item.(map[string]interface{})
		if action["type"] == actionType {
			return action["id"].(string)
		}
	}
	t.Fatalf("incident %s has no %s action", incident.GetName(), actionType)
	return ""
}

func createApproval(t *testing.T, ctx context.Context, env *environment, incident *unstructured.Unstructured, actionID string, dryRun bool, reason string) *unstructured.Unstructured {
	t.Helper()
	name := fmt.Sprintf("e2e-%d", time.Now().UnixNano())
	approval := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "safety.exitguard.io/v1alpha1", "kind": "RemediationApproval", "metadata": map[string]interface{}{"name": name},
		"spec": map[string]interface{}{"incidentRef": map[string]interface{}{"name": incident.GetName(), "uid": string(incident.GetUID())}, "actionID": actionID, "dryRun": dryRun, "reason": reason},
	}}
	created, err := env.dynamic.Resource(approvalGVR).Create(ctx, approval, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create approval: %v", err)
	}
	return created
}

func waitApproval(t *testing.T, ctx context.Context, env *environment, name, phase string) *unstructured.Unstructured {
	t.Helper()
	var approval *unstructured.Unstructured
	waitFor(t, "approval "+name+" phase "+phase, 90*time.Second, func() (bool, error) {
		current, err := env.dynamic.Resource(approvalGVR).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		currentPhase, _, _ := unstructured.NestedString(current.Object, "status", "phase")
		if currentPhase == phase {
			approval = current
			return true, nil
		}
		if currentPhase == "Failed" || currentPhase == "Expired" || currentPhase == "Superseded" || currentPhase == "Succeeded" || currentPhase == "DryRunSucceeded" {
			return false, fmt.Errorf("approval reached terminal phase %s while waiting for %s", currentPhase, phase)
		}
		return false, nil
	})
	return approval
}

func assertFinding(t *testing.T, incident *unstructured.Unstructured, finding string) {
	t.Helper()
	if !hasFinding(incident, finding) {
		t.Fatalf("incident %s has no %s finding", incident.GetName(), finding)
	}
}

func hasFinding(incident *unstructured.Unstructured, finding string) bool {
	findings, _, _ := unstructured.NestedSlice(incident.Object, "status", "findings")
	for _, item := range findings {
		if item.(map[string]interface{})["type"] == finding {
			return true
		}
	}
	return false
}

func hasTruncatedFinding(incident *unstructured.Unstructured, finding string) bool {
	findings, _, _ := unstructured.NestedSlice(incident.Object, "status", "findings")
	for _, item := range findings {
		entry := item.(map[string]interface{})
		if entry["type"] == finding && entry["truncated"] == true {
			return true
		}
	}
	return false
}

func hasRecommendedAction(incident *unstructured.Unstructured, actionType string) bool {
	actions, _, _ := unstructured.NestedSlice(incident.Object, "status", "recommendedActions")
	for _, item := range actions {
		if item.(map[string]interface{})["type"] == actionType {
			return true
		}
	}
	return false
}

func incidentConditionStatus(incident *unstructured.Unstructured, conditionType string) string {
	conditions, _, _ := unstructured.NestedSlice(incident.Object, "status", "conditions")
	for _, item := range conditions {
		condition := item.(map[string]interface{})
		if condition["type"] == conditionType {
			status, _ := condition["status"].(string)
			return status
		}
	}
	return ""
}

func fixtureCRD(name, group, plural, kind string) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: apiextensionsv1.CustomResourceDefinitionSpec{
		Group: group, Scope: apiextensionsv1.NamespaceScoped,
		Names:    apiextensionsv1.CustomResourceDefinitionNames{Plural: plural, Singular: plural[:len(plural)-1], Kind: kind, ListKind: kind + "List"},
		Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{Name: "v1alpha1", Served: true, Storage: true, Schema: &apiextensionsv1.CustomResourceValidation{OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{Type: "object", XPreserveUnknownFields: boolPtr(true)}}}},
	}}
}

func waitCRDEstablished(t *testing.T, ctx context.Context, env *environment, name string) {
	t.Helper()
	waitFor(t, "CRD established", 60*time.Second, func() (bool, error) {
		crd, err := env.ext.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, condition := range crd.Status.Conditions {
			if condition.Type == apiextensionsv1.Established && condition.Status == apiextensionsv1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
}

func waitGone(t *testing.T, description string, get func() error) {
	t.Helper()
	waitFor(t, description, 60*time.Second, func() (bool, error) {
		err := get()
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
}

func waitFor(t *testing.T, description string, timeout time.Duration, condition wait.ConditionFunc) {
	t.Helper()
	err := wait.PollUntilContextTimeout(context.Background(), 500*time.Millisecond, timeout, true, func(context.Context) (bool, error) {
		return condition()
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timed out waiting for %s", description)
		}
		t.Fatalf("wait for %s: %v", description, err)
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func stringPtr(value string) *string { return &value }
func boolPtr(value bool) *bool       { return &value }
