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

package policy

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
)

func TestCompileMatchesSelectorsScopeAndExactMappings(t *testing.T) {
	catalog := testCatalog(t)
	policy := validPolicy("selectors", 3, safetyv1alpha1.TargetRule{
		APIGroups:          []string{""},
		Resources:          []string{"pods", "namespaces"},
		NamespaceSelector:  &metav1.LabelSelector{MatchLabels: map[string]string{"environment": "prod"}},
		ObjectSelector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
		ExcludedNamespaces: []string{"blocked"},
	})
	policy.Spec.FinalizerOwners = []safetyv1alpha1.FinalizerOwner{{
		Finalizer: "widgets.example.io/cleanup",
		ControllerRef: safetyv1alpha1.ControllerReference{
			APIVersion: "apps/v1", Kind: "Deployment", Namespace: "operators", Name: "widget-controller",
		},
	}}
	compiled, status := Compile(policy, catalog, time.Unix(100, 0))
	if !compiled.Ready() {
		t.Fatalf("compiled policy is not ready: %#v", status.Conditions)
	}
	if status.ObservedGeneration != policy.Generation || status.ResolvedResourceCount != 2 {
		t.Errorf("status = %#v, want generation %d and two resources", status, policy.Generation)
	}
	if got := compiled.Settings().Diagnosis.MaxCRDInstances; got != 5000 {
		t.Errorf("max CRD instances = %d, want 5000", got)
	}
	assertCondition(t, status, ConditionReady, metav1.ConditionTrue)
	assertCondition(t, status, ConditionDiscoveryResolved, metav1.ConditionTrue)
	assertCondition(t, status, ConditionSelectorsValid, metav1.ConditionTrue)

	pods := Target{
		GroupResource:   schema.GroupResource{Resource: "pods"},
		Namespaced:      true,
		Namespace:       "workloads",
		Labels:          map[string]string{"app": "api"},
		NamespaceLabels: map[string]string{"environment": "prod"},
	}
	if !compiled.Match(pods) {
		t.Error("matching namespaced pod was not selected")
	}
	pods.Namespace = "blocked"
	if compiled.Match(pods) {
		t.Error("excluded namespace was selected")
	}
	pods.Namespace = "workloads"
	pods.NamespaceLabels["environment"] = "dev"
	if compiled.Match(pods) {
		t.Error("namespace selector mismatch was selected")
	}

	clusterTarget := Target{
		GroupResource: schema.GroupResource{Resource: "namespaces"},
		Namespaced:    false,
		Labels:        map[string]string{"app": "api"},
	}
	if !compiled.Match(clusterTarget) {
		t.Error("namespace selector should not exclude a cluster-scoped target")
	}
	clusterTarget.Namespaced = true
	if compiled.Match(clusterTarget) {
		t.Error("target with incorrect scope was selected")
	}

	owner, found := compiled.FinalizerOwner("widgets.example.io/cleanup")
	if !found || owner.Name != "widget-controller" {
		t.Errorf("finalizer owner = (%#v, %v), want explicit mapping", owner, found)
	}
	if _, found := compiled.FinalizerOwner("example.io/cleanup"); found {
		t.Error("unmapped finalizer received an inferred owner")
	}

	policy.Spec.FinalizerOwners[0].ControllerRef.Name = "mutated"
	owner, _ = compiled.FinalizerOwner("widgets.example.io/cleanup")
	if owner.Name != "widget-controller" {
		t.Error("compiled owner changed after source mutation")
	}
}

func TestWildcardExcludesHighChurnButExplicitRuleSelectsIt(t *testing.T) {
	catalog := testCatalog(t)
	wildcard, wildcardStatus := Compile(validPolicy("wildcard", 0, safetyv1alpha1.TargetRule{
		APIGroups: []string{"*"}, Resources: []string{"*"},
	}), catalog, time.Now())
	if !wildcard.Ready() {
		t.Fatalf("wildcard policy is not ready: %#v", wildcardStatus.Conditions)
	}
	for _, target := range []Target{
		{GroupResource: schema.GroupResource{Resource: "events"}, Namespaced: true},
		{GroupResource: schema.GroupResource{Group: "events.k8s.io", Resource: "events"}, Namespaced: true},
		{GroupResource: schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, Namespaced: true},
	} {
		if wildcard.Match(target) {
			t.Errorf("wildcard selected high-churn resource %s", target.GroupResource)
		}
	}
	if !wildcard.Match(Target{GroupResource: schema.GroupResource{Resource: "pods"}, Namespaced: true}) {
		t.Error("wildcard did not select ordinary resource")
	}

	explicit, status := Compile(validPolicy("events", 0, safetyv1alpha1.TargetRule{
		APIGroups: []string{"events.k8s.io"}, Resources: []string{"events"},
	}), catalog, time.Now())
	if !explicit.Ready() {
		t.Fatalf("explicit policy is not ready: %#v", status.Conditions)
	}
	if !explicit.Match(Target{GroupResource: schema.GroupResource{Group: "events.k8s.io", Resource: "events"}, Namespaced: true}) {
		t.Error("explicit policy did not select Events")
	}
}

func TestInvalidSelectorsAndUnresolvedResourcesAreIgnored(t *testing.T) {
	catalog := testCatalog(t)
	tests := []struct {
		name      string
		rule      safetyv1alpha1.TargetRule
		condition string
	}{
		{
			name: "selector",
			rule: safetyv1alpha1.TargetRule{
				APIGroups: []string{""}, Resources: []string{"pods"},
				ObjectSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key: "app", Operator: metav1.LabelSelectorOperator("Invalid"), Values: []string{"api"},
				}}},
			},
			condition: ConditionSelectorsValid,
		},
		{
			name:      "resource",
			rule:      safetyv1alpha1.TargetRule{APIGroups: []string{"missing.example.io"}, Resources: []string{"widgets"}},
			condition: ConditionDiscoveryResolved,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compiled, status := Compile(validPolicy(test.name, 0, test.rule), catalog, time.Now())
			if compiled.Ready() || compiled.Match(Target{GroupResource: schema.GroupResource{Resource: "pods"}, Namespaced: true}) {
				t.Error("invalid policy participated in matching")
			}
			assertCondition(t, status, test.condition, metav1.ConditionFalse)
			assertCondition(t, status, ConditionReady, metav1.ConditionFalse)
		})
	}
}

// Regression: accepted policies with many unresolved selections used to produce
// status conditions exceeding metav1.Condition's 32,768-character API limit,
// so the scanner could not persist the policy's failure status.
func TestCompileBoundsConditionMessagesForPublicAPI(t *testing.T) {
	const (
		ruleCount                = 1500
		conditionMessageAPILimit = 32_768
	)

	source := validPolicy("many-unresolved", 0, safetyv1alpha1.TargetRule{})
	source.Spec.TargetRules = make([]safetyv1alpha1.TargetRule, ruleCount)
	for index := range source.Spec.TargetRules {
		source.Spec.TargetRules[index] = safetyv1alpha1.TargetRule{
			APIGroups: []string{fmt.Sprintf("missing-%04d.example.io", index)},
			Resources: []string{"widgets"},
		}
	}

	_, status := Compile(source, testCatalog(t), time.Now())
	for _, condition := range status.Conditions {
		if got := len([]rune(condition.Message)); got > conditionMessageAPILimit {
			t.Errorf("condition %s message has %d characters, exceeds public API limit %d", condition.Type, got, conditionMessageAPILimit)
		}
	}
}

func TestSelectWinningUsesPriorityThenLexicographicName(t *testing.T) {
	catalog := testCatalog(t)
	target := Target{GroupResource: schema.GroupResource{Resource: "pods"}, Namespaced: true}
	compile := func(name string, priority int32) *CompiledPolicy {
		result, _ := Compile(validPolicy(name, priority, safetyv1alpha1.TargetRule{
			APIGroups: []string{""}, Resources: []string{"pods"},
		}), catalog, time.Now())
		return result
	}
	low := compile("aardvark", 1)
	highZ := compile("zebra", 2)
	highA := compile("alpha", 2)
	if winner := SelectWinning([]*CompiledPolicy{low, highZ, highA}, target); winner != highA {
		t.Errorf("winner = %v, want alpha at highest priority", winner.Name())
	}
}

func TestRiskOrderingAndRemediationLimits(t *testing.T) {
	tests := []struct {
		name      string
		action    safetyv1alpha1.RemediationActionType
		finalizer string
		want      safetyv1alpha1.RiskLevel
	}{
		{name: "ordinary", action: safetyv1alpha1.ActionRemoveResourceFinalizer, finalizer: "example.io/cleanup", want: safetyv1alpha1.RiskMedium},
		{name: "foreground", action: safetyv1alpha1.ActionRemoveResourceFinalizer, finalizer: metav1.FinalizerDeleteDependents, want: safetyv1alpha1.RiskHigh},
		{name: "pv protection", action: safetyv1alpha1.ActionRemoveResourceFinalizer, finalizer: "kubernetes.io/pv-protection", want: safetyv1alpha1.RiskHigh},
		{name: "crd cleanup", action: safetyv1alpha1.ActionRemoveCRDFinalizer, finalizer: apiextensionsv1.CustomResourceCleanupFinalizer, want: safetyv1alpha1.RiskHigh},
		{name: "namespace", action: safetyv1alpha1.ActionForceFinalizeNamespace, want: safetyv1alpha1.RiskCritical},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := RiskFor(test.action, test.finalizer); got != test.want {
				t.Errorf("RiskFor() = %s, want %s", got, test.want)
			}
		})
	}

	catalog := testCatalog(t)
	source := validPolicy("limits", 0, safetyv1alpha1.TargetRule{APIGroups: []string{""}, Resources: []string{"pods"}})
	source.Spec.Remediation.MaxRisk = safetyv1alpha1.RiskMedium
	source.Spec.Remediation.AllowedFinalizers = []string{"example.io/cleanup", metav1.FinalizerDeleteDependents}
	source.Spec.Remediation.AllowNamespaceForce = true
	compiled, _ := Compile(source, catalog, time.Now())
	eligibilityTests := []struct {
		name, finalizer string
		action          safetyv1alpha1.RemediationActionType
		wantAllowed     bool
		wantReason      string
	}{
		{name: "ordinary allowlisted", action: safetyv1alpha1.ActionRemoveResourceFinalizer, finalizer: "example.io/cleanup", wantAllowed: true},
		{name: "protective finalizer risk", action: safetyv1alpha1.ActionRemoveResourceFinalizer, finalizer: metav1.FinalizerDeleteDependents, wantReason: "action risk High exceeds policy maxRisk Medium"},
		{name: "not allowlisted", action: safetyv1alpha1.ActionRemoveResourceFinalizer, finalizer: "other.example.io/cleanup", wantReason: "finalizer is not in policy allowedFinalizers"},
		{name: "namespace risk", action: safetyv1alpha1.ActionForceFinalizeNamespace, wantReason: "action risk Critical exceeds policy maxRisk Medium"},
	}
	for _, test := range eligibilityTests {
		t.Run(test.name, func(t *testing.T) {
			allowed, reason := compiled.ActionEligibility(test.action, test.finalizer)
			if allowed != test.wantAllowed || reason != test.wantReason {
				t.Errorf("ActionEligibility() = (%v, %q), want (%v, %q)", allowed, reason, test.wantAllowed, test.wantReason)
			}
		})
	}
}

func TestInvalidDurationsAndLimitsRejectPolicy(t *testing.T) {
	catalog := testCatalog(t)
	source := validPolicy("invalid-config", 0, safetyv1alpha1.TargetRule{APIGroups: []string{""}, Resources: []string{"pods"}})
	source.Spec.TerminationAge.Duration = 0
	source.Spec.Remediation.ApprovalTTL.Duration = -time.Second
	source.Spec.Retention.ResolvedIncidentTTL.Duration = 0
	source.Spec.Diagnosis.MaxNamespaceObjects = 0
	source.Spec.Diagnosis.MaxCRDInstances = 0
	source.Spec.Remediation.MaxRisk = safetyv1alpha1.RiskLevel("Tiny")
	compiled, status := Compile(source, catalog, time.Now())
	if compiled.Ready() {
		t.Error("invalid runtime limits compiled as ready")
	}
	assertCondition(t, status, ConditionReady, metav1.ConditionFalse)
}

func TestMaxCRDInstancesRejectsOutOfRangeValues(t *testing.T) {
	catalog := testCatalog(t)
	for _, value := range []int32{0, 100001} {
		t.Run(fmt.Sprintf("value-%d", value), func(t *testing.T) {
			source := validPolicy("invalid-crd-limit", 0, safetyv1alpha1.TargetRule{APIGroups: []string{""}, Resources: []string{"pods"}})
			source.Spec.Diagnosis.MaxCRDInstances = value
			compiled, status := Compile(source, catalog, time.Now())
			if compiled.Ready() {
				t.Fatalf("maxCRDInstances %d compiled as ready", value)
			}
			assertCondition(t, status, ConditionReady, metav1.ConditionFalse)
		})
	}
}

func validPolicy(name string, priority int32, rule safetyv1alpha1.TargetRule) *safetyv1alpha1.TerminationPolicy {
	return &safetyv1alpha1.TerminationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name + "-uid"), Generation: 7},
		Spec: safetyv1alpha1.TerminationPolicySpec{
			Priority:       priority,
			TargetRules:    []safetyv1alpha1.TargetRule{rule},
			TerminationAge: metav1.Duration{Duration: 10 * time.Minute},
			Diagnosis: safetyv1alpha1.DiagnosisPolicy{
				CheckAPIServices: true, CheckWebhooks: true, MaxNamespaceObjects: 5000, MaxCRDInstances: 5000,
			},
			Remediation: safetyv1alpha1.RemediationPolicy{
				MaxRisk: safetyv1alpha1.RiskNone, ApprovalTTL: metav1.Duration{Duration: time.Hour},
			},
			Retention: safetyv1alpha1.RetentionPolicy{ResolvedIncidentTTL: metav1.Duration{Duration: 30 * 24 * time.Hour}},
		},
	}
}

func testCatalog(t *testing.T) catalogdiscovery.Snapshot {
	t.Helper()
	client := staticDiscovery{resources: []*metav1.APIResourceList{
		{GroupVersion: "v1", APIResources: []metav1.APIResource{
			{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get", "list"}},
			{Name: "namespaces", Kind: "Namespace", Namespaced: false, Verbs: []string{"get", "list"}},
			{Name: "events", Kind: "Event", Namespaced: true, Verbs: []string{"get", "list"}},
		}},
		{GroupVersion: "events.k8s.io/v1", APIResources: []metav1.APIResource{
			{Name: "events", Kind: "Event", Namespaced: true, Verbs: []string{"get", "list"}},
		}},
		{GroupVersion: "coordination.k8s.io/v1", APIResources: []metav1.APIResource{
			{Name: "leases", Kind: "Lease", Namespaced: true, Verbs: []string{"get", "list"}},
		}},
	}}
	catalog := catalogdiscovery.NewCatalog(client, time.Minute, logr.Discard())
	if err := catalog.Refresh(); err != nil {
		t.Fatalf("refresh test catalog: %v", err)
	}
	return catalog.Snapshot()
}

type staticDiscovery struct {
	resources []*metav1.APIResourceList
}

func (s staticDiscovery) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	return nil, s.resources, nil
}

func assertCondition(t *testing.T, status safetyv1alpha1.TerminationPolicyStatus, conditionType string, want metav1.ConditionStatus) {
	t.Helper()
	for _, condition := range status.Conditions {
		if condition.Type == conditionType {
			if condition.Status != want {
				t.Errorf("condition %s = %s (%s), want %s", conditionType, condition.Status, condition.Message, want)
			}
			return
		}
	}
	t.Errorf("condition %s not found", conditionType)
}
