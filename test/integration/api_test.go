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

//go:build integration

package integration

import (
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
)

func TestCRDValidationAndDefaults(t *testing.T) {
	t.Run("policy defaults", func(t *testing.T) {
		ctx := boundedContext(t)
		name := fixtureName(t, "defaults")
		policy := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": safetyv1alpha1.GroupVersion.String(),
			"kind":       "TerminationPolicy",
			"metadata": map[string]any{
				"name": name,
			},
			"spec": map[string]any{
				"targetRules": []any{map[string]any{
					"apiGroups": []any{""},
					"resources": []any{"namespaces"},
				}},
			},
		}}
		if err := suite.client.Create(ctx, policy); err != nil {
			t.Fatalf("create minimal policy: %v", err)
		}

		got := &unstructured.Unstructured{}
		got.SetGroupVersionKind(safetyv1alpha1.GroupVersion.WithKind("TerminationPolicy"))
		if err := suite.client.Get(ctx, ctrlclient.ObjectKey{Name: name}, got); err != nil {
			t.Fatalf("get defaulted policy: %v", err)
		}
		assertNestedValue(t, got.Object, int64(0), "spec", "priority")
		assertNestedValue(t, got.Object, "10m", "spec", "terminationAge")
		assertNestedValue(t, got.Object, true, "spec", "diagnosis", "checkAPIServices")
		assertNestedValue(t, got.Object, true, "spec", "diagnosis", "checkWebhooks")
		assertNestedValue(t, got.Object, int64(5000), "spec", "diagnosis", "maxCRDInstances")
		assertNestedValue(t, got.Object, int64(5000), "spec", "diagnosis", "maxNamespaceObjects")
		assertNestedValue(t, got.Object, "None", "spec", "remediation", "maxRisk")
		assertNestedValue(t, got.Object, "1h", "spec", "remediation", "approvalTTL")
		assertNestedValue(t, got.Object, "720h", "spec", "retention", "resolvedIncidentTTL")
	})

	t.Run("incident spec is immutable", func(t *testing.T) {
		ctx := boundedContext(t)
		incident := validIncident(fixtureName(t, "immutable-incident"))
		if err := suite.client.Create(ctx, incident); err != nil {
			t.Fatalf("create incident: %v", err)
		}
		incident.Spec.Target.Name = "changed"
		if err := suite.client.Update(ctx, incident); !apierrors.IsInvalid(err) {
			t.Fatalf("immutable incident update error = %v, want Invalid", err)
		}
	})

	t.Run("approval requires reason and immutable spec", func(t *testing.T) {
		ctx := boundedContext(t)
		invalid := validApproval(fixtureName(t, "invalid-approval"))
		invalid.Spec.Reason = ""
		if err := suite.client.Create(ctx, invalid); !apierrors.IsInvalid(err) {
			t.Fatalf("empty approval reason error = %v, want Invalid", err)
		}

		approval := validApproval(fixtureName(t, "immutable-approval"))
		if err := suite.client.Create(ctx, approval); err != nil {
			t.Fatalf("create approval: %v", err)
		}
		approval.Spec.DryRun = true
		if err := suite.client.Update(ctx, approval); !apierrors.IsInvalid(err) {
			t.Fatalf("immutable approval update error = %v, want Invalid", err)
		}
	})
}

func validIncident(name string) *safetyv1alpha1.DeletionIncident {
	return &safetyv1alpha1.DeletionIncident{
		TypeMeta:   metav1.TypeMeta{APIVersion: safetyv1alpha1.GroupVersion.String(), Kind: "DeletionIncident"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: safetyv1alpha1.DeletionIncidentSpec{
			Target: safetyv1alpha1.TargetReference{
				Version:   "v1",
				Resource:  "configmaps",
				Kind:      "ConfigMap",
				Namespace: "default",
				Name:      "stuck",
				UID:       types.UID("11111111-1111-1111-1111-111111111111"),
			},
			FirstObservedTime: metav1.Now(),
		},
	}
}

func validApproval(name string) *safetyv1alpha1.RemediationApproval {
	return &safetyv1alpha1.RemediationApproval{
		TypeMeta:   metav1.TypeMeta{APIVersion: safetyv1alpha1.GroupVersion.String(), Kind: "RemediationApproval"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: safetyv1alpha1.RemediationApprovalSpec{
			IncidentRef: safetyv1alpha1.ObjectIdentityReference{
				Name: "immutable-incident",
				UID:  types.UID("22222222-2222-2222-2222-222222222222"),
			},
			ActionID: "action-1",
			Reason:   "operator approved remediation",
		},
	}
}

func assertNestedValue(t *testing.T, object map[string]any, want any, fields ...string) {
	t.Helper()
	got, found, err := unstructured.NestedFieldNoCopy(object, fields...)
	if err != nil {
		t.Fatalf("read %v: %v", fields, err)
	}
	if !found {
		t.Fatalf("field %v was not defaulted", fields)
	}
	if got != want {
		t.Fatalf("field %v = %#v, want %#v", fields, got, want)
	}
}
