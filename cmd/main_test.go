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

package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
)

func TestNewSchemeRegistersRequiredAPIs(t *testing.T) {
	t.Parallel()

	scheme, err := newScheme()
	if err != nil {
		t.Fatalf("newScheme() error: %v", err)
	}

	for _, object := range []runtime.Object{
		&corev1.Namespace{},
		&apiextensionsv1.CustomResourceDefinition{},
		&apiregistrationv1.APIService{},
		&safetyv1alpha1.TerminationPolicy{},
		&safetyv1alpha1.DeletionIncident{},
		&safetyv1alpha1.RemediationApproval{},
	} {
		if _, _, err := scheme.ObjectKinds(object); err != nil {
			t.Errorf("object %T is not registered: %v", object, err)
		}
	}
}
