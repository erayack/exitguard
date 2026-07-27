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
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
	policyengine "github.com/erayack/exitguard/internal/policy"
)

// Reader exposes only the GET and partial-metadata LIST operations diagnosis needs.
type Reader interface {
	Get(ctx context.Context, resource schema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error)
	ListMetadata(ctx context.Context, resource schema.GroupVersionResource, namespace string, options metav1.ListOptions) (*metav1.PartialObjectMetadataList, error)
}

// Snapshot is immutable per-scan evidence shared by target diagnoses.
type Snapshot struct {
	Catalog            catalogdiscovery.Snapshot
	APIServices        []apiregistrationv1.APIService
	MutatingWebhooks   []admissionv1.MutatingWebhookConfiguration
	ValidatingWebhooks []admissionv1.ValidatingWebhookConfiguration
	Services           []corev1.Service
	EndpointSlices     []discoveryv1.EndpointSlice
	Deployments        []appsv1.Deployment
	StatefulSets       []appsv1.StatefulSet
	DaemonSets         []appsv1.DaemonSet
	NamespaceLabels    map[string]map[string]string
}

// Request pins one diagnosis to a target, policy revision, and scan snapshot.
type Request struct {
	Target   safetyv1alpha1.TargetReference
	Policy   *policyengine.CompiledPolicy
	Snapshot Snapshot
	Now      time.Time
}

// Result is deterministic diagnosis output and contains no persisted side effects.
type Result struct {
	TargetFound       bool
	UIDMatches        bool
	ThresholdElapsed  bool
	DiagnosisComplete bool
	TargetSnapshot    safetyv1alpha1.TargetSnapshot
	Findings          []safetyv1alpha1.Finding
	Actions           []safetyv1alpha1.RemediationAction
}

// Engine performs read-only deletion diagnosis.
type Engine struct {
	reader Reader
}

// NewEngine creates a side-effect-free diagnosis engine.
func NewEngine(reader Reader) *Engine {
	return &Engine{reader: reader}
}
