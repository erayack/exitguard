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

package discovery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestCatalogVersionSelectionAndFiltering(t *testing.T) {
	client := &fakeClient{responses: []discoveryResponse{{
		groups: []*metav1.APIGroup{{
			Name:             "apps.example.io",
			PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: "apps.example.io/v1", Version: "v1"},
			Versions: []metav1.GroupVersionForDiscovery{
				{GroupVersion: "apps.example.io/v1", Version: "v1"},
				{GroupVersion: "apps.example.io/v1beta1", Version: "v1beta1"},
			},
		}, {
			Name:             "fallback.example.io",
			PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: "fallback.example.io/v1", Version: "v1"},
			Versions: []metav1.GroupVersionForDiscovery{
				{GroupVersion: "fallback.example.io/v1", Version: "v1"},
				{GroupVersion: "fallback.example.io/v1beta1", Version: "v1beta1"},
			},
		}},
		resources: []*metav1.APIResourceList{
			resourceList("apps.example.io/v1beta1", apiResource("widgets", "WidgetBeta", true, "list", "get")),
			resourceList("apps.example.io/v1", apiResource("widgets", "Widget", true, "watch", "get", "list")),
			resourceList("fallback.example.io/v1beta1", apiResource("gadgets", "Gadget", false, "get", "list")),
			resourceList("v1",
				apiResource("pods", "Pod", true, "get", "list"),
				apiResource("pods/status", "Pod", true, "get", "list"),
				apiResource("secrets", "Secret", true, "get"),
				apiResource("configmaps", "ConfigMap", true, "list"),
				apiResource("events", "Event", true, "get", "list"),
			),
			resourceList("coordination.k8s.io/v1", apiResource("leases", "Lease", true, "get", "list")),
		},
	}}}
	catalog := NewCatalog(client, time.Minute, logr.Discard())
	if err := catalog.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	snapshot := catalog.Snapshot()
	if got, want := snapshot.Len(), 5; got != want {
		t.Fatalf("resource count = %d, want %d", got, want)
	}
	widgets, found := snapshot.Resolve(schema.GroupResource{Group: "apps.example.io", Resource: "widgets"})
	if !found {
		t.Fatal("widgets were not discovered")
	}
	if got, want := widgets.PreferredVersion.Version, "v1"; got != want {
		t.Errorf("preferred version = %q, want %q", got, want)
	}
	if got, want := widgets.PreferredVersion.Kind, "Widget"; got != want {
		t.Errorf("preferred kind = %q, want %q", got, want)
	}
	alternates := widgets.AlternateVersions()
	if len(alternates) != 1 || alternates[0].Version != "v1beta1" {
		t.Errorf("alternate versions = %#v, want v1beta1", alternates)
	}
	ordered := widgets.OrderedVersions("v1beta1")
	if len(ordered) != 2 || ordered[0].Version != "v1beta1" || ordered[1].Version != "v1" {
		t.Errorf("requested version order = %#v, want v1beta1 then v1", ordered)
	}
	gadgets, found := snapshot.Resolve(schema.GroupResource{Group: "fallback.example.io", Resource: "gadgets"})
	if !found || gadgets.PreferredVersion.Version != "v1beta1" {
		t.Errorf("preferred fallback = %#v, want served v1beta1", gadgets)
	}
	if _, found := snapshot.Resolve(schema.GroupResource{Resource: "pods/status"}); found {
		t.Error("subresource was retained")
	}
	if _, found := snapshot.Resolve(schema.GroupResource{Resource: "secrets"}); found {
		t.Error("get-only resource was retained")
	}
	if _, found := snapshot.Resolve(schema.GroupResource{Resource: "configmaps"}); found {
		t.Error("list-only resource was retained")
	}
	for _, gr := range []schema.GroupResource{{Resource: "events"}, {Group: "coordination.k8s.io", Resource: "leases"}} {
		resource, found := snapshot.Resolve(gr)
		if !found {
			t.Fatalf("explicit high-churn resource %s was omitted", gr)
		}
		if resource.EligibleForWildcard() {
			t.Errorf("high-churn resource %s is wildcard eligible", gr)
		}
	}
}

func TestResolvedResourceKeepsSnapshotBackingPrivate(t *testing.T) {
	preferredVerbs := []string{"get", "list"}
	alternateVerbs := []string{"get", "list", "watch"}
	alternates := []Version{{Version: "v1beta1", Kind: "WidgetBeta", Namespaced: true, verbs: alternateVerbs}}
	resource := newResource(
		schema.GroupResource{Group: "apps.example.io", Resource: "widgets"},
		Version{Version: "v1", Kind: "Widget", Namespaced: true, verbs: preferredVerbs},
		alternates,
	)
	snapshot := newSnapshot([]Resource{resource})

	preferredVerbs[0] = "delete"
	alternateVerbs[0] = "delete"
	alternates[0].Version = "mutated"

	resolved, found := snapshot.Resolve(resource.GroupResource)
	if !found {
		t.Fatal("resource was not resolved")
	}
	verbs := resolved.PreferredVersion.Verbs()
	versions := resolved.AlternateVersions()
	verbs[0] = "patch"
	versions[0].Version = "mutated-again"
	alternateCopy := versions[0].Verbs()
	alternateCopy[0] = "patch"

	again, found := snapshot.Resolve(resource.GroupResource)
	if !found {
		t.Fatal("resource disappeared after caller mutations")
	}
	if got := again.PreferredVersion.Verbs(); len(got) != 2 || got[0] != "get" {
		t.Fatalf("preferred verbs leaked mutable backing: %#v", got)
	}
	gotAlternates := again.AlternateVersions()
	if len(gotAlternates) != 1 || gotAlternates[0].Version != "v1beta1" {
		t.Fatalf("alternate versions leaked mutable backing: %#v", gotAlternates)
	}
	if got := gotAlternates[0].Verbs(); len(got) != 3 || got[0] != "get" {
		t.Fatalf("alternate verbs leaked mutable backing: %#v", got)
	}
}

func TestCatalogRetainsLastSuccessAfterFailure(t *testing.T) {
	client := &fakeClient{responses: []discoveryResponse{
		{resources: []*metav1.APIResourceList{resourceList("v1", apiResource("pods", "Pod", true, "get", "list"))}},
		{err: errors.New("discovery unavailable")},
	}}
	catalog := NewCatalog(client, time.Minute, logr.Discard())
	if err := catalog.Refresh(); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	firstSuccess, firstErr := catalog.LastResult()
	if firstSuccess.IsZero() || firstErr != nil {
		t.Fatalf("first result = (%v, %v), want successful timestamp", firstSuccess, firstErr)
	}

	if err := catalog.Refresh(); err == nil {
		t.Fatal("second refresh succeeded, want error")
	}
	if _, found := catalog.Snapshot().Resolve(schema.GroupResource{Resource: "pods"}); !found {
		t.Fatal("failed refresh discarded previous catalog")
	}
	lastSuccess, lastErr := catalog.LastResult()
	if !lastSuccess.Equal(firstSuccess) || lastErr == nil {
		t.Fatalf("last result = (%v, %v), want prior timestamp and current error", lastSuccess, lastErr)
	}
}

func TestCatalogRefreshRecordsMissingClientError(t *testing.T) {
	catalog := NewCatalog(nil, time.Minute, logr.Discard())
	if err := catalog.Refresh(); err == nil {
		t.Fatal("Refresh() error = nil, want missing-client error")
	}
	lastSuccess, lastErr := catalog.LastResult()
	if !lastSuccess.IsZero() || lastErr == nil {
		t.Fatalf("LastResult() = (%v, %v), want recorded missing-client error", lastSuccess, lastErr)
	}
}

func TestCatalogStartRefreshesImmediatelyAndOnCadence(t *testing.T) {
	client := &fakeClient{
		responses: []discoveryResponse{{resources: []*metav1.APIResourceList{resourceList("v1", apiResource("pods", "Pod", true, "get", "list"))}}},
		calls:     make(chan struct{}, 4),
	}
	catalog := NewCatalog(client, 10*time.Millisecond, logr.Discard())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- catalog.Start(ctx) }()

	for call := 0; call < 2; call++ {
		select {
		case <-client.calls:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for discovery call %d", call+1)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not stop after cancellation")
	}
}

type discoveryResponse struct {
	groups    []*metav1.APIGroup
	resources []*metav1.APIResourceList
	err       error
}

type fakeClient struct {
	mu        sync.Mutex
	responses []discoveryResponse
	calls     chan struct{}
	index     int
}

func (f *fakeClient) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls != nil {
		select {
		case f.calls <- struct{}{}:
		default:
		}
	}
	index := f.index
	if index >= len(f.responses) {
		index = len(f.responses) - 1
	} else {
		f.index++
	}
	response := f.responses[index]
	return response.groups, response.resources, response.err
}

func resourceList(groupVersion string, resources ...metav1.APIResource) *metav1.APIResourceList {
	return &metav1.APIResourceList{GroupVersion: groupVersion, APIResources: resources}
}

func apiResource(name, kind string, namespaced bool, verbs ...string) metav1.APIResource {
	return metav1.APIResource{Name: name, Kind: kind, Namespaced: namespaced, Verbs: verbs}
}
