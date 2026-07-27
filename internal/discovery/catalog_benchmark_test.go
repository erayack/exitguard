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
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/erayack/exitguard/internal/perftest"
)

type discoveryAlgorithmScale struct {
	name              string
	groups            int
	resourcesPerGroup int
	lookups           int
}

var discoveryAlgorithmScales = []discoveryAlgorithmScale{
	{name: "small", groups: 4, resourcesPerGroup: 4, lookups: 64},
	{name: "medium", groups: 20, resourcesPerGroup: 10, lookups: 1_000},
	{name: "large", groups: 50, resourcesPerGroup: 20, lookups: 10_000},
}

var (
	discoverySnapshotSink Snapshot
	discoveryLookupSink   Resource
	discoveryHitSink      int
)

func BenchmarkDiscoverySnapshotBuild(b *testing.B) {
	for _, scale := range discoveryAlgorithmScales {
		b.Run(scale.name, func(b *testing.B) {
			groups, lists := discoveryBenchmarkInput(scale)
			wantResources := scale.groups * scale.resourcesPerGroup
			var snapshot Snapshot
			var err error

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				snapshot, err = buildSnapshot(groups, lists)
			}
			b.StopTimer()
			discoverySnapshotSink = snapshot
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(scale.groups), "groups/op")
			b.ReportMetric(float64(wantResources), "resources/op")

			if snapshot.Len() != wantResources {
				b.Fatalf("snapshot resources = %d, want %d", snapshot.Len(), wantResources)
			}
			for _, resource := range snapshot.Resources() {
				if resource.PreferredVersion.Version != "v1" || len(resource.AlternateVersions) != 1 {
					b.Fatalf("unexpected versions for %s: %#v", resource.GroupResource, resource)
				}
			}
			b.ReportMetric(0, "mismatches/op")
		})
	}
}

func BenchmarkDiscoverySnapshotLookup(b *testing.B) {
	for _, scale := range discoveryAlgorithmScales {
		b.Run(scale.name, func(b *testing.B) {
			groups, lists := discoveryBenchmarkInput(scale)
			snapshot, err := buildSnapshot(groups, lists)
			if err != nil {
				b.Fatal(err)
			}
			keys := discoveryBenchmarkLookups(scale)
			wantHits := 0
			for _, key := range keys {
				resource, found := snapshot.Resolve(key)
				if found {
					if resource.GroupResource != key {
						b.Fatalf("resolved %s for lookup %s", resource.GroupResource, key)
					}
					wantHits++
				}
			}

			hits := 0
			var resolved Resource
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				hits = 0
				for _, key := range keys {
					var found bool
					resolved, found = snapshot.Resolve(key)
					if found {
						hits++
					}
				}
			}
			b.StopTimer()
			discoveryLookupSink = resolved
			discoveryHitSink = hits
			b.ReportMetric(float64(scale.groups), "groups/op")
			b.ReportMetric(float64(snapshot.Len()), "resources/op")
			b.ReportMetric(float64(len(keys)), "lookups/op")

			if hits != wantHits || hits == 0 || hits == len(keys) {
				b.Fatalf("lookup hits = %d, want mixed result with %d hits", hits, wantHits)
			}
			if perftest.Checksum(resolved.GroupResource.String(), resolved.PreferredVersion.Version) == 0 {
				b.Fatal("lookup result was not observable")
			}
			b.ReportMetric(float64(hits), "hits/op")
			b.ReportMetric(0, "mismatches/op")
		})
	}
}

func discoveryBenchmarkInput(scale discoveryAlgorithmScale) ([]*metav1.APIGroup, []*metav1.APIResourceList) {
	groups := make([]*metav1.APIGroup, scale.groups)
	lists := make([]*metav1.APIResourceList, 0, scale.groups*2)
	for groupIndex := range scale.groups {
		group := fmt.Sprintf("group-%02d.benchmark.io", groupIndex)
		groups[groupIndex] = &metav1.APIGroup{
			Name:             group,
			PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: group + "/v1", Version: "v1"},
			Versions: []metav1.GroupVersionForDiscovery{
				{GroupVersion: group + "/v1", Version: "v1"},
				{GroupVersion: group + "/v1beta1", Version: "v1beta1"},
			},
		}
		for _, version := range []string{"v1", "v1beta1"} {
			resources := make([]metav1.APIResource, scale.resourcesPerGroup)
			for resourceIndex := range resources {
				globalIndex := groupIndex*scale.resourcesPerGroup + resourceIndex
				resources[resourceIndex] = metav1.APIResource{
					Name: fmt.Sprintf("resources-%04d", resourceIndex), Kind: fmt.Sprintf("Resource%04d", globalIndex),
					Namespaced: globalIndex%5 != 0, Verbs: metav1.Verbs{"list", "get"},
				}
			}
			lists = append(lists, &metav1.APIResourceList{GroupVersion: group + "/" + version, APIResources: resources})
		}
	}
	return groups, lists
}

func discoveryBenchmarkLookups(scale discoveryAlgorithmScale) []schema.GroupResource {
	keys := make([]schema.GroupResource, scale.lookups)
	for index := range keys {
		if index%4 == 0 {
			keys[index] = schema.GroupResource{Group: "missing.benchmark.io", Resource: fmt.Sprintf("missing-%04d", index)}
			continue
		}
		groupIndex := index % scale.groups
		resourceIndex := index % scale.resourcesPerGroup
		keys[index] = schema.GroupResource{
			Group: fmt.Sprintf("group-%02d.benchmark.io", groupIndex), Resource: fmt.Sprintf("resources-%04d", resourceIndex),
		}
	}
	return keys
}
