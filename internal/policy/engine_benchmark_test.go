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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	catalogdiscovery "github.com/erayack/exitguard/internal/discovery"
	"github.com/erayack/exitguard/internal/perftest"
)

type policyAlgorithmScale struct {
	name      string
	policies  int
	groups    int
	resources int
	objects   int
}

var policyAlgorithmScales = []policyAlgorithmScale{
	{name: "small", policies: 4, groups: 4, resources: 16, objects: 64},
	{name: "medium", policies: 20, groups: 10, resources: 100, objects: 1_000},
	{name: "large", policies: 80, groups: 20, resources: 800, objects: 10_000},
}

var (
	policyCompileSink []*CompiledPolicy
	policyWinnerSink  *CompiledPolicy
	policyMatchSink   int
)

func BenchmarkPolicyCompile(b *testing.B) {
	for _, scale := range policyAlgorithmScales {
		b.Run(scale.name, func(b *testing.B) {
			catalog, resources, err := policyBenchmarkCatalog(scale)
			if err != nil {
				b.Fatal(err)
			}
			sources := policyBenchmarkSources(scale)
			now := perftest.FixedNow()
			compiled := make([]*CompiledPolicy, len(sources))
			statuses := make([]safetyv1alpha1.TerminationPolicyStatus, len(sources))

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for index, source := range sources {
					compiled[index], statuses[index] = Compile(source, catalog, now)
				}
			}
			b.StopTimer()
			policyCompileSink = compiled
			b.ReportMetric(float64(scale.policies), "policies/op")
			b.ReportMetric(float64(scale.resources+1), "resources/op")

			for index, candidate := range compiled {
				if !candidate.Ready() {
					b.Fatalf("compiled policy %d is not ready", index)
				}
				groupIndex := index % scale.groups
				wantResolved := resources[groupIndex] + 1
				if got := int(statuses[index].ResolvedResourceCount); got != wantResolved {
					b.Fatalf("compiled policy %d resolved %d resources, want %d", index, got, wantResolved)
				}
			}
			b.ReportMetric(0, "mismatches/op")
		})
	}
}

func BenchmarkPolicyMatchWinner(b *testing.B) {
	for _, scale := range policyAlgorithmScales {
		b.Run(scale.name, func(b *testing.B) {
			catalog, resourcesPerGroup, err := policyBenchmarkCatalog(scale)
			if err != nil {
				b.Fatal(err)
			}
			if len(resourcesPerGroup) != scale.groups {
				b.Fatalf("resource groups = %d, want %d", len(resourcesPerGroup), scale.groups)
			}
			sources := policyBenchmarkSources(scale)
			compiled := make([]*CompiledPolicy, len(sources))
			for index, source := range sources {
				candidate, status := Compile(source, catalog, perftest.FixedNow())
				if !candidate.Ready() {
					b.Fatalf("compile match fixture %d: %#v", index, status.Conditions)
				}
				compiled[index] = candidate
			}
			targets := policyBenchmarkTargets(catalog.Resources(), scale.objects)
			wantMatches := 0
			for _, target := range targets {
				if SelectWinning(compiled, target) != nil {
					wantMatches++
				}
			}

			matches := 0
			var winner *CompiledPolicy
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				matches = 0
				for _, target := range targets {
					winner = SelectWinning(compiled, target)
					if winner != nil {
						matches++
					}
				}
			}
			b.StopTimer()
			policyWinnerSink = winner
			policyMatchSink = matches
			b.ReportMetric(float64(scale.policies), "policies/op")
			b.ReportMetric(float64(scale.resources+1), "resources/op")
			b.ReportMetric(float64(scale.objects), "objects/op")

			if matches != wantMatches || matches != len(targets) {
				b.Fatalf("matched %d targets, want %d", matches, wantMatches)
			}
			if winner == nil || perftest.Checksum(winner.Name(), string(winner.UID())) == 0 {
				b.Fatal("winner result was not observable")
			}
			b.ReportMetric(float64(matches), "matches/op")
			b.ReportMetric(0, "mismatches/op")
		})
	}
}

func policyBenchmarkCatalog(scale policyAlgorithmScale) (catalogdiscovery.Snapshot, []int, error) {
	groups := make([]*metav1.APIGroup, scale.groups+1)
	lists := make([]*metav1.APIResourceList, 0, scale.groups*2+1)
	resourcesPerGroup := make([]int, scale.groups)
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
			apiResources := make([]metav1.APIResource, 0, scale.resources/scale.groups+1)
			for index := groupIndex; index < scale.resources; index += scale.groups {
				if version == "v1" {
					resourcesPerGroup[groupIndex]++
				}
				apiResources = append(apiResources, metav1.APIResource{
					Name: fmt.Sprintf("resources-%04d", index), Kind: fmt.Sprintf("Resource%04d", index),
					Namespaced: index%5 != 0, Verbs: metav1.Verbs{"get", "list"},
				})
			}
			lists = append(lists, &metav1.APIResourceList{GroupVersion: group + "/" + version, APIResources: apiResources})
		}
	}
	groups[scale.groups] = &metav1.APIGroup{
		Name: "", PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: "v1", Version: "v1"},
		Versions: []metav1.GroupVersionForDiscovery{{GroupVersion: "v1", Version: "v1"}},
	}
	lists = append(lists, &metav1.APIResourceList{GroupVersion: "v1", APIResources: []metav1.APIResource{{
		Name: "namespaces", Kind: "Namespace", Verbs: metav1.Verbs{"get", "list"},
	}}})
	catalog := catalogdiscovery.NewCatalog(policyBenchmarkDiscovery{groups: groups, lists: lists}, time.Hour, logr.Discard())
	if err := catalog.Refresh(); err != nil {
		return catalogdiscovery.Snapshot{}, nil, err
	}
	return catalog.Snapshot(), resourcesPerGroup, nil
}

type policyBenchmarkDiscovery struct {
	groups []*metav1.APIGroup
	lists  []*metav1.APIResourceList
}

func (d policyBenchmarkDiscovery) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	return d.groups, d.lists, nil
}

func policyBenchmarkSources(scale policyAlgorithmScale) []*safetyv1alpha1.TerminationPolicy {
	sources := make([]*safetyv1alpha1.TerminationPolicy, scale.policies)
	for index := range sources {
		group := fmt.Sprintf("group-%02d.benchmark.io", index%scale.groups)
		source := validPolicy(perftest.Name("policy", index), int32(index%5), safetyv1alpha1.TargetRule{
			APIGroups: []string{group}, Resources: []string{"*"},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "scanner"}},
			ObjectSelector:    &metav1.LabelSelector{MatchLabels: map[string]string{"environment": "production"}},
		})
		source.Spec.TargetRules = append(source.Spec.TargetRules, safetyv1alpha1.TargetRule{APIGroups: []string{""}, Resources: []string{"namespaces"}})
		sources[index] = source
	}
	return sources
}

func policyBenchmarkTargets(resources []catalogdiscovery.Resource, count int) []Target {
	targets := make([]Target, count)
	for index := range targets {
		resource := resources[index%len(resources)]
		target := Target{
			GroupResource: resource.GroupResource,
			Namespaced:    resource.PreferredVersion.Namespaced,
			Labels:        map[string]string{"environment": "production"},
		}
		if target.Namespaced {
			target.Namespace = perftest.Name("namespace", index%16)
			target.NamespaceLabels = map[string]string{"team": "scanner"}
		}
		targets[index] = target
	}
	return targets
}
