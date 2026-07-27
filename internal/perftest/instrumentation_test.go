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

package perftest_test

import (
	"context"
	"reflect"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	safetyv1alpha1 "github.com/erayack/exitguard/api/v1alpha1"
	"github.com/erayack/exitguard/internal/perftest"
)

func TestCountersConcurrentResetDeltaAndMismatch(t *testing.T) {
	var counters perftest.Counters
	before := counters.Snapshot()
	const workers = 8
	const callsPerWorker = 1_000
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			for range callsPerWorker {
				counters.Record(perftest.TypedGet)
			}
		})
	}
	group.Wait()

	delta := counters.Snapshot().Delta(before)
	if got, want := delta.Value(perftest.TypedGet), int64(workers*callsPerWorker); got != want {
		t.Fatalf("typed gets = %d, want %d", got, want)
	}
	if err := counters.Check(map[perftest.Operation]int64{perftest.TypedGet: workers * callsPerWorker}); err != nil {
		t.Fatalf("check matching counters: %v", err)
	}
	if err := counters.Check(map[perftest.Operation]int64{perftest.TypedGet: 1}); err == nil {
		t.Fatal("mismatched counters unexpectedly passed")
	}
	if got := counters.Value(perftest.Mismatch); got != 1 {
		t.Fatalf("mismatches = %d, want 1", got)
	}

	counters.Reset()
	if got := counters.Snapshot().Total(); got != 0 {
		t.Fatalf("total after reset = %d, want 0", got)
	}
}

func TestPagerBoundariesTokensAndCounters(t *testing.T) {
	var counters perftest.Counters
	pager := perftest.Pager[int]{Items: []int{0, 1, 2, 3, 4, 5, 6}, PageSize: 3, Counters: &counters, ListOperation: perftest.MetadataList}
	var got []int
	var token string
	for {
		items, next, err := pager.Page(token, 2)
		if err != nil {
			t.Fatalf("page %q: %v", token, err)
		}
		got = append(got, items...)
		if len(items) > 0 {
			items[0] = -1
		}
		if next == "" {
			break
		}
		token = next
	}
	if want := []int{0, 1, 2, 3, 4, 5, 6}; !reflect.DeepEqual(got, want) {
		t.Fatalf("items = %v, want %v", got, want)
	}
	if pager.Items[0] != 0 {
		t.Fatal("returned page aliased fixture storage")
	}
	if err := counters.Check(map[perftest.Operation]int64{perftest.MetadataList: 4, perftest.MetadataPage: 4}); err != nil {
		t.Fatal(err)
	}

	counters.Reset()
	if _, _, err := pager.Page("not-a-token", 0); err == nil {
		t.Fatal("invalid continue token unexpectedly passed")
	}
	if err := counters.Check(map[perftest.Operation]int64{perftest.MetadataList: 1, perftest.MetadataPage: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureValidationAndDeterminism(t *testing.T) {
	if err := (perftest.Scale{}).Validate(); err == nil {
		t.Fatal("empty scale unexpectedly passed")
	}
	scale := perftest.Scale{Name: "small", Policies: 1, Resources: 2, Objects: 3, PageSize: 1}
	if err := scale.Validate(); err != nil {
		t.Fatalf("valid scale: %v", err)
	}
	if perftest.UID("object", 7) != "object-000007" || perftest.ResourceVersion(7) != "8" {
		t.Fatal("fixture identifiers are not deterministic")
	}
	if got := perftest.SortedStrings([]string{"c", "a", "b"}); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("sorted strings = %v", got)
	}
	checksum := perftest.Checksum("a", "b")
	if checksum == 0 || checksum == perftest.Checksum("ab") {
		t.Fatal("fixture checksum is not stable or delimited")
	}
}

func TestCountingClientCountsDelegatedCalls(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := safetyv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &safetyv1alpha1.TerminationPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy"}}
	delegate := clientfake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(policy).WithObjects(policy).Build()
	var counters perftest.Counters
	counting := perftest.NewCountingClient(delegate, &counters)
	ctx := context.Background()

	var current safetyv1alpha1.TerminationPolicy
	if err := counting.Get(ctx, client.ObjectKey{Name: policy.Name}, &current); err != nil {
		t.Fatal(err)
	}
	if err := counting.List(ctx, &safetyv1alpha1.TerminationPolicyList{}); err != nil {
		t.Fatal(err)
	}
	if err := counting.List(ctx, &safetyv1alpha1.DeletionIncidentList{}); err != nil {
		t.Fatal(err)
	}
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "fixture"}}
	if err := counting.Create(ctx, configMap); err != nil {
		t.Fatal(err)
	}
	base := configMap.DeepCopy()
	configMap.Labels = map[string]string{"fixture": "true"}
	if err := counting.Patch(ctx, configMap, client.MergeFrom(base)); err != nil {
		t.Fatal(err)
	}
	current.Status.ObservedGeneration = 1
	if err := counting.Status().Update(ctx, &current); err != nil {
		t.Fatal(err)
	}
	if err := counting.Delete(ctx, configMap); err != nil {
		t.Fatal(err)
	}

	expected := map[perftest.Operation]int64{
		perftest.TypedGet:     1,
		perftest.PolicyList:   1,
		perftest.IncidentList: 1,
		perftest.Create:       1,
		perftest.Patch:        1,
		perftest.StatusWrite:  1,
		perftest.Delete:       1,
		perftest.Write:        4,
	}
	if err := counters.Check(expected); err != nil {
		t.Fatal(err)
	}
}
