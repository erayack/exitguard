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

// Package perftest contains deterministic, test-only performance harness helpers.
package perftest

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Operation identifies an observable client or harness operation.
type Operation uint8

// Operation values classify observable test-harness calls and outcomes.
const (
	DiscoveryRequest Operation = iota
	MetadataList
	MetadataPage
	TypedGet
	DynamicGet
	TypedList
	DynamicList
	IncidentList
	PolicyList
	Create
	Update
	Patch
	StatusWrite
	Delete
	Finalizer
	DryRun
	Retry
	Write
	Mismatch
	operationCount
)

var operationNames = [...]string{
	"discovery_request",
	"metadata_list",
	"metadata_page",
	"typed_get",
	"dynamic_get",
	"typed_list",
	"dynamic_list",
	"incident_list",
	"policy_list",
	"create",
	"update",
	"patch",
	"status_write",
	"delete",
	"finalizer",
	"dry_run",
	"retry",
	"write",
	"mismatch",
}

// String returns the stable metric name for an operation.
func (o Operation) String() string {
	if o >= operationCount {
		return fmt.Sprintf("operation_%d", o)
	}
	return operationNames[o]
}

// Snapshot is an immutable point-in-time copy of operation counts.
type Snapshot struct {
	values [operationCount]int64
}

// Value returns the count for one operation.
func (s Snapshot) Value(operation Operation) int64 {
	if operation >= operationCount {
		return 0
	}
	return s.values[operation]
}

// Total returns the sum of all counts except mismatch bookkeeping.
func (s Snapshot) Total() int64 {
	var total int64
	for operation := Operation(0); operation < Mismatch; operation++ {
		total += s.values[operation]
	}
	return total
}

// Delta subtracts an earlier snapshot from this snapshot.
func (s Snapshot) Delta(earlier Snapshot) Snapshot {
	var delta Snapshot
	for operation := Operation(0); operation < operationCount; operation++ {
		delta.values[operation] = s.values[operation] - earlier.values[operation]
	}
	return delta
}

// Counters records operations safely across concurrent benchmark workers.
type Counters struct {
	values [operationCount]atomic.Int64
}

// Add records count occurrences of an operation.
func (c *Counters) Add(operation Operation, count int64) {
	if c == nil || operation >= operationCount {
		return
	}
	c.values[operation].Add(count)
}

// Record records one occurrence of an operation.
func (c *Counters) Record(operation Operation) {
	c.Add(operation, 1)
}

// Value returns the current count for one operation.
func (c *Counters) Value(operation Operation) int64 {
	if c == nil || operation >= operationCount {
		return 0
	}
	return c.values[operation].Load()
}

// Snapshot returns an immutable copy of all current counts.
func (c *Counters) Snapshot() Snapshot {
	var snapshot Snapshot
	if c == nil {
		return snapshot
	}
	for operation := Operation(0); operation < operationCount; operation++ {
		snapshot.values[operation] = c.values[operation].Load()
	}
	return snapshot
}

// Reset sets every operation count to zero.
func (c *Counters) Reset() {
	if c == nil {
		return
	}
	for operation := Operation(0); operation < operationCount; operation++ {
		c.values[operation].Store(0)
	}
}

// Check verifies exact expected counts and records a mismatch on failure.
// Operations absent from expected must have a zero count.
func (c *Counters) Check(expected map[Operation]int64) error {
	actual := c.Snapshot()
	problems := make([]string, 0)
	for operation := Operation(0); operation < Mismatch; operation++ {
		want := expected[operation]
		if got := actual.Value(operation); got != want {
			problems = append(problems, fmt.Sprintf("%s=%d, want %d", operation, got, want))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	c.Record(Mismatch)
	return fmt.Errorf("operation count mismatch: %s", strings.Join(problems, "; "))
}
