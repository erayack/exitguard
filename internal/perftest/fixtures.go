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

package perftest

import (
	"fmt"
	"hash/fnv"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// Scale describes fixed benchmark fixture dimensions.
type Scale struct {
	Name      string
	Policies  int
	Resources int
	Objects   int
	PageSize  int
}

// Validate rejects ambiguous or non-progressing fixture dimensions.
func (s Scale) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("scale name is required")
	}
	if s.Policies <= 0 || s.Resources <= 0 || s.Objects <= 0 || s.PageSize <= 0 {
		return fmt.Errorf("scale %q dimensions must be positive", s.Name)
	}
	return nil
}

// FixedNow returns the common deterministic fixture time.
func FixedNow() time.Time {
	return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
}

// Name returns a stable indexed fixture name.
func Name(prefix string, index int) string {
	return fmt.Sprintf("%s-%06d", prefix, index)
}

// UID returns a stable indexed fixture UID.
func UID(prefix string, index int) types.UID {
	return types.UID(Name(prefix, index))
}

// ResourceVersion returns a stable positive fixture resource version.
func ResourceVersion(index int) string {
	return fmt.Sprintf("%d", index+1)
}

// SortedStrings returns a detached, deterministically ordered copy.
func SortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

// Checksum returns a stable non-cryptographic sink for verified benchmark output.
func Checksum(parts ...string) uint64 {
	digest := fnv.New64a()
	for _, part := range parts {
		_, _ = digest.Write([]byte(part))
		_, _ = digest.Write([]byte{0})
	}
	return digest.Sum64()
}
