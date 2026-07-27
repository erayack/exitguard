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
	"strconv"
	"strings"
)

const continuePrefix = "offset:"

// Pager provides deterministic offset-based pages over an immutable fixture.
type Pager[T any] struct {
	Items         []T
	PageSize      int
	Counters      *Counters
	ListOperation Operation
}

// Validate checks that a pager can always make forward progress.
func (p Pager[T]) Validate() error {
	if p.PageSize <= 0 {
		return fmt.Errorf("page size must be positive")
	}
	if p.ListOperation >= operationCount {
		return fmt.Errorf("invalid list operation %d", p.ListOperation)
	}
	return nil
}

// Page returns one detached page and a deterministic continue token.
func (p Pager[T]) Page(token string, requestedLimit int64) ([]T, string, error) {
	p.Counters.Record(p.ListOperation)
	p.Counters.Record(MetadataPage)
	if err := p.Validate(); err != nil {
		return nil, "", err
	}

	start, err := pageOffset(token, len(p.Items))
	if err != nil {
		return nil, "", err
	}
	pageSize := p.PageSize
	if requestedLimit > 0 && requestedLimit < int64(pageSize) {
		pageSize = int(requestedLimit)
	}
	end := min(start+pageSize, len(p.Items))
	items := append([]T(nil), p.Items[start:end]...)
	if end == len(p.Items) {
		return items, "", nil
	}
	return items, continuePrefix + strconv.Itoa(end), nil
}

func pageOffset(token string, length int) (int, error) {
	if token == "" {
		return 0, nil
	}
	if !strings.HasPrefix(token, continuePrefix) {
		return 0, fmt.Errorf("invalid continue token %q", token)
	}
	offset, err := strconv.Atoi(strings.TrimPrefix(token, continuePrefix))
	if err != nil || offset <= 0 || offset >= length {
		return 0, fmt.Errorf("invalid continue token %q", token)
	}
	return offset, nil
}
