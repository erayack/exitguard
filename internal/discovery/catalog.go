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

// Package discovery maintains the REST resource metadata used by scanners.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// DefaultRefreshInterval is the planned cadence for API discovery updates.
const DefaultRefreshInterval = 5 * time.Minute

// Client is the discovery operation required to build a catalog.
type Client interface {
	ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error)
}

// Version describes one served REST representation of a GroupResource.
type Version struct {
	Version    string
	Kind       string
	Namespaced bool
	verbs      []string
}

// Verbs returns the sorted operations exposed by this served representation.
func (v Version) Verbs() []string {
	return append([]string(nil), v.verbs...)
}

// Resource describes one listable/gettable GroupResource without duplicating versions.
// Its slice-backed metadata is established only by this package and remains immutable.
type Resource struct {
	GroupResource    schema.GroupResource
	PreferredVersion Version
	alternates       []Version
}

func newResource(groupResource schema.GroupResource, preferred Version, alternates []Version) Resource {
	resource := newResourceOwned(groupResource, cloneVersion(preferred), make([]Version, len(alternates)))
	for i := range alternates {
		resource.alternates[i] = cloneVersion(alternates[i])
	}
	return resource
}

// newResourceOwned is limited to construction paths that exclusively own all
// supplied slice backing until newSnapshot takes its detached copy.
func newResourceOwned(groupResource schema.GroupResource, preferred Version, alternates []Version) Resource {
	return Resource{GroupResource: groupResource, PreferredVersion: preferred, alternates: alternates}
}

// AlternateVersions returns a detached copy of the non-preferred representations.
func (r Resource) AlternateVersions() []Version {
	return append([]Version(nil), r.alternates...)
}

// Supports reports whether the selected preferred version exposes verb.
func (r Resource) Supports(verb string) bool {
	return slices.Contains(r.PreferredVersion.verbs, verb)
}

// OrderedVersions returns each served representation once, preferring requested when available.
func (r Resource) OrderedVersions(requested string) []Version {
	versions := make([]Version, 0, 1+len(r.alternates))
	appendVersion := func(candidate Version) {
		if slices.ContainsFunc(versions, func(existing Version) bool { return existing.Version == candidate.Version }) {
			return
		}
		versions = append(versions, candidate)
	}
	if requested != "" {
		if r.PreferredVersion.Version == requested {
			appendVersion(r.PreferredVersion)
		}
		for _, alternate := range r.alternates {
			if alternate.Version == requested {
				appendVersion(alternate)
			}
		}
	}
	appendVersion(r.PreferredVersion)
	for _, alternate := range r.alternates {
		appendVersion(alternate)
	}
	return versions
}

// EligibleForWildcard excludes high-churn resources from wildcard policy expansion.
func (r Resource) EligibleForWildcard() bool {
	gr := r.GroupResource
	return gr.Resource != "events" && (gr.Group != "coordination.k8s.io" || gr.Resource != "leases")
}

// Snapshot is an immutable point-in-time view of a catalog.
type Snapshot struct {
	resources map[schema.GroupResource]Resource
	ordered   []Resource
}

// Resources returns a sorted copy of all scan candidates.
func (s Snapshot) Resources() []Resource {
	return cloneResources(s.ordered)
}

// Resolve returns the immutable metadata for gr.
func (s Snapshot) Resolve(gr schema.GroupResource) (Resource, bool) {
	resource, found := s.resources[gr]
	return resource, found
}

// Len returns the number of unique GroupResources.
func (s Snapshot) Len() int {
	return len(s.resources)
}

// Catalog atomically publishes successful Kubernetes discovery snapshots.
type Catalog struct {
	client   Client
	interval time.Duration
	log      logr.Logger

	mu          sync.RWMutex
	snapshot    Snapshot
	lastSuccess time.Time
	lastErr     error
}

// NewCatalog creates a catalog. A zero interval selects the fixed five-minute cadence.
func NewCatalog(client Client, interval time.Duration, log logr.Logger) *Catalog {
	if interval == 0 {
		interval = DefaultRefreshInterval
	}
	return &Catalog{
		client:   client,
		interval: interval,
		log:      log,
		snapshot: Snapshot{resources: map[schema.GroupResource]Resource{}},
	}
}

// Start refreshes immediately, then at the configured cadence until ctx is canceled.
// Discovery failures are recorded but do not discard the last successful snapshot.
func (c *Catalog) Start(ctx context.Context) error {
	if c.client == nil {
		return errors.New("discovery client is required")
	}
	if c.interval <= 0 {
		return errors.New("discovery refresh interval must be positive")
	}

	c.refreshAndLog()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.refreshAndLog()
		}
	}
}

// Refresh performs one discovery attempt and publishes it only when fully successful.
func (c *Catalog) Refresh() error {
	if c.client == nil {
		err := errors.New("discovery client is required")
		c.recordError(err)
		discoveryRefreshes.WithLabelValues("error").Inc()
		return err
	}
	groups, lists, err := c.client.ServerGroupsAndResources()
	if err != nil {
		c.recordError(err)
		discoveryRefreshes.WithLabelValues("error").Inc()
		return fmt.Errorf("discover API resources: %w", err)
	}

	snapshot, err := buildSnapshot(groups, lists)
	if err != nil {
		c.recordError(err)
		discoveryRefreshes.WithLabelValues("error").Inc()
		return err
	}
	c.mu.Lock()
	c.snapshot = snapshot
	c.lastSuccess = time.Now()
	c.lastErr = nil
	c.mu.Unlock()
	discoveryRefreshes.WithLabelValues("success").Inc()
	discoveredResources.Set(float64(snapshot.Len()))
	return nil
}

// Snapshot returns an immutable copy of the latest successful catalog.
func (c *Catalog) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return newSnapshot(cloneResources(c.snapshot.ordered))
}

// LastResult reports the latest successful refresh time and latest error.
func (c *Catalog) LastResult() (time.Time, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSuccess, c.lastErr
}

func (c *Catalog) refreshAndLog() {
	if err := c.Refresh(); err != nil {
		c.log.Error(err, "refresh API discovery; retaining previous catalog")
		return
	}
	c.log.V(1).Info("refreshed API discovery", "resources", c.Snapshot().Len())
}

func (c *Catalog) recordError(err error) {
	c.mu.Lock()
	c.lastErr = err
	c.mu.Unlock()
}

func buildSnapshot(groups []*metav1.APIGroup, lists []*metav1.APIResourceList) (Snapshot, error) {
	preferences := discoveryPreferences(groups)
	versionsByResource := make(map[schema.GroupResource][]Version)
	for _, list := range lists {
		if list == nil {
			continue
		}
		groupVersion, err := schema.ParseGroupVersion(list.GroupVersion)
		if err != nil {
			return Snapshot{}, fmt.Errorf("parse discovered groupVersion %q: %w", list.GroupVersion, err)
		}
		for _, apiResource := range list.APIResources {
			if strings.Contains(apiResource.Name, "/") || !slices.Contains(apiResource.Verbs, "get") || !slices.Contains(apiResource.Verbs, "list") {
				continue
			}
			verbs := append([]string(nil), apiResource.Verbs...)
			sort.Strings(verbs)
			gr := groupVersion.WithResource(apiResource.Name).GroupResource()
			versionsByResource[gr] = append(versionsByResource[gr], Version{
				Version:    groupVersion.Version,
				Kind:       apiResource.Kind,
				Namespaced: apiResource.Namespaced,
				verbs:      verbs,
			})
		}
	}

	resources := make([]Resource, 0, len(versionsByResource))
	for gr, versions := range versionsByResource {
		orderVersions(versions, preferences[gr.Group])
		resources = append(resources, newResourceOwned(gr, versions[0], versions[1:]))
	}
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].GroupResource.String() < resources[j].GroupResource.String()
	})
	return newSnapshot(resources), nil
}

func discoveryPreferences(groups []*metav1.APIGroup) map[string]map[string]int {
	preferences := map[string]map[string]int{"": {"v1": 0}}
	for _, group := range groups {
		if group == nil {
			continue
		}
		ranks := make(map[string]int, len(group.Versions)+1)
		next := 0
		if group.PreferredVersion.Version != "" {
			ranks[group.PreferredVersion.Version] = next
			next++
		}
		for _, version := range group.Versions {
			if _, exists := ranks[version.Version]; exists {
				continue
			}
			ranks[version.Version] = next
			next++
		}
		preferences[group.Name] = ranks
	}
	return preferences
}

func orderVersions(versions []Version, preference map[string]int) {
	const unknownRank = int(^uint(0) >> 1)
	sort.SliceStable(versions, func(i, j int) bool {
		left, leftFound := preference[versions[i].Version]
		if !leftFound {
			left = unknownRank
		}
		right, rightFound := preference[versions[j].Version]
		if !rightFound {
			right = unknownRank
		}
		if left != right {
			return left < right
		}
		return versions[i].Version < versions[j].Version
	})
}

func newSnapshot(resources []Resource) Snapshot {
	byResource := make(map[schema.GroupResource]Resource, len(resources))
	for _, resource := range resources {
		resource = cloneResource(resource)
		byResource[resource.GroupResource] = resource
	}
	return Snapshot{resources: byResource, ordered: cloneResources(resources)}
}

func cloneResources(resources []Resource) []Resource {
	cloned := make([]Resource, len(resources))
	for i := range resources {
		cloned[i] = cloneResource(resources[i])
	}
	return cloned
}

func cloneResource(resource Resource) Resource {
	return newResource(resource.GroupResource, resource.PreferredVersion, resource.alternates)
}

func cloneVersion(version Version) Version {
	version.verbs = append([]string(nil), version.verbs...)
	return version
}
